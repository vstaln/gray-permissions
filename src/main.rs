//! `permissions` sidecar: approval gate over the gray wire v1. No tools;
//! claims `tool/before` + `/permissions` (+ `/perms`, `/access` aliases).
//! Asking goes through `host/ask` (same contract as `gray-questions`):
//! empty/timeout answers deny (fail closed).
//!
//! The prompt mirrors Devin CLI: Allow (Once/Session/Project/Always scope
//! slider), Bypass mode, Deny. Session grants are memory-only; Project and
//! Always persist explicit allow rules to `.gray/permissions.json` in the
//! project and the user's home. Deny and Esc cancel the whole turn via the
//! `cancel` verdict; `e` edits a bash command and runs it as `modify`.
//! The mode itself never persists: every session starts in `auto` (or the
//! `GRAY_PERMISSION`/`GRAY_PERMISSIONS` launch env).

use gray_permissions::{
    APPROVAL_QUESTION_ID, ApprovalGate, LABEL_DENY, MODE_FULL, Outcome, Scope, approval_question,
    call_label, decide_from_answers, manifest, run_permissions_command, save_rule,
};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// How long `tool/before` waits for a `host/ask` reply. Must sit under
/// the host's ask-gated outer deadline (330s).
const ASK_TTL: Duration = Duration::from_secs(300);

type Pending = Arc<Mutex<HashMap<String, mpsc::Sender<serde_json::Value>>>>;

fn load_mode() -> String {
    for key in ["GRAY_PERMISSION", "GRAY_PERMISSIONS"] {
        if let Ok(v) = std::env::var(key)
            && !v.trim().is_empty()
        {
            return v;
        }
    }
    gray_permissions::MODE_AUTO.to_string()
}

fn next_id(counter: &Arc<Mutex<u64>>) -> String {
    let mut n = counter.lock().expect("id counter");
    *n += 1;
    format!("p{n}")
}

fn tool_before(
    out: &Arc<Mutex<std::io::Stdout>>,
    pending: &Pending,
    counter: &Arc<Mutex<u64>>,
    gate: &ApprovalGate,
    params: &serde_json::Value,
) -> serde_json::Value {
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params.get("args").cloned().unwrap_or(serde_json::json!({}));
    let cwd = params
        .get("session")
        .and_then(|s| s.get("cwd"))
        .and_then(|c| c.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if name.is_empty() {
        return serde_json::json!({"decision": "deny", "reason": "empty tool name"});
    }
    match gate.check_cached(name, &args, &cwd) {
        Ok(true) => return serde_json::json!({"decision": "allow"}),
        Err(reason) => return serde_json::json!({"decision": "deny", "reason": reason}),
        Ok(false) => {}
    }
    // Nobody at a screen (`gray -p`: subagents, gateway turns, scripts):
    // run it, as the old core gate did. Static Deny verdicts (read-only
    // mode) already returned above, so they still hold headless.
    static HEADLESS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *HEADLESS.get_or_init(gray_permissions::host_is_headless) {
        return serde_json::json!({"decision": "allow"});
    }
    let label = call_label(name, &args);
    let q = approval_question(name, &label, &cwd);
    let id = next_id(counter);
    let (tx, rx) = mpsc::channel();
    pending.lock().expect("pending").insert(id.clone(), tx);
    let req = serde_json::json!({
        "id": id,
        "method": "host/ask",
        "params": {
            "questions": [q],
            "blocking": true,
        },
    });
    {
        let mut o = out.lock().expect("stdout");
        let _ = writeln!(o, "{req}");
        let _ = o.flush();
    }
    let picked: Vec<String> = match rx.recv_timeout(ASK_TTL) {
        Ok(result) => {
            if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
                pending.lock().expect("pending").remove(&id);
                // Headless host (`gray -p`, subagents, gateway child turns):
                // gray installs no ask service, so there is nobody to ask.
                // Match the old core gate — prompts are an interactive-TUI
                // feature, and a headless run was launched by someone who
                // already chose to run it. Static Deny verdicts (read-only
                // mode) never reach here, so they still hold.
                if headless_host(err) {
                    return serde_json::json!({"decision": "allow"});
                }
                return serde_json::json!({"decision": "deny", "reason": "approval prompt unavailable"});
            }
            result
                .get("answers")
                .and_then(|a| a.get(APPROVAL_QUESTION_ID))
                .and_then(|e| e.get("answers"))
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        }
        Err(_) => {
            pending.lock().expect("pending").remove(&id);
            return serde_json::json!({"decision": "deny", "reason": "approval timed out"});
        }
    };
    match decide_from_answers(&picked) {
        Outcome::Allow => serde_json::json!({"decision": "allow"}),
        Outcome::AllowSession => {
            gate.remember(name, &args, &cwd);
            serde_json::json!({"decision": "allow"})
        }
        o @ (Outcome::AllowProject | Outcome::AllowAlways) => {
            let scope = if matches!(o, Outcome::AllowProject) {
                Scope::Project
            } else {
                Scope::User
            };
            if let Err(e) = save_rule(scope, name, &args, &cwd) {
                eprintln!(
                    "permissions: could not persist rule ({e}); remembered for session instead"
                );
                gate.remember(name, &args, &cwd);
            }
            serde_json::json!({"decision": "allow"})
        }
        Outcome::Bypass => {
            gate.set_mode(MODE_FULL);
            serde_json::json!({"decision": "allow"})
        }
        Outcome::Edit(text) => {
            if name != "bash" {
                return serde_json::json!({
                    "decision": "deny",
                    "reason": format!("edited arguments unsupported for {name}"),
                });
            }
            let mut rewritten = args.clone();
            rewritten["command"] = serde_json::json!(text);
            serde_json::json!({"decision": "modify", "args": rewritten})
        }
        Outcome::DenyWith(note) => serde_json::json!({
            "decision": "deny",
            "reason": format!("{name} declined by user: {note}"),
        }),
        // Deny row or Esc: stop the turn, like Devin — do NOT re-attempt
        // via write/edit/bash workarounds.
        Outcome::Reject => serde_json::json!({
            "decision": "cancel",
            "reason": format!("{name} declined by user ({LABEL_DENY}) — turn stopped"),
        }),
    }
}

/// Whether a `host/ask` error means the host has no ask service at all
/// (non-interactive run), as opposed to a broken prompt in a live TUI.
fn headless_host(err: &str) -> bool {
    err.contains("ask service not installed")
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest());
        return;
    }
    let gate = ApprovalGate::new(&load_mode());
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let counter = Arc::new(Mutex::new(0u64));

    let (work_tx, work_rx) = mpsc::channel::<serde_json::Value>();
    let reader_pending = pending.clone();
    let reader = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            // `plugin/shutdown` is a notification (no id): stop reading so
            // the work channel closes and the main loop exits. See
            // gray-questions for the TTL rationale.
            if v.get("method").and_then(|m| m.as_str()) == Some("plugin/shutdown") {
                break;
            }
            if let Some(id) = v.get("id").and_then(|i| i.as_str())
                && v.get("method").is_none()
                && let Some(tx) = reader_pending.lock().expect("pending").remove(id)
            {
                let _ = tx.send(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
                continue;
            }
            if v.get("id").and_then(|i| i.as_u64()).is_none() {
                continue;
            };
            if work_tx.send(v).is_err() {
                break;
            }
        }
    });

    for req in work_rx {
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(serde_json::json!(0));
        let params = req
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let reply = match method {
            "plugin/manifest" => serde_json::json!({ "id": id, "result": manifest() }),
            "tool/before" => serde_json::json!({
                "id": id,
                "result": tool_before(&stdout, &pending, &counter, &gate, &params),
            }),
            "tool/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                serde_json::json!({ "id": id, "result": {
                    "content": format!("unknown tool: {name}"),
                    "is_error": true,
                }})
            }
            "command/run" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if gray_permissions::COMMANDS.contains(&name) {
                    let argv: Vec<String> = params
                        .get("argv")
                        .and_then(|a| a.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|e| e.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let text = run_permissions_command(&gate, &argv);
                    serde_json::json!({ "id": id, "result": { "text": text } })
                } else {
                    serde_json::json!({ "id": id, "error": {
                        "code": -32601,
                        "message": format!("command not found: {name}"),
                    }})
                }
            }
            _ => serde_json::json!({ "id": id, "error": {
                "code": -32601,
                "message": format!("method not found: {method}"),
            }}),
        };
        let mut o = stdout.lock().expect("stdout");
        let _ = writeln!(o, "{reply}");
        let _ = o.flush();
    }
    let _ = reader.join();
}

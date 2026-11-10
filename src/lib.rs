//! `gray_permissions` shared core: approval modes, static verdicts, and the
//! `/permissions` command model. The sidecar binary (`src/main.rs`) and any
//! host-side helpers must agree on these; this lib is the single definition.
//!
//! The prompt mirrors Devin CLI: Allow (Once / Session / Project / Always
//! scope slider), Bypass mode, Deny. Deny and Esc cancel the turn via the
//! `cancel` verdict; `e` edits the command and ships it back as `modify`.
//! Project rules persist to `<cwd>/.gray/permissions.json`, Always rules to
//! `~/.gray/permissions.json`.
//!
//! History: reshaped from gray's former `crates/gray-core/src/approvals.rs`
//! as a sidecar: the plugin owns policy, the host owns user I/O via
//! `host/ask` (owned by the `gray-questions` contract).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Codex approval preset ids, reused as gray's on-disk mode strings.
pub const MODE_READ_ONLY: &str = "read-only";
pub const MODE_AUTO: &str = "auto";
pub const MODE_FULL: &str = "full";

/// Plugin name claimed in `plugin/manifest`.
pub const PLUGIN_NAME: &str = "permissions";
/// Protocol version claimed in `plugin/manifest`.
pub const PROTOCOL: &str = "1.1";
/// Slash commands claimed in `plugin/manifest`.
pub const COMMANDS: &[&str] = &["/permissions", "/perms", "/access"];
/// Hook claimed in `plugin/manifest`.
pub const HOOK_TOOL_BEFORE: &str = "tool/before";

/// Per-call verdict the gate can return without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(&'static str),
    Ask,
}

/// Where a picked scope persists its rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `<cwd>/.gray/permissions.json`
    Project,
    /// `~/.gray/permissions.json`
    User,
}

/// User decision on an asked call (Devin-CLI parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Allow, scope Once.
    Allow,
    /// Allow + remember for the session.
    AllowSession,
    /// Allow + persist a rule to the project file.
    AllowProject,
    /// Allow + persist a rule to the user file.
    AllowAlways,
    /// Switch the mode to `full` and allow.
    Bypass,
    /// `e`-edited subject: run the tool with modified args.
    Edit(String),
    /// A typed note: deny the call with the note as the reason; the turn
    /// continues so the model can adapt.
    DenyWith(String),
    /// Deny row, Esc, or no answer: cancel the whole turn.
    Reject,
}

/// One question row sent to `host/ask` for an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskQuestion {
    pub id: String,
    pub header: String,
    /// "Allow {tool}?" then the whole command or path on the next lines.
    pub question: String,
    /// Dim context under the subject (the working directory).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub options: Vec<AskOption>,
    /// The answer is exactly one of the options: the host adds no free-form
    /// "Other" row.
    #[serde(default)]
    pub no_other: bool,
    /// `e` opens the subject for editing before confirm.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub editable: bool,
}

/// One option row sent to `host/ask` for an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskOption {
    pub label: String,
    pub description: String,
    /// Scope slider values cycled with left/right ("Once", "Session", ...).
    /// The picked one ships in the answers as `scope: <label>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Exact labels rendered above (display text is untrusted input:
/// substring matching once escalated any note containing "always" into
/// session-wide memory — kept from the original).
pub const LABEL_ALLOW: &str = "Allow";
pub const LABEL_BYPASS: &str = "Bypass mode";
pub const LABEL_DENY: &str = "Deny";

/// Scope slider values on the Allow row, in cycle order (Devin parity).
pub const SCOPES: &[&str] = &["Once", "Session", "Project", "Always"];

pub const APPROVAL_QUESTION_ID: &str = "tool-approval";

/// Session-scoped memory of accepted calls (codex `with_cached_approval`).
#[derive(Debug, Default)]
pub struct ApprovalCache {
    paths: Mutex<HashSet<PathBuf>>,
    commands: Mutex<HashSet<String>>,
}

impl ApprovalCache {
    pub fn remember_path(&self, path: PathBuf) {
        let _ = self.paths.lock().map(|mut g| g.insert(path));
    }

    pub fn remembered_path(&self, path: &Path) -> bool {
        self.paths.lock().map(|g| g.contains(path)).unwrap_or(false)
    }

    /// Raw command bytes are the cache identity: any normalization risks
    /// approving a different shell program. Different bytes re-ask.
    pub fn remember_command(&self, command: String) {
        let _ = self.commands.lock().map(|mut g| g.insert(command));
    }

    pub fn remembered_command(&self, command: &str) -> bool {
        self.commands
            .lock()
            .map(|g| g.contains(command))
            .unwrap_or(false)
    }
}

/// Approval mode + session memory. `Clone` shares both across calls.
#[derive(Debug, Clone)]
pub struct ApprovalGate {
    mode: Arc<Mutex<String>>,
    cache: Arc<ApprovalCache>,
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new(MODE_AUTO.to_string())),
            cache: Arc::new(ApprovalCache::default()),
        }
    }
}

impl ApprovalGate {
    pub fn new(mode: &str) -> Self {
        let gate = Self::default();
        gate.set_mode(mode);
        gate
    }

    pub fn mode(&self) -> String {
        self.mode
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Sets the mode; unknown values fall back to `auto` (fail safe).
    pub fn set_mode(&self, mode: &str) {
        let clean = normalize_mode(mode).unwrap_or(MODE_AUTO);
        if let Ok(mut g) = self.mode.lock() {
            *g = clean.to_string();
        }
    }

    /// Static verdict + session memory, without asking. `Ok(true)` = run,
    /// `Ok(false)` = must ask, `Err(msg)` = deny.
    pub fn check_cached(
        &self,
        tool: &str,
        args: &serde_json::Value,
        cwd: &Path,
    ) -> Result<bool, String> {
        match verdict(&self.mode(), tool, args, cwd) {
            Verdict::Allow => Ok(true),
            Verdict::Deny(msg) => Err(msg.to_string()),
            Verdict::Ask => {
                let rules = load_rules(cwd);
                if rules.allow(tool, args, cwd) {
                    return Ok(true);
                }
                if (tool == "write" || tool == "edit")
                    && let Some(p) = tool_path(args)
                {
                    let full = if Path::new(&p).is_absolute() {
                        PathBuf::from(&p)
                    } else {
                        cwd.join(&p)
                    };
                    if self.cache.remembered_path(&full) {
                        return Ok(true);
                    }
                }
                if tool == "bash"
                    && let Some(cmd) = args.get("command").and_then(|v| v.as_str())
                    && self.cache.remembered_command(cmd)
                {
                    return Ok(true);
                }
                Ok(false)
            }
        }
    }

    /// Remember an accepted call for the rest of the session.
    pub fn remember(&self, tool: &str, args: &serde_json::Value, cwd: &Path) {
        if (tool == "write" || tool == "edit")
            && let Some(p) = tool_path(args)
        {
            let full = if Path::new(&p).is_absolute() {
                PathBuf::from(&p)
            } else {
                cwd.join(&p)
            };
            self.cache.remember_path(full);
        }
        if tool == "bash"
            && let Some(cmd) = args.get("command").and_then(|v| v.as_str())
        {
            self.cache.remember_command(cmd.to_string());
        }
    }
}

/// Parses a mode string; `None` when unknown.
pub fn normalize_mode(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().replace(' ', "-").as_str() {
        "read-only" | "readonly" | "read_only" | "ro" => Some(MODE_READ_ONLY),
        "auto" | "ask" | "default" | "ask-for-approval" | "workspace" => Some(MODE_AUTO),
        "full" | "full-access" | "full_access" | "never" | "yolo" => Some(MODE_FULL),
        _ => None,
    }
}

/// One row of the `/permissions` picker: (mode id, label, description),
/// mirroring codex's preset label + description copy.
pub fn permission_modes() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            MODE_AUTO,
            "Ask for approval",
            "Read and edit files in the workspace. Every command and anything outside the workspace asks for approval.",
        ),
        (
            MODE_FULL,
            "Full Access",
            "No approval prompts: edits and commands run unattended. Exercise caution.",
        ),
        (
            MODE_READ_ONLY,
            "Read Only",
            "Read-only tools only: edits, commands, and network access are denied.",
        ),
    ]
}

/// Extracts the target path from tool args (same alias set the tools use).
pub fn tool_path(args: &serde_json::Value) -> Option<String> {
    args.get("path")
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("file"))
        .or_else(|| args.get("filename"))
        .or_else(|| args.get("target"))
        .or_else(|| args.get("destination"))
        .or_else(|| args.get("target_file"))
        .or_else(|| args.get("targetFile"))
        .or_else(|| args.get("TargetFile"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// True when `path` resolves inside `cwd` (nearest-existing-ancestor walk
/// with symlink resolution; unresolvable returns false — uncertainty asks).
pub fn path_in_cwd(cwd: &Path, path: &str) -> bool {
    use std::ffi::OsString;
    let joined: PathBuf = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };
    let Ok(root) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let mut ancestor: &Path = &joined;
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        if ancestor.exists() {
            break;
        }
        match ancestor.file_name() {
            Some(name) => {
                missing.push(name.to_os_string());
                match ancestor.parent() {
                    Some(parent) => ancestor = parent,
                    None => return false,
                }
            }
            None => return false,
        }
    }
    let Ok(mut target) = std::fs::canonicalize(ancestor) else {
        return false;
    };
    for comp in missing.iter().rev() {
        let p = Path::new(comp);
        if p.components().count() != 1
            || !matches!(p.components().next(), Some(std::path::Component::Normal(_)))
        {
            return false;
        }
        target.push(comp);
    }
    target.starts_with(root)
}

/// Static verdict for a tool call: no asking, no session memory yet.
pub fn verdict(mode: &str, tool: &str, args: &serde_json::Value, cwd: &Path) -> Verdict {
    match normalize_mode(mode).unwrap_or(MODE_AUTO) {
        MODE_FULL => Verdict::Allow,
        MODE_READ_ONLY => match tool {
            "read" | "ls" | "find" | "grep" | "skill" | "request_user_input" => Verdict::Allow,
            _ => Verdict::Deny("read-only mode: mutating tools are disabled"),
        },
        _ => match tool {
            "read" | "ls" | "find" | "grep" | "skill" | "request_user_input" => Verdict::Allow,
            "write" | "edit" => match tool_path(args) {
                Some(p) if path_in_cwd(cwd, &p) => Verdict::Allow,
                Some(_) => Verdict::Ask,
                None => Verdict::Ask,
            },
            "bash" => Verdict::Ask,
            // Fail closed: unknown/sidecar tools prompt, never silent Allow.
            _ => Verdict::Ask,
        },
    }
}

/// Human name for a tool in the prompt, matching gray's tool rows:
/// `mcp__filmcraft__render_frame` -> `filmcraft · render frame`.
pub fn display_tool_name(tool: &str) -> String {
    if let Some((server, name)) = tool
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split_once("__"))
        .filter(|(s, n)| !s.is_empty() && !n.is_empty())
    {
        return format!("{server} \u{b7} {}", name.replace(['_', '-'], " "));
    }
    tool.to_string()
}

/// Build the `host/ask` question for an approval. Full target, no
/// truncation: a prompt hiding the tail of a command approves something
/// the user did not see. Mirrors the Devin CLI prompt: Allow with a
/// Once/Session/Project/Always scope slider, Bypass mode, Deny; `e` edits
/// the command (bash only).
pub fn approval_question(tool: &str, label: &str, cwd: &Path) -> AskQuestion {
    AskQuestion {
        id: APPROVAL_QUESTION_ID.to_string(),
        header: "Allow?".to_string(),
        question: format!("Allow {}?\n{label}", display_tool_name(tool)),
        detail: format!("Working directory: {}", cwd.display()),
        no_other: true,
        editable: tool == "bash",
        options: vec![
            AskOption {
                label: LABEL_ALLOW.to_string(),
                description: "Run it.".to_string(),
                scopes: SCOPES.iter().map(|s| s.to_string()).collect(),
            },
            AskOption {
                label: LABEL_BYPASS.to_string(),
                description:
                    "Run this and stop asking: every tool is allowed for the rest of the session."
                        .to_string(),
                scopes: Vec::new(),
            },
            AskOption {
                label: LABEL_DENY.to_string(),
                description: "Reject it and stop the turn.".to_string(),
                scopes: Vec::new(),
            },
        ],
    }
}

/// Map a `host/ask` result to an [`Outcome`]. Fail-closed: anything but an
/// explicit Allow/Bypass rejects (Esc ships empty answers, like codex —
/// and like Devin it cancels the turn rather than answering the call).
pub fn decide_from_answers(answers: &[String]) -> Outcome {
    // An `e` edit wins over the highlighted row (Devin runs the edited
    // command on enter).
    if let Some(e) = answers.iter().find_map(|a| a.strip_prefix("edited: ")) {
        let e = e.trim();
        if !e.is_empty() {
            return Outcome::Edit(e.to_string());
        }
    }
    // A typed note denies with that note as the reason: the model sees it
    // and adapts, which beats silently stopping the turn.
    if let Some(n) = answers.iter().find_map(|a| a.strip_prefix("user_note: ")) {
        let n = n.trim();
        if !n.is_empty() {
            return Outcome::DenyWith(n.to_string());
        }
    }
    let has = |l: &str| answers.iter().any(|a| a == l);
    if has(LABEL_BYPASS) {
        return Outcome::Bypass;
    }
    if has(LABEL_ALLOW) {
        let scope = answers
            .iter()
            .find_map(|a| a.strip_prefix("scope: "))
            .unwrap_or("Once");
        return match scope {
            s if s.eq_ignore_ascii_case("session") => Outcome::AllowSession,
            s if s.eq_ignore_ascii_case("project") => Outcome::AllowProject,
            s if s.eq_ignore_ascii_case("always") => Outcome::AllowAlways,
            _ => Outcome::Allow,
        };
    }
    Outcome::Reject
}

/// Short human label for a tool call (command or path), for the ask prompt.
pub fn call_label(tool: &str, args: &serde_json::Value) -> String {
    if tool == "bash" {
        return args
            .get("command")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("(empty command)")
            .to_string();
    }
    tool_path(args).unwrap_or_else(|| args.to_string())
}

/// Handle `/permissions` argv: `[]` prints mode + usage; `[mode]` sets it.
pub fn run_permissions_command(gate: &ApprovalGate, argv: &[String]) -> String {
    match argv.first().map(|s| s.as_str()) {
        None => {
            let mut out = format!("permissions: {}\n", gate.mode());
            out.push_str("usage: /permissions <read-only|auto|full>\n");
            for (id, label, desc) in permission_modes() {
                out.push_str(&format!("  {id} — {label}: {desc}\n"));
            }
            out
        }
        Some(mode) => match normalize_mode(mode) {
            Some(clean) => {
                gate.set_mode(clean);
                format!("permissions: {clean}")
            }
            None => format!("unknown mode {mode:?} — usage: /permissions <read-only|auto|full>"),
        },
    }
}

/// The `plugin/manifest` result value.
/// Whether a gray host argv is a one-shot print run (`-p`/`--print`/
/// `--prompt`): subagents, gateway child turns and scripts. Such a host has
/// nobody at a screen to approve anything.
pub fn is_print_argv(argv: &[String]) -> bool {
    for a in argv.iter().skip(1) {
        if a == "--" {
            return false;
        }
        if a == "-p"
            || a == "--print"
            || a == "--prompt"
            || a.starts_with("--print=")
            || a.starts_with("--prompt=")
            || a.starts_with("-p=")
        {
            return true;
        }
    }
    false
}

/// Whether the gray host that spawned this plugin is headless. Linux reads
/// the parent's argv from /proc; elsewhere this is `false`, so the gate keeps
/// failing closed.
pub fn host_is_headless() -> bool {
    #[cfg(target_os = "linux")]
    {
        let ppid = std::os::unix::process::parent_id();
        if let Ok(raw) = std::fs::read(format!("/proc/{ppid}/cmdline")) {
            let argv: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            return is_print_argv(&argv);
        }
    }
    false
}

pub fn manifest() -> serde_json::Value {
    serde_json::json!({
        "name": PLUGIN_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": PROTOCOL,
        "tools": [],
        "commands": COMMANDS,
        "hooks": [HOOK_TOOL_BEFORE],
        // `host/ask` is a gated host surface: undeclared, gray refuses it
        // (`capability_not_granted`) and every Ask verdict became a deny.
        "capabilities": ["host.ask"],
    })
}

/// Persisted allow rules from the Project and Always scopes. Merged view
/// of `~/.gray/permissions.json` (user) and `<cwd>/.gray/permissions.json`
/// (project). File format:
/// `{ "allow": { "commands": [...], "paths": [...], "tools": [...] } }`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleSet {
    /// Bash command prefixes; a call matches on equality or `rule + " "`.
    pub commands: Vec<String>,
    /// Resolved write/edit paths; exact match.
    pub paths: Vec<String>,
    /// Tool names always allowed (used for tools without a path/command).
    pub tools: Vec<String>,
}

impl RuleSet {
    /// Whether a persisted rule already allows this call.
    pub fn allow(&self, tool: &str, args: &serde_json::Value, cwd: &Path) -> bool {
        if self.tools.iter().any(|t| t == tool) {
            return true;
        }
        if tool == "bash"
            && let Some(cmd) = args.get("command").and_then(|v| v.as_str())
        {
            let cmd = cmd.trim();
            return self
                .commands
                .iter()
                .any(|r| cmd == r || cmd.starts_with(&format!("{r} ")));
        }
        if (tool == "write" || tool == "edit")
            && let Some(p) = tool_path(args)
        {
            let full = resolve_in(cwd, &p);
            return self.paths.iter().any(|r| full == Path::new(r));
        }
        false
    }
}

fn rules_path(scope: Scope, cwd: &Path) -> PathBuf {
    match scope {
        Scope::Project => cwd.join(".gray").join("permissions.json"),
        Scope::User => std::env::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gray")
            .join("permissions.json"),
    }
}

fn read_rules(path: &Path) -> RuleSet {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return RuleSet::default();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return RuleSet::default();
    };
    let list = |key: &str| -> Vec<String> {
        v.get("allow")
            .and_then(|a| a.get(key))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    RuleSet {
        commands: list("commands"),
        paths: list("paths"),
        tools: list("tools"),
    }
}

/// Rules visible to `cwd`: user file then project file merged.
pub fn load_rules(cwd: &Path) -> RuleSet {
    let mut r = read_rules(&rules_path(Scope::User, cwd));
    let p = read_rules(&rules_path(Scope::Project, cwd));
    r.commands.extend(p.commands);
    r.paths.extend(p.paths);
    r.tools.extend(p.tools);
    r
}

fn resolve_in(cwd: &Path, p: &str) -> PathBuf {
    if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        cwd.join(p)
    }
}

/// Persist an allow rule for this call in the scope's file. Bash stores
/// the command (prefix-matched later), write/edit the resolved path, and
/// anything else the bare tool name. The file is re-read on every check,
/// so the rule takes effect immediately.
pub fn save_rule(
    scope: Scope,
    tool: &str,
    args: &serde_json::Value,
    cwd: &Path,
) -> std::io::Result<()> {
    let path = rules_path(scope, cwd);
    let mut rules = read_rules(&path);
    match tool {
        "bash" => {
            if let Some(c) = args.get("command").and_then(|v| v.as_str()) {
                let c = c.trim().to_string();
                if !c.is_empty() && !rules.commands.contains(&c) {
                    rules.commands.push(c);
                }
            }
        }
        "write" | "edit" => {
            if let Some(p) = tool_path(args) {
                let full = resolve_in(cwd, &p).display().to_string();
                if !rules.paths.contains(&full) {
                    rules.paths.push(full);
                }
            }
        }
        _ => {
            if !tool.is_empty() && !rules.tools.iter().any(|t| t == tool) {
                rules.tools.push(tool.to_string());
            }
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let out = serde_json::json!({
        "allow": {
            "commands": rules.commands,
            "paths": rules.paths,
            "tools": rules.tools,
        }
    });
    std::fs::write(&path, serde_json::to_string_pretty(&out)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cwd() -> PathBuf {
        PathBuf::from("/work/proj")
    }

    #[test]
    fn approval_question_matches_the_devin_prompt_shape() {
        let q = serde_json::to_value(approval_question("bash", "echo hi\nls", &cwd())).unwrap();
        assert_eq!(q["question"], "Allow bash?\necho hi\nls");
        assert_eq!(q["detail"], "Working directory: /work/proj");
        assert_eq!(q["no_other"], true);
        assert_eq!(q["editable"], true);
        let labels: Vec<&str> = q["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, ["Allow", "Bypass mode", "Deny"]);
        let scopes: Vec<&str> = q["options"][0]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(scopes, ["Once", "Session", "Project", "Always"]);
        // Non-bash tools get no `e` editor.
        let q = serde_json::to_value(approval_question("write", "a.rs", &cwd())).unwrap();
        assert!(q.get("editable").is_none() || q["editable"] == false);
    }

    #[test]
    fn manifest_declares_the_ask_capability() {
        assert_eq!(manifest()["capabilities"], json!(["host.ask"]));
    }

    #[test]
    fn print_flags_mark_a_headless_host() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_print_argv(&argv(&["gray", "-p", "hi"])));
        assert!(is_print_argv(&argv(&[
            "/x/gray", "--model", "m", "--print", "hi"
        ])));
        assert!(is_print_argv(&argv(&["gray", "--prompt=hi"])));
        assert!(is_print_argv(&argv(&["gray", "--bare", "-p", "-"])));
        assert!(!is_print_argv(&argv(&["gray"])));
        assert!(!is_print_argv(&argv(&["gray", "-r", "sess"])));
        assert!(!is_print_argv(&argv(&["gray", "--", "-p"])));
    }

    #[test]
    fn normalize_accepts_aliases_and_rejects_unknown() {
        assert_eq!(normalize_mode("read-only"), Some(MODE_READ_ONLY));
        assert_eq!(normalize_mode("RO"), Some(MODE_READ_ONLY));
        assert_eq!(normalize_mode("auto"), Some(MODE_AUTO));
        assert_eq!(normalize_mode("Full Access"), Some(MODE_FULL));
        assert_eq!(normalize_mode("yolo"), Some(MODE_FULL));
        assert_eq!(normalize_mode("bogus"), None);
    }

    #[test]
    fn full_allows_everything() {
        for tool in ["read", "write", "edit", "bash", "schedule_task", "whatever"] {
            assert_eq!(
                verdict("full", tool, &json!({}), &cwd()),
                Verdict::Allow,
                "{tool}"
            );
        }
    }

    #[test]
    fn read_only_denies_mutations_but_allows_reads() {
        for tool in ["read", "ls", "find", "grep", "skill", "request_user_input"] {
            assert_eq!(
                verdict("read-only", tool, &json!({}), &cwd()),
                Verdict::Allow,
                "{tool}"
            );
        }
        for tool in ["write", "edit", "bash", "schedule_task"] {
            assert!(
                matches!(
                    verdict("read-only", tool, &json!({}), &cwd()),
                    Verdict::Deny(_)
                ),
                "{tool}"
            );
        }
    }

    #[test]
    fn auto_verdict_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let existing = work.join("a.rs");
        std::fs::write(&existing, "x").unwrap();
        assert_eq!(verdict("auto", "read", &json!({}), &work), Verdict::Allow);
        assert_eq!(
            verdict("auto", "write", &json!({"path": "a.rs"}), &work),
            Verdict::Allow
        );
        assert_eq!(
            verdict("auto", "bash", &json!({"command": "ls"}), &cwd()),
            Verdict::Ask
        );
        assert_eq!(verdict("auto", "write", &json!({}), &work), Verdict::Ask);
        assert_eq!(
            verdict("auto", "write", &json!({"path": "/etc/passwd"}), &work),
            Verdict::Ask
        );
        assert_eq!(
            verdict("auto", "schedule_task", &json!({}), &cwd()),
            Verdict::Ask
        );
    }

    #[test]
    fn unknown_tools_fail_closed_in_auto() {
        for tool in ["whatever", "sidecar_plugin_tool", "schedule_task", ""] {
            assert_eq!(
                verdict("auto", tool, &json!({}), &cwd()),
                Verdict::Ask,
                "{tool} must prompt, never silent Allow"
            );
        }
    }

    #[test]
    fn cached_gate_remembers_session_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let gate = ApprovalGate::new("auto");
        // bash always asks the first time…
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls"}), &work),
            Ok(false)
        );
        // …until remembered.
        gate.remember("bash", &json!({"command": "ls"}), &work);
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls"}), &work),
            Ok(true)
        );
        // Different bytes re-ask.
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls  "}), &work),
            Ok(false)
        );
    }

    #[test]
    fn decide_maps_devin_scopes_edits_and_notes() {
        assert_eq!(decide_from_answers(&["Allow".into()]), Outcome::Allow);
        assert_eq!(
            decide_from_answers(&["Allow".into(), "scope: Session".into()]),
            Outcome::AllowSession
        );
        assert_eq!(
            decide_from_answers(&["Allow".into(), "scope: Project".into()]),
            Outcome::AllowProject
        );
        assert_eq!(
            decide_from_answers(&["Allow".into(), "scope: Always".into()]),
            Outcome::AllowAlways
        );
        assert_eq!(
            decide_from_answers(&["Bypass mode".into()]),
            Outcome::Bypass
        );
        assert_eq!(decide_from_answers(&["Deny".into()]), Outcome::Reject);
        // Esc ships empty answers → reject (cancels the turn, Devin parity).
        assert_eq!(decide_from_answers(&[]), Outcome::Reject);
        // `e` edit wins over the highlighted row.
        assert_eq!(
            decide_from_answers(&["Allow".into(), "edited: git diff".into()]),
            Outcome::Edit("git diff".into())
        );
        // A typed note denies with it as the reason — and still cannot
        // escalate (the old "always" substring bug class).
        assert_eq!(
            decide_from_answers(&["user_note: always do this".into()]),
            Outcome::DenyWith("always do this".into())
        );
    }

    #[test]
    fn rules_match_prefixes_paths_and_tool_names() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let rules = RuleSet {
            commands: vec!["git status".into(), "ls".into()],
            paths: vec![work.join("a.rs").display().to_string()],
            tools: vec!["schedule_task".into()],
        };
        assert!(rules.allow("bash", &json!({"command": "git status"}), &work));
        assert!(rules.allow("bash", &json!({"command": "git status -s"}), &work));
        assert!(rules.allow("bash", &json!({"command": "ls -la"}), &work));
        assert!(!rules.allow("bash", &json!({"command": "lsd"}), &work));
        assert!(!rules.allow("bash", &json!({"command": "git push"}), &work));
        assert!(rules.allow("write", &json!({"path": "a.rs"}), &work));
        assert!(!rules.allow("write", &json!({"path": "b.rs"}), &work));
        assert!(rules.allow("schedule_task", &json!({}), &work));
        assert!(!rules.allow("bash", &json!({}), &work));
    }

    #[test]
    fn save_rule_persists_and_load_rules_merges() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("proj");
        std::fs::create_dir_all(&work).unwrap();
        save_rule(
            Scope::Project,
            "bash",
            &json!({"command": "cargo build"}),
            &work,
        )
        .unwrap();
        // The project file holds exactly the saved rule; the merged set
        // also carries whatever the real user file has, so only check
        // membership there.
        assert_eq!(
            read_rules(&rules_path(Scope::Project, &work)).commands,
            ["cargo build"]
        );
        assert!(
            load_rules(&work)
                .commands
                .iter()
                .any(|c| c == "cargo build")
        );
        let raw = std::fs::read_to_string(work.join(".gray/permissions.json")).unwrap();
        assert!(raw.contains("cargo build"));
    }

    #[test]
    fn manifest_shape() {
        let m = manifest();
        assert_eq!(m["name"], "permissions");
        assert_eq!(m["protocol"], "1.1");
        assert!(
            m["commands"]
                .as_array()
                .unwrap()
                .contains(&json!("/permissions"))
        );
        assert_eq!(m["hooks"], json!(["tool/before"]));
    }

    #[test]
    fn permissions_command_sets_and_prints() {
        let gate = ApprovalGate::new("auto");
        assert!(run_permissions_command(&gate, &[]).contains("auto"));
        assert_eq!(
            run_permissions_command(&gate, &["full".to_string()]),
            "permissions: full"
        );
        assert_eq!(gate.mode(), "full");
        assert!(run_permissions_command(&gate, &["bogus".to_string()]).contains("unknown mode"));
    }

    #[test]
    fn mcp_tools_read_as_server_and_tool() {
        assert_eq!(
            display_tool_name("mcp__filmcraft__render_frame"),
            "filmcraft \u{b7} render frame"
        );
        assert_eq!(display_tool_name("bash"), "bash");
        assert_eq!(display_tool_name("mcp__broken"), "mcp__broken");
        let q = approval_question("mcp__filmcraft__render_frame", "{}", &cwd());
        assert!(
            q.question
                .starts_with("Allow filmcraft \u{b7} render frame?")
        );
    }
}

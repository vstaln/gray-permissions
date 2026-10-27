//! Wire-level tests: drive the built sidecar binary over stdio like the
//! gray host does. Ask-path verdicts need a scripted `host/ask` answer.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

struct Harness {
    child: Child,
    stdin: ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
    _reader: std::thread::JoinHandle<()>,
}

impl Harness {
    fn spawn() -> Self {
        let dir = tempfile::tempdir().expect("tmp home");
        let mut child = Command::new(env!("CARGO_BIN_EXE_permissions"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("GRAY_HOME", dir.path())
            .env_remove("GRAY_PERMISSION")
            .env_remove("GRAY_PERMISSIONS")
            .spawn()
            .expect("spawn permissions sidecar");
        std::mem::forget(dir); // lives as long as the child; tempdir cleans on drop at test end
        let stdin = child.stdin.take().expect("stdin");
        let stdout: ChildStdout = child.stdout.take().expect("stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines: rx,
            _reader: reader,
        }
    }

    fn send(&mut self, v: &serde_json::Value) {
        writeln!(self.stdin, "{v}").expect("write");
        self.stdin.flush().expect("flush");
    }

    /// Next sidecar→host `host/ask` (string id), if any, else the host reply.
    fn next_any(&self) -> serde_json::Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(15))
            .expect("reply within 15s");
        serde_json::from_str(&line).expect("valid json reply")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn session(cwd: &str) -> serde_json::Value {
    serde_json::json!({"id": "", "cwd": cwd})
}

#[test]
fn manifest_shape() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let m = h.next_any();
    assert_eq!(m["id"], 1);
    assert_eq!(m["result"]["name"], "permissions");
    assert_eq!(m["result"]["protocol"], "1.1");
    assert_eq!(m["result"]["tools"], serde_json::json!([]));
    let cmds = m["result"]["commands"].as_array().unwrap();
    assert!(cmds.contains(&serde_json::json!("/permissions")));
    assert!(cmds.contains(&serde_json::json!("/perms")));
    assert!(cmds.contains(&serde_json::json!("/access")));
    assert_eq!(m["result"]["hooks"], serde_json::json!(["tool/before"]));
}

#[test]
fn read_allows_and_read_only_shape_without_asking() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let _ = h.next_any();
    // read allows in auto without any host/ask round-trip
    h.send(&serde_json::json!({
        "id": 2, "method": "tool/before",
        "params": {"name": "read", "args": {}, "session": session("/tmp")}
    }));
    let r = h.next_any();
    assert_eq!(
        r,
        serde_json::json!({"id": 2, "result": {"decision": "allow"}})
    );
    // unknown tool asks: answer "No" via host/ask → deny
    h.send(&serde_json::json!({
        "id": 3, "method": "tool/before",
        "params": {"name": "mystery", "args": {}, "session": session("/tmp")}
    }));
    let ask = h.next_any();
    assert_eq!(ask["method"], "host/ask");
    let ask_id = ask["id"].as_str().unwrap().to_string();
    assert_eq!(ask["params"]["blocking"], true);
    // The host draws the subject whole, the cwd dim, and no "Other" row.
    let q = &ask["params"]["questions"][0];
    assert_eq!(q["question"], "Allow mystery?\n{}");
    assert_eq!(q["detail"], "Working directory: /tmp");
    assert_eq!(q["no_other"], true);
    h.send(&serde_json::json!({
        "id": ask_id,
        "result": {"answers": {"tool-approval": {"answers": ["Deny"]}}}
    }));
    let r = h.next_any();
    assert_eq!(r["id"], 3);
    assert_eq!(r["result"]["decision"], "cancel");
}

#[test]
fn session_memory_accept_once() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let _ = h.next_any();
    let bash = |id: u64| {
        serde_json::json!({
            "id": id, "method": "tool/before",
            "params": {"name": "bash", "args": {"command": "ls /tmp"}, "session": session("/tmp")}
        })
    };
    h.send(&bash(2));
    let ask = h.next_any();
    let ask_id = ask["id"].as_str().unwrap().to_string();
    h.send(&serde_json::json!({
        "id": ask_id,
        "result": {"answers": {"tool-approval": {"answers": ["Allow", "scope: Session"]}}}
    }));
    let r = h.next_any();
    assert_eq!(r["result"]["decision"], "allow");
    // same bytes: allowed with NO second host/ask
    h.send(&bash(3));
    let r = h.next_any();
    assert_eq!(
        r,
        serde_json::json!({"id": 3, "result": {"decision": "allow"}})
    );
}

#[test]
fn edited_command_comes_back_as_modify() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let _ = h.next_any();
    h.send(&serde_json::json!({
        "id": 2, "method": "tool/before",
        "params": {"name": "bash", "args": {"command": "git push"}, "session": session("/tmp")}
    }));
    let ask = h.next_any();
    let ask_id = ask["id"].as_str().unwrap().to_string();
    h.send(&serde_json::json!({
        "id": ask_id,
        "result": {"answers": {"tool-approval": {"answers": ["Allow", "edited: git status"]}}}
    }));
    let r = h.next_any();
    assert_eq!(r["result"]["decision"], "modify");
    assert_eq!(r["result"]["args"]["command"], "git status");
}

#[test]
fn esc_empty_answers_cancel_the_turn() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let _ = h.next_any();
    h.send(&serde_json::json!({
        "id": 2, "method": "tool/before",
        "params": {"name": "bash", "args": {"command": "ls"}, "session": session("/tmp")}
    }));
    let ask = h.next_any();
    let ask_id = ask["id"].as_str().unwrap().to_string();
    h.send(&serde_json::json!({
        "id": ask_id,
        "result": {"answers": {}}
    }));
    let r = h.next_any();
    assert_eq!(r["result"]["decision"], "cancel");
}

#[test]
fn permissions_command_round_trip() {
    let mut h = Harness::spawn();
    h.send(&serde_json::json!({"id": 1, "method": "plugin/manifest"}));
    let _ = h.next_any();
    h.send(&serde_json::json!({
        "id": 2, "method": "command/run",
        "params": {"name": "/permissions", "argv": [], "session": session("/tmp")}
    }));
    let r = h.next_any();
    assert!(
        r["result"]["text"].as_str().unwrap().contains("auto"),
        "{r}"
    );
    h.send(&serde_json::json!({
        "id": 3, "method": "command/run",
        "params": {"name": "/perms", "argv": ["full"], "session": session("/tmp")}
    }));
    let r = h.next_any();
    assert_eq!(r["result"]["text"], "permissions: full");
    h.send(&serde_json::json!({
        "id": 4, "method": "command/run",
        "params": {"name": "/access", "argv": ["bogus"], "session": session("/tmp")}
    }));
    let r = h.next_any();
    assert!(
        r["result"]["text"]
            .as_str()
            .unwrap()
            .contains("unknown mode"),
        "{r}"
    );
}

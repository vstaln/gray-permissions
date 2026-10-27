<p align="center">
  <img src="assets/gray-logo.svg" alt="gray" width="96">
</p>
<h1 align="center">gray-permissions</h1>
<p align="center">A permission guard and `/permissions` UI for gray tool calls.</p>
<p align="center">
  <a href="https://github.com/vstaln/gray-permissions/blob/main/LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="gray plugin" src="https://img.shields.io/badge/gray-plugin-7aa2f7.svg">
  <img alt="rust" src="https://img.shields.io/badge/built%20with-rust-orange.svg">
</p>

A self-contained Rust sidecar that evaluates every tool call before it runs
and asks for approval when a call needs explicit consent.

## What it does

- Claims the `tool/before` hook: every tool call gets a static verdict —
  **Allow** (reads, workspace writes), **Deny** (read-only mode mutations),
  or **Ask** (commands, outside-workspace edits, unknown tools).
- `Ask` sends `host/ask` with Yes / Yes-for-session / No choices. Empty,
  timed-out, or unavailable answers deny; the gate fails closed.
- `/permissions` (+ `/perms`, `/access`) prints the current mode;
  `/permissions <read-only|auto|full>` changes it for the current session
  only. Every new session starts in `auto` (or `GRAY_PERMISSION` if set at
  launch) and asks again; nothing is persisted.
- Modes: `auto` asks when needed, `full` runs without prompts, and
  `read-only` denies mutations. Unknown mode strings fall back to `auto`.

## Install

Requires a gray build with the `host/ask` bridge:

```sh
cargo build --release
gray plugin install <release-tarball-url>
gray plugin install permissions
```

## Development

```sh
cargo test
cargo fmt --check
```

## Wire

- `plugin/manifest` → `{name: "permissions", tools: [], commands: ["/permissions", "/perms", "/access"], hooks: ["tool/before"]}`
- `tool/before` → `{"decision": "allow"}` / `{"decision": "deny", "reason": …}` / `{"decision": "ask", …}`
- `command/run` → `{"text": …}` mode output
- `event/notify`, unknown lines → ignored; `plugin/shutdown` → clean exit

---
Part of the [gray](https://github.com/vstaln/gray) plugin ecosystem —
the open-source AI agent harness. <https://gray.alignment.id>

# gray-permissions

Sidecar plugin for the [gray](https://github.com/vstaln/gray) agent harness:
the guard on tool calls ("hey, can I run this command?").

Rust, std-only I/O over the gray wire v1 (NDJSON over stdio). No async
runtime, no gray dependencies — the binary is self-contained.

## What it does

- Claims the `tool/before` hook: every tool call gets a static verdict —
  **Allow** (reads, workspace writes), **Deny** (read-only mode mutations),
  **Ask** (commands, outside-workspace edits, unknown tools — fail closed).
- `Ask` sends `host/ask` (Yes / Yes-for-session / No — exact-label match
  only, the old substring-escalation fix is kept). Empty/timeout answers
  deny. Session memory is in-process (raw command bytes / resolved paths).
- `/permissions` (+ `/perms`, `/access`): bare prints mode + usage,
  `/permissions <read-only|auto|full>` sets it, persisted to
  `$GRAY_HOME/permissions-mode.json` (seeded from `GRAY_PERMISSION`).
- Modes mirror codex presets: `auto` (ask), `full` (never ask), `read-only`
  (deny mutations). Unknown mode strings fall back to `auto`.

## Install

Requires a gray build with the `host/ask` bridge (gray ≥ 0.1.0 with
`feat/plugin-ask`):

```sh
cargo build --release
gray plugin install <release-tarball-url>   # day one
gray plugin install permissions             # after index publish
```

## Development

```sh
cargo test
cargo fmt --check
```

## Wire

- `plugin/manifest` → `{name: "permissions", tools: [], commands: ["/permissions", "/perms", "/access"], hooks: ["tool/before"]}`
- `tool/before` → `{"decision": "allow"}` / `{"decision": "deny", "reason": …}` (only `allow` runs the tool)
- `command/run` → `{"text": …}` mode output
- `event/notify`, unknown lines → ignored; `plugin/shutdown` → clean exit

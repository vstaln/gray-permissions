#!/bin/sh
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sys="$(uname -s)"
case "$sys" in
MINGW* | MSYS* | CYGWIN*) rel="x86_64-pc-windows-msvc/permissions.exe" ;;
Darwin*)
    case "$(uname -m)" in
    arm64) rel="aarch64-apple-darwin/permissions" ;;
    *) rel="x86_64-apple-darwin/permissions" ;;
    esac ;;
*)
    case "$(uname -m)" in
    aarch64 | arm64) rel="aarch64-unknown-linux-musl/permissions" ;;
    *) rel="x86_64-unknown-linux-musl/permissions" ;;
    esac ;;
esac
if [ -x "$here/$rel" ]; then exec "$here/$rel" "$@"; fi
for cand in "$here/target/release/permissions.exe" "$here/target/release/permissions" "$here/target/debug/permissions.exe" "$here/target/debug/permissions"; do
    if [ -x "$cand" ]; then exec "$cand" "$@"; fi
done
echo "permissions binary not found in $here" >&2
exit 1

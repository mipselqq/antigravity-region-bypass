#!/usr/bin/env bash
# One patch/settings implementation on every platform: the Rust engine.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) release_name=antigravity-bypass-russia-macos-arm64 ;;
  Darwin:x86_64) release_name=antigravity-bypass-russia-macos-x64 ;;
  *) release_name=antigravity-bypass-russia ;;
esac
if [[ -f "$repo_root/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
  cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"
fi
for engine in "$repo_root/target/release/antigravity-bypass-russia" "$script_dir/$release_name" "$repo_root/$release_name"; do
  if [[ -x "$engine" ]]; then exec "$engine" "$@"; fi
done
printf '%s\n' 'Rust engine not found. Put the platform release binary beside this script, or install Rust and run from the repository without sudo.' >&2
exit 1

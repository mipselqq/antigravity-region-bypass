"""Build one self-contained macOS launcher from the two verified Rust binaries."""
import argparse
import base64
import gzip
from pathlib import Path
import textwrap


def bundle(arm64: bytes, x64: bytes) -> str:
    script = '''#!/usr/bin/env bash
# Antigravity Bypass Russia: native engines included for Intel and Apple Silicon.
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
  printf '%s\\n' 'This launcher is for macOS.' >&2
  exit 1
fi
arch="$(uname -m)"
case "$arch" in arm64|x86_64) ;; *) printf '%s\\n' 'Unsupported architecture.' >&2; exit 1 ;; esac
umask 077
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/antigravity-bypass.XXXXXXXX")"
engine="$work_dir/antigravity-bypass-russia"
cleanup() { rm -f -- "$engine"; rmdir -- "$work_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$arch" in
'''
    for arch, data in [("arm64", arm64), ("x86_64", x64)]:
        payload = "\n".join(textwrap.wrap(base64.b64encode(gzip.compress(data, mtime=0)).decode("ascii"), 76))
        script += f"{arch})\nbase64 -D <<'ANTIGRAVITY_ENGINE' | gzip -d > \"$engine\"\n{payload}\nANTIGRAVITY_ENGINE\n;;\n"
    return script + '''esac
chmod 700 "$engine"
"$engine" "$@"
'''


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm64", required=True, type=Path)
    parser.add_argument("--x64", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(bundle(args.arm64.read_bytes(), args.x64.read_bytes()), encoding="utf-8", newline="\n")
    args.output.chmod(0o755)

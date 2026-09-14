"""Check both payloads, argument forwarding and failure status without running a patch."""
import base64
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from bundle_macos_launcher import bundle

arm = b'#!/usr/bin/env bash\nprintf "arm64\\n"\nprintf "%s\\n" "$@"\nexit 7\n'
x64 = arm.replace(b"arm64", b"x86_64")
script = bundle(arm, x64)
payloads = re.findall(r"<<'ANTIGRAVITY_ENGINE'[^\n]*\n(.*?)\nANTIGRAVITY_ENGINE", script, re.S)
assert [gzip.decompress(base64.b64decode(p)) for p in payloads] == [arm, x64]
bash = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
assert bash and Path(bash).is_file(), "Bash is required to verify the release launcher"
with tempfile.TemporaryDirectory(prefix="ag-bundle-test-") as temp:
    root = Path(temp)
    launcher = root / "unlock_and_restore.sh"
    launcher.write_text(script, encoding="utf-8", newline="\n")
    subprocess.run([bash, "-n", str(launcher)], check=True, timeout=10)
    for arch in ["arm64", "x86_64"]:
        environment = root / "test-env.sh"
        environment.write_text(
            f'uname() {{ if [[ "$1" == -s ]]; then echo Darwin; else echo {arch}; fi; }}\n'
            # Test the real decoder on the host with its supported flag.
            + ('base64() { command base64 -d; }\n' if sys.platform != 'darwin' else ''),
            encoding="utf-8", newline="\n")
        env = dict(os.environ, BASH_ENV=environment.as_posix(), MSYS_NO_PATHCONV="1", PATH="")
        result = subprocess.run([bash, str(launcher), "--check", "space and кириллица"], env=env,
                                capture_output=True, encoding="utf-8", timeout=10)
        assert result.returncode == 7, result
        assert result.stdout.splitlines() == [arch, "--check", "space and кириллица"], result
print("PASS: macOS bundle payloads, shell syntax, both architectures, arguments and exit status")

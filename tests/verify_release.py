"""Read-only smoke checks against the actual release binary."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

root = Path(__file__).resolve().parents[1]
version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
if os.environ.get("GITHUB_REF_TYPE") == "tag":
    assert os.environ["GITHUB_REF_NAME"] == f"v{version}", "Tag and package version differ"
binary = Path(sys.argv[1]).resolve()


def run(*args):
    return subprocess.run([str(binary), *args], capture_output=True, encoding="utf-8", timeout=30)


result = run("--version")
assert result.returncode == 0 and result.stdout.strip() == f"antigravity-bypass-russia v{version}", result
result = run("--help")
assert result.returncode == 0 and all(word in result.stdout for word in ["unlock", "rollback", "diagnostics"]), result
for args in [("invalid-command",), ("status", "extra")]:
    result = run(*args)
    assert result.returncode == 2, result
result = run("status")
assert result.returncode == 0, result
plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
rows = [line for line in plain.splitlines() if line]
assert len(rows) == 8 and all(len(line) == 69 for line in rows), plain
assert all(label in plain for label in ["Обход:", "Antigravity:", "Antigravity IDE:", "Antigravity CLI:"]), plain
print(f"PASS: release {version}, help, argument errors, status and frame alignment")

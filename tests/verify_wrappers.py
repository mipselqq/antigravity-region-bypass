"""Exercise launchers in temporary folders with a fake engine; never apply bypass."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARGUMENTS = ["patch-files", "C:/Example Folder/путь", "--check"]


def run(command):
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90)


with tempfile.TemporaryDirectory(prefix="ag wrapper ") as temporary:
    folder = Path(temporary)
    source = folder / "probe.rs"
    source.write_text('fn main() { for a in std::env::args().skip(1) { println!("{}", a.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()); } std::process::exit(7); }')
    binary = folder / ("antigravity-bypass-russia.exe" if os.name == "nt" else "antigravity-bypass-russia")
    subprocess.run(["rustc", str(source), "-o", str(binary)], check=True, timeout=90)

    if os.name == "nt":
        wrapper = folder / "unlock_and_restore.ps1"
        shutil.copyfile(ROOT / "scripts" / wrapper.name, wrapper)
        for shell_name in ["powershell.exe", "pwsh.exe"]:
            shell = shutil.which(shell_name)
            if not shell:
                print(f"SKIP: {shell_name} not installed")
                continue
            # Set console encoding explicitly for the test subprocess (PS 5.1 defaults to OEM).
            quote = lambda value: "'" + value.replace("'", "''") + "'"
            command = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); & " + quote(str(wrapper))
            command += " " + " ".join(map(quote, ARGUMENTS)) + "; exit $LASTEXITCODE"
            result = run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command])
            assert result.returncode == 7, (shell_name, result.returncode, result.stdout, result.stderr)
            assert result.stdout.splitlines() == [a.encode("utf-8").hex() for a in ARGUMENTS], (shell_name, result.stdout)
            print(f"PASS: {shell_name} preserves arguments and failure exit code")

    bash = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
    if bash and Path(bash).is_file():
        wrapper = folder / "unlock_and_restore.sh"
        shutil.copyfile(ROOT / "scripts" / wrapper.name, wrapper)
        if os.name == "nt":
            shutil.copyfile(binary, folder / "antigravity-bypass-russia")
        elif os.uname().sysname == "Darwin":
            arch = "arm64" if os.uname().machine == "arm64" else "x64"
            shutil.copyfile(binary, folder / f"antigravity-bypass-russia-macos-{arch}")
            (folder / f"antigravity-bypass-russia-macos-{arch}").chmod(0o755)
        result = run([bash, "-n", str(wrapper)])
        assert result.returncode == 0, result.stderr
        # Git Bash rewrites /-prefixed arguments for native programs unless disabled.
        os.environ["MSYS_NO_PATHCONV"] = "1"
        result = run([bash, str(wrapper), *ARGUMENTS])
        assert result.returncode == 7, (result.returncode, result.stdout, result.stderr)
        assert result.stdout.splitlines() == [a.encode("utf-8").hex() for a in ARGUMENTS], result.stdout
        print("PASS: Bash syntax, arguments and failure exit code")
    else:
        print("SKIP: Bash not installed")

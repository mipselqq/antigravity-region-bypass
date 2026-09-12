"""Package an already-built release; never publish or modify installed software."""
import argparse
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-pc-windows-msvc": ("windows-x64", "antigravity-bypass-russia.exe", "unlock_and_restore.ps1"),
    "aarch64-apple-darwin": ("macos-arm64", "antigravity-bypass-russia-macos-arm64", "unlock_and_restore.sh"),
    "x86_64-apple-darwin": ("macos-x64", "antigravity-bypass-russia-macos-x64", "unlock_and_restore.sh"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    if not args.binary.is_file():
        parser.error("Release binary does not exist")
    platform, binary_name, wrapper = TARGETS[args.target]
    name = f"antigravity-bypass-russia-{version}-{platform}"
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ag-release-") as temporary:
        folder = Path(temporary)
        shutil.copyfile(args.binary, folder / binary_name)
        shutil.copyfile(ROOT / "scripts" / wrapper, folder / wrapper)
        for doc in ["RELEASE_NOTES_1.3.0.md", "LICENSE"]:
            shutil.copyfile(ROOT / doc, folder / doc)
        if platform.startswith("windows"):
            archive = args.output / (name + ".zip")
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for path in sorted(folder.iterdir()):
                    output.write(path, path.name)
        else:
            (folder / binary_name).chmod(0o755)
            (folder / wrapper).chmod(0o755)
            archive = args.output / (name + ".tar.gz")
            with tarfile.open(archive, "w:gz") as output:
                for path in sorted(folder.iterdir()):
                    output.add(path, arcname=path.name)
    shutil.copyfile(args.binary, args.output / binary_name)
    shutil.copyfile(ROOT / "scripts" / wrapper, args.output / wrapper)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(archive.resolve())


if __name__ == "__main__":
    main()

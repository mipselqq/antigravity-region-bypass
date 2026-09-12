# Windows PowerShell 5.1 and PowerShell 7: both launch the same Rust engine.
# This script does not edit settings.json, executables, or network settings itself.
$ErrorActionPreference = 'Stop'
$engineArgs = @($args)
$repoRoot = Split-Path -Parent $PSScriptRoot
$candidates = @(
    (Join-Path $repoRoot 'target\release\antigravity-bypass-russia.exe'),
    (Join-Path $PSScriptRoot 'antigravity-bypass-russia.exe'),
    (Join-Path $repoRoot 'antigravity-bypass-russia.exe')
)
if ((Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.toml')) -and (Get-Command cargo -ErrorAction SilentlyContinue)) {
    & cargo build --release --locked --manifest-path (Join-Path $repoRoot 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$engine = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $engine) {
    throw 'Rust engine not found. Place the release EXE next to this script, or install Rust and run this script from the repository.'
}
& $engine @engineArgs
exit $LASTEXITCODE

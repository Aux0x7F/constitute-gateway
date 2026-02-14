param(
    [ValidateSet('auto','linux','windows')]
    [string]$Target = 'auto'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Test-WslCommand([string]$cmd) {
    & wsl -e bash -lc $cmd | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-WslLinuxBuild([string]$repoPath) {
    $wslPath = & wsl wslpath -a "$repoPath" 2>$null
    if (-not $wslPath) {
        Write-Error "WSL not available or wslpath failed. Install WSL2 + Ubuntu and retry."
        exit 1
    }

    if (-not (Test-WslCommand 'command -v cargo >/dev/null 2>&1')) {
        Write-Warning "Rust toolchain not found inside WSL."
        $answer = Read-Host 'Install Rust (rustup + stable) in WSL now? [Y/n]'
        if ($answer -match '^(n|no)$') {
            Write-Error "Rust is required for Linux build. Install in WSL and retry."
            exit 1
        }

        # Interactive-safe bootstrap: installs curl if needed, then rustup minimal profile.
        & wsl -e bash -lc 'set -euo pipefail; if ! command -v curl >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y curl ca-certificates; fi; curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal; source "$HOME/.cargo/env"; rustup toolchain install stable --profile minimal; rustup default stable'
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to bootstrap Rust in WSL."
            exit $LASTEXITCODE
        }
    }

    $wslPathEscaped = $wslPath -replace "'", "'\\''"
    & wsl -e bash -lc "set -euo pipefail; source \"`$HOME/.cargo/env\" >/dev/null 2>&1 || true; cd '$wslPathEscaped'; cargo build --release --features platform-linux; ./scripts/linux/package.sh"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($Target -eq 'auto') {
    if ($IsWindows) {
        Write-Host "Detected Windows. Building Windows binary (release)."
        cargo build --release --features platform-windows
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Write-Host "To build Linux package from Windows, run: .\scripts\windows\build.ps1 -Target linux"
        exit 0
    }
    Write-Host "Detected non-Windows. Building Linux release package."
    cargo build --release --features platform-linux
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    bash ./scripts/linux/package.sh
    exit $LASTEXITCODE
}

if ($Target -eq 'windows') {
    if (-not $IsWindows) {
        Write-Error "windows target is only supported on Windows hosts."
        exit 1
    }
    cargo build --release --features platform-windows
    exit $LASTEXITCODE
}

if ($Target -eq 'linux') {
    if ($IsWindows) {
        Invoke-WslLinuxBuild $repo
        exit $LASTEXITCODE
    }
    cargo build --release --features platform-linux
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    bash ./scripts/linux/package.sh
    exit $LASTEXITCODE
}
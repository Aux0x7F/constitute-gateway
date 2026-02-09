param(
    [ValidateSet('auto','snap','windows')]
    [string]$Target = 'auto'
)

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Invoke-WslSnapBuild([string]$repoPath) {
    $wslPath = & wsl wslpath -a "$repoPath" 2>$null
    if (-not $wslPath) {
        Write-Error "WSL not available or wslpath failed. Install WSL2 and Ubuntu, then retry."
        exit 1
    }
    & wsl -e bash -lc "cd '$wslPath' && make snap"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($Target -eq 'auto') {
    if ($IsWindows) {
        Write-Host "Detected Windows. Building Windows binary (release)."
        cargo build --release --features platform-windows
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Write-Host "To build snap from Windows, run: .\\scripts\\build.ps1 -Target snap"
        exit 0
    }
    Write-Host "Detected non-Windows. Building snap."
    make snap
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

if ($Target -eq 'snap') {
    if ($IsWindows) {
        Invoke-WslSnapBuild $repo
        exit $LASTEXITCODE
    }
    make snap
    exit $LASTEXITCODE
}

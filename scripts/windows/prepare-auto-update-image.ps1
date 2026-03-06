param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [ValidateSet('stable','testing','next')]
    [string]$Stream = 'stable',
    [ValidateSet('x86_64','aarch64')]
    [string]$Arch = 'x86_64',
    [string]$OutDir = '',
    [string]$SshKeyPath = '',
    [string]$TimerInterval = '30m',
    [switch]$DevPoll,
    [string]$Device = ''
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $env:USERPROFILE 'Downloads\constitute-gateway-fcos'
}

function Quote-Bash([string]$s) {
    return "'" + ($s -replace "'", "'\\''") + "'"
}

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    throw 'WSL is required for FCOS auto-update image prep on Windows.'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOutDir = (Resolve-Path $OutDir).Path
$resolvedOutDirWslInput = $resolvedOutDir -replace '\\', '/'
$wslOutDir = & wsl wslpath -a "$resolvedOutDirWslInput" 2>$null
if (-not $wslOutDir) {
    throw "Unable to map output directory into WSL: $resolvedOutDir"
}

$args = @(
    '--repo-owner', $RepoOwner,
    '--repo-name', $RepoName,
    '--stream', $Stream,
    '--arch', $Arch,
    '--download-dir', $wslOutDir
)

if ($DevPoll) {
    $args += '--dev-poll'
} else {
    $args += @('--timer-interval', $TimerInterval)
}

if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) {
    $resolvedKey = $SshKeyPath
    if (-not [System.IO.Path]::IsPathRooted($resolvedKey)) {
        $resolvedKey = Join-Path (Get-Location).Path $resolvedKey
    }
    if (-not (Test-Path $resolvedKey)) {
        throw "SSH key path not found: $resolvedKey"
    }
    $resolvedKeyWslInput = $resolvedKey -replace '\\', '/'
    $wslKey = & wsl wslpath -a "$resolvedKeyWslInput" 2>$null
    if (-not $wslKey) {
        throw "Unable to map SSH key path into WSL: $resolvedKey"
    }
    $args += @('--ssh-key-file', $wslKey)
}

if (-not [string]::IsNullOrWhiteSpace($Device)) {
    $args += @('--device', $Device)
}

$bashArgs = ($args | ForEach-Object { Quote-Bash $_ }) -join ' '
$scriptUrl = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/main/scripts/fcos/prepare-auto-update-image.sh"

$cmd = @"
set -euo pipefail
TMP_SCRIPT=\"\$(mktemp)\"
curl -fsSL $(Quote-Bash $scriptUrl) -o \"\$TMP_SCRIPT\"
bash \"\$TMP_SCRIPT\" $bashArgs
rm -f \"\$TMP_SCRIPT\"
"@

Write-Host "Running FCOS auto-update image prep via WSL..."
& wsl -e bash -lc $cmd
if ($LASTEXITCODE -ne 0) {
    throw "WSL prep command failed with exit code $LASTEXITCODE"
}

Write-Host "FCOS auto-update image prep complete. Output: $resolvedOutDir"


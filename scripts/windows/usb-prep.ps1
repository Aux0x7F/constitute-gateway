param(
    [ValidateSet('stable','testing','next')]
    [string]$Stream = 'stable',
    [ValidateSet('x86_64','aarch64')]
    [string]$Arch = 'x86_64',
    [string]$OutDir = '.\infra\fcos\generated',
    [switch]$UseWsl,
    [string]$IgnitionPath = '',
    [string]$Device = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Quote-Bash([string]$s) {
    return "'" + ($s -replace "'", "'\\''") + "'"
}

function Invoke-WslImagePrep {
    param(
        [string]$RepoRoot,
        [string]$Stream,
        [string]$Arch,
        [string]$OutDir,
        [string]$IgnitionPath,
        [string]$Device
    )

    $wslRepo = & wsl wslpath -a "$RepoRoot" 2>$null
    if (-not $wslRepo) {
        throw 'WSL not available or wslpath failed. Install WSL2 + Ubuntu and retry.'
    }

    $wslScript = "$wslRepo/scripts/fcos/usb-prep-linux.sh"
    $args = @()
    $args += '--stream ' + (Quote-Bash $Stream)
    $args += '--arch ' + (Quote-Bash $Arch)

    $resolvedOutDir = $OutDir
    if (-not [System.IO.Path]::IsPathRooted($resolvedOutDir)) {
        $resolvedOutDir = Join-Path $RepoRoot $resolvedOutDir
    }
    New-Item -ItemType Directory -Force -Path $resolvedOutDir | Out-Null
    $wslOutDir = & wsl wslpath -a "$resolvedOutDir" 2>$null
    if (-not $wslOutDir) {
        throw "Unable to map output directory into WSL: $resolvedOutDir"
    }
    $args += '--download-dir ' + (Quote-Bash $wslOutDir)

    if ($IgnitionPath) {
        $resolvedIgnition = $IgnitionPath
        if (-not [System.IO.Path]::IsPathRooted($resolvedIgnition)) {
            $resolvedIgnition = Join-Path $RepoRoot $resolvedIgnition
        }
        if (-not (Test-Path $resolvedIgnition)) {
            throw "Ignition path not found: $resolvedIgnition"
        }
        $wslIgnition = & wsl wslpath -a "$resolvedIgnition" 2>$null
        if (-not $wslIgnition) {
            throw "Unable to map Ignition path into WSL: $resolvedIgnition"
        }
        $args += '--ignition ' + (Quote-Bash $wslIgnition)
    }

    if ($Device) {
        $args += '--device ' + (Quote-Bash $Device)
    }

    $cmd = "set -euo pipefail; cd " + (Quote-Bash $wslRepo) + "; bash " + (Quote-Bash $wslScript) + " " + ($args -join ' ')
    Write-Host 'Running FCOS image prep via WSL...'
    & wsl -e bash -lc $cmd
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if ($UseWsl -or $IgnitionPath -or $Device) {
    Invoke-WslImagePrep -RepoRoot $repoRoot -Stream $Stream -Arch $Arch -OutDir $OutDir -IgnitionPath $IgnitionPath -Device $Device
    exit 0
}

$streamUrl = "https://builds.coreos.fedoraproject.org/streams/$Stream.json"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$meta = Invoke-RestMethod -Uri $streamUrl
$disk = $meta.architectures.$Arch.artifacts.metal.formats.iso.disk
if (-not $disk) {
    throw "Unable to resolve FCOS ISO metadata for stream=$Stream arch=$Arch"
}

$isoUrl = $disk.location
$isoSha = $disk.sha256.ToLower()
$isoName = Split-Path -Path $isoUrl -Leaf
$isoPath = Join-Path $OutDir $isoName

Write-Host "Downloading $isoUrl"
Invoke-WebRequest -Uri $isoUrl -OutFile $isoPath

$got = (Get-FileHash $isoPath -Algorithm SHA256).Hash.ToLower()
if ($got -ne $isoSha) {
    throw "Checksum mismatch for $isoName"
}

Write-Host "ISO ready: $isoPath"
Write-Host "Verified SHA256: $isoSha"
Write-Host 'Base-image mode complete (upstream default FCOS ISO only). For full prep (Ignition embed and optional direct write), run with -UseWsl.'
Write-Host 'Example: powershell -ExecutionPolicy Bypass -File .\scripts\windows\usb-prep.ps1 -UseWsl -IgnitionPath .\infra\fcos\generated\config.ign'
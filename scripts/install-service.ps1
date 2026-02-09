param(
    [string]$ServiceName = 'ConstituteGateway',
    [string]$NssmPath = '.\\nssm\\nssm.exe'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$bin = Join-Path $repo 'target\release\constitute-gateway.exe'
$config = Join-Path $repo 'config.json'
$configExample = Join-Path $repo 'config.example.json'

function Download-WithRetry([string]$Uri, [string]$OutFile, [int]$Retries = 4, [int]$DelaySec = 2) {
    for ($i = 0; $i -le $Retries; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile
            return $true
        } catch {
            if ($i -ge $Retries) { break }
            Start-Sleep -Seconds $DelaySec
        }
    }
    return $false
}

function Build-Release([string]$TargetDir) {
    if ($TargetDir) { $env:CARGO_TARGET_DIR = $TargetDir }
    cargo build --release --features platform-windows -j 1
    return $LASTEXITCODE -eq 0
}

if (-not (Test-Path $NssmPath)) {
    Write-Host "nssm.exe not found; downloading..."
    $tmp = Join-Path $repo '.nssm-tmp'
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp 'nssm.zip'

    $ok = Download-WithRetry 'https://nssm.cc/release/nssm-2.24.zip' $zip
    if (-not $ok) {
        $ok = Download-WithRetry 'https://github.com/kohsuke/nssm/releases/download/v2.24/nssm-2.24.zip' $zip
    }
    if (-not $ok) {
        throw "Unable to download NSSM after retries. Please retry later or place nssm.exe at $NssmPath"
    }

    Expand-Archive $zip -DestinationPath $tmp
    $src = Join-Path $tmp 'nssm-2.24\win64\nssm.exe'
    $destDir = Split-Path -Parent (Join-Path $repo $NssmPath)
    if (-not $destDir) { $destDir = Join-Path $repo 'nssm' }
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    Copy-Item $src (Join-Path $destDir 'nssm.exe') -Force
    Remove-Item -Recurse -Force $tmp
}

if (-not (Test-Path $NssmPath)) {
    throw "nssm.exe not found at $NssmPath"
}

if (-not (Test-Path $bin)) {
    Write-Host "Binary not found; building release..."
    if (-not (Build-Release "")) {
        Write-Host "Release build failed. This is commonly caused by Windows exploit protection flagging Rust build scripts (proc-macro2)."
        Write-Host "If you see T1059 detections, temporarily disable exploit protection for rustc/cargo or allow-list the toolchain paths."
        Write-Host "Retrying with short target dir..."
        $shortDir = 'C:\\tmp\\cg-target'
        New-Item -ItemType Directory -Force -Path $shortDir | Out-Null
        if (-not (Build-Release $shortDir)) {
            throw "cargo build failed (even with short target dir)."
        }
        $bin = Join-Path $shortDir 'release\constitute-gateway.exe'
    }
}

if (-not (Test-Path $bin)) {
    throw "Binary not found after build: $bin"
}

if (-not (Test-Path $config)) {
    if (Test-Path $configExample) {
        Copy-Item $configExample $config
    } else {
        throw "config.json missing and no config.example.json to copy"
    }
}

& $NssmPath install $ServiceName $bin
& $NssmPath set $ServiceName AppDirectory $repo
& $NssmPath set $ServiceName AppParameters "--config $config"
& $NssmPath set $ServiceName Start SERVICE_DELAYED_AUTO_START
& $NssmPath start $ServiceName
Write-Host "Service installed and started: $ServiceName (delayed auto-start)"

param(
    [string]$ServiceName = 'ConstituteGateway',
    [string]$NssmPath = '',
    [string]$Zone = ''
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
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

function Service-Exists([string]$Name) {
    try {
        Get-Service -Name $Name -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Resolve-BinaryPath([string]$Root) {
    $candidates = @(
        Join-Path $Root 'constitute-gateway.exe',
        Join-Path $Root 'target\release\constitute-gateway.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    return ''
}

function Invoke-Nssm([string]$ExePath, [string[]]$Args) {
    & $ExePath @Args
    if ($LASTEXITCODE -ne 0) {
        throw "nssm failed (exit $LASTEXITCODE): $($Args -join ' ')"
    }
}

$defaultToolsRoot = if ($env:ProgramData) {
    Join-Path $env:ProgramData 'Constitute\Gateway\tools'
} elseif ($env:LOCALAPPDATA) {
    Join-Path $env:LOCALAPPDATA 'Constitute\Gateway\tools'
} else {
    Join-Path $repo '.tools'
}

if ([string]::IsNullOrWhiteSpace($NssmPath)) {
    $NssmPath = Join-Path $defaultToolsRoot 'nssm.exe'
}

$resolvedNssmPath = if ([System.IO.Path]::IsPathRooted($NssmPath)) {
    $NssmPath
} else {
    Join-Path $repo $NssmPath
}

if (-not (Test-Path $resolvedNssmPath)) {
    Write-Host 'nssm.exe not found; downloading...'
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("constitute-gateway-nssm-" + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $zip = Join-Path $tmp 'nssm.zip'

        $ok = Download-WithRetry 'https://nssm.cc/release/nssm-2.24.zip' $zip
        if (-not $ok) {
            $ok = Download-WithRetry 'https://github.com/kohsuke/nssm/releases/download/v2.24/nssm-2.24.zip' $zip
        }
        if (-not $ok) {
            throw "Unable to download NSSM after retries. Please retry later or place nssm.exe at $resolvedNssmPath"
        }

        Expand-Archive $zip -DestinationPath $tmp
        $src = Join-Path $tmp 'nssm-2.24\win64\nssm.exe'
        $destDir = Split-Path -Parent $resolvedNssmPath
        if (-not $destDir) {
            throw "Unable to determine destination directory for $resolvedNssmPath"
        }
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        Copy-Item $src $resolvedNssmPath -Force
    } finally {
        if (Test-Path $tmp) {
            Remove-Item -Recurse -Force $tmp
        }
    }
}

if (-not (Test-Path $resolvedNssmPath)) {
    throw "nssm.exe not found at $resolvedNssmPath"
}

$bin = Resolve-BinaryPath -Root $repo
if (-not $bin) {
    if (Test-Path (Join-Path $repo 'Cargo.toml')) {
        Write-Host 'Binary not found; building release...'
        if (-not (Build-Release '')) {
            Write-Host 'Release build failed. This is commonly caused by Windows exploit protection flagging Rust build scripts (proc-macro2).'
            Write-Host 'If you see T1059 detections, temporarily disable exploit protection for rustc/cargo or allow-list the toolchain paths.'
            Write-Host 'Retrying with short target dir...'
            $shortDir = 'C:\tmp\cg-target'
            New-Item -ItemType Directory -Force -Path $shortDir | Out-Null
            if (-not (Build-Release $shortDir)) {
                throw 'cargo build failed (even with short target dir).'
            }
            $bin = Join-Path $shortDir 'release\constitute-gateway.exe'
        } else {
            $bin = Resolve-BinaryPath -Root $repo
        }
    } else {
        throw 'Binary not found and source tree unavailable for build. Expected constitute-gateway.exe in install bundle.'
    }
}

if (-not $bin -or -not (Test-Path $bin)) {
    throw "Binary not found after build: $bin"
}

if (-not (Test-Path $config)) {
    if (Test-Path $configExample) {
        Copy-Item $configExample $config
    } else {
        throw 'config.json missing and no config.example.json to copy'
    }
}

$dataDir = Join-Path $env:ProgramData 'Constitute\Gateway\data'
$zoneSeed = Join-Path $dataDir 'zone.seed'
if (-not (Test-Path $zoneSeed)) {
    if (-not $Zone) {
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            $Zone = Read-Host 'Enter zone key (leave empty to generate default)'
        }
    }
    if ($Zone) {
        New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
        Set-Content -Path $zoneSeed -Value $Zone -NoNewline
    }
}

$serviceExists = Service-Exists -Name $ServiceName
if (-not $serviceExists) {
    Invoke-Nssm -ExePath $resolvedNssmPath -Args @('install', $ServiceName, $bin)
}

Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'Application', $bin)
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppDirectory', $repo)
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppParameters', "--config $config")
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'Start', 'SERVICE_DELAYED_AUTO_START')

if ($serviceExists) {
    Invoke-Nssm -ExePath $resolvedNssmPath -Args @('restart', $ServiceName)
    Write-Host "Service updated and restarted: $ServiceName"
} else {
    Invoke-Nssm -ExePath $resolvedNssmPath -Args @('start', $ServiceName)
    Write-Host "Service installed and started: $ServiceName (delayed auto-start)"
}

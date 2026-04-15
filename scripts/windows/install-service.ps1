param(
    [string]$ServiceName = 'ConstituteGateway',
    [string]$NssmPath = '',
    [string]$Zone = '',
    [string]$StateRoot = '',
    [string]$ConfigPath = '',
    [string]$PairIdentity = '',
    [switch]$PairGenerate
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$configExample = Join-Path $repo 'config.example.json'
$legacyConfig = Join-Path $repo 'config.json'

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

function Resolve-StateRoot([string]$Root, [string]$RepoRoot) {
    if (-not [string]::IsNullOrWhiteSpace($Root)) {
        return $Root
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        return (Join-Path $env:ProgramData 'Constitute\Gateway')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return (Join-Path $env:LOCALAPPDATA 'Constitute\Gateway')
    }
    return (Join-Path $RepoRoot '.state')
}

function Convert-ToBase64UrlSha256([string]$InputText) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $sha.ComputeHash($bytes)
        return [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    } finally {
        $sha.Dispose()
    }
}

function Normalize-Config {
    param(
        [string]$Path,
        [string]$StateRootPath,
        [string]$DefaultDataDir,
        [string]$PairIdentityLabel,
        [bool]$ShouldGeneratePairCode
    )

    $cfg = Get-Content $Path -Raw | ConvertFrom-Json
    $raw = [string]$cfg.data_dir
    $trimmed = $raw.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        $cfg | Add-Member -NotePropertyName data_dir -NotePropertyValue $DefaultDataDir -Force
    } elseif ($trimmed -in @('./data', '.\data', 'data')) {
        $cfg | Add-Member -NotePropertyName data_dir -NotePropertyValue $DefaultDataDir -Force
    } elseif ([System.IO.Path]::IsPathRooted($trimmed)) {
        $cfg | Add-Member -NotePropertyName data_dir -NotePropertyValue $trimmed -Force
    } else {
        $resolved = Join-Path $StateRootPath ($trimmed.TrimStart('.', '\', '/'))
        $cfg | Add-Member -NotePropertyName data_dir -NotePropertyValue $resolved -Force
    }

    $defaultRelays = @('wss://nos.lol', 'wss://relay.primal.net', 'wss://nostr.mom')
    $legacyRelays = @('wss://relay.snort.social', 'wss://relay.damus.io')
    $existingRelays = @()
    if ($null -ne $cfg.nostr_relays) {
        $existingRelays = @($cfg.nostr_relays | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $hasCustomRelay = ($existingRelays | Where-Object { $_ -notin $legacyRelays }).Count -gt 0
    if ($existingRelays.Count -eq 0 -or -not $hasCustomRelay) {
        $cfg | Add-Member -NotePropertyName nostr_relays -NotePropertyValue $defaultRelays -Force
    }

    $existingAdvertise = @()
    if ($null -ne $cfg.advertise_relays) {
        $existingAdvertise = @($cfg.advertise_relays | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $placeholderAdvertise = $existingAdvertise | Where-Object { $_ -match 'gateway\.example|replace-host|\.example(?::|/|$)' }
    $needsAdvertise = $existingAdvertise.Count -eq 0 -or $placeholderAdvertise.Count -eq $existingAdvertise.Count
    if ($needsAdvertise) {
        $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1
        $lanIp = $null
        if ($defaultRoute) {
            $lanIp = Get-NetIPAddress -InterfaceIndex $defaultRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254*' } |
                Select-Object -First 1 -ExpandProperty IPAddress
        }
        if (-not [string]::IsNullOrWhiteSpace($lanIp)) {
            $cfg | Add-Member -NotePropertyName advertise_relays -NotePropertyValue @("ws://$lanIp:7447") -Force
        }
    }

    $existingIdentity = [string]$cfg.pair_identity_label
    $existingCode = [string]$cfg.pair_code
    $existingHash = [string]$cfg.pair_code_hash
    $identityId = [string]$cfg.identity_id

    if (-not [string]::IsNullOrWhiteSpace($PairIdentityLabel)) {
        $cfg | Add-Member -NotePropertyName pair_identity_label -NotePropertyValue $PairIdentityLabel -Force
    }

    $effectiveIdentity = [string]$cfg.pair_identity_label
    $generatedPairCode = ''
    if ($ShouldGeneratePairCode -and -not [string]::IsNullOrWhiteSpace($effectiveIdentity) -and [string]::IsNullOrWhiteSpace($identityId)) {
        $identityChanged = (-not [string]::IsNullOrWhiteSpace($PairIdentityLabel)) -and ($existingIdentity -ne $effectiveIdentity)
        $missingPair = [string]::IsNullOrWhiteSpace($existingCode) -or [string]::IsNullOrWhiteSpace($existingHash)
        if ($identityChanged -or $missingPair) {
            $generatedPairCode = (Get-Random -Minimum 100000 -Maximum 1000000).ToString()
            $cfg | Add-Member -NotePropertyName pair_code -NotePropertyValue $generatedPairCode -Force
            $cfg | Add-Member -NotePropertyName pair_code_hash -NotePropertyValue (Convert-ToBase64UrlSha256 "$effectiveIdentity|$generatedPairCode") -Force
        }
    }

    if ($null -eq $cfg.pair_request_interval_secs) {
        $cfg | Add-Member -NotePropertyName pair_request_interval_secs -NotePropertyValue 15 -Force
    }
    if ($null -eq $cfg.pair_request_attempts) {
        $cfg | Add-Member -NotePropertyName pair_request_attempts -NotePropertyValue 24 -Force
    }

    $cfg | ConvertTo-Json -Depth 40 | Set-Content -Encoding UTF8 $Path
    return $generatedPairCode
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

$StateRoot = Resolve-StateRoot -Root $StateRoot -RepoRoot $repo
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $StateRoot 'config.json'
}

$dataDir = Join-Path $StateRoot 'data'
$logsDir = Join-Path $StateRoot 'logs'

New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

if (-not (Test-Path $ConfigPath)) {
    if (Test-Path $legacyConfig) {
        Copy-Item $legacyConfig $ConfigPath -Force
    } elseif (Test-Path $configExample) {
        Copy-Item $configExample $ConfigPath -Force
    } else {
        throw "config template missing: expected $legacyConfig or $configExample"
    }
}

$legacyDataDir = Join-Path $repo 'data'
if (Test-Path $legacyDataDir) {
    Copy-Item -Path (Join-Path $legacyDataDir '*') -Destination $dataDir -Recurse -Force -ErrorAction SilentlyContinue
}

$generatedPairCode = Normalize-Config -Path $ConfigPath -StateRootPath $StateRoot -DefaultDataDir $dataDir -PairIdentityLabel $PairIdentity -ShouldGeneratePairCode $PairGenerate.IsPresent

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
$appParams = "--config `"$ConfigPath`""
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppDirectory', $StateRoot)
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppParameters', $appParams)
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'Start', 'SERVICE_DELAYED_AUTO_START')
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppStdout', (Join-Path $logsDir 'gateway.out.log'))
Invoke-Nssm -ExePath $resolvedNssmPath -Args @('set', $ServiceName, 'AppStderr', (Join-Path $logsDir 'gateway.err.log'))

if ($serviceExists) {
    Invoke-Nssm -ExePath $resolvedNssmPath -Args @('restart', $ServiceName)
    Write-Host "Service updated and restarted: $ServiceName"
} else {
    Invoke-Nssm -ExePath $resolvedNssmPath -Args @('start', $ServiceName)
    Write-Host "Service installed and started: $ServiceName (delayed auto-start)"
}

if (-not [string]::IsNullOrWhiteSpace($generatedPairCode)) {
    Write-Host "Pairing code (claim in Settings > Pairing > Add Device): $generatedPairCode"
}

param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [string]$ServiceName = 'ConstituteGateway',
    [string]$InstallDir = '',
    [string]$PairIdentity = '',
    [string]$PairCode = '',
    [string]$PairCodeHash = '',
    [int]$UpdateIntervalMinutes = 30,
    [string]$UpdateTaskName = '',
    [switch]$SkipUpdateTask
)

$ErrorActionPreference = 'Stop'
$base = "https://github.com/$RepoOwner/$RepoName/releases/latest/download"
$zipName = 'constitute-gateway-windows.zip'

if ($UpdateIntervalMinutes -lt 5) { $UpdateIntervalMinutes = 5 }
if ($UpdateIntervalMinutes -gt 1440) { $UpdateIntervalMinutes = 1440 }
if ([string]::IsNullOrWhiteSpace($UpdateTaskName)) {
    $UpdateTaskName = "$ServiceName-AutoUpdate"
}

function Ensure-UpdateTask {
    param(
        [string]$TaskName,
        [int]$IntervalMinutes,
        [string]$ScriptPath,
        [string]$RepoOwner,
        [string]$RepoName,
        [string]$ServiceName,
        [string]$InstallDir
    )

    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Warning 'Scheduled task cmdlets are unavailable; skipping auto-update task setup.'
        return
    }

    $taskArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$ScriptPath`"",
        '-RepoOwner', "`"$RepoOwner`"",
        '-RepoName', "`"$RepoName`"",
        '-ServiceName', "`"$ServiceName`"",
        '-InstallDir', "`"$InstallDir`"",
        '-UpdateIntervalMinutes', $IntervalMinutes,
        '-UpdateTaskName', "`"$TaskName`""
    )

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($taskArgs -join ' ')
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -User 'SYSTEM' `
        -RunLevel Highest `
        -Description 'Constitute Gateway auto-update (release channel)' `
        -Force | Out-Null

    Write-Host "Auto-update task configured: $TaskName (every $IntervalMinutes minutes)"
}

function Service-Exists {
    param([string]$Name)
    try {
        Get-Service -Name $Name -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Set-ReleaseMetadata {
    param(
        [string]$ConfigPath,
        [string]$Channel = 'release',
        [string]$Track = 'latest',
        [string]$Branch = ''
    )

    if (-not (Test-Path $ConfigPath)) { return }
    try {
        $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $cfg | Add-Member -NotePropertyName release_channel -NotePropertyValue $Channel -Force
        $cfg | Add-Member -NotePropertyName release_track -NotePropertyValue $Track -Force
        $cfg | Add-Member -NotePropertyName release_branch -NotePropertyValue $Branch -Force
        $cfg | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 $ConfigPath
    } catch {
        Write-Warning "Failed to patch release metadata in ${ConfigPath}: $($_.Exception.Message)"
    }
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($env:ProgramData) {
        $InstallDir = Join-Path $env:ProgramData 'Constitute\Gateway\bundle'
    } elseif ($env:LOCALAPPDATA) {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Constitute\Gateway\bundle'
    } else {
        throw 'Unable to determine default install directory'
    }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("constitute-gateway-install-" + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    $zipPath = Join-Path $tmp $zipName
    $sumPath = Join-Path $tmp 'SHA256SUMS'

    Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zipPath
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumPath

    $hashLine = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower() + "  $zipName"
    $expected = Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zipName) }
    if (-not $expected) { throw "Checksum entry not found for $zipName" }
    if ($expected.Trim() -ne $hashLine.Trim()) { throw "Checksum mismatch for $zipName" }

    $extractDir = Join-Path $tmp 'extract'
    Expand-Archive $zipPath -DestinationPath $extractDir

    $bundleScript = Join-Path $extractDir 'scripts\windows\install-service.ps1'
    $bundleBinary = Join-Path $extractDir 'constitute-gateway.exe'
    if (-not (Test-Path $bundleScript)) { throw 'Release bundle missing scripts/windows/install-service.ps1' }
    if (-not (Test-Path $bundleBinary)) { throw 'Release bundle missing constitute-gateway.exe' }

    $skipInstall = $false
    $installedBinary = Join-Path $InstallDir 'constitute-gateway.exe'
    if ((Test-Path $installedBinary) -and (Service-Exists -Name $ServiceName) -and (-not $PairIdentity) -and (-not $PairCode) -and (-not $PairCodeHash)) {
        $currentHash = (Get-FileHash $installedBinary -Algorithm SHA256).Hash.ToLower()
        $bundleHash = (Get-FileHash $bundleBinary -Algorithm SHA256).Hash.ToLower()
        if ($currentHash -eq $bundleHash) {
            $skipInstall = $true
            Write-Host 'No binary change detected; skipping reinstall/restart.'
        }
    }

    if (-not $skipInstall) {
        if (Test-Path $InstallDir) {
            Remove-Item -Recurse -Force $InstallDir
        }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item -Recurse -Force (Join-Path $extractDir '*') $InstallDir

        $serviceArgs = @('-ServiceName', $ServiceName)
        if (-not [string]::IsNullOrWhiteSpace($PairIdentity)) { $serviceArgs += @('-PairIdentity', $PairIdentity) }
        if (-not [string]::IsNullOrWhiteSpace($PairCode)) { $serviceArgs += @('-PairCode', $PairCode) }
        if (-not [string]::IsNullOrWhiteSpace($PairCodeHash)) { $serviceArgs += @('-PairCodeHash', $PairCodeHash) }

        & powershell -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'scripts\windows\install-service.ps1') @serviceArgs
        if ($LASTEXITCODE -ne 0) {
            throw "install-service.ps1 failed with exit code $LASTEXITCODE"
        }
    }

    $installedConfig = Join-Path $InstallDir 'config.json'
    Set-ReleaseMetadata -ConfigPath $installedConfig -Channel 'release' -Track 'latest' -Branch ''

    if (-not $SkipUpdateTask) {
        $installedScript = Join-Path $InstallDir 'scripts\windows\install-latest.ps1'
        if (-not (Test-Path $installedScript)) {
            throw 'install-latest.ps1 not found in installed bundle; cannot configure auto-update task'
        }
        Ensure-UpdateTask `
            -TaskName $UpdateTaskName `
            -IntervalMinutes $UpdateIntervalMinutes `
            -ScriptPath $installedScript `
            -RepoOwner $RepoOwner `
            -RepoName $RepoName `
            -ServiceName $ServiceName `
            -InstallDir $InstallDir
    }

    Write-Host "Install/update complete: $ServiceName ($InstallDir)"
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
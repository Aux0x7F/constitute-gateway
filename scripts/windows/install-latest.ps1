param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [string]$ServiceName = 'ConstituteGateway',
    [string]$InstallDir = '',
    [switch]$DevSource,
    [string]$DevBranch = 'main',
    [string]$DevSourceDir = '',
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
        [string]$InstallDir,
        [bool]$DevSourceMode,
        [string]$DevBranch,
        [string]$DevSourceDir
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

    if ($DevSourceMode) {
        $taskArgs += @('-DevSource')
        $taskArgs += @('-DevBranch', "`"$DevBranch`"")
        $taskArgs += @('-DevSourceDir', "`"$DevSourceDir`"")
    }

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
        -Description 'Constitute Gateway auto-update (release or dev-source)' `
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

if ($DevSource -and [string]::IsNullOrWhiteSpace($DevSourceDir)) {
    if ($env:ProgramData) {
        $DevSourceDir = Join-Path $env:ProgramData 'Constitute\Gateway\source'
    } elseif ($env:LOCALAPPDATA) {
        $DevSourceDir = Join-Path $env:LOCALAPPDATA 'Constitute\Gateway\source'
    } else {
        throw 'Unable to determine default source directory'
    }
}
if ($DevSource -and [string]::IsNullOrWhiteSpace($DevSourceDir)) {
    $DevSourceDir = $InstallDir
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($DevSource) {
        $InstallDir = $DevSourceDir
    } elseif ($env:ProgramData) {
        $InstallDir = Join-Path $env:ProgramData 'Constitute\Gateway\bundle'
    } elseif ($env:LOCALAPPDATA) {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Constitute\Gateway\bundle'
    } else {
        throw 'Unable to determine default install directory'
    }
}

if ($DevSource) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git is required for -DevSource'
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo is required for -DevSource'
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if (-not (Test-Path (Join-Path $InstallDir '.git'))) {
        & git clone "https://github.com/$RepoOwner/$RepoName.git" $InstallDir
        if ($LASTEXITCODE -ne 0) { throw "git clone failed with exit code $LASTEXITCODE" }
    }

    & git -C $InstallDir fetch --prune origin
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed with exit code $LASTEXITCODE" }
    & git -C $InstallDir checkout $DevBranch
    if ($LASTEXITCODE -ne 0) { throw "git checkout $DevBranch failed with exit code $LASTEXITCODE" }
    & git -C $InstallDir reset --hard "origin/$DevBranch"
    if ($LASTEXITCODE -ne 0) { throw "git reset origin/$DevBranch failed with exit code $LASTEXITCODE" }

    Push-Location $InstallDir
    try {
        cargo build --release --features platform-windows -j 1
        if ($LASTEXITCODE -ne 0) {
            throw 'cargo build failed for dev-source install'
        }
    } finally {
        Pop-Location
    }

    $devInstallService = Join-Path $InstallDir 'scripts\windows\install-service.ps1'
    if (-not (Test-Path $devInstallService)) {
        throw "install-service.ps1 missing in dev source checkout: $devInstallService"
    }

    & powershell -ExecutionPolicy Bypass -File $devInstallService -ServiceName $ServiceName
    if ($LASTEXITCODE -ne 0) {
        throw "install-service.ps1 failed with exit code $LASTEXITCODE"
    }

    $installedConfig = Join-Path $InstallDir 'config.json'
    Set-ReleaseMetadata -ConfigPath $installedConfig -Channel 'dev-source' -Track $DevBranch -Branch $DevBranch

    if (-not $SkipUpdateTask) {
        $installedScript = Join-Path $InstallDir 'scripts\windows\install-latest.ps1'
        if (-not (Test-Path $installedScript)) {
            throw 'install-latest.ps1 not found in dev source checkout; cannot configure auto-update task'
        }
        Ensure-UpdateTask `
            -TaskName $UpdateTaskName `
            -IntervalMinutes $UpdateIntervalMinutes `
            -ScriptPath $installedScript `
            -RepoOwner $RepoOwner `
            -RepoName $RepoName `
            -ServiceName $ServiceName `
            -InstallDir $InstallDir `
            -DevSourceMode $true `
            -DevBranch $DevBranch `
            -DevSourceDir $InstallDir
    }

    Write-Host "Install/update complete: $ServiceName ($InstallDir, dev-source branch $DevBranch)"
    exit 0
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
    if ((Test-Path $installedBinary) -and (Service-Exists -Name $ServiceName)) {
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

        & powershell -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'scripts\windows\install-service.ps1') -ServiceName $ServiceName
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
            -InstallDir $InstallDir `
            -DevSourceMode $false `
            -DevBranch '' `
            -DevSourceDir ''
    }

    Write-Host "Install/update complete: $ServiceName ($InstallDir)"
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}

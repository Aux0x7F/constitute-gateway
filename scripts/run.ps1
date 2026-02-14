param(
    [string]$Command = '',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = 'Stop'
$DefaultServiceName = 'ConstituteGateway'

function Get-ServiceInfo([string]$ServiceName = $DefaultServiceName) {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        return [pscustomobject]@{
            Exists = $true
            Name = $ServiceName
            Status = [string]$svc.Status
        }
    } catch {
        return [pscustomobject]@{
            Exists = $false
            Name = $ServiceName
            Status = 'NotInstalled'
        }
    }
}

function Invoke-ServiceAction([string]$Action, [string]$ServiceName = $DefaultServiceName) {
    $svc = Get-ServiceInfo $ServiceName
    switch ($Action) {
        'status' {
            Write-Host "Service ${ServiceName}: $($svc.Status)"
        }
        'start' {
            if (-not $svc.Exists) { throw "Service not installed: $ServiceName" }
            Start-Service -Name $ServiceName
            Write-Host "Service started: $ServiceName"
        }
        'stop' {
            if (-not $svc.Exists) { throw "Service not installed: $ServiceName" }
            Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
            Write-Host "Service stopped: $ServiceName"
        }
        'restart' {
            if (-not $svc.Exists) { throw "Service not installed: $ServiceName" }
            Restart-Service -Name $ServiceName
            Write-Host "Service restarted: $ServiceName"
        }
        'uninstall' {
            if (-not $svc.Exists) { throw "Service not installed: $ServiceName" }
            try { Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
            & sc.exe delete $ServiceName | Out-Host
            Write-Host "Service removed from SCM: $ServiceName"
            Write-Host 'Binary/config/data were not deleted.'
        }
        default {
            throw "Unknown service action: $Action"
        }
    }
}

function Invoke-Tool([string]$name, [string[]]$extra) {
    switch ($name) {
        'build-windows' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\build.ps1') -Target windows @extra }
        'build-linux' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\build.ps1') -Target linux @extra }
        'install-service' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\install-service.ps1') @extra }
        'update-windows' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\install-latest.ps1') @extra }
        'check-release' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\check-update.ps1') @extra }
        'run-gateway' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\run-gateway.ps1') @extra }
        'fcos-download-base-image' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\usb-prep.ps1') @extra }
        'fcos-full-prep' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\usb-prep.ps1') -UseWsl @extra }
        'service-status' { Invoke-ServiceAction 'status' }
        'service-start' { Invoke-ServiceAction 'start' }
        'service-stop' { Invoke-ServiceAction 'stop' }
        'service-restart' { Invoke-ServiceAction 'restart' }
        'service-uninstall' { Invoke-ServiceAction 'uninstall' }
        # Compatibility aliases (kept for existing automation).
        'fcos-image-only' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\usb-prep.ps1') @extra }
        'usb-prep' { & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'windows\usb-prep.ps1') @extra }
        default { throw "Unknown command: $name" }
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Show-BuildMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Build Menu'
        Write-Host '1) Build Windows binary'
        Write-Host '2) Build Linux package via WSL'
        Write-Host '0) Back'
        $buildChoice = Read-Host 'Select build option'
        switch ($buildChoice) {
            '1' { Invoke-Tool 'build-windows' @(); return }
            '2' { Invoke-Tool 'build-linux' @(); return }
            '0' { return }
            default { Write-Host 'Invalid option' }
        }
    }
}

if ($Command) {
    Invoke-Tool $Command $ExtraArgs
    exit 0
}

$svc = Get-ServiceInfo

Write-Host "Constitute Gateway Script Runner (Windows)"
Write-Host "Service '$($svc.Name)': $($svc.Status)"
Write-Host '1) Build'
if ($svc.Exists) {
    Write-Host '2) Update from latest release'
} else {
    Write-Host '2) Install from latest release'
}
Write-Host '3) Check latest release asset'
Write-Host '4) Run gateway foreground'
if ($svc.Exists) {
    Write-Host '5) Service status'
    Write-Host '6) Service start'
    Write-Host '7) Service stop'
    Write-Host '8) Service restart'
    Write-Host '9) Service uninstall'
} else {
    Write-Host '5) Install Windows service'
}
Write-Host '10) Download upstream FCOS base ISO only (no Ignition, no write)'
Write-Host '11) FCOS full prep via WSL (optional Ignition + optional direct write)'
Write-Host '0) Exit'
$choice = Read-Host 'Select option'

switch ($choice) {
    '1' { Show-BuildMenu }
    '2' { Invoke-Tool 'update-windows' @() }
    '3' { Invoke-Tool 'check-release' @() }
    '4' { Invoke-Tool 'run-gateway' @() }
    '5' {
        if ($svc.Exists) { Invoke-Tool 'service-status' @() }
        else { Invoke-Tool 'install-service' @() }
    }
    '6' { if ($svc.Exists) { Invoke-Tool 'service-start' @() } else { throw 'Invalid option' } }
    '7' { if ($svc.Exists) { Invoke-Tool 'service-stop' @() } else { throw 'Invalid option' } }
    '8' { if ($svc.Exists) { Invoke-Tool 'service-restart' @() } else { throw 'Invalid option' } }
    '9' {
        if ($svc.Exists) {
            $confirm = Read-Host "Type YES to uninstall service '$($svc.Name)'"
            if ($confirm -eq 'YES') { Invoke-Tool 'service-uninstall' @() }
            else { Write-Host 'Uninstall aborted.' }
        } else {
            throw 'Invalid option'
        }
    }
    '10' { Invoke-Tool 'fcos-download-base-image' @() }
    '11' {
        $args = @()
        $defaultIgnition = '.\infra\fcos\generated\config.ign'
        $ignPrompt = "Ignition path (blank = use $defaultIgnition if present; none if absent)"
        $ignitionPath = Read-Host $ignPrompt
        if ([string]::IsNullOrWhiteSpace($ignitionPath) -and (Test-Path $defaultIgnition)) {
            $ignitionPath = $defaultIgnition
        }
        if (-not [string]::IsNullOrWhiteSpace($ignitionPath)) {
            $args += @('-IgnitionPath', $ignitionPath)
        }

        $device = Read-Host 'Direct USB write device in WSL (blank = image only, e.g. /dev/sdX to write)'
        if (-not [string]::IsNullOrWhiteSpace($device)) {
            $args += @('-Device', $device)
        }

        Invoke-Tool 'fcos-full-prep' $args
    }
    '0' { exit 0 }
    default { throw 'Invalid option' }
}
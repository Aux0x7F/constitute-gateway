param(
    [string]$ServiceName = 'ConstituteGateway',
    [string]$NssmPath = '.\\nssm\\nssm.exe'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$bin = Join-Path $repo 'constitute-gateway.exe'

if (-not (Test-Path $NssmPath)) {
    throw "nssm.exe not found at $NssmPath"
}
if (-not (Test-Path $bin)) {
    throw "Binary not found: $bin"
}

& $NssmPath install $ServiceName $bin
& $NssmPath set $ServiceName AppDirectory $repo
& $NssmPath set $ServiceName AppParameters "--config $repo\config.json"
& $NssmPath start $ServiceName
Write-Host "Service installed and started: $ServiceName"

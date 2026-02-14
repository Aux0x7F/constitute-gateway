param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [string]$ServiceName = 'ConstituteGateway'
)

$ErrorActionPreference = 'Stop'
$base = "https://github.com/$RepoOwner/$RepoName/releases/latest/download"
$zipName = 'constitute-gateway-windows.zip'
$zipPath = Join-Path $PSScriptRoot $zipName
$sumPath = Join-Path $PSScriptRoot 'SHA256SUMS'
$extractDir = Join-Path $PSScriptRoot 'constitute-gateway'

Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zipPath
Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumPath

$hashLine = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower() + "  $zipName"
$hashLine | Out-File -Encoding ascii (Join-Path $PSScriptRoot 'hash.check')

$expected = Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zipName) }
if (-not $expected) { throw "Checksum entry not found for $zipName" }
if ($expected.Trim() -ne $hashLine.Trim()) { throw "Checksum mismatch for $zipName" }

if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive $zipPath -DestinationPath $extractDir

& powershell -ExecutionPolicy Bypass -File (Join-Path $extractDir 'scripts\windows\install-service.ps1') -ServiceName $ServiceName -NssmPath (Join-Path $extractDir 'nssm\nssm.exe')


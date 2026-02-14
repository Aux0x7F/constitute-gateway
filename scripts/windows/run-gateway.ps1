param(
    [string]$Config = 'config.json',
    [string]$LogLevel = 'warn'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bin = Join-Path $repo 'target\release\constitute-gateway.exe'
$configPath = Join-Path $repo $Config
$configExample = Join-Path $repo 'config.example.json'

if (-not (Test-Path $bin)) {
    throw "Binary not found: $bin (run .\scripts\windows\build.ps1 -Target windows)"
}
if (-not (Test-Path $configPath)) {
    if (Test-Path $configExample) {
        Copy-Item $configExample $configPath
    } else {
        throw "config.json missing and no config.example.json to copy"
    }
}

& $bin --config $configPath --log-level $LogLevel


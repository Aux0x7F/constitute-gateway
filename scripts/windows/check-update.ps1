param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [string]$AssetPattern = 'constitute-gateway-windows.zip'
)

$ErrorActionPreference = 'Stop'
$api = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
$release = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'constitute-gateway-updater' }
$asset = $release.assets | Where-Object { $_.name -eq $AssetPattern } | Select-Object -First 1

if (-not $asset) {
    throw "Asset not found: $AssetPattern"
}

$dest = Join-Path $PSScriptRoot $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest
Write-Host "Downloaded: $dest"

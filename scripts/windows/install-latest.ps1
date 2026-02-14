param(
    [string]$RepoOwner = 'Aux0x7F',
    [string]$RepoName = 'constitute-gateway',
    [string]$ServiceName = 'ConstituteGateway',
    [string]$InstallDir = ''
)

$ErrorActionPreference = 'Stop'
$base = "https://github.com/$RepoOwner/$RepoName/releases/latest/download"
$zipName = 'constitute-gateway-windows.zip'

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

    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $extractDir '*') $InstallDir

    & powershell -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'scripts\windows\install-service.ps1') -ServiceName $ServiceName
    if ($LASTEXITCODE -ne 0) {
        throw "install-service.ps1 failed with exit code $LASTEXITCODE"
    }

    Write-Host "Install/update complete: $ServiceName ($InstallDir)"
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}

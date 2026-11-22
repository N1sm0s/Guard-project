$ErrorActionPreference = 'Stop'

# Run once while signed in as the second human reviewer. This points that
# Windows profile at the existing local IntegrityGuard data root so both
# reviewers see the same immutable network events and review ledger.
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sharedDataRoot = Join-Path $projectRoot 'data'
if (-not (Test-Path -LiteralPath $sharedDataRoot -PathType Container)) {
    throw "Shared IntegrityGuard data root does not exist: $sharedDataRoot"
}

$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$configDir = Join-Path $localAppData 'IntegrityGuard'
$configPath = Join-Path $configDir 'data-location.txt'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null

if (Test-Path -LiteralPath $configPath) {
    $backup = "$configPath.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $configPath -Destination $backup
    Write-Output "Previous data-root setting backed up to: $backup"
}

$probePath = Join-Path $sharedDataRoot ".reviewer-access-$([guid]::NewGuid().ToString('N')).tmp"
$stream = [System.IO.File]::Open($probePath, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
$stream.Dispose()
Remove-Item -LiteralPath $probePath -Force

Set-Content -LiteralPath $configPath -Value $sharedDataRoot -Encoding utf8
Write-Output "Reviewer: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Output "Shared data root configured: $sharedDataRoot"
Write-Output "Restart IntegrityGuard under this Windows account to review the shared queue."

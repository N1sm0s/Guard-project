# Elevated: close the running IntegrityGuard, put the staged build in place (old one kept as backup),
# start the new build elevated. Log: outputs\lab\swap-app-elevated.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\swap-app-elevated.txt"
$staged = Join-Path $root "build\staging-dist-20261123f\IntegrityGuard"
$installed = Join-Path $root "dist\IntegrityGuard"
$backup = Join-Path $root "dist\IntegrityGuard-backup-20261123f"

function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

$running = Get-Process IntegrityGuard -ErrorAction SilentlyContinue
if ($running) {
    foreach ($p in $running) { [void]$p.CloseMainWindow() }
    Start-Sleep -Seconds 15
    $left = Get-Process IntegrityGuard -ErrorAction SilentlyContinue
    if ($left) { $left | Stop-Process -Force; Start-Sleep -Seconds 3; Log "force-stopped previous instance" }
    else { Log "previous instance closed gracefully" }
} else { Log "no previous instance" }

if (Test-Path $backup) { Remove-Item $backup -Recurse -Force }
Move-Item $installed $backup
Log "old build moved to backup"
Move-Item $staged $installed
Log "new build in place"

Start-Process -FilePath (Join-Path $installed "IntegrityGuard.exe") -WorkingDirectory $installed
Start-Sleep -Seconds 20
$now = Get-Process IntegrityGuard -ErrorAction SilentlyContinue | Select-Object Id, Path
Log ("running: " + ($now | Out-String))
Log ("done " + (Get-Date -Format o))

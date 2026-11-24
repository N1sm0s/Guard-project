# Elevated: close the running IntegrityGuard gracefully, move the current build aside (kept as backup),
# put the staged build in place, start it. Log: outputs\lab\swap-app-20261124-elevated.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\swap-app-20261124-elevated.txt"
$staged = Join-Path $root "build\staging-dist-20261124\IntegrityGuard"
$installed = Join-Path $root "dist\IntegrityGuard"
$backup = Join-Path $root "dist\IntegrityGuard-backup-20261124c"

function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

if (-not (Test-Path (Join-Path $staged "IntegrityGuard.exe"))) { Log "staged exe missing; abort"; exit 1 }
if (Test-Path $backup) { Log "backup path already exists; abort"; exit 1 }

$running = Get-Process IntegrityGuard -ErrorAction SilentlyContinue
if ($running) {
    foreach ($p in $running) { [void]$p.CloseMainWindow() }
    Start-Sleep -Seconds 15
    $left = Get-Process IntegrityGuard -ErrorAction SilentlyContinue
    if ($left) { $left | Stop-Process -Force; Start-Sleep -Seconds 3; Log "force-stopped previous instance" }
    else { Log "previous instance closed gracefully" }
} else { Log "no previous instance" }

Move-Item $installed $backup
Log "current build moved to backup"
Move-Item $staged $installed
Log "staged build in place"

Start-Process -FilePath (Join-Path $installed "IntegrityGuard.exe") -WorkingDirectory $installed
Start-Sleep -Seconds 20
$now = Get-Process IntegrityGuard -ErrorAction SilentlyContinue | Select-Object Id, Path
Log ("running: " + ($now | Out-String))
Log ("done " + (Get-Date -Format o))

# Elevated: stop an orphaned app-owned pktmon capture (its ETL path contains integrityguard-pktmon-),
# verify pktmon is free, then run the lab scan capture. Log: outputs\lab\session\release-pktmon-run.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\session\release-pktmon-run.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

if ((@(Get-CimInstance Win32_Process -Filter "Name='IntegrityGuard.exe'")).Count -gt 0) { Log "IntegrityGuard still running; stop" ; exit 1 }

$status = (pktmon status 2>&1 | Out-String)
Log ("status exit: " + $LASTEXITCODE)
Log ("status text (non-ASCII replaced): " + ($status -replace '[^\x20-\x7E\r\n]', '?'))
Log ("status before: " + $status.Length + " chars; owned marker present: " + ($status -match 'integrityguard-pktmon-'))
if ($status -match 'integrityguard-pktmon-') {
    $out = (pktmon stop 2>&1 | Out-String)
    Log ("pktmon stop: " + $out.Trim())
    Start-Sleep -Seconds 2
    $after = (pktmon status 2>&1 | Out-String)
    Log ("status after: " + $after.Length + " chars; owned marker present: " + ($after -match 'integrityguard-pktmon-'))
} else {
    Log "no app-owned capture marker found; nothing stopped"
}

& (Join-Path $root "tools\lab\lab_scan_more_elevated.ps1")
Log ("done " + (Get-Date -Format o))

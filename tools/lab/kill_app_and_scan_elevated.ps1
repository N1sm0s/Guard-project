# Elevated: stop the IntegrityGuard monitor task and process, stop only the app-owned pktmon
# capture (ETL under integrityguard-pktmon-*\segment.etl), then run the lab scan capture.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\session\kill-and-scan-run.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

try { Stop-ScheduledTask -TaskName "IntegrityGuard Network Monitor" -ErrorAction Stop; Log "monitor task stopped" } catch { Log ("monitor task: " + $_.Exception.Message) }
Get-Process IntegrityGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 4
Log ("app processes left: " + (@(Get-Process IntegrityGuard -ErrorAction SilentlyContinue)).Count)

$status = (pktmon status 2>&1 | Out-String)
Log ("pktmon status: " + $status.Trim())
$m = [regex]::Match($status, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
if ($m.Success) {
    $etl = $m.Groups[1].Value.Trim()
    if ($etl -match 'integrityguard-pktmon-[^\\]+\\segment\.etl$') {
        pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop (app-owned): " + $_.Trim()) }
    } else { Log "pktmon capture is not app-owned; not stopped. Scan run will refuse." }
}

& (Join-Path $root "tools\lab\lab_scan_more_elevated.ps1")
Log ("done " + (Get-Date -Format o))

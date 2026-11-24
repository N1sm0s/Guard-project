# Elevated, READ-ONLY diagnosis: which IntegrityGuard processes exist, how they were started,
# the monitor task definition and last run, and the pktmon session. Stops nothing.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\session\diagnose-run.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

Log "--- IntegrityGuard processes (elevated view)"
Get-CimInstance Win32_Process -Filter "Name='IntegrityGuard.exe'" | ForEach-Object {
    Log ("PID " + $_.ProcessId + " parent " + $_.ParentProcessId + " started " + $_.CreationDate + " path " + $_.ExecutablePath + " cmd " + $_.CommandLine)
}
if (-not (Get-CimInstance Win32_Process -Filter "Name='IntegrityGuard.exe'")) { Log "none" }

Log "--- scheduled task 'IntegrityGuard Network Monitor'"
try {
    $t = Get-ScheduledTask -TaskName "IntegrityGuard Network Monitor" -ErrorAction Stop
    Log ("state " + $t.State + " enabled " + $t.Settings.Enabled + " runlevel " + $t.Principal.RunLevel)
    Log ("actions " + (($t.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " ; "))
    Log ("triggers " + (($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "))
    $info = Get-ScheduledTaskInfo -TaskName "IntegrityGuard Network Monitor"
    Log ("last run " + $info.LastRunTime + " result " + $info.LastTaskResult + " next " + $info.NextRunTime)
} catch { Log ("task query failed: " + $_.Exception.Message) }

Log "--- pktmon status"
Log ((pktmon status 2>&1 | Out-String).Trim())

Log ("done " + (Get-Date -Format o))

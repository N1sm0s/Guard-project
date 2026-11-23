# Elevated: benign-14, legitimate SSH sessions to the victim from the lab host (172.20.0.1), with ordinary
# commands and short idle periods (successful logins, not failed attempts). Lab only. Journal before start.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "benign14-run.txt"
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }
Remove-Item $progress -ErrorAction SilentlyContinue

$activity = "legitimate SSH sessions from the lab host to the victim: login, ordinary commands, short idle, lab only"
$start = Utc
Journal @{ scenario_id = "benign-14"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
           operator = "pavel"; activity = $activity; status = "open-before-start" }
Log ("start benign-14 " + $start)
$etl = Join-Path $dir "benign-14.etl"
$pcap = Join-Path $dir "benign-14.pcapng"
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
pktmon stop 2>&1 | Out-Null
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
Start-Sleep -Seconds 2
$ok = 0
for ($i = 1; $i -le 60; $i++) {
    ssh -i $key -o BatchMode=yes -o ConnectTimeout=5 pavel2@172.20.0.10 "uptime >/dev/null; sleep 4" 2>$null
    if ($LASTEXITCODE -eq 0) { $ok++ }
    Start-Sleep -Seconds 3
}
Log ("sessions ok: " + $ok)
Start-Sleep -Seconds 2
pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
$end = Utc
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
Journal @{ scenario_id = "benign-14"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
           operator = "pavel"; activity = $activity; pcapng = "benign-14.pcapng" }
Log ("end " + $end)
Log ("done " + (Get-Date -Format o))

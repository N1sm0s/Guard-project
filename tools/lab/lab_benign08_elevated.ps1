# Elevated: scenario benign-08 (normal web service inside the lab).
# Victim serves a small web page on port 8080 (no sudo), attacker makes many separate HTTP requests,
# each on a new TCP connection. Journal entry is written before start and closed after.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
. (Join-Path $PSScriptRoot 'pktmon_session.ps1')
Assert-PktmonStopped
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "benign-08-run.txt"
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }
Remove-Item $progress -ErrorAction SilentlyContinue

$activity = "normal web service: victim serves a page on 8080, attacker makes many separate HTTP requests inside lab"
$start = Utc
Journal @{ scenario_id = "benign-08"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
           operator = "pavel"; activity = $activity; status = "open-before-start" }
Log ("start " + $start)

ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "nohup python3 -m http.server 8080 --bind 172.20.0.10 >/tmp/httpd.log 2>&1 & echo started" 2>&1 | Out-String | ForEach-Object { Log ("server: " + $_.Trim()) }
Start-Sleep -Seconds 2

$etl = Join-Path $dir "benign-08.etl"
$pcap = Join-Path $dir "benign-08.pcapng"
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
    Assert-PktmonStopped
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
    Assert-PktmonOwned -EtlPath $etl
Start-Sleep -Seconds 2
$cmd = 'ok=0; for i in $(seq 1 300); do curl -s -o /dev/null --no-keepalive -w "%{http_code}" http://172.20.0.10:8080/ | grep -q 200 && ok=$((ok+1)); sleep 0.5; done; echo "ok=$ok"'
$run = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 $cmd 2>&1 | Out-String
Log ("run: " + $run.Trim())
Start-Sleep -Seconds 2
Stop-PktmonOwned -EtlPath $etl | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
$end = Utc
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "pkill -f 'http.server 8080'; echo stopped" 2>&1 | Out-String | ForEach-Object { Log ("server stop: " + $_.Trim()) }
Journal @{ scenario_id = "benign-08"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
           operator = "pavel"; activity = $activity; pcapng = "benign-08.pcapng" }
Log ("end " + $end)
Log ("done " + (Get-Date -Format o))

# Elevated: re-run scenario benign-07 (UDP application bursts, new source port per burst, victim -> attacker).
# Journal entry is written before start and closed after. Output: outputs\lab\session\benign-07.pcapng
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "benign-07-run.txt"
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }
Remove-Item $progress -ErrorAction SilentlyContinue

$start = Utc
Journal @{ scenario_id = "benign-07"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
           operator = "pavel"; activity = "UDP application bursts with new source port, victim to attacker"; status = "open-before-start" }
Log ("start " + $start)
$etl = Join-Path $dir "benign-07.etl"
$pcap = Join-Path $dir "benign-07.pcapng"
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
pktmon stop 2>&1 | Out-Null
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
Start-Sleep -Seconds 2
$cmd = 'for i in $(seq 1 60); do for j in 1 2 3 4; do echo app > /dev/udp/172.20.0.5/5353; sleep 0.05; done; sleep 2.5; done; echo done'
$run = ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 $cmd 2>&1 | Out-String
Log ("run: " + $run.Trim())
Start-Sleep -Seconds 2
pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
$end = Utc
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
Journal @{ scenario_id = "benign-07"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
           operator = "pavel"; activity = "UDP application bursts with new source port, victim to attacker"; pcapng = "benign-07.pcapng" }
Log ("end " + $end)
Log ("done " + (Get-Date -Format o))

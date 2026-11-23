# Elevated: fresh calibration background (benign-10), lab-only, different mix from benign-09:
# web requests and ssh sessions from the attacker VM, plus small UDP datagrams from the victim to the attacker.
# Journal entry before start, pcapng after. Used only for threshold calibration, never for test.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "benign10-run.txt"
$attackerMac = "00:15:5d:00:7e:05"
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }
Remove-Item $progress -ErrorAction SilentlyContinue

ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "nohup python3 -m http.server 8080 --bind 172.20.0.10 >/tmp/httpd.log 2>&1 & echo started" 2>&1 | Out-String | ForEach-Object { Log ("server: " + $_.Trim()) }
Start-Sleep -Seconds 2
$start = Utc
Journal @{ scenario_id = "benign-10"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
           attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = "mixed"; operator = "pavel";
           activity = "calibration background: web and ssh from attacker, UDP datagrams victim to attacker, lab subnet only";
           status = "open-before-start" }
Log ("start benign-10 " + $start)
$etl = Join-Path $dir "benign-10.etl"
$pcap = Join-Path $dir "benign-10.pcapng"
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
pktmon stop 2>&1 | Out-Null
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
Start-Sleep -Seconds 2
$job = Start-Job -ScriptBlock {
    param($k)
    ssh -i $k -o BatchMode=yes pavel2@172.20.0.10 'for i in $(seq 1 150); do for j in 1 2 3; do echo tick > /dev/udp/172.20.0.5/5353; done; sleep 2; done; echo done'
} -ArgumentList $key
$cmd = 'for i in $(seq 1 150); do curl -s -o /dev/null --no-keepalive http://172.20.0.10:8080/ ; ssh -o BatchMode=yes -o ConnectTimeout=3 pavel2@172.20.0.10 uptime >/dev/null 2>&1; sleep 2; done; echo done'
$run = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 $cmd 2>&1 | Out-String
Log ("run: " + $run.Trim())
Wait-Job $job -Timeout 60 | Out-Null
Receive-Job $job | Out-Null
Remove-Job $job -Force
Start-Sleep -Seconds 2
pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
$end = Utc
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "pkill -f 'http.server 8080'; echo stopped" 2>&1 | Out-String | ForEach-Object { Log ("server stop: " + $_.Trim()) }
Journal @{ scenario_id = "benign-10"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
           attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = "mixed"; operator = "pavel";
           activity = "calibration background: web and ssh from attacker, UDP datagrams victim to attacker, lab subnet only";
           pcapng = "benign-10.pcapng" }
Log ("end " + $end)
Log ("done " + (Get-Date -Format o))

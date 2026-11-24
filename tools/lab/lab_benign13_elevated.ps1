# Elevated: benign-13, realistic UDP request/response background inside the lab (DNS-like lookups,
# new source port per request, reply expected). Lab-only. Journal before start; capture all components.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
. (Join-Path $PSScriptRoot 'pktmon_session.ps1')
Assert-PktmonStopped
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "benign13-run.txt"
$attackerMac = "00:15:5d:00:7e:05"
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }
Remove-Item $progress -ErrorAction SilentlyContinue

ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "pgrep -f udp_responder.py >/dev/null || nohup python3 /tmp/udp_responder.py >/tmp/udp_responder.log 2>&1 & echo responder_ok" 2>&1 | Out-String | ForEach-Object { Log ("responder: " + $_.Trim()) }
Start-Sleep -Seconds 2
$activity = "realistic UDP request/response background: DNS-like lookups, new source port per request, replies from victim, lab only"
$start = Utc
Journal @{ scenario_id = "benign-13"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
           attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = "python3"; operator = "pavel";
           activity = $activity; status = "open-before-start" }
Log ("start benign-13 " + $start)
$etl = Join-Path $dir "benign-13.etl"
$pcap = Join-Path $dir "benign-13.pcapng"
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
    Assert-PktmonStopped
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
    Assert-PktmonOwned -EtlPath $etl
Start-Sleep -Seconds 2
$run = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 "python3 /tmp/udp_request_client.py" 2>&1 | Out-String
Log ("run: " + $run.Trim())
Start-Sleep -Seconds 2
Stop-PktmonOwned -EtlPath $etl | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
$end = Utc
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
Journal @{ scenario_id = "benign-13"; label = "benign"; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
           attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = "python3"; operator = "pavel";
           activity = $activity; pcapng = "benign-13.pcapng" }
Log ("end " + $end)
Log ("done " + (Get-Date -Format o))

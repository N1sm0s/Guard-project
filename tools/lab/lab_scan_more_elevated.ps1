# Elevated: more port-scan variants inside the lab only (attacker 172.20.0.5 -> victim 172.20.0.10).
# Four new scan sessions, different nmap modes, so a held-out variant can be tested later.
# Journal entry before each start, pcapng per scenario. Log: outputs\lab\session\scan-more-run.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
. (Join-Path $PSScriptRoot 'pktmon_session.ps1')
Assert-PktmonStopped
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "scan-more-run.txt"
$attackerMac = "00:15:5d:00:7e:05"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Remove-Item $progress -ErrorAction SilentlyContinue
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }

$scenarios = @(
    @{ id = "scan-05"; label = "attack:port_scan_connect"; tool = "nmap";
       activity = "nmap TCP connect scan (no raw SYN) of ports 1-1000";
       cmd = "nmap -sT -T3 -p 1-1000 -n 172.20.0.10 | tail -2" },
    @{ id = "scan-06"; label = "attack:port_scan_udp"; tool = "nmap";
       activity = "nmap UDP scan of the 50 most common ports";
       cmd = "sudo nmap -sU -T3 --top-ports 50 -n 172.20.0.10 | tail -2" },
    @{ id = "scan-07"; label = "attack:port_scan_fast"; tool = "nmap";
       activity = "nmap fast SYN scan of ports 1-10000 at up to 1000 packets per second";
       cmd = "sudo nmap -sS -T5 --max-rate 1000 -p 1-10000 -n 172.20.0.10 | tail -2" },
    @{ id = "scan-08"; label = "attack:port_scan_sparse"; tool = "nmap";
       activity = "nmap SYN scan of 12 common service ports with 5 second gaps between probes";
       cmd = "sudo nmap -sS -T2 -p 21,22,23,25,53,80,110,139,443,445,3306,8080 -n 172.20.0.10 | tail -2" }
)

# Recovery: if a lab capture of this session is still running (an earlier run stopped early),
# stop it cleanly and convert it, then close its journal entry.
$activeStatus = (pktmon status 2>&1 | Out-String)
$activePath = Get-PktmonSessionEtlPath $activeStatus
if ($activePath -and ($activePath -like (Join-Path $dir "scan-0*.etl"))) {
    $rid = [IO.Path]::GetFileNameWithoutExtension($activePath)
    Log ("recovering running capture " + $rid)
    Stop-PktmonOwned -EtlPath $activePath | ForEach-Object { Log ("pktmon stop (recovery): " + $_.Trim()) }
    pktmon etl2pcap $activePath --out (Join-Path $dir ($rid + ".pcapng")) 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap (recovery): " + $_.Trim()) }
    $sc0 = $scenarios | Where-Object { $_.id -eq $rid } | Select-Object -First 1
    if ($sc0) {
        Journal @{ scenario_id = $sc0.id; label = $sc0.label; lab_subnet = "172.20.0.0/24"; start_utc = "recovered"; end_utc = (Utc);
                   attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc0.tool; operator = "pavel";
                   activity = $sc0.activity; pcapng = ($rid + ".pcapng"); note = "closed by recovery after an early stop" }
    }
}

foreach ($sc in $scenarios) {
    if (Test-Path (Join-Path $dir ($sc.id + ".pcapng"))) { Log ("skip " + $sc.id + ": pcapng already exists"); continue }
    $start = Utc
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
               attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc.tool; operator = "pavel";
               activity = $sc.activity; status = "open-before-start" }
    Log ("start " + $sc.id + " " + $start)
    $etl = Join-Path $dir ($sc.id + ".etl")
    $pcap = Join-Path $dir ($sc.id + ".pcapng")
    Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
    Assert-PktmonStopped
    pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
    Assert-PktmonOwned -EtlPath $etl
    Start-Sleep -Seconds 2
    $run = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 $sc.cmd 2>&1 | Out-String
    Log ("run: " + $run.Trim())
    Start-Sleep -Seconds 2
    Stop-PktmonOwned -EtlPath $etl | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
    $end = Utc
    pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
               attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc.tool; operator = "pavel";
               activity = $sc.activity; pcapng = (Split-Path $pcap -Leaf) }
    Log ("end " + $sc.id + " " + $end)
}
Log ("done " + (Get-Date -Format o))

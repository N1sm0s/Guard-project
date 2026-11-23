# Elevated: realistic lab attack scenarios from IG-Attacker against IG-Victim (172.20.0.10), inside the isolated lab.
# Tools: nmap (SYN scan, slow timing scan, version probe), SSH connection attempts that fail authentication,
# low-rate SYN flood. Each scenario: journal entry before start, capture all components, run, stop, convert.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "attacks-run.txt"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Remove-Item $progress -ErrorAction SilentlyContinue
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }

$attackerMac = "00:15:5d:00:7e:05"
$scenarios = @(
    @{ id = "scan-01"; label = "attack:port_scan_syn"; tool = "nmap";
       activity = "nmap SYN scan of ports 1-1024, normal timing";
       cmd = "sudo nmap -sS -T4 -p 1-1024 -n 172.20.0.10 | tail -3" },
    @{ id = "scan-02"; label = "attack:port_scan_slow"; tool = "nmap";
       activity = "nmap slow SYN scan of ports 1-300 with paranoid-like timing";
       cmd = "sudo nmap -sS -T2 -p 1-300 -n 172.20.0.10 | tail -3" },
    @{ id = "scan-03"; label = "attack:service_probe"; tool = "nmap";
       activity = "nmap version detection on common service ports";
       cmd = "sudo nmap -sV -p 22,80,443,8080 -n 172.20.0.10 | tail -3" },
    @{ id = "ssh-01"; label = "attack:ssh_auth_attempts"; tool = "ssh";
       activity = "repeated SSH connections with failing authentication, one per second";
       cmd = 'for i in $(seq 1 60); do ssh -o BatchMode=yes -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new labuser@172.20.0.10 true >/dev/null 2>&1; sleep 1; done; echo done' },
    @{ id = "flood-02"; label = "attack:syn_flood_low_rate"; tool = "hping3";
       activity = "SYN flood at about 50 packets per second to port 80";
       cmd = "sudo timeout 60 hping3 -S -p 80 -i u20000 172.20.0.10 >/dev/null 2>&1; echo done" }
)

foreach ($sc in $scenarios) {
    $start = Utc
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
               attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc.tool; operator = "pavel";
               activity = $sc.activity; status = "open-before-start" }
    Log ("start " + $sc.id + " " + $start)
    $etl = Join-Path $dir ($sc.id + ".etl")
    $pcap = Join-Path $dir ($sc.id + ".pcapng")
    Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
    pktmon stop 2>&1 | Out-Null
    pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_.Trim()) }
    Start-Sleep -Seconds 2
    $run = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 $sc.cmd 2>&1 | Out-String
    Log ("run: " + $run.Trim())
    Start-Sleep -Seconds 2
    pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop: " + $_.Trim()) }
    $end = Utc
    pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_.Trim()) }
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
               attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc.tool; operator = "pavel";
               activity = $sc.activity; pcapng = (Split-Path $pcap -Leaf) }
    Log ("end " + $sc.id + " " + $end)
}
Log ("done " + (Get-Date -Format o))

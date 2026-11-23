# Elevated: expand lab data. Mixed benign background (web + ssh + ping, lab-only), more scan and SSH variants,
# and a second low-rate flood variant. Journal entry before each start, pcapng per scenario.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "expand-run.txt"
$attackerMac = "00:15:5d:00:7e:05"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Remove-Item $progress -ErrorAction SilentlyContinue
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }

$scenarios = @(
    @{ id = "benign-09"; label = "benign"; tool = "mixed";
       activity = "mixed background: web requests, ssh sessions, ping, inside lab subnet, about 6 minutes";
       server = $true;
       cmd = 'for i in $(seq 1 240); do curl -s -o /dev/null --no-keepalive http://172.20.0.10:8080/ ; ssh -o BatchMode=yes -o ConnectTimeout=3 pavel2@172.20.0.10 true >/dev/null 2>&1; ping -c 1 -W 1 172.20.0.10 >/dev/null; sleep 1.5; done; echo done' },
    @{ id = "scan-04"; label = "attack:port_scan_syn"; tool = "nmap"; server = $false;
       activity = "nmap SYN scan of ports 1-5000 with max rate 300 packets per second";
       cmd = "sudo nmap -sS -T3 --max-rate 300 -p 1-5000 -n 172.20.0.10 | tail -2" },
    @{ id = "ssh-02"; label = "attack:ssh_auth_attempts"; tool = "ssh"; server = $false;
       activity = "120 SSH connections with failing authentication, 1 per second";
       cmd = 'for i in $(seq 1 120); do ssh -o BatchMode=yes -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new labuser@172.20.0.10 true >/dev/null 2>&1; sleep 1; done; echo done' },
    @{ id = "flood-03"; label = "attack:udp_flood_low_rate"; tool = "hping3"; server = $false;
       activity = "UDP flood at about 100 packets per second to port 123 for 60 seconds";
       cmd = "sudo timeout 60 hping3 --udp -p 123 -i u10000 172.20.0.10 >/dev/null 2>&1; echo done" }
)

foreach ($sc in $scenarios) {
    if ($sc.server) {
        ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "nohup python3 -m http.server 8080 --bind 172.20.0.10 >/tmp/httpd.log 2>&1 & echo started" 2>&1 | Out-String | ForEach-Object { Log ("server: " + $_.Trim()) }
        Start-Sleep -Seconds 2
    }
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
    if ($sc.server) {
        ssh -i $key -o BatchMode=yes pavel2@172.20.0.10 "pkill -f 'http.server 8080'; echo stopped" 2>&1 | Out-String | ForEach-Object { Log ("server stop: " + $_.Trim()) }
    }
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $end;
               attacker_mac = $attackerMac; victim_ip = "172.20.0.10"; tool = $sc.tool; operator = "pavel";
               activity = $sc.activity; pcapng = (Split-Path $pcap -Leaf) }
    Log ("end " + $sc.id + " " + $end)
}
Log ("done " + (Get-Date -Format o))

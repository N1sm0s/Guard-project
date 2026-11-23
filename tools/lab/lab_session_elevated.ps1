# Elevated lab session: for each scenario, write its journal entry BEFORE start, capture all Pktmon
# components while the scenario runs over SSH, stop, convert to pcapng, close the journal entry.
# Scenarios are lab-only: attacker 172.20.0.5 -> victim 172.20.0.10 (isolated lab, no internet).
# Outputs: outputs\lab\session\<scenario>.pcapng and outputs\lab\session\session-log.jsonl, progress in session.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dir = Join-Path $root "outputs\lab\session"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"
$progress = Join-Path $dir "session.txt"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Remove-Item $progress -ErrorAction SilentlyContinue
function Log($text) { $text | Out-File -FilePath $progress -Append -Encoding utf8 }
function Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Journal($obj) { ($obj | ConvertTo-Json -Compress) | Out-File -FilePath (Join-Path $dir "session-log.jsonl") -Append -Encoding utf8 }

$scenarios = @(
    @{ id = "benign-06"; label = "benign"; activity = "ping and short ssh sessions inside lab subnet"; secs = 90;
       cmd = "for i in `$(seq 1 30); do ping -c 1 -W 1 172.20.0.10 >/dev/null; ssh -o BatchMode=yes -o ConnectTimeout=3 pavel2@172.20.0.10 true >/dev/null 2>&1; sleep 1; done; echo done" },
    @{ id = "udp-03"; label = "attack:udp_flood"; activity = "hping3 UDP flood to victim port 53"; secs = 60;
       cmd = "sudo timeout 60 hping3 --udp --flood -p 53 172.20.0.10 >/dev/null 2>&1; echo done" },
    @{ id = "benign-07"; label = "benign"; activity = "UDP application bursts with new source port, victim to attacker"; secs = 90;
       cmd = "python3 -c 'import socket,time; end=time.time()+85; n=0`nwhile time.time()<end:`n    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)`n    [s.sendto(b`"app`",(`"172.20.0.5`",5353)) for _ in range(4)]`n    s.close(); time.sleep(2.5)'; echo done" }
)

foreach ($sc in $scenarios) {
    $start = Utc
    Journal @{ scenario_id = $sc.id; label = $sc.label; lab_subnet = "172.20.0.0/24"; start_utc = $start; end_utc = $start;
               operator = "pavel"; activity = $sc.activity; status = "open-before-start" }
    Log ("start " + $sc.id + " " + $start)
    $etl = Join-Path $dir ($sc.id + ".etl")
    $pcap = Join-Path $dir ($sc.id + ".pcapng")
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
               operator = "pavel"; activity = $sc.activity; pcapng = (Split-Path $pcap -Leaf) }
    Log ("end " + $sc.id + " " + $end)
}
Log ("done " + (Get-Date -Format o))

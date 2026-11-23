# Elevated test: capture all components, generate lab ping, convert.
# Interrupts the app's own Pktmon session (the app resumes on its next cycle).
# Output: outputs\lab\pktmon-all-test.txt and outputs\lab\pktmon-all-test.pcapng
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$out = Join-Path $root "outputs\lab\pktmon-all-test.txt"
$etl = Join-Path $root "outputs\lab\pktmon-all-test.etl"
$pcap = Join-Path $root "outputs\lab\pktmon-all-test.pcapng"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"

function Log($text) { $text | Out-File -FilePath $out -Append -Encoding utf8 }

Remove-Item $out, $etl, $pcap -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pre-stop: " + $_) }
pktmon start --capture --comp all --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("start: " + $_) }
Start-Sleep -Seconds 2
$ping = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 "ping -c 10 -i 0.5 172.20.0.10 | tail -2" 2>&1 | Out-String
Log ("ping: " + $ping)
Start-Sleep -Seconds 2
pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("stop: " + $_) }
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_) }
Log ("done " + (Get-Date -Format o))

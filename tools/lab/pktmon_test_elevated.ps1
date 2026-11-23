# Elevated Pktmon test for the lab: capture host switch port and both VM ports, generate traffic, convert.
# Run through "Run as administrator". Output goes to outputs\lab\pktmon-test-elevated.txt.
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$out = Join-Path $root "outputs\lab\pktmon-test-elevated.txt"
$etl = Join-Path $env:TEMP "lab-test2.etl"
$pcap = Join-Path $env:TEMP "lab-test2.pcapng"
$key = Join-Path $env:USERPROFILE ".ssh\ig_lab"

function Log($text) { $text | Out-File -FilePath $out -Append -Encoding utf8 }

Remove-Item $out, $etl, $pcap -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

pktmon start --capture --comp 106 --comp 208 --comp 220 --file-name $etl 2>&1 | Out-String | ForEach-Object { Log ("pktmon start: " + $_) }
Start-Sleep -Seconds 2

$ping = ssh -i $key -o BatchMode=yes pavel@172.20.0.5 "ping -c 10 -i 0.5 172.20.0.10 | tail -2" 2>&1 | Out-String
Log ("ping: " + $ping)
Start-Sleep -Seconds 2

pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop: " + $_) }
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-String | ForEach-Object { Log ("etl2pcap: " + $_) }

if (Test-Path $pcap) {
    Copy-Item $pcap (Join-Path $root "outputs\lab\lab-test2.pcapng") -Force
    Log "copied to outputs\lab\lab-test2.pcapng"
} else {
    Log "pcapng was not produced"
}
Log ("done " + (Get-Date -Format o))

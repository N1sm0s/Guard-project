# Elevated, read-only: write the output of "pktmon list" to outputs\lab\pktmon-list.txt
$out = "F:\New\integrityguard\outputs\lab\pktmon-list.txt"
pktmon list 2>&1 | Out-File -FilePath $out -Encoding utf8
"done " + (Get-Date -Format o) | Out-File -FilePath $out -Append -Encoding utf8

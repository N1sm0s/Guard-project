# Elevated, READ-ONLY: record the exact text of `pktmon status` when no capture runs, so the
# stopped-state check can match the real text. Writes ASCII only (code points and hex).
# Stops nothing. Log: outputs\lab\session\pktmon-status-dump.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$log = Join-Path $root "outputs\lab\session\pktmon-status-dump.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
Remove-Item $log -ErrorAction SilentlyContinue
$raw = Join-Path $env:TEMP "pktmon-status-raw.bin"
cmd /c "pktmon status > `"$raw`" 2>&1"
$code = $LASTEXITCODE
$bytes = [IO.File]::ReadAllBytes($raw)
$hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join " "
$cp866 = [Text.Encoding]::GetEncoding(866).GetString($bytes)
$esc = -join ($cp866.ToCharArray() | ForEach-Object { if ([int]$_ -lt 128 -and [int]$_ -ge 32) { [string]$_ } elseif ($_ -eq "`r") { "\r" } elseif ($_ -eq "`n") { "\n" } else { "\u" + ([int]$_).ToString("x4") } })
"exit code: $code" | Out-File $log -Append -Encoding ascii
"byte count: $($bytes.Length)" | Out-File $log -Append -Encoding ascii
"hex: $hex" | Out-File $log -Append -Encoding ascii
"cp866 decoded (escaped): $esc" | Out-File $log -Append -Encoding ascii
Remove-Item $raw -ErrorAction SilentlyContinue
"done" | Out-File $log -Append -Encoding ascii

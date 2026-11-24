# Elevated: end every process related to IntegrityGuard, then stop only the app-owned pktmon capture,
# then run the lab scan capture. A process is ended only if its name is IntegrityGuard.exe and its
# executable path is inside dist\IntegrityGuard; ancestors are ended only if also inside that folder.
# Log: outputs\lab\session\kill-related-run.txt
$ErrorActionPreference = "Continue"
$root = "F:\New\integrityguard"
$dist = Join-Path $root "dist\IntegrityGuard"
$log = Join-Path $root "outputs\lab\session\kill-related-run.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function Log($text) { $text | Out-File -FilePath $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue
Log ("start " + (Get-Date -Format o))

function InScope($path) { return ($path -and $path.StartsWith(($dist + "\"), [StringComparison]::OrdinalIgnoreCase)) }

$all = Get-CimInstance Win32_Process
$byId = @{}; foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }

# seed: IntegrityGuard.exe processes inside dist\IntegrityGuard; add their ancestors whose executable is inside that folder
$targets = @{}
foreach ($p in $all) {
    if ($p.Name -eq "IntegrityGuard.exe" -and (InScope $p.ExecutablePath)) { $targets[[int]$p.ProcessId] = $p }
}
$added = $true
while ($added) {
    $added = $false
    foreach ($id in @($targets.Keys)) {
        $parent = [int]$targets[$id].ParentProcessId
        if ($byId.ContainsKey($parent) -and -not $targets.ContainsKey($parent)) {
            $pp = $byId[$parent]
            if (InScope $pp.ExecutablePath) { $targets[$parent] = $pp; $added = $true }
            else { Log ("parent " + $parent + " (" + $pp.Name + ", " + $pp.ExecutablePath + ") is outside the project; not ended") }
        }
    }
}
if ($targets.Count -eq 0) { Log "no related processes found" }
foreach ($id in $targets.Keys) {
    $t = $targets[$id]
    Log ("ending PID " + $id + " " + $t.Name + " " + $t.ExecutablePath)
    Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 4
Log ("IntegrityGuard processes left: " + (@(Get-CimInstance Win32_Process -Filter "Name='IntegrityGuard.exe'")).Count)

$status = (pktmon status 2>&1 | Out-String)
$m = [regex]::Match($status, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
if ($m.Success) {
    $etl = $m.Groups[1].Value.Trim()
    if ($etl -match 'integrityguard-pktmon-[^\\]+\\segment\.etl$') {
        pktmon stop 2>&1 | Out-String | ForEach-Object { Log ("pktmon stop (app-owned): " + $_.Trim()) }
    } else { Log ("pktmon capture is not app-owned (" + $etl + "); not stopped") }
} else { Log "no active pktmon capture with an ETL path" }

& (Join-Path $root "tools\lab\lab_scan_more_elevated.ps1")
Log ("done " + (Get-Date -Format o))

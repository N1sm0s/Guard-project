$ErrorActionPreference = 'Stop'
$recordPath = 'F:\New\integrityguard\data\online\pktmon_recovery.json'
$logPath = 'F:\New\integrityguard\data\online\pktmon_recovery.log'
Start-Transcript -LiteralPath $logPath -Force | Out-Null

# Stop only a capture whose ETL path is inside this app's uniquely named temp
# directory. Re-read status immediately before stopping and require the same
# ETL path, so a capture started by another tool is left untouched.
$pktmon = Join-Path $env:SystemRoot 'System32\pktmon.exe'
$statusArgs = @('status')
try {
$status = (& $pktmon @statusArgs 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Could not read Pktmon status; nothing was stopped.' }
Write-Output "Initial Pktmon status:`n$status"

$notRunningPattern = '(?i)not running|is stopped|not started|не запущен|не выполняется|остановлен|сбор не ведется|сбор не ведётся'
if ($status -match $notRunningPattern) {
    Write-Output 'Pktmon is already stopped; no action taken.'
    exit 0
}

$etlMatch = [regex]::Match($status, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
if (-not $etlMatch.Success) { throw 'Active ETL path is unknown; nothing was stopped.' }
$activeEtl = [IO.Path]::GetFullPath($etlMatch.Groups[1].Value.Trim())
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]'\')
$ownedPrefix = Join-Path $tempRoot 'integrityguard-pktmon-'
$ownedPattern = '^' + [regex]::Escape($ownedPrefix) + '[^\\]+\\segment\.etl$'
if ($activeEtl -notmatch $ownedPattern) { throw "Active Pktmon capture is not identified as IntegrityGuard-owned: $activeEtl" }

$captureDir = Split-Path -Parent $activeEtl
$ownerPath = Join-Path $captureDir 'owner.json'
$dirInfo = Get-Item -LiteralPath $captureDir -ErrorAction Stop
$dirLastWrite = $dirInfo.LastWriteTime
$appProcesses = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @('IntegrityGuard.exe', 'pythonw.exe') -and
    (($_.ExecutablePath -like 'F:\New\integrityguard\*') -or
     ($_.CommandLine -like '*F:\New\integrityguard*'))
})
Write-Output "ETL path: $activeEtl; directory last write: $($dirLastWrite.ToString('o'))"
Write-Output ('Matching app processes: ' + (($appProcesses | ForEach-Object {
    "PID=$($_.ProcessId), created=$($_.CreationDate), image=$($_.ExecutablePath), command=$($_.CommandLine)"
}) -join ' | '))

if (Test-Path -LiteralPath $ownerPath) {
    $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
    $ownerProc = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$owner.pid)" -ErrorAction SilentlyContinue
    if ($ownerProc) {
        $procCreated = [Management.ManagementDateTimeConverter]::ToDateTime($ownerProc.CreationDate)
        $ownerCreated = [DateTimeOffset]::FromUnixTimeMilliseconds(
            [long]([double]$owner.process_create_time * 1000)).LocalDateTime
        if ([Math]::Abs(($procCreated - $ownerCreated).TotalSeconds) -lt 2) {
            throw "Pktmon owner PID $($owner.pid) is still alive; leaving its capture untouched."
        }
    }
} else {
    # Legacy captures predate owner.json. Recover only if the exact app-owned
    # capture directory has been idle for at least 30 minutes and no current
    # IntegrityGuard process predates the directory's last write.
    if ($dirLastWrite -gt (Get-Date).AddMinutes(-30)) {
        throw 'Legacy IntegrityGuard capture is recent and has no owner marker; refusing to stop it.'
    }
    $oldAppProcesses = @($appProcesses | Where-Object {
        [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate) -le $dirLastWrite
    })
    if ($oldAppProcesses.Count -gt 0) {
        throw 'A matching IntegrityGuard process predates the capture activity; refusing to stop it.'
    }
}

$confirm = (& $pktmon status 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Could not recheck Pktmon ownership; nothing was stopped.' }
$confirmMatch = [regex]::Match($confirm, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
if (-not $confirmMatch.Success -or
    [IO.Path]::GetFullPath($confirmMatch.Groups[1].Value.Trim()) -ne $activeEtl -or
    $confirm -match $notRunningPattern) {
    throw 'Pktmon ownership changed during recheck; nothing was stopped.'
}
$confirmDir = Get-Item -LiteralPath (Split-Path -Parent $activeEtl) -ErrorAction Stop
if ($confirmDir.LastWriteTime -gt (Get-Date).AddMinutes(-30)) {
    throw 'Capture directory activity is recent; nothing was stopped.'
}

& $pktmon stop | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Pktmon stop failed.' }
Start-Sleep -Milliseconds 500
$after = (& $pktmon status 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $after -notmatch $notRunningPattern) {
    throw 'Could not verify that the IntegrityGuard Pktmon session stopped.'
}

$record = [ordered]@{
    stopped_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    etl_path = $activeEtl
    reason = 'recover IntegrityGuard live flow telemetry after stale app-owned Pktmon session'
    verified_stopped = $true
}
$record | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding UTF8
Write-Output "Stopped verified IntegrityGuard Pktmon capture: $activeEtl"
} catch {
    Write-Error $_
    exit 1
} finally {
    Stop-Transcript | Out-Null
}

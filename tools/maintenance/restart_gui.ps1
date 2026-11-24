$ErrorActionPreference = "Stop"

$projectRoot = "F:\New\integrityguard"
$targetDir = Join-Path $projectRoot "dist\IntegrityGuard"
$stageDir = Join-Path $projectRoot "dist\IntegrityGuard-staging-20261119\IntegrityGuard"
$backupDir = Join-Path $projectRoot "outputs\IntegrityGuard-pre-runtime-chain-fix-20261119"
$exe = Join-Path $targetDir "IntegrityGuard.exe"
$stageExe = Join-Path $stageDir "IntegrityGuard.exe"
$taskName = "IntegrityGuard Network Monitor"

foreach ($path in @($targetDir, $stageDir, $backupDir)) {
    $fullPath = [IO.Path]::GetFullPath($path)
    if (-not $fullPath.StartsWith($projectRoot + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside project root: $fullPath"
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
if (-not (Test-Path -LiteralPath $stageExe)) {
    throw "Staged IntegrityGuard executable was not found: $stageExe"
}
if (Test-Path -LiteralPath $backupDir) {
    throw "Backup destination already exists: $backupDir"
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.Principal.RunLevel -ne "Highest" -or
    $task.Actions[0].Execute -ne $exe -or
    $task.Actions[0].Arguments -ne "--tray") {
    throw "The verified elevated network-monitor startup task is not configured for this executable."
}

# A force-killed GUI can leave its Pktmon ETW session running. Before changing
# the package, inspect the active ETL path and only stop a session whose path is
# inside this app's unique temporary capture directory. Never stop a foreign
# Pktmon session during an update.
$pktmon = Join-Path $env:SystemRoot "System32\pktmon.exe"
$pktmonStatus = (& $pktmon status 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Could not read elevated Pktmon status; refusing to restart while capture ownership is unknown."
}
$notRunning = $pktmonStatus -match '(?i)not running|is stopped|not started|не запущен|не выполняется|остановлен|сбор не ведется|сбор не ведётся'
$logMatch = [regex]::Match($pktmonStatus, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
$stopOwnedPktmon = $false
if (-not $notRunning) {
    if (-not $logMatch.Success) {
        throw "Pktmon is active but its ETL path could not be identified; refusing to stop it."
    }
    $activeEtl = [IO.Path]::GetFullPath($logMatch.Groups[1].Value.Trim())
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]'\')
    $ownedPrefix = Join-Path $tempRoot "integrityguard-pktmon-"
    $ownedPattern = '^' + [regex]::Escape($ownedPrefix) + '[^\\]+\\segment\.etl$'
    if ($activeEtl -notmatch $ownedPattern) {
        throw "Pktmon is active with a non-IntegrityGuard ETL path; refusing to stop a foreign capture."
    }
    $ownerPath = Join-Path (Split-Path -Parent $activeEtl) 'owner.json'
    if (-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)) {
        throw "Pktmon ETL looks like an app path but has no owner marker; refusing to stop it."
    }
    $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
    $ownerPid = [int]$owner.pid
    $ownerCreated = [double]$owner.process_create_time
    if ($ownerPid -le 0 -or $ownerCreated -le 0) {
        throw "Pktmon owner marker is invalid; refusing to stop the session."
    }
    $stopOwnedPktmon = $true
}

$stagedSha = (Get-FileHash -LiteralPath $stageExe -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedModelSha = "6352a8eb6292b68d89ffc8bc63669065a24b3f4514cb8f11e0d5cf2f5bedaa54"
$stagedModel = Join-Path $stageDir "_internal\models\network_flow_v3_candidate.pt"
if ((Get-FileHash -LiteralPath $stagedModel -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedModelSha) {
    throw "Staged package does not contain the expected unchanged v3 candidate."
}

$oldProcesses = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "IntegrityGuard.exe" -and $_.ExecutablePath -eq $exe
})
foreach ($oldProcess in $oldProcesses) {
    Stop-Process -Id $oldProcess.ProcessId -Force
}

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 250
    $remaining = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq "IntegrityGuard.exe" -and $_.ExecutablePath -eq $exe
    })
} while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline)
if ($remaining.Count -gt 0) {
    throw "The previous IntegrityGuard process did not stop."
}
if ($stopOwnedPktmon) {
    # The app shutdown/build steps can take time. Re-read both the global session
    # path and persisted process identity immediately before the global stop.
    $beforeStop = (& $pktmon status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $beforeStop -match '(?i)not running|is stopped|not started|не запущен|не выполняется|остановлен|сбор не ведется|сбор не ведётся') {
        throw "Pktmon session changed before restart; package update was aborted."
    }
    $beforeStopMatch = [regex]::Match($beforeStop, '(?im)([A-Z]:\\[^\r\n]*?\.etl)\s*$')
    if (-not $beforeStopMatch.Success -or
        [IO.Path]::GetFullPath($beforeStopMatch.Groups[1].Value.Trim()) -ne $activeEtl) {
        throw "Active Pktmon ETL changed before restart; no session was stopped."
    }
    $ownerAgain = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
    if ([int]$ownerAgain.pid -ne $ownerPid -or [double]$ownerAgain.process_create_time -ne $ownerCreated) {
        throw "Pktmon owner marker changed before restart; no session was stopped."
    }
    $ownerProc = Get-CimInstance Win32_Process -Filter "ProcessId=$ownerPid" -ErrorAction SilentlyContinue
    if ($ownerProc) {
        $ownerProcCreated = [Management.ManagementDateTimeConverter]::ToDateTime($ownerProc.CreationDate)
        $expectedCreated = [DateTimeOffset]::FromUnixTimeMilliseconds([long]($ownerCreated * 1000)).LocalDateTime
        if ([Math]::Abs(($ownerProcCreated - $expectedCreated).TotalSeconds) -lt 2) {
            throw "Pktmon owner PID $ownerPid is still alive; no session was stopped."
        }
    }
    & $pktmon stop | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not stop the verified IntegrityGuard-owned Pktmon capture; package update was aborted."
    }
    Start-Sleep -Milliseconds 500
    $stoppedStatus = (& $pktmon status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $stoppedStatus -notmatch '(?i)not running|is stopped|not started|не запущен|не выполняется|остановлен|сбор не ведется|сбор не ведётся') {
        throw "Pktmon stop was not verified; package update was aborted."
    }
}

Move-Item -LiteralPath $targetDir -Destination $backupDir
try {
    Move-Item -LiteralPath $stageDir -Destination $targetDir
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 1
        $newProcesses = @(Get-CimInstance Win32_Process | Where-Object {
            $_.Name -eq "IntegrityGuard.exe" -and $_.ExecutablePath -eq $exe
        })
    } while ($newProcesses.Count -eq 0 -and (Get-Date) -lt $deadline)
    if ($newProcesses.Count -ne 1) {
        throw "Expected one restarted IntegrityGuard process; found $($newProcesses.Count)."
    }
} catch {
    $newProcesses = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq "IntegrityGuard.exe" -and $_.ExecutablePath -eq $exe
    })
    foreach ($newProcess in $newProcesses) {
        Stop-Process -Id $newProcess.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path -LiteralPath $targetDir) -and -not (Test-Path -LiteralPath $stageDir)) {
        Move-Item -LiteralPath $targetDir -Destination $stageDir
    }
    if (Test-Path -LiteralPath $backupDir) {
        Move-Item -LiteralPath $backupDir -Destination $targetDir
    }
    throw
}

$record = [ordered]@{
    restarted_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    task_name = $taskName
    process_id = $newProcesses[0].ProcessId
    executable = $exe
    executable_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    staged_executable_sha256 = $stagedSha
    task_run_level = $task.Principal.RunLevel.ToString()
    reason = "apply verified IntegrityGuard network-monitor update"
}
$record | ConvertTo-Json | Set-Content -LiteralPath "F:\New\integrityguard\data\online\last_network_monitor_restart.json" -Encoding UTF8
Write-Output "IntegrityGuard network monitor restarted as PID $($record.process_id)."

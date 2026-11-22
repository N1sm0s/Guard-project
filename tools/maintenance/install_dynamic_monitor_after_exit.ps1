param(
    [Parameter(Mandatory = $true)][int]$PidToWait,
    [Parameter(Mandatory = $true)][string]$ExpectedLiveHash,
    [Parameter(Mandatory = $true)][string]$ExpectedStageHash
)

$ErrorActionPreference = 'Stop'
$root = 'F:\New\integrityguard'
$live = Join-Path $root 'dist\IntegrityGuard'
$stage = Join-Path $root 'outputs\IntegrityGuard-dynamic-final-20261120\IntegrityGuard'
$backup = Join-Path $root 'outputs\IntegrityGuard-before-dynamic-final-20261120'
$log = Join-Path $root 'outputs\dynamic-monitor-install.log'
$taskName = 'IntegrityGuard Network Monitor'

function Write-InstallLog([string]$message) {
    Add-Content -LiteralPath $log -Encoding utf8 -Value ("{0:o} {1}" -f (Get-Date), $message)
}

try {
    Write-InstallLog "Waiting for IntegrityGuard PID $PidToWait to exit gracefully."
    while (Get-Process -Name IntegrityGuard -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 2
    }
    Start-Sleep -Seconds 3

    $liveExe = Join-Path $live 'IntegrityGuard.exe'
    $stageExe = Join-Path $stage 'IntegrityGuard.exe'
    if (-not (Test-Path -LiteralPath $liveExe) -or -not (Test-Path -LiteralPath $stageExe)) {
        throw 'Installed or staged executable is missing.'
    }
    $liveHash = (Get-FileHash -LiteralPath $liveExe -Algorithm SHA256).Hash
    $stageHash = (Get-FileHash -LiteralPath $stageExe -Algorithm SHA256).Hash
    if ($liveHash -ne $ExpectedLiveHash) { throw "Installed executable hash changed: $liveHash" }
    if ($stageHash -ne $ExpectedStageHash) { throw "Staged executable hash changed: $stageHash" }
    if (Test-Path -LiteralPath $backup) { throw "Backup already exists: $backup" }

    Move-Item -LiteralPath $live -Destination $backup
    try {
        Move-Item -LiteralPath $stage -Destination $live
    } catch {
        Move-Item -LiteralPath $backup -Destination $live
        throw
    }
    Write-InstallLog "Installed staged build with SHA-256 $stageHash; prior directory retained at $backup."

    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $newProcess = Get-Process -Name IntegrityGuard -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } | Select-Object -First 1
    } until ($newProcess -or (Get-Date) -gt $deadline)
    if (-not $newProcess) { throw 'The existing startup task did not launch the updated app within 60 seconds.' }
    Write-InstallLog "Updated app relaunched by the existing task (PID $($newProcess.Id))."
} catch {
    Write-InstallLog "INSTALL FAILED: $($_.Exception.Message)"
}

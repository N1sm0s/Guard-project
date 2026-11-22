$ErrorActionPreference = "Stop"

$taskName = "IntegrityGuard Network Monitor"
$exe = "F:\New\integrityguard\dist\IntegrityGuard\IntegrityGuard.exe"
$expectedRunValue = '"F:\New\integrityguard\dist\IntegrityGuard\IntegrityGuard.exe" --tray'
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Current IntegrityGuard executable was not found: $exe"
}

$action = New-ScheduledTaskAction -Execute $exe -Argument "--tray" `
    -WorkingDirectory (Split-Path -Parent $exe)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Resume the current IntegrityGuard network monitor after the user signs in. Capture is paused while Windows is off." `
    -Force | Out-Null

# Retire the two stale launch paths so an obsolete or unprivileged copy cannot
# start alongside the current elevated network monitor.
foreach ($staleTask in @("IntegrityLab-AutoMonitoring", "IntegrityGuard Monitor")) {
    $existing = Get-ScheduledTask -TaskName $staleTask -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.State -eq "Running") {
            Stop-ScheduledTask -TaskName $staleTask -ErrorAction SilentlyContinue
        }
        Disable-ScheduledTask -TaskName $staleTask | Out-Null
    }
}

$runValue = (Get-ItemProperty -Path $runKey -Name IntegrityGuard -ErrorAction SilentlyContinue).IntegrityGuard
if ($runValue -eq $expectedRunValue) {
    Remove-ItemProperty -Path $runKey -Name IntegrityGuard
}

$registered = Get-ScheduledTask -TaskName $taskName
if ($registered.Principal.RunLevel -ne "Highest" -or
    $registered.Actions[0].Execute -ne $exe -or
    $registered.Triggers.Count -lt 1) {
    throw "Startup task verification failed."
}

$report = [ordered]@{
    task_name = $taskName
    executable = $exe
    argument = "--tray"
    run_level = $registered.Principal.RunLevel.ToString()
    trigger = "user_logon"
    capture_while_powered_off = $false
    configured_at = (Get-Date).ToUniversalTime().ToString("o")
}
$reportPath = "F:\New\integrityguard\data\online\network_monitor_startup.json"
$report | ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Output "Configured $taskName to resume current IntegrityGuard network monitoring at user logon."

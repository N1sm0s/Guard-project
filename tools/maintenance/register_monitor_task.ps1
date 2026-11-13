$log = 'F:\New\integrityguard\tools\maintenance\register_task.log'
Start-Transcript -Path $log -Force | Out-Null
try {
    $taskName = 'IntegrityGuard Monitor'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Output "removed existing task"
    }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument '-NoProfile -ExecutionPolicy Bypass -File "F:\New\integrityguard\tools\maintenance\run_monitor_service.ps1"' `
        -WorkingDirectory 'F:\New\integrityguard'
    $trigger1 = New-ScheduledTaskTrigger -AtStartup
    $trigger2 = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId 'NISMO\pavel' -LogonType S4U -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal `
        -Settings $settings -Description 'Continuous runtime integrity monitoring of a deployed package (integrityguard.cli monitor), independent of GUI/desktop logon.'
    Write-Output "registered"
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 3
    Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
    Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
} catch {
    Write-Output "FAILED: $($_.Exception.Message)"
} finally {
    Stop-Transcript | Out-Null
}

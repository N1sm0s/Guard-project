$log = 'F:\New\integrityguard\tools\maintenance\register_retrain_task.log'
Start-Transcript -Path $log -Force | Out-Null
try {
    $taskName = 'IntegrityGuard NN Retrain'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Output "removed existing task"
    }

    $ErrorActionPreference = 'Stop'
    # pythonw: no console window flashing on the desktop every 2 minutes.
    $action = New-ScheduledTaskAction -Execute 'F:\New\integrityguard\.venv\Scripts\pythonw.exe' `
        -Argument '"F:\New\integrityguard\tools\maintenance\retrain_now.py"' `
        -WorkingDirectory 'F:\New\integrityguard'
    # Every 2 minutes, indefinitely; the script itself skips when nothing new arrived.
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 2)
    # Interactive logon: needs no administrator rights, runs while this user is logged on.
    $principal = New-ScheduledTaskPrincipal -UserId 'NISMO\pavel' -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'Retrains the shadow (advisory-only) network classifier from network_events.sqlite every 2 minutes when new teacher-labeled examples exist. Log: data\models\retrain.log.'
    Write-Output "registered"
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 25
    Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
    Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
} catch {
    Write-Output "FAILED: $($_.Exception.Message)"
} finally {
    Stop-Transcript | Out-Null
}

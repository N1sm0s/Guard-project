$ErrorActionPreference = "Stop"

$taskName = "IntegrityGuard NN Retrain"
$python   = "F:\New\integrityguard\.venv\Scripts\pythonw.exe"
$script   = "F:\New\integrityguard\tools\maintenance\retrain_now.py"
$workDir  = "F:\New\integrityguard"

$action = New-ScheduledTaskAction -Execute $python -Argument $script -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Force | Out-Null

Write-Host "OK: Task '$taskName' registered."

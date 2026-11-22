$shell   = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk     = Join-Path $desktop 'IntegrityGuard.lnk'
if (Test-Path $lnk) {
    $s = $shell.CreateShortcut($lnk)
    Write-Host "Target:  $($s.TargetPath)"
    Write-Host "Args:    $($s.Arguments)"
    Write-Host "WorkDir: $($s.WorkingDirectory)"
} else {
    Write-Host "Ярлык не найден: $lnk"
    Write-Host "Все .lnk на рабочем столе:"
    Get-ChildItem $desktop -Filter '*.lnk' | Select-Object Name
}
Write-Host "python.exe exists: $(Test-Path 'F:\New\integrityguard\.venv\Scripts\python.exe')"
Write-Host "pyw exists:        $(Test-Path 'F:\New\integrityguard\IntegrityGuard.pyw')"

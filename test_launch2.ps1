$python = 'F:\New\integrityguard\.venv\Scripts\python.exe'
$pyw    = 'F:\New\integrityguard\IntegrityGuard.pyw'
$root   = 'F:\New\integrityguard'
$log    = 'F:\New\integrityguard\launch_error.log'
Set-Location $root
# Запускаем и перехватываем stderr в файл
$p = Start-Process -FilePath $python -ArgumentList $pyw `
    -WorkingDirectory $root `
    -RedirectStandardError $log `
    -PassThru -NoNewWindow
Start-Sleep -Seconds 5
if ($p.HasExited) {
    Write-Host "Процесс завершился с кодом: $($p.ExitCode)"
    Write-Host "--- Ошибка ---"
    Get-Content $log
} else {
    Write-Host "Процесс запущен PID: $($p.Id)"
    $p.Kill()
}

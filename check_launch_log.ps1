# Запускаем pythonw.exe и ждём 6 секунд, потом читаем хвост app.log
$python = 'F:\New\integrityguard\.venv\Scripts\pythonw.exe'
$pyw    = 'F:\New\integrityguard\IntegrityGuard.pyw'
$root   = 'F:\New\integrityguard'
$log    = "$root\data\app.log"

# Запоминаем размер лога ДО запуска
$before = (Get-Item $log -ErrorAction SilentlyContinue).Length

$p = Start-Process -FilePath $python -ArgumentList """$pyw""" `
    -WorkingDirectory $root -PassThru
Write-Host "Запущен PID: $($p.Id)"
Start-Sleep -Seconds 6

# Проверяем жив ли процесс
if ($p.HasExited) {
    Write-Host "Процесс завершился с кодом: $($p.ExitCode)"
} else {
    Write-Host "Процесс живой через 6 сек (OK)"
    $p.Kill()
}

# Новые строки в логе
$after = (Get-Item $log -ErrorAction SilentlyContinue).Length
if ($after -gt $before) {
    Write-Host "--- Новые строки в app.log ---"
    $fs = [System.IO.File]::OpenRead($log)
    $fs.Seek($before, 'Begin') | Out-Null
    $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
    Write-Host $reader.ReadToEnd()
    $reader.Close(); $fs.Close()
} else {
    Write-Host "app.log не изменился — ошибок при старте нет"
}

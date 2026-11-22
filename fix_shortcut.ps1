# Удаляем старые ярлыки
Get-ChildItem "$env:USERPROFILE\Desktop\Integrity*.lnk" -ErrorAction SilentlyContinue | Remove-Item -Force

# Очищаем зависший lock-файл если нет живого pythonw-процесса с окном
$lock = "$env:LOCALAPPDATA\IntegrityGuard\gui.lock"
if (Test-Path $lock) {
    $alive = Get-Process pythonw -ErrorAction SilentlyContinue |
             Where-Object { $_.MainWindowHandle -ne 0 }
    if (-not $alive) {
        Remove-Item $lock -Force
        Write-Host "Удалён зависший gui.lock"
    }
}

# Создаём правильный ярлык
$python  = 'F:\New\integrityguard\.venv\Scripts\pythonw.exe'
$pyw     = 'F:\New\integrityguard\IntegrityGuard.pyw'
$icon    = 'F:\New\integrityguard\assets\integrityguard.ico'
$workdir = 'F:\New\integrityguard'
$lnkPath = "$env:USERPROFILE\Desktop\IntegrityGuard.lnk"

$ws  = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($lnkPath)
$lnk.TargetPath       = $python
$lnk.Arguments        = "`"$pyw`""
$lnk.WorkingDirectory = $workdir
$lnk.IconLocation     = $icon
$lnk.WindowStyle      = 1
$lnk.Description      = "IntegrityGuard (dev)"
$lnk.Save()

Write-Host "Ярлык создан: $lnkPath"

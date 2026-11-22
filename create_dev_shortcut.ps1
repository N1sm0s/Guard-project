# Создаёт ярлык "IntegrityGuard (dev)" на рабочем столе.
# Этот ярлык запускает программу ПРЯМО из исходников (.pyw),
# поэтому все изменения в коде вступают в силу немедленно — без пересборки .exe.
$root = $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$pyw    = Join-Path $root "IntegrityGuard.pyw"
$ico    = Join-Path $root "assets\integrityguard.ico"

if (-not (Test-Path $python)) {
    Write-Error "Python venv not found: $python"
    exit 1
}
if (-not (Test-Path $pyw)) {
    Write-Error "IntegrityGuard.pyw not found: $pyw"
    exit 1
}

$shell    = New-Object -ComObject WScript.Shell
$desktop  = [Environment]::GetFolderPath("Desktop")
$lnkPath  = Join-Path $desktop "IntegrityGuard.lnk"

$s = $shell.CreateShortcut($lnkPath)
$s.TargetPath      = $python
$s.Arguments       = "`"$pyw`""
$s.WorkingDirectory = $root
if (Test-Path $ico) { $s.IconLocation = $ico }
$s.Description     = "IntegrityGuard (из исходников, изменения сразу)"
$s.WindowStyle     = 7   # 7 = Minimized — консольное окно не мешает
$s.Save()

Write-Host "Ярлык создан: $lnkPath"
Write-Host "Запускает: $python `"$pyw`""

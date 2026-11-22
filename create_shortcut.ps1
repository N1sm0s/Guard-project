# Создаёт/обновляет ярлык IntegrityGuard на рабочем столе и рядом со скриптом.
# По умолчанию ярлык запускает программу НАПРЯМУЮ из исходников (.pyw) —
# все изменения в коде вступают в силу немедленно, без пересборки .exe.
# Для запуска из собранного .exe используйте флаг -UseExe.
param(
    [switch]$UseExe
)

$root   = $PSScriptRoot
$ico    = Join-Path $root "assets\integrityguard.ico"
$shell  = New-Object -ComObject WScript.Shell

$candidates = @(
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "IntegrityGuard.lnk"),
    (Join-Path $root "IntegrityGuard.lnk")
)

if ($UseExe) {
    # --- Режим .exe (собранный PyInstaller-билд) ---
    $app = Join-Path $root "dist\IntegrityGuard\IntegrityGuard.exe"
    if (-not (Test-Path $app)) {
        Write-Error "Portable application not found: $app. Run install.bat or build_exe.bat first."
        exit 1
    }
    $target    = $app
    $args_str  = ""
    $workdir   = Split-Path -Parent $app
    $iconPath  = $app
    $desc      = "IntegrityGuard"
    Write-Host "Режим: запуск из dist\IntegrityGuard\IntegrityGuard.exe"
} else {
    # --- Режим исходников (python.exe + IntegrityGuard.pyw) ---
    $python = Join-Path $root ".venv\Scripts\python.exe"
    $pyw    = Join-Path $root "IntegrityGuard.pyw"
    if (-not (Test-Path $python)) {
        Write-Error "Python venv not found: $python. Run install.bat first."
        exit 1
    }
    if (-not (Test-Path $pyw)) {
        Write-Error "IntegrityGuard.pyw not found: $pyw"
        exit 1
    }
    $target    = $python
    $args_str  = "`"$pyw`""
    $workdir   = $root
    $iconPath  = if (Test-Path $ico) { $ico } else { $python }
    $desc      = "IntegrityGuard (из исходников)"
    Write-Host "Режим: запуск из исходников (.pyw) — изменения вступают в силу немедленно"
}

$targets = @($candidates | Where-Object { Test-Path -LiteralPath $_ })
if ($targets.Count -eq 0) {
    Write-Host "Существующих ярлыков нет — создаю."
    $targets = $candidates
}

foreach ($path in $targets) {
    $s = $shell.CreateShortcut($path)
    $s.TargetPath       = $target
    $s.Arguments        = $args_str
    $s.WorkingDirectory = $workdir
    $s.IconLocation     = $iconPath
    $s.Description      = $desc
    $s.WindowStyle      = 7
    $s.Save()
    Write-Host "Ярлык готов: $path"
}

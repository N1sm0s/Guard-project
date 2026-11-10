# Refreshes existing IntegrityGuard shortcuts. If none exist yet (first install),
# creates one on the Desktop and one next to this script, so the program can always
# be launched by a shortcut as required.
$root = $PSScriptRoot
$app = Join-Path $root "dist\IntegrityGuard\IntegrityGuard.exe"
if (-not (Test-Path $app)) {
    Write-Error "Portable application not found: $app. Run install.bat or build_exe.bat first."
    exit 1
}
$appDirectory = Split-Path -Parent $app
$shell = New-Object -ComObject WScript.Shell
$candidates = @((Join-Path ([Environment]::GetFolderPath("Desktop")) "IntegrityGuard.lnk"), (Join-Path $root "IntegrityGuard.lnk"))
$targets = @($candidates | Where-Object { Test-Path -LiteralPath $_ })
if ($targets.Count -eq 0) {
    Write-Host "No existing IntegrityGuard shortcuts found; creating them (first install)."
    $targets = $candidates
}
foreach ($path in $targets) {
    $s = $shell.CreateShortcut($path)
    $s.TargetPath = $app
    $s.Arguments = ""
    $s.WorkingDirectory = $appDirectory
    $s.IconLocation = $app
    $s.Description = "IntegrityGuard"
    $s.Save()
    Write-Host "Shortcut ready: $path"
}

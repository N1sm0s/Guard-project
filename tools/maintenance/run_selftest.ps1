Set-Location F:\New\integrityguard
Set-Item -Path Env:QT_QPA_PLATFORM -Value offscreen
& .\.venv\Scripts\python.exe IntegrityGuard.pyw --selftest-gui
Write-Output ("EXITCODE=" + $LASTEXITCODE)

Set-Location F:\New\integrityguard
Set-Item -Path Env:QT_QPA_PLATFORM -Value offscreen
& .\.venv\Scripts\python.exe -m pytest -q
Write-Output ("EXITCODE=" + $LASTEXITCODE)

Set-Location "F:\New\integrityguard"
Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m integrityguard.gui" -WindowStyle Normal
Write-Host "GUI launched."

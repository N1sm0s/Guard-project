$files = @(
  "F:\New\integrityguard\integrityguard\network_telemetry.py",
  "F:\New\integrityguard\integrityguard\network_classifier.py",
  "F:\New\integrityguard\integrityguard\network_classifier_train.py",
  "F:\New\integrityguard\integrityguard\network_evidence.py",
  "F:\New\integrityguard\integrityguard\gui.py"
)
foreach ($f in $files) {
  & "F:\New\integrityguard\.venv\Scripts\python.exe" -m py_compile $f
  if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $f" } else { Write-Host "OK: $f" }
}

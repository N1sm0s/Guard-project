@echo off
schtasks /create ^
  /tn "IntegrityGuard NN Retrain" ^
  /tr "\"F:\New\integrityguard\.venv\Scripts\pythonw.exe\" \"F:\New\integrityguard\tools\maintenance\retrain_now.py\"" ^
  /sc minute /mo 1 ^
  /f
if %errorlevel% equ 0 (
    echo OK: task registered, runs every 1 minute.
) else (
    echo FAIL: errorlevel=%errorlevel%
)

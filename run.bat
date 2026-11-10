@echo off
chcp 65001 > nul
cd /d "%~dp0"
.venv\Scripts\python.exe IntegrityGuard.pyw
if errorlevel 1 goto :error
pause
exit /b 0
:error
echo.
echo Запуск не удался. Проверьте установку через install.bat.
pause
exit /b 1

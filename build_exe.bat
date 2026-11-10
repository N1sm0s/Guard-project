@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Run install.bat first.
    exit /b 1
)
echo === IntegrityGuard onedir build ===
".venv\Scripts\python.exe" -m pip install --upgrade PyInstaller || goto :error
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean IntegrityGuard.spec || goto :error
echo.
echo Build complete: dist\IntegrityGuard\IntegrityGuard.exe
echo Writable data: %%LOCALAPPDATA%%\IntegrityGuard\data
exit /b 0
:error
echo.
echo Build failed. Review the PyInstaller output above.
exit /b 1


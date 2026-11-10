@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === IntegrityGuard: установка ===
where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
if not exist ".venv\Scripts\pythonw.exe" (
    echo [1/3] Создание окружения Python...
    %PY% -m venv .venv || goto :error
)
echo [2/3] Установка библиотек (PyTorch около 200 МБ, это займёт несколько минут)...
".venv\Scripts\python.exe" -m pip install --upgrade pip -q || goto :error
".venv\Scripts\python.exe" -m pip install torch --index-url https://download.pytorch.org/whl/cpu || goto :error
".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error
echo [3/3] Сборка portable-приложения...
call build_exe.bat || goto :error
powershell -NoProfile -ExecutionPolicy Bypass -File create_shortcut.ps1
echo.
echo Готово. Приложение: dist\IntegrityGuard\IntegrityGuard.exe
echo Ярлык IntegrityGuard создан на рабочем столе (и указывает на portable-приложение).
pause
exit /b 0
:error
echo.
echo Установка не завершена. Проверьте, что установлен Python 3.10+ (python.org) и есть доступ в интернет.
pause
exit /b 1

@echo off
cd /d F:\New\integrityguard
set PYTHONUTF8=1

echo.
echo =======================================================
echo   IntegrityGuard Gate 5 -- Автозапуск обучения
echo   Цель: fp0_min >= 0.80 на CTU-13 captures 53 и 54
echo =======================================================
echo.

:: Проверяем аргументы
set MODE=full
if "%1"=="--skip-tune" set MODE=skip-tune
if "%1"=="--train-only" set MODE=train-only
if "%1"=="--eval-only" set MODE=eval-only
if "%1"=="--status" goto :status

:: Убедиться что outputs/network-eval существует
if not exist outputs\network-eval mkdir outputs\network-eval

:: Установить optuna если нужен
echo [autorun] Установка зависимостей...
F:\New\integrityguard\.venv\Scripts\python.exe -m pip install -q optuna 2>nul

echo [autorun] Режим: %MODE%
echo [autorun] Лог: outputs\network-eval\autorun.log
echo.

if "%MODE%"=="full" (
    echo [autorun] Запуск полного цикла: Optuna -^> обучение -^> Gate 5
    F:\New\integrityguard\.venv\Scripts\python.exe tools\autorun.py --trials 100 --tune-epochs 300
)
if "%MODE%"=="skip-tune" (
    echo [autorun] Пропускаем Optuna, запускаем обучение...
    F:\New\integrityguard\.venv\Scripts\python.exe tools\autorun.py --skip-tune
)
if "%MODE%"=="train-only" (
    echo [autorun] Только обучение с лучшими параметрами...
    F:\New\integrityguard\.venv\Scripts\python.exe tools\autorun.py --train-only
)
if "%MODE%"=="eval-only" (
    echo [autorun] Только оценка Gate 5...
    F:\New\integrityguard\.venv\Scripts\python.exe tools\autorun.py --eval-only
)

echo.
echo [autorun] Завершено. Лог: outputs\network-eval\autorun.log
goto :end

:status
echo [autorun] Статус прогонов:
F:\New\integrityguard\.venv\Scripts\python.exe tools\autorun.py --status

:end
pause

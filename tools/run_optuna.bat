@echo off
cd /d F:\New\integrityguard
set PYTHONUTF8=1
echo === Optuna: установка зависимостей ===
F:\New\integrityguard\.venv\Scripts\python.exe -m pip install -q optuna
echo === Optuna: запуск поиска (100 trials, 300 эпох/trial) ===
F:\New\integrityguard\.venv\Scripts\python.exe tools\tune_optuna.py --trials 100 --epochs 300 > outputs\network-eval\optuna_search.log 2>&1
echo Завершено. Лог: outputs\network-eval\optuna_search.log

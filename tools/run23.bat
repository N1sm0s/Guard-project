@echo off
cd /d F:\New\integrityguard
set PYTHONUTF8=1
F:\New\integrityguard\.venv\Scripts\python.exe tools\train_gate5_run23.py > outputs\network-eval\train_run23.log 2>&1

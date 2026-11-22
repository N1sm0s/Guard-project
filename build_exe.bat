@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Packaging uses a SEPARATE venv (.venv-build) from the one you develop/
rem train in (.venv). The dev venv may have a CUDA-enabled torch installed
rem for local GPU training; that build also bundles torch's full CUDA 12
rem runtime (cuDNN/cuBLAS/cuSOLVER/cuFFT/nvJitLink, several GB) even though
rem this app only ever runs on CPU (see online_learn.build_candidate /
rem train.py, which force torch.set_num_threads(1) and never call .cuda()).
rem Building from .venv-build with the CPU-only torch wheel keeps the
rem packaged app lean without touching your training environment.
if not exist ".venv-build\Scripts\python.exe" (
    echo Creating .venv-build CPU-only packaging environment...
    python -m venv .venv-build || goto :error
    ".venv-build\Scripts\python.exe" -m pip install --upgrade pip || goto :error
    ".venv-build\Scripts\python.exe" -m pip install torch --index-url https://download.pytorch.org/whl/cpu || goto :error
    ".venv-build\Scripts\python.exe" -m pip install "PySide6>=6.5" numpy matplotlib psutil "fpdf2>=2.7" || goto :error
)
echo === IntegrityGuard onedir build (CPU-only, .venv-build) ===
".venv-build\Scripts\python.exe" -m pip install --upgrade PyInstaller || goto :error
".venv-build\Scripts\python.exe" -m PyInstaller --noconfirm --clean IntegrityGuard.spec || goto :error
echo.
echo Build complete: dist\IntegrityGuard\IntegrityGuard.exe
echo Writable data: %%LOCALAPPDATA%%\IntegrityGuard\data
exit /b 0
:error
echo.
echo Build failed. Review the PyInstaller output above.
exit /b 1


"""Запуск графического интерфейса IntegrityGuard (без окна консоли)."""
import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", ROOT)).resolve() if FROZEN else ROOT
os.chdir(ROOT)
os.environ.setdefault("PYTHONUTF8", "1")                # кириллица в файлах и выводе — всегда UTF-8
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
# Qt's Windows DLL loader can pick up unrelated ICU/VC runtimes from PATH
# (for example, tools injected by a parent process). Put the PySide6 wheel's
# own DLL directory first before importing the GUI in both source and frozen
# launches.
if os.name == "nt":
    qt_runtime = (RESOURCE_ROOT / "PySide6") if FROZEN else (
        Path(sys.prefix) / "Lib" / "site-packages" / "PySide6"
    )
    if qt_runtime.is_dir():
        os.environ["PATH"] = str(qt_runtime) + os.pathsep + os.environ.get("PATH", "")
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(qt_runtime))
sys.path.insert(0, str(RESOURCE_ROOT))
from integrityguard.paths import DATA_ROOT

if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest-gui"]:
        from integrityguard.gui_selftest import run

        sys.exit(run())
    if sys.stdout is None or sys.stderr is None:          # pythonw: вывод некуда писать — ведём журнал в файл
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(DATA_ROOT / "app.log", "a", encoding="utf-8", buffering=1)
    # недостающие небольшие библиотеки доустанавливаются сами (например, после обновления программы)
    import importlib.util
    import subprocess
    missing = [m for m in ("psutil", "matplotlib") if importlib.util.find_spec(m) is None]
    if missing and not FROZEN:
        exe = Path(sys.executable).with_name("python.exe" if os.name == "nt" else "python")
        try:
            subprocess.run([str(exe if exe.exists() else sys.executable), "-m", "pip", "install", "-q", *missing],
                           timeout=600, creationflags=0x08000000 if os.name == "nt" else 0,
                           stdout=sys.stdout, stderr=sys.stderr)
        except Exception as e:  # noqa: BLE001 — без сети программа запускается и без них
            print("auto-install failed:", e)
    try:
        from integrityguard.gui import main
        main(start_minimized="--tray" in sys.argv[1:])
    except Exception:
        import traceback
        traceback.print_exc()
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, traceback.format_exc()[-900:], "IntegrityGuard: ошибка запуска", 0x10)
        except Exception:
            pass
        raise

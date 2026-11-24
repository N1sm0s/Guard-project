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
    if sys.argv[1:2] in (["--selftest-gui"], ["--selftest-copilot"],
                         ["--selftest-labels"], ["--selftest-real-wheels"]):
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
        selftest_log = open(DATA_ROOT / "selftest.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = selftest_log
    if sys.argv[1:2] == ["--training-worker"]:
        from integrityguard.training_process import worker_main

        sys.exit(worker_main(sys.argv[2:]))
    if sys.argv[1:] == ["--selftest-gui"]:
        from integrityguard.gui_selftest import run

        sys.exit(run())
    if sys.argv[1:] == ["--selftest-copilot"]:
        from integrityguard.gui_selftest import run

        sys.exit(run(copilot_check=True))
    if len(sys.argv) == 3 and sys.argv[1] == "--selftest-labels":
        from integrityguard.gui_selftest import run

        sys.exit(run(label_catalog=sys.argv[2]))
    if len(sys.argv) == 4 and sys.argv[1] == "--selftest-real-wheels":
        from integrityguard.gui_selftest import run

        sys.exit(run(sys.argv[2:]))
    if sys.stdout is None or sys.stderr is None:          # pythonw: вывод некуда писать — ведём журнал в файл
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(DATA_ROOT / "app.log", "a", encoding="utf-8", buffering=1)
    # Запуск UI не должен ждать сеть/pip (раньше установка могла блокировать до 10 минут).
    # Необязательные функции сами проверяют наличие psutil; зависимости ставятся через install.bat.
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

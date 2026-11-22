"""Dev-loop watcher: rebuilds the IntegrityGuard.exe via PyInstaller on source changes.

Polls mtimes (no extra dependency) of every tracked source file; on any change it waits a
short debounce window to batch rapid edits, then runs `pyinstaller IntegrityGuard.spec`.
PyInstaller cannot overwrite dist/IntegrityGuard.exe while that process is running (Windows
file lock), so this detects that case and says so plainly instead of failing silently.
"""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG = Path(__file__).with_name("rebuild.log")
WATCH_GLOBS = ["integrityguard/*.py", "IntegrityGuard.pyw", "IntegrityGuard.spec"]
POLL_SECONDS = 2.0
DEBOUNCE_SECONDS = 1.5


def _snapshot() -> dict[str, float]:
    sig: dict[str, float] = {}
    for pattern in WATCH_GLOBS:
        for path in ROOT.glob(pattern):
            try:
                sig[str(path)] = path.stat().st_mtime_ns
            except OSError:
                pass
    return sig


def _log(line: str) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = f"[{stamp}] {line}"
    print(text, flush=True)
    with LOG.open("a", encoding="utf-8") as stream:
        stream.write(text + "\n")


def _exe_is_running() -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq IntegrityGuard.exe"],
                             capture_output=True, text=True, timeout=10)
        return "IntegrityGuard.exe" in out.stdout
    except Exception:
        return False


def _rebuild() -> None:
    if _exe_is_running():
        _log("IntegrityGuard.exe сейчас запущен; PyInstaller не сможет перезаписать файл. "
             "Закройте программу (значок в трее -> Выход), пересборка повторится при следующем изменении.")
        return
    _log("Изменения в исходниках обнаружены -> пересборка PyInstaller...")
    result = subprocess.run([sys.executable, "-m", "PyInstaller", "IntegrityGuard.spec", "--noconfirm"],
                            cwd=ROOT, capture_output=True, text=True, timeout=900)
    if result.returncode == 0:
        _log("Пересборка завершена успешно: dist/IntegrityGuard.exe обновлён.")
    else:
        tail = "\n".join((result.stdout + result.stderr).splitlines()[-25:])
        _log(f"Пересборка ЗАВЕРШИЛАСЬ С ОШИБКОЙ (код {result.returncode}):\n{tail}")


def main() -> None:
    _log(f"Наблюдение запущено: {', '.join(WATCH_GLOBS)} (опрос {POLL_SECONDS} с, задержка {DEBOUNCE_SECONDS} с)")
    last = _snapshot()
    pending_since: float | None = None
    while True:
        time.sleep(POLL_SECONDS)
        current = _snapshot()
        if current != last:
            pending_since = pending_since or time.monotonic()
            last = current
            continue
        if pending_since is not None and time.monotonic() - pending_since >= DEBOUNCE_SECONDS:
            pending_since = None
            _rebuild()


if __name__ == "__main__":
    main()

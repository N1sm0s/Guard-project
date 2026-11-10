"""Разовая проверка: автопроверка каталога (без выбора и без кнопок) на странице «Проверка пакета».

Создаёт окно в офскрин-режиме, указывает каталог демо-пакета (просто вписывая путь — без галочек)
и проверяет, что проверка выполнилась сама, без вызова _check() вручную — ни разу: ни сразу после
указания пути, ни после правки файла внутри, ни после очистки поля (должна остановиться).
"""
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from PySide6.QtWidgets import QApplication
from integrityguard import gui as G

tmp = Path(tempfile.mkdtemp(prefix="ig_watchtest_"))
G.DATA = tmp

app = QApplication([])
app.setStyle("Fusion")
w = G.MainWindow()


def pump(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)


pump(0.3)
# ждём автоподготовку: демо-набор и его первичную проверку
end = time.monotonic() + 120
while time.monotonic() < end and not (w.demo_labels and not w._workers):
    app.processEvents()
    time.sleep(0.05)
assert w.demo_labels, "демо-набор не подготовился"
n0 = len(w._read_events())
print("демо-пакетов:", len(w.demo_labels), "| проверок до теста:", n0)

lb = w.demo_labels[0]
proj = tmp / "demo_packages" / lb["project"] / "candidates" / lb["candidate"]
watched = tmp / "watched_pkg"
shutil.copytree(proj, watched)

w.pkg.setText(str(watched))            # просто вписали путь — ничего больше выбирать не нужно
end = time.monotonic() + 40
while time.monotonic() < end and (w._workers or len(w._read_events()) <= n0):
    app.processEvents()
    time.sleep(0.05)
n1 = len(w._read_events())
print("[OK]  " if n1 > n0 else "[FAIL]", "проверка при указании пути сработала сама:", n1, ">", n0)

# правим файл в каталоге -> жмём ничего, ждём, проверка должна повториться сама
man = watched / "manifest.json"
txt = man.read_text(encoding="utf-8")
man.write_text(txt, encoding="utf-8")  # перезапись меняет mtime, этого достаточно для сигнатуры наблюдателя
os.utime(watched / "model.pt", None)
end = time.monotonic() + 40
while time.monotonic() < end and (w._workers or len(w._read_events()) <= n1):
    app.processEvents()
    time.sleep(0.05)
n2 = len(w._read_events())
print("[OK]  " if n2 > n1 else "[FAIL]", "повторная проверка при изменении файла сработала сама:", n2, ">", n1)

w.pkg.setText("")                      # очистка поля — единственный способ остановить наблюдение
pump(0.2)
print("[OK]  " if not w._watch_timer.isActive() else "[FAIL]", "очистка поля останавливает наблюдение")

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

"""Разовая проверка редизайна «Проверка пакета»: максимум 2 клика, минимум кнопок, максимум автоматизации.

Проверяет:
1. блок «Дополнительные параметры» свёрнут по умолчанию (не пугает при первом запуске);
2. кнопка «Показать на примере» одним кликом подставляет готовый пакет и сама запускает проверку —
   без выбора демо-пакета вручную и без нажатия «Проверить»;
3. разворачивание/сворачивание дополнительных параметров работает в обе стороны.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from PySide6.QtWidgets import QApplication
from integrityguard import gui as G

tmp = Path(tempfile.mkdtemp(prefix="ig_onboardtest_"))
G.DATA = tmp

app = QApplication([])
app.setStyle("Fusion")
w = G.MainWindow()
w.show()                               # isVisible() у дочерних виджетов требует показанного окна


def pump(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)


pump(0.3)
print("[OK]  " if not w._adv_body.isVisible() else "[FAIL]", "дополнительные параметры свёрнуты по умолчанию")

w._toggle_advanced()
pump(0.1)
print("[OK]  " if w._adv_body.isVisible() else "[FAIL]", "разворачиваются по клику")
w._toggle_advanced()
pump(0.1)
print("[OK]  " if not w._adv_body.isVisible() else "[FAIL]", "сворачиваются обратно по клику")

# ждём автоподготовку демо-набора (как при первом реальном запуске программы)
end = time.monotonic() + 120
while time.monotonic() < end and not (w.demo_labels and not w._workers):
    app.processEvents()
    time.sleep(0.05)
assert w.demo_labels, "демо-набор не подготовился"

n0 = len(w._read_events())
w.pkg.setText("")
w._set_badge(None)
pump(0.2)

w._try_demo()                          # ровно один клик пользователя
end = time.monotonic() + 40
while time.monotonic() < end and (w._workers or len(w._read_events()) <= n0):
    app.processEvents()
    time.sleep(0.05)
pump(0.3)                              # дать обработать сигнал done() фонового потока (обновление карточки)
n1 = len(w._read_events())
pkg_filled = bool(w.pkg.text().strip())
print("[OK]  " if pkg_filled else "[FAIL]", "кнопка «Показать на примере» сама подставила пакет:", w.pkg.text())
print("[OK]  " if n1 > n0 else "[FAIL]", "и сама же запустила проверку, без «Проверить»:", n1, ">", n0)
print("[OK]  " if w.badge.text() != "—" else "[FAIL]", "результат отображён в карточке:", w.badge.text())

w._quitting = True
w.close()
import shutil
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

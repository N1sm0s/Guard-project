"""Разовая проверка трёх улучшений удобства: сортировка таблиц, фильтр в журнале событий,
удаление эталона из реестра."""
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from PySide6.QtWidgets import QApplication, QMessageBox
from integrityguard import gui as G

tmp = Path(tempfile.mkdtemp(prefix="ig_usability_"))
G.DATA = tmp

app = QApplication([])
app.setStyle("Fusion")
w = G.MainWindow()
w.show()


def pump(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)


pump(0.3)
w.demo_btn.click()
end = time.monotonic() + 60
while time.monotonic() < end and w._workers:
    app.processEvents()
    time.sleep(0.05)
pump(2.0)
end = time.monotonic() + 60
while time.monotonic() < end and w._workers:
    app.processEvents()
    time.sleep(0.05)
pump(1.0)

# --- 1) сортировка журнала событий не ломает связь строки с её событием (через Qt.UserRole)
from PySide6.QtCore import Qt as _Qt

w._load_events()
print("[OK]  " if w.e_table.rowCount() > 0 else "[FAIL]", "журнал событий заполнен:", w.e_table.rowCount())

w.e_table.sortItems(1, _Qt.AscendingOrder)  # сортировка по столбцу «Пакет»
pump(0.1)
mismatch = 0
for row in range(w.e_table.rowCount()):
    it = w.e_table.item(row, 0)
    ev = it.data(_Qt.UserRole)
    if not ev or ev.get("package") != w.e_table.item(row, 1).text():
        mismatch += 1
print("[OK]  " if mismatch == 0 else "[FAIL]", "после сортировки данные строки совпадают со столбцом «Пакет»:", mismatch, "несовпадений")

w.e_table.selectRow(0)
pump(0.1)
sel_ev = w.e_table.item(0, 0).data(_Qt.UserRole)
shown = w.e_detail.toPlainText()
print("[OK]  " if sel_ev and sel_ev.get("package", "") in shown else "[FAIL]",
     "деталь события соответствует выбранной (отсортированной) строке")

# --- 2) фильтр в журнале событий по имени пакета
all_packages = {ev["package"] for ev in w.events}
if all_packages:
    needle = next(iter(all_packages))
    w.e_filter.setText(needle)
    pump(0.1)
    rows_shown = w.e_table.rowCount()
    all_match = all(w.e_table.item(r, 1).text() == needle for r in range(rows_shown))
    print("[OK]  " if rows_shown > 0 and all_match else "[FAIL]", "фильтр по пакету показывает только совпадающие строки:", rows_shown)
    w.e_filter.setText("")
    pump(0.1)
    print("[OK]  " if w.e_table.rowCount() >= rows_shown else "[FAIL]", "очистка фильтра возвращает полный список")
else:
    print("[FAIL] нет событий для проверки фильтра")

# --- 3) удаление эталона из реестра (с подтверждением)
w.nav.button(w._page_index("Эталоны и версии")).click()
pump(0.2)
before = w.b_table.rowCount()
print("[OK]  " if before > 0 else "[FAIL]", "эталоны зарегистрированы для теста:", before)
w.b_table.selectRow(0)
pump(0.1)
target_name = w.b_table.item(0, 0).text()
target_dir = Path(w.cfg("registry")) / "baselines" / target_name

orig_exec = QMessageBox.exec
QMessageBox.exec = lambda self: QMessageBox.No  # сначала проверяем отмену
try:
    w._delete_baseline()
    pump(0.1)
    print("[OK]  " if target_dir.exists() and w.b_table.rowCount() == before else "[FAIL]",
         "отмена подтверждения не удаляет эталон")
finally:
    QMessageBox.exec = orig_exec

orig_exec = QMessageBox.exec
QMessageBox.exec = lambda self: QMessageBox.Yes
try:
    w._delete_baseline()
    end = time.monotonic() + 10
    while time.monotonic() < end and w._workers:
        app.processEvents()
        time.sleep(0.05)
    pump(0.2)
    print("[OK]  " if not target_dir.exists() and w.b_table.rowCount() == before - 1 else "[FAIL]",
         "подтверждённое удаление убирает эталон из реестра и из таблицы:", target_dir.exists(), w.b_table.rowCount())
finally:
    QMessageBox.exec = orig_exec

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

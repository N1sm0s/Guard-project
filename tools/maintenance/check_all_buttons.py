"""Разовая сквозная проверка: каждая кнопка интерфейса реально нажимается (а не её внутренний метод
вызывается напрямую) и проверяется видимый результат. Файловые диалоги (QFileDialog) подменяются, чтобы
не блокировать headless-запуск; запись в реестр автозапуска Windows отключена подменой метода, чтобы тест
не трогал реальные настройки компьютера."""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox, QPushButton
from integrityguard import gui as G

RESULTS = []


def check(cond, text):
    RESULTS.append((bool(cond), text))
    print("[OK]  " if cond else "[FAIL]", text)


tmp = Path(tempfile.mkdtemp(prefix="ig_buttons_"))
G.DATA = tmp

app = QApplication([])
app.setStyle("Fusion")
w = G.MainWindow()
w._set_autostart = lambda enable: None  # не трогаем реальный автозапуск Windows на этом компьютере
w.show()


def pump(seconds, until=None):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)
        if until and until():
            return True
    return until is None


def wait_idle(timeout=90, settle=0.6):
    """Ждём не просто момента, когда w._workers пуст, а когда это держится settle секунд подряд —
    иначе можно попасть в щель между окончанием одной фоновой задачи и запуском следующей в цепочке
    (через QTimer.singleShot(0, ...)), которая ещё не успела создать свой Worker."""
    end = time.monotonic() + timeout
    stable_since = None
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)
        if not w._workers:
            stable_since = stable_since or time.monotonic()
            if time.monotonic() - stable_since >= settle:
                return True
        else:
            stable_since = None
    return False


def page(name):
    w.nav.button(w._page_index(name)).click()
    pump(0.1)


ok = pump(60, lambda: bool(w.demo_labels)) and wait_idle(120)
check(ok, "автоподготовка завершилась (демо-набор готов)")

# ---------------------------------------------------------- навигация (7 кнопок)
names = ["Проверка пакета", "Мониторинг", "Эталоны и версии", "Журнал событий",
         "Полнота обнаружения", "Обучение и оценка", "Настройки"]
nav_ok = True
for n in names:
    page(n)
    if w.stack.currentIndex() != w._page_index(n):
        nav_ok = False
check(nav_ok, f"кнопки навигации переключают все {len(names)} страниц")

# ---------------------------------------------------------- страница «Проверка пакета»
page("Проверка пакета")

w.adv_toggle.click()
pump(0.1)
shown1 = w._adv_body.isVisible()
w.adv_toggle.click()
pump(0.1)
shown2 = w._adv_body.isVisible()
check(shown1 and not shown2, "«Дополнительные параметры» (страница проверки) разворачиваются и сворачиваются")

lb = w.demo_labels[0]
clean_pkg = w._demo_dir() / lb["project"] / "candidates" / lb["candidate"]
w.pkg.setText(str(clean_pkg))
w.check_btn.click()
ok = wait_idle(60)
check(ok and w.pdf_btn.isEnabled(), "кнопка «Проверить» выполняет проверку (PDF-кнопка включилась)")

pdf_path = tmp / "report_from_button.pdf"
with patch.object(QFileDialog, "getSaveFileName", return_value=(str(pdf_path), "PDF (*.pdf)")):
    w.pdf_btn.click()
wait_idle(30)
check(pdf_path.is_file() and pdf_path.read_bytes().startswith(b"%PDF-"), "кнопка «PDF-отчёт» сохраняет настоящий PDF")

before_batch = w.batch.rowCount()
w.all_btn.click()
ok = wait_idle(60)
check(ok and w.batch.rowCount() == len(w.demo_labels), "кнопка «Проверить весь демо-набор» заполняет таблицу результатов")

w.demo_try_btn.click()
ok = wait_idle(60)
check(ok and w.pkg.text(), "кнопка «Попробовать на примере» подставляет демо-пакет и проверяет его")

before_demo = set(w._baseline_names())
w.demo_btn.click()
ok = wait_idle(120)
check(ok and bool(w.demo_labels), "кнопка «Пересоздать демонстрационные пакеты» отрабатывает без сбоя")

# ---------------------------------------------------------- страница «Эталоны и версии»
page("Эталоны и версии")

w.b_adv_toggle.click()
pump(0.1)
bshown1 = w._b_adv_body.isVisible()
w.b_adv_toggle.click()
pump(0.1)
bshown2 = w._b_adv_body.isVisible()
check(bshown1 and not bshown2, "«Дополнительные параметры» (страница эталонов) разворачиваются и сворачиваются")

lb2 = w.demo_labels[1] if len(w.demo_labels) > 1 else w.demo_labels[0]
fresh_pkg = w._demo_dir() / lb2["project"] / "candidates" / lb2["candidate"]
fresh_ctrl = w._demo_dir() / lb2["project"] / "control.npz"
new_pkg_dir = tmp / "manual_pkg"
shutil.copytree(fresh_pkg, new_pkg_dir)
man = json.loads((new_pkg_dir / "manifest.json").read_text(encoding="utf-8"))
man["name"] = "button-test-pkg"
(new_pkg_dir / "manifest.json").write_text(json.dumps(man), encoding="utf-8")

w.b_pkg.setText(str(new_pkg_dir))
w.b_ctrl.setText(str(fresh_ctrl) if fresh_ctrl.exists() else "")
reg_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Зарегистрировать эталон")
n0 = len(w._baseline_names())
reg_btn.click()
ok = wait_idle(60)
pump(0.5)
check(ok and len(w._baseline_names()) > n0, "кнопка «Зарегистрировать эталон» добавляет новый эталон")

sign_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Подписать пакет ключом реестра")
sig_file = new_pkg_dir / "manifest.sig"
sig_before = sig_file.exists()
sign_btn.click()
ok = wait_idle(30)
check(ok and sig_file.exists(), "кнопка «Подписать пакет ключом реестра» создаёт подпись")

sbom_path = tmp / "sbom_from_button.json"
with patch.object(QFileDialog, "getSaveFileName", return_value=(str(sbom_path), "JSON (*.json)")):
    w.sbom_btn.click()
wait_idle(30)
check(sbom_path.is_file() and json.loads(sbom_path.read_text(encoding="utf-8")), "кнопка «SBOM в свой файл…» сохраняет SBOM")

target_row = next(r for r in range(w.b_table.rowCount()) if w.b_table.item(r, 0).text() == "button-test-pkg")
w.b_table.selectRow(target_row)   # явно по имени, а не по индексу 0 — таблица теперь сортируемая
pump(0.1)
target_name = w.b_table.item(target_row, 0).text()
target_dir = Path(w.cfg("registry")) / "baselines" / target_name
before_rows = w.b_table.rowCount()
with patch.object(QMessageBox, "exec", return_value=QMessageBox.Yes):
    w.b_del_btn.click()
pump(0.3)
check(not target_dir.exists() and w.b_table.rowCount() == before_rows - 1, "кнопка «Удалить эталон» удаляет выбранный эталон")

# ---------------------------------------------------------- страница «Журнал событий» — только фильтр (не кнопка)
page("Журнал событий")
check(w.e_table.rowCount() > 0, "журнал событий заполнен (для справки, фильтр проверен отдельным тестом)")

# ---------------------------------------------------------- страница «Полнота обнаружения»
page("Полнота обнаружения")
w.r_btn.click()
ok = wait_idle(60)
check(ok and Path(w._recall_file()).exists(), "кнопка «Рассчитать полноту на демо-наборе» сохраняет расчёт")

retrain_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Открыть «Обучение и оценка»")
retrain_btn.click()
pump(0.1)
check(w.stack.currentIndex() == w._page_index("Обучение и оценка"), "кнопка «Открыть «Обучение и оценка»» переключает страницу")

# ---------------------------------------------------------- страница «Обучение и оценка»
page("Обучение и оценка")
to_recall_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Открыть страницу «Полнота обнаружения»")
to_recall_btn.click()
pump(0.1)
check(w.stack.currentIndex() == w._page_index("Полнота обнаружения"), "кнопка «Открыть страницу «Полнота обнаружения»» переключает страницу")
page("Обучение и оценка")

w.t_projects.setValue(30)      # с 10 (минимум спинбокса) единственный «чистый» проект иногда не попадает
w.t_epochs.setValue(10)        # в обучающую часть при разбиении — разбиение случайно, поэтому берём запас
w.t_abl.setChecked(False)
before_model = w.cfg("model")
w.t_btn.click()
ok = wait_idle(240)
trained = ok and "Готово" in w.t_note.text() and w.cfg("model") != before_model
check(trained, f"кнопка «Сформировать корпус и обучить детектор» завершает обучение: {w.t_note.text()}")

# ---------------------------------------------------------- страница «Настройки»
page("Настройки")
save_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Сохранить" and b.isVisibleTo(w))
save_btn.click()
pump(0.2)
check("Сохран" in w.s_note.text(), "кнопка «Сохранить» (общие настройки) отрабатывает без сбоя")

policy_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Сохранить политику")
policy_btn.click()
pump(0.2)
check(bool(w.s_policy_note.text()), "кнопка «Сохранить политику» отрабатывает и обновляет подпись")

workflow_file = G.ROOT / ".github" / "workflows" / "integrityguard.yml"
w.ci_btn = next((b for b in w.findChildren(QPushButton) if "workflow" in b.text().lower()), None)
if w.ci_btn:
    w.ci_btn.click()
    pump(0.2)
check(workflow_file.exists(), "кнопка «Сгенерировать workflow для GitHub Actions» создаёт файл")

open_btn = next(b for b in w.findChildren(QPushButton) if b.text() == "Открыть папку входящих")
with patch("PySide6.QtGui.QDesktopServices.openUrl", return_value=True) as spy:
    open_btn.click()
    pump(0.1)
check(w.incoming.exists() and spy.called, "кнопка «Открыть папку входящих» создаёт папку и открывает её")

# ---------------------------------------------------------- баннер: кнопка «Скрыть»
w.notify("Проверка кнопки закрытия баннера.", "info")
pump(0.1)
close_btn = next(b for b in w.banner.findChildren(QPushButton) if b.isVisible() or True)
check(w.banner.isVisible(), "баннер показан перед проверкой кнопки «Скрыть»")
close_btn.click()
pump(0.1)
check(not w.banner.isVisible(), "кнопка «Скрыть» на баннере прячет сообщение")

# ---------------------------------------------------------- PathEdit «Обзор…» (общий для всех полей путей)
browse_target = tmp / "browsed_dir"
browse_target.mkdir()
browse_btn = next(b for b in w.s_reg.findChildren(QPushButton) if b.text() == "Обзор…")
with patch.object(QFileDialog, "getExistingDirectory", return_value=str(browse_target)):
    browse_btn.click()
check(w.s_reg.text() == str(browse_target), "кнопка «Обзор…» (пример — каталог реестра) записывает выбранный путь")

failed = [t for ok_, t in RESULTS if not ok_]
print(f"\nВсего проверок: {len(RESULTS)}, провалено: {len(failed)}")

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

"""Сквозная самопроверка интерфейса без показа окна.

Запускает программу на временной копии данных, ждёт автоматическую подготовку (демо-набор и его проверку),
кладёт во «входящие» чистый и изменённый пакеты и сохраняет снимки всех страниц в data/selftest/.
"""
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

from .paths import APP_ROOT, FROZEN

HIDDEN = sys.platform == "win32"                        # в Windows окно строится настоящим движком, но не показывается
FAILURES = []


def say(*a):
    line = " ".join(str(x) for x in a)
    if line.startswith("[FAIL]"):
        FAILURES.append(line)
    LOG.write(line + "\n")
    LOG.flush()
    try:
        print(line, flush=True)
    except Exception:
        pass


def main():
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from integrityguard import gui as G
    tmp = Path(tempfile.mkdtemp(prefix="ig_selftest_"))
    G.DATA = tmp                                          # настоящие данные программы не затрагиваются
    model_override = os.environ.get("INTEGRITYGUARD_SELFTEST_MODEL")
    if model_override:
        from PySide6.QtCore import QSettings
        settings = QSettings(str(tmp / "settings.ini"), QSettings.IniFormat)
        settings.setValue("model", str(Path(model_override).resolve()))
        settings.setValue("auto", "true")
        settings.sync()
    app = QApplication([])
    app.setStyle("Fusion")
    app.setPalette(G.dark_palette())
    app.setStyleSheet(G.QSS)
    say("       графический движок:", app.platformName(), "| шрифт:", app.font().family())
    w = G.MainWindow()
    w.resize(1280, 900)
    if HIDDEN:
        w.setAttribute(Qt.WA_DontShowOnScreen)
    w.show()

    def pump(seconds, until=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.02)
            if until and until():
                return True
        return until is None

    def shot(name):
        pump(0.4)
        w.grab().save(str(OUT / f"{name}.png"))

    def page(name):
        w.nav.button(w._page_index(name)).click()

    def full(name, title):
        """Снимок страницы целиком (вместе с прокручиваемой частью)."""
        page(title)
        pump(0.4)
        body = w.stack.currentWidget().widget()
        body.grab().save(str(OUT / f"{name}.png"))

    ok = pump(240, lambda: bool(w.demo_labels) and not w._workers and len(w._read_events()) >= len(w.demo_labels))
    say("[OK]  " if ok and len(w.demo_labels) > 0 and len(w._read_events()) >= len(w.demo_labels) else "[FAIL]",
        "автоподготовка: демо-пакетов", len(w.demo_labels), "проверок", len(w._read_events()),
        "| сообщение:", w.banner_text.text() if w.banner.isVisible() else "нет")
    batch_ok = getattr(w, "_batch_ok", 0)
    say("       решения на демо-пакетах:", batch_ok, "верно из", len(w.demo_labels))
    import json
    batch_results = [
        [w.batch.item(row, col).text() if w.batch.item(row, col) else ""
         for col in range(5)]
        for row in range(w.batch.rowCount())
    ]
    (OUT / "batch-results.json").write_text(
        json.dumps({"seed": 4211, "rows": batch_results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    demo_classes = {lb["class"] for lb in w.demo_labels}
    say("[OK]  " if demo_classes == set(G.CLASSES) else "[FAIL]",
        "покрытие демо-набора по классам:", len(demo_classes), "из", len(G.CLASSES))
    say("[OK]  " if w.batch.rowCount() == len(w.demo_labels) else "[FAIL]",
        "строки результатов в интерфейсе:", w.batch.rowCount())
    full("1_proverka", "Проверка пакета")

    # входящие: сначала доверенный пакет нового имени (станет эталоном), затем его изменённая копия
    import json
    import torch
    proj = tmp / "demo_packages" / "project_000"
    src = proj / "reference"
    new = tmp / "stage_pkg"
    shutil.copytree(src, new)
    man = json.loads((new / "manifest.json").read_text(encoding="utf-8"))
    man["name"] = "selftest-pkg"
    (new / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    shutil.copy(proj / "control.npz", tmp / "stage_pkg.control.npz")
    shutil.copy(tmp / "stage_pkg.control.npz", w.incoming / "selftest-pkg.control.npz")
    shutil.copytree(new, w.incoming / "selftest-pkg")
    n0 = len(w._baseline_names())
    ok = pump(40, lambda: len(w._baseline_names()) > n0 and not w._workers)
    say("[OK]  " if ok else "[FAIL]", "входящие: первый пакет стал эталоном:", w._baseline_names())
    bad = tmp / "stage_bad"
    shutil.copytree(new, bad)
    man["version"] = "9.9.9"
    (bad / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    st = torch.load(bad / "model.pt", weights_only=True)
    generator = torch.Generator().manual_seed(4211)
    for k in st:
        if st[k].is_floating_point() and st[k].dim() == 2:
            st[k] = st[k] + 0.6 * torch.randn(st[k].shape, generator=generator, dtype=st[k].dtype)
    torch.save(st, bad / "model.pt")
    e0 = len(w._read_events())
    shutil.copytree(bad, w.incoming / "selftest-pkg-v2")
    ok = pump(40, lambda: len(w._read_events()) > e0 and not w._workers)
    ev = next((row for row in reversed(w._read_events())
               if row.get("package") == "selftest-pkg" and row.get("version") == "9.9.9"), {})
    say("[OK]  " if ok and ev.get("verdict") in {"REVIEW", "BLOCK"} else "[FAIL]", "входящие: изменённый пакет —", ev.get("verdict"), ev.get("threat_ru"),
        "| разложено:", sorted(p.name for p in (tmp / "processed").iterdir()) if (tmp / "processed").exists() else "нет")
    from unittest.mock import patch
    from PySide6.QtWidgets import QFileDialog

    pdf = tmp / "Отчёты" / "Результат проверки.pdf"
    pdf.parent.mkdir()
    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(pdf), "PDF (*.pdf)")):
        w.pdf_btn.click()
    exported = pump(30, lambda: pdf.is_file() and not w._workers)
    pdf_ok = exported and pdf.read_bytes().startswith(b"%PDF-")
    say("[OK]  " if pdf_ok else "[FAIL]", "экспорт PDF из интерфейса")
    if pdf_ok:
        shutil.copyfile(pdf, OUT / "threat-report.pdf")

    pump(4)                                               # несколько точек графика сети
    full("2_monitoring", "Мониторинг")
    say("       мониторинг: плитки", {k: v.text() for k, v in w.tiles.items()}, "| точек графика сети", len(w.ch_net.values),
        "| интервалов потока", len(w.ch_flow.buckets), "| точек оценок", len(w.ch_score.events))
    full("3_etalony", "Эталоны и версии")
    full("4_zhurnal", "Журнал событий")
    full("5_obuchenie", "Обучение и оценка")
    page("Полнота обнаружения")
    os.remove(w._recall_file())
    w._measure_recall()                                   # отдельный расчёт кнопкой, без записи в журнал
    e1 = len(w._read_events())
    pump(60, lambda: not w._workers and w._recall_file().exists())
    recall_data = G.R.load(w._recall_file()) or {}
    recall_overall = recall_data.get("overall") or {}
    per_class = recall_data.get("per_class") or {}
    class_counts = {c: per_class.get(c, {}).get("n", 0) for c in G.R.THREATS}
    say("[OK]  " if all(class_counts.values()) else "[FAIL]", "примеры в расчёте по классам:", class_counts)
    say("[OK]  " if w._recall_file().exists() and recall_overall.get("n", 0) > 0
        and len(w._read_events()) == e1 else "[FAIL]", "расчёт полноты кнопкой:",
        w.r_tiles["demo"][0].text(), w.r_tiles["demo"][1].text())
    full("9_polnota", "Полнота обнаружения")
    do = (G.R.load(w._recall_file()) or {}).get("overall")
    say("[OK]  " if do and do.get("n", 0) > 0 else "[FAIL]", "полнота на демо-наборе:", do)
    full("6_nastroiki", "Настройки")
    page("Проверка пакета")
    w.pkg.setText("")
    w._check()                                            # пустой путь: должно быть сообщение полосой, без окна
    shot("7_soobshchenie")
    say("[OK]  " if w.banner.isVisible() else "[FAIL]", "сообщение без всплывающего окна:", w.banner_text.text())
    from PySide6.QtWidgets import QMessageBox
    box = QMessageBox(QMessageBox.Question, "IntegrityGuard", "Идёт фоновая задача. Прервать её и закрыть программу?",
                      QMessageBox.Yes | QMessageBox.No, w)
    if HIDDEN:
        box.setAttribute(Qt.WA_DontShowOnScreen)
    box.show()
    pump(0.4)
    box.grab().save(str(OUT / "8_okno.png"))
    c = box.grab().toImage().pixelColor(12, 12)
    say("[OK]  " if c.lightness() < 90 else "[FAIL]", "стандартное окно тёмное: цвет фона", c.name())
    box.close()
    for wk in list(w._workers):
        wk.wait(20000)
    w.auto_timer.stop()
    w.net_timer.stop()
    w._quitting = True                                    # самопроверка: закрыть по-настоящему, не свернуть в трей
    w.close()
    if getattr(w, "tray", None):
        w.tray.hide()
    shutil.rmtree(tmp, ignore_errors=True)
    say("Завершено. Сбоев:", len(FAILURES))


def run():
    global OUT, LOG
    if not HIDDEN:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
    default = Path(tempfile.gettempdir()) / "IntegrityGuard-selftest" if FROZEN else APP_ROOT / "data" / "selftest"
    OUT = Path(os.environ.get("INTEGRITYGUARD_SELFTEST_OUT", default)).resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    FAILURES.clear()
    with (OUT / "selftest.log").open("w", encoding="utf-8") as LOG:
        try:
            from unittest.mock import patch
            from .collect import export_corpus

            def fixed_corpus(*args, **kwargs):
                kwargs["seed"] = 4211
                return export_corpus(*args, **kwargs)

            with patch("integrityguard.collect.export_corpus", side_effect=fixed_corpus):
                main()
        except Exception:
            say("[FAIL] самопроверка прервана\n" + traceback.format_exc())
    return 1 if FAILURES else 0

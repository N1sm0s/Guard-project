"""Разовая проверка автоматизации «Эталоны и версии»: один осознанный клик — «Зарегистрировать эталон» —
а подпись, SBOM и обновление таблиц происходят сами, без отдельных кликов.

Проверяет:
1. блок «Дополнительные параметры» (ручная подпись, SBOM в свой файл) свёрнут по умолчанию и разворачивается
   по клику в обе стороны;
2. после «Зарегистрировать эталон» пакет оказывается подписан (manifest.sig) без отдельного клика «Подписать»;
3. после регистрации сам создаётся SBOM-файл в data/sbom/<имя>.json без диалога сохранения;
4. таблица «Зарегистрированные эталоны» сама обновляется и показывает новую запись.
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
from integrityguard.collect import export_corpus

tmp = Path(tempfile.mkdtemp(prefix="ig_baseline_auto_"))
G.DATA = tmp

app = QApplication([])
app.setStyle("Fusion")
w = G.MainWindow()
w.show()
w.stack.setCurrentIndex(w._page_index("Эталоны и версии"))  # иначе видимость дочерних виджетов не определена


def pump(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)


pump(0.3)
print("[OK]  " if not w._b_adv_body.isVisible() else "[FAIL]", "ручная подпись/SBOM свёрнуты по умолчанию")

w._toggle_b_adv()
pump(0.1)
print("[OK]  " if w._b_adv_body.isVisible() else "[FAIL]", "разворачиваются по клику")
w._toggle_b_adv()
pump(0.1)
print("[OK]  " if not w._b_adv_body.isVisible() else "[FAIL]", "сворачиваются обратно по клику")

# готовим настоящий (не фиктивный) доверенный пакет той же генерацией, что использует демо-набор
corpus_dir = tmp / "corpus"
export_corpus(corpus_dir, 1, seed=1, class_names=["clean"])
project = next(corpus_dir.glob("project_*"))
pkg_dir = project / "reference"
ctrl = project / "control.npz"
assert (pkg_dir / "manifest.json").exists(), "эталонный пакет не создан генератором корпуса"
(pkg_dir / "manifest.sig").unlink(missing_ok=True)  # имитируем ещё не подписанный пакет

w.b_pkg.setText(str(pkg_dir))
w.b_ctrl.setText(str(ctrl) if ctrl.exists() else "")
pump(0.1)

sig_before = (pkg_dir / "manifest.sig").exists()

# ровно один клик пользователя
w._register(None)

end = time.monotonic() + 60
while time.monotonic() < end and w._workers:
    app.processEvents()
    time.sleep(0.05)
pump(0.5)  # дать обработать очередь done-сигналов (регистрация -> авто-подпись/SBOM)

end = time.monotonic() + 60
while time.monotonic() < end and w._workers:
    app.processEvents()
    time.sleep(0.05)
pump(0.5)

signed = (pkg_dir / "manifest.sig").exists()
print("[OK]  " if (not sig_before and signed) else "[FAIL]", "пакет подписан сам, без клика «Подписать»:", signed)

sbom_candidates = list((tmp / "sbom").glob("*.json")) if (tmp / "sbom").exists() else []
print("[OK]  " if sbom_candidates else "[FAIL]", "SBOM сохранён сам, без диалога:", sbom_candidates)

print("[OK]  " if w.b_table.rowCount() >= 1 else "[FAIL]", "таблица эталонов обновилась сама:", w.b_table.rowCount())

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

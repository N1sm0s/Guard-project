"""Разовая проверка: генератор CI/CD workflow и баннер-напоминание о переобучении."""
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

tmp = Path(tempfile.mkdtemp(prefix="ig_settings_auto_"))
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

# --- генератор CI workflow
w._generate_ci_workflow()
out = G.ROOT / ".github" / "workflows" / "integrityguard.yml"
text = out.read_text(encoding="utf-8") if out.exists() else ""
ok = out.exists() and "check" in text and "--strict" in text
print("[OK]  " if ok else "[FAIL]", "workflow-файл создан с командой check --strict:", out)

# --- баннер о переобучении: низкая полнота на тестовой выборке -> баннер виден
import json
from integrityguard.recall import THREATS

real_model_path = Path(w.cfg("model"))
real_metrics = real_model_path.parent / "metrics.json"
backup = real_metrics.read_text(encoding="utf-8") if real_metrics.exists() else None

fake_model_dir = tmp / "fake_model"
fake_model_dir.mkdir(parents=True, exist_ok=True)
fake_model_path = fake_model_dir / "detector.pt"
fake_model_path.write_bytes(b"\x00")  # cfg() требует реально существующий файл
w.settings.setValue("model", str(fake_model_path))


def fake_metrics(recall_value):
    per_class = {c: {"n": 10, "detected": recall_value, "recall": recall_value} for c in THREATS}
    return {
        "hybrid": {"binary": {"recall": recall_value}, "per_class": per_class},
        "hash_baseline": {"per_class_detected": {c: 0.0 for c in THREATS}},
    }


try:
    metrics_path = fake_model_dir / "metrics.json"
    metrics_path.write_text(json.dumps(fake_metrics(0.5)), encoding="utf-8")

    w._load_recall()
    # страница «Полнота обнаружения» может не быть активной вкладкой стека — isVisible() тогда всегда False
    # по цепочке предков, даже если сам баннер явно показан; isHidden() смотрит только на сам виджет.
    print("[OK]  " if not w.r_retrain_banner.isHidden() else "[FAIL]", "баннер «переобучить» показан при низкой полноте")

    (fake_model_dir / "metrics.json").write_text(json.dumps(fake_metrics(0.95)), encoding="utf-8")
    w._load_recall()
    print("[OK]  " if w.r_retrain_banner.isHidden() else "[FAIL]", "баннер скрыт при хорошей полноте")
finally:
    w.settings.remove("model")  # возвращаем настройки как было — снова используется настоящая модель проекта
    intact = (backup is None and not real_metrics.exists()) or (
        backup is not None and real_metrics.exists() and real_metrics.read_text(encoding="utf-8") == backup
    )
    print("[OK]  " if intact else "[FAIL]", "настоящий metrics.json проекта не задет")

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

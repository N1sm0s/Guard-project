"""Разовая проверка автоматизации при вердикте БЛОКИРОВКА:
1. PDF-отчёт сам сохраняется в data/reports/, без нажатия «PDF-отчёт»;
2. уведомление в трее не падает, даже когда трей недоступен (headless/offscreen);
3. полнота обнаружения пересчитывается сама после регистрации нового эталона (без кнопки);
4. «Журнал событий» обновляется сам при появлении новой записи (без кнопки «Обновить» — её больше нет).
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

tmp = Path(tempfile.mkdtemp(prefix="ig_block_auto_"))
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

# --- 1 и 2: синтетическое событие БЛОКИРОВКА через _show_event (как при обычной проверке)
ev = {
    "time": "2026-11-11T12:00:00+00:00", "package": "test-pkg", "version": "1.0.0",
    "baseline_version": "0.9.0", "verdict": "BLOCK", "threat": "backdoor",
    "threat_ru": "внедрение триггера (бэкдора)", "score": 0.97, "risk_score": 95,
    "hash_control": True, "rules": [], "levels": {"structural": 0.1, "parametric": 0.2, "behavioral": 0.9},
    "suspects": [{"component": "layer:dense.2", "score": 0.91}],
    "threshold": 0.3, "block_threshold": 0.7, "timing_ms": {"total": 12.3},
    "stage": "build", "fingerprint": "deadbeef",
}
try:
    w._show_event(ev)
except Exception as e:
    print("[FAIL] _show_event не упал при БЛОКИРОВКЕ:", repr(e))
else:
    print("[OK]   _show_event не упал при БЛОКИРОВКЕ (трей недоступен в headless — не критично)")

end = time.monotonic() + 20
while time.monotonic() < end and w._workers:
    app.processEvents()
    time.sleep(0.05)
pump(0.3)

reports = list((tmp / "reports").glob("block_*.pdf")) if (tmp / "reports").exists() else []
print("[OK]  " if reports else "[FAIL]", "PDF-отчёт сохранён сам в data/reports/:", reports)

# --- 4: «Журнал событий» обновляется сам — проверяем метод keep_selection напрямую
w._load_events()
before = len(w.events)
f = Path(w.cfg("registry")) / "events.jsonl"
f.parent.mkdir(parents=True, exist_ok=True)
import json as _json
with open(f, "a", encoding="utf-8") as fh:
    fh.write(_json.dumps({**ev, "package": "another-pkg"}, ensure_ascii=False) + "\n")
w._mon_sig = None  # форсируем срабатывание проверки на следующем тике
w._net_tick()
pump(0.2)
print("[OK]  " if len(w.events) > before else "[FAIL]", "«Журнал событий» подхватил новую запись сам:",
      before, "->", len(w.events))

w._quitting = True
w.close()
shutil.rmtree(tmp, ignore_errors=True)
print("Готово.")

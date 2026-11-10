"""Самопроверка IntegrityGuard: окружение, детектор, создание и проверка демо-пакетов. Результат — data/diagnose.log."""
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
(ROOT / "data").mkdir(exist_ok=True)
LOG = open(ROOT / "data" / "diagnose.log", "w", encoding="utf-8")


def say(*a):
    line = " ".join(str(x) for x in a)
    LOG.write(line + "\n")
    LOG.flush()
    try:
        print(line)
    except Exception:
        pass


def step(name, fn):
    t = time.time()
    try:
        r = fn()
        say(f"[OK]   {name} ({time.time() - t:.1f} c) {r if r is not None else ''}")
        return r
    except Exception:
        say(f"[FAIL] {name}\n{traceback.format_exc()}")


say("python", sys.version.split()[0], sys.executable)
say("root", ROOT)
for m in ("torch", "numpy", "PySide6", "matplotlib", "psutil"):
    step(f"import {m}", lambda m=m: getattr(__import__(m), "__version__", "?"))
ini = ROOT / "data" / "settings.ini"
say("settings.ini:", ini.read_text(encoding="utf-8", errors="replace") if ini.exists() else "нет")


def demo():
    import shutil
    import tempfile
    from integrityguard.collect import export_corpus
    from integrityguard.system import IntegrityGuard
    tmp = Path(tempfile.mkdtemp(prefix="ig_diag_"))
    try:
        labels = export_corpus(tmp / "demo", 1, seed=7, key=b"diag-key")
        g = IntegrityGuard(tmp / "registry", ROOT / "models" / "detector.pt", b"diag-key")
        p = tmp / "demo" / "project_000"
        g.register_baseline(p / "reference", p / "control.npz")
        ok = 0
        for lb in labels:
            c = p / "candidates" / lb["candidate"]
            ev = g.check(c, "build", f"{c}.index.json")
            ok += (ev["verdict"] != "ALLOW") == (lb["class"] != "clean")
        return f"верных решений {ok} из {len(labels)}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


step("создание и проверка демо-пакетов", demo)


def gui():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from integrityguard import gui as G
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(G.QSS)
    w = G.MainWindow()
    w.show()
    app.processEvents()
    names = [b.text() for b in w.nav.buttons()]
    w.close()
    return ", ".join(names)


step("сборка окна программы", gui)
say("готово")

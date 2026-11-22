import sqlite3
from pathlib import Path

DATA = Path(r"F:\New\integrityguard\data")

paths = {
    "network_events (NetworkEventLog)": DATA / "online" / "network_events.sqlite",
    "network_label_reviews": DATA / "online" / "network_label_reviews.sqlite",
    "label_registry": DATA / "label_registry.sqlite",
    "label_reviews (audit)": DATA / "label_reviews.sqlite",
}

for name, path in paths.items():
    if not path.exists():
        print(f"{name}: missing ({path})")
        continue
    try:
        db = sqlite3.connect(str(path))
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"{name}: tables={tables}")
        for t in tables:
            try:
                n = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                print(f"  {t}: {n} rows")
            except sqlite3.DatabaseError as e:
                print(f"  {t}: error {e}")
        db.close()
    except Exception as e:
        print(f"{name}: error opening ({e})")

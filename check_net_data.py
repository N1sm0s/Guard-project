import sqlite3, os
from pathlib import Path

# Проверим network_events.sqlite
for db_path in [
    "network_events.sqlite",
    "data/online/network_runtime_metrics.sqlite",
    "network_label_reviews.sqlite",
]:
    p = Path(db_path)
    if not p.exists():
        print(f"НЕТ: {db_path}")
        continue
    db = sqlite3.connect(str(p))
    c = db.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in c.fetchall()]
    print(f"OK: {db_path} -> таблицы: {tables}")
    for t in tables:
        c.execute(f"SELECT COUNT(*) FROM [{t}]")
        cnt = c.fetchone()[0]
        print(f"  {t}: {cnt} строк")
    db.close()

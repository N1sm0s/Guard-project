import sqlite3, json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
db_path = ROOT / "data" / "online" / "network_events.sqlite"

conn = sqlite3.connect(str(db_path))
# Смотреть структуру таблицы
cols = [row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()]
print("Columns:", cols)

# Первые несколько строк
rows = conn.execute("SELECT * FROM events LIMIT 2").fetchall()
for row in rows:
    d = dict(zip(cols, row))
    # Декодируем JSON если нужно
    for k, v in d.items():
        if isinstance(v, str) and v.startswith('{'):
            try:
                d[k] = json.loads(v)
            except:
                pass
    print("\nRow keys:", list(d.keys()))
    print("event_id:", d.get('event_id','?'))
    print("label:", d.get('label','?'))
    print("decision:", d.get('decision','?'))
    snap = d.get('snapshot') or d.get('snapshot_data') or {}
    if isinstance(snap, str):
        try: snap = json.loads(snap)
        except: pass
    remote = snap.get('remote_endpoints', []) if isinstance(snap, dict) else []
    print(f"remote_endpoints count: {len(remote)}")
    break

# Считаем метки
label_col = None
for c in cols:
    if 'label' in c.lower() or 'decision' in c.lower():
        label_col = c
        break

print(f"\nLabel column: {label_col}")
if label_col:
    counts = Counter(row[0] for row in conn.execute(f"SELECT {label_col} FROM events"))
    print("Distribution:", dict(counts))

# Проверяем есть ли flow_id в снимках
row = conn.execute("SELECT * FROM events LIMIT 1").fetchone()
if row:
    d = dict(zip(cols, row))
    for k,v in d.items():
        if isinstance(v, str) and len(v)>5:
            try:
                parsed = json.loads(v)
                if isinstance(parsed, dict) and 'remote_endpoints' in parsed:
                    eps = parsed['remote_endpoints']
                    print(f"\nSnapshot field: {k}")
                    print(f"remote_endpoints[0] keys: {list(eps[0].keys()) if eps else 'empty'}")
                    if eps:
                        print("first ep id:", eps[0].get('id', 'NO_ID'))
                    break
            except:
                pass

conn.close()

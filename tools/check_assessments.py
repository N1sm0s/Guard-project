import sqlite3, json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
db_path = ROOT / "data" / "online" / "network_events.sqlite"
conn = sqlite3.connect(str(db_path))

# Смотрим assessment_json
rows = conn.execute("SELECT event_id, assessment_json FROM events WHERE assessment_json IS NOT NULL LIMIT 5").fetchall()
decisions = []
for event_id, aj in conn.execute("SELECT event_id, assessment_json FROM events WHERE assessment_json IS NOT NULL").fetchall():
    try:
        a = json.loads(aj)
        decisions.append(a.get('decision') or a.get('model_decision') or '?')
    except:
        decisions.append('parse_error')

print("Assessment decisions distribution:")
for k, v in Counter(decisions).most_common():
    print(f"  {k}: {v}")

# Показать пример
if rows:
    print("\nSample assessment_json:")
    a = json.loads(rows[0][1])
    # Только ключи и короткие значения
    for k, v in a.items():
        if isinstance(v, str) and len(v) > 100:
            print(f"  {k}: {v[:100]}...")
        else:
            print(f"  {k}: {v}")

conn.close()

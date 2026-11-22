import sqlite3, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

db_main = ROOT / "data" / "online" / "network_events.sqlite"
db_reviews = ROOT / "data" / "online" / "network_label_reviews.sqlite"

for db_path in [db_main, db_reviews]:
    if not db_path.exists():
        print(f"{db_path.name}: NOT FOUND")
        continue
    print(f"\n=== {db_path.name} ===")
    conn = sqlite3.connect(str(db_path))
    tables = [t[0] for t in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    print("Tables:", tables)
    for t in tables:
        cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {cnt} rows")
    conn.close()

# Посмотреть verified_snapshot_labels
print("\n=== verified_snapshot_labels ===")
from integrityguard.network_evidence import NetworkEventLog
from integrityguard.network_label_reviews import NetworkLabelReviews

event_log = NetworkEventLog(str(db_main))
reviews = NetworkLabelReviews(str(db_reviews))
labeled = reviews.verified_snapshot_labels(event_log)
print(f"verified count: {len(labeled)}")
if labeled:
    print("sample:", json.dumps(labeled[0], indent=2, default=str)[:500])

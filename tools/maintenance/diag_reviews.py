"""Quick diagnostic: why does verified_snapshot_labels return 0?"""
import hashlib
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

rv_path = ROOT / "data" / "online" / "network_label_reviews.sqlite"
ev_path = ROOT / "data" / "online" / "network_events.sqlite"

rv = sqlite3.connect(rv_path)
ev = sqlite3.connect(ev_path)

# Pick first event that has reviews
row = rv.execute(
    "SELECT DISTINCT event_id FROM reviews LIMIT 1"
).fetchone()
eid = row[0]
print("Testing event_id:", eid)

# Check reviews for this event
reviews = rv.execute(
    "SELECT flow_id,snapshot_sha256,reviewer,label,evidence_sha256,evidence "
    "FROM reviews WHERE event_id=? LIMIT 5",
    (eid,)
).fetchall()
print(f"Reviews found: {len(reviews)}")
for r in reviews:
    intact = hashlib.sha256(r[5]).hexdigest() == r[4]
    print(f"  flow_id={r[0][:12]} sha_ok={intact} label={r[2]} reviewer={r[3]}")

# Check event snapshot
ev_row = ev.execute(
    "SELECT snapshot_sha256, snapshot_json FROM events WHERE event_id=?",
    (eid,)
).fetchone()
if ev_row:
    import json
    snap = json.loads(ev_row[1])
    re_ids = {str(ep.get("id")) for ep in (snap.get("remote_endpoints") or [])
              if isinstance(ep, dict) and ep.get("id")}
    rev_flow_ids = {r[0] for r in reviews}
    print(f"Snapshot remote_endpoint ids: {len(re_ids)}, sample: {list(re_ids)[:3]}")
    print(f"Review flow_ids: {list(rev_flow_ids)[:3]}")
    print(f"Overlap: {len(re_ids & rev_flow_ids)}")
    # Check snapshot SHA match
    canon = json.dumps(snap, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sha = hashlib.sha256(canon.encode()).hexdigest()
    print(f"Snapshot SHA ok: {sha == ev_row[0]}")
else:
    print("Event NOT found in events table!")

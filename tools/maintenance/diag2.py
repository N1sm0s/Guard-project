import hashlib, sqlite3, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
rv = sqlite3.connect(ROOT / "data/online/network_label_reviews.sqlite")
ev = sqlite3.connect(ROOT / "data/online/network_events.sqlite")
eid = rv.execute("SELECT DISTINCT event_id FROM reviews LIMIT 1").fetchone()[0]
rv_sha = rv.execute("SELECT snapshot_sha256 FROM reviews WHERE event_id=? LIMIT 1", (eid,)).fetchone()[0]
ev_sha = ev.execute("SELECT snapshot_sha256 FROM events WHERE event_id=?", (eid,)).fetchone()[0]
print("rv_sha:", rv_sha[:20], "...")
print("ev_sha:", ev_sha[:20], "...")
print("match:", rv_sha.lower() == str(ev_sha).lower())

# Now test decision() directly
from integrityguard.network_label_reviews import NetworkLabelReviews
reviews = NetworkLabelReviews(ROOT / "data/online/network_label_reviews.sqlite")
flow_id = rv.execute("SELECT flow_id FROM reviews WHERE event_id=? LIMIT 1", (eid,)).fetchone()[0]
dec = reviews.decision(eid, flow_id, rv_sha)
print("decision:", dec)

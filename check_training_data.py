"""
Check where the 644 training samples come from.
"""
import sqlite3
import json
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

events_db = r"F:\New\integrityguard\data\online\network_events.sqlite"
reviews_db = r"F:\New\integrityguard\data\online\network_label_reviews.sqlite"

# Load ALL events
with sqlite3.connect(events_db) as c:
    all_events = c.execute(
        "SELECT event_id, captured_at_utc, snapshot_sha256, snapshot_json FROM events ORDER BY captured_at_utc"
    ).fetchall()

# Load ALL reviews
with sqlite3.connect(reviews_db) as c:
    all_reviews = c.execute(
        "SELECT event_id, flow_id, snapshot_sha256, reviewer, label FROM reviews"
    ).fetchall()

print(f"Total events: {len(all_events)}")
print(f"Total reviews: {len(all_reviews)}")

# Build review map
review_map = {}
for event_id, flow_id, snap_sha, reviewer, label in all_reviews:
    key = (event_id, flow_id)
    review_map.setdefault(key, {})[reviewer] = label

# Count labeled events
allow_count = 0
block_count = 0
partial_count = 0
none_count = 0

allow_dates = []
block_dates = []

for event_id, captured_at, snap_sha, snap_json in all_events:
    try:
        snap = json.loads(snap_json) if snap_json else {}
    except Exception:
        snap = {}
    
    remote_eps = snap.get("remote_endpoints") or []
    flow_ids = {str(f.get("id")) for f in remote_eps if isinstance(f, dict) and f.get("id")}
    
    if not flow_ids:
        continue
    
    labeled_flows = {}
    for flow_id in flow_ids:
        key = (event_id, flow_id)
        if key in review_map:
            latest = review_map[key]
            labels = set(latest.values())
            if len(labels) == 1:
                labeled_flows[flow_id] = next(iter(labels))
    
    if any(v == 1 for v in labeled_flows.values()):
        block_count += 1
        block_dates.append(captured_at[:16])
    elif len(labeled_flows) == len(flow_ids) and all(v == 0 for v in labeled_flows.values()):
        allow_count += 1
        allow_dates.append(captured_at[:16])
    elif labeled_flows:
        partial_count += 1
    else:
        none_count += 1

print(f"\nALL {len(all_events)} events:")
print(f"  BLOCK: {block_count}")
print(f"  ALLOW: {allow_count}")
print(f"  PARTIAL (some flows labeled): {partial_count}")
print(f"  NOT LABELED: {none_count}")
print(f"  Total labeled (BLOCK+ALLOW): {allow_count + block_count}")
print()

if allow_dates:
    print(f"ALLOW date range: {allow_dates[0]} to {allow_dates[-1]}")
    print(f"Sample ALLOW dates: {allow_dates[:5]}")
if block_dates:
    print(f"BLOCK date range: {block_dates[0]} to {block_dates[-1]}")

# Check flow count distribution
print("\n=== Flow count distribution (last 20 events) ===")
for event_id, captured_at, snap_sha, snap_json in all_events[-20:]:
    try:
        snap = json.loads(snap_json) if snap_json else {}
    except Exception:
        snap = {}
    remote_eps = snap.get("remote_endpoints") or []
    flow_ids = [str(f.get("id")) for f in remote_eps if isinstance(f, dict) and f.get("id")]
    labeled = sum(1 for fid in flow_ids if (event_id, fid) in review_map)
    print(f"  {captured_at[:16]} flows={len(flow_ids)}, labeled={labeled}")

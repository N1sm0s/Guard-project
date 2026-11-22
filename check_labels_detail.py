"""
Diagnostics: why new labels don't make it into training.
"""
import sqlite3
import json
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

events_db = r"F:\New\integrityguard\data\online\network_events.sqlite"
reviews_db = r"F:\New\integrityguard\data\online\network_label_reviews.sqlite"

with sqlite3.connect(events_db) as c:
    events = c.execute(
        "SELECT event_id, snapshot_sha256, snapshot_json FROM events ORDER BY captured_at_utc DESC LIMIT 50"
    ).fetchall()

with sqlite3.connect(reviews_db) as c:
    reviews = c.execute(
        "SELECT event_id, flow_id, snapshot_sha256, reviewer, label FROM reviews"
    ).fetchall()

review_map = {}
for event_id, flow_id, snap_sha, reviewer, label in reviews:
    key = (event_id, flow_id)
    review_map.setdefault(key, []).append((reviewer, label, snap_sha))

print(f"Total events in DB: {len(events)}")
print(f"Total review records: {len(reviews)}")
print(f"Unique (event_id, flow_id) pairs with review: {len(review_map)}")
print()

print("=== Last 10 events ===")
for event_id, snap_sha, snap_json in events[:10]:
    try:
        snap = json.loads(snap_json) if snap_json else {}
    except Exception:
        snap = {}
    
    remote_eps = snap.get("remote_endpoints") or []
    flow_ids = {str(f.get("id")) for f in remote_eps if isinstance(f, dict) and f.get("id")}
    
    labeled_flows = {}
    for flow_id in flow_ids:
        key = (event_id, flow_id)
        if key in review_map:
            revs = review_map[key]
            latest = {}
            for reviewer, label, rsha in revs:
                latest[reviewer] = (label, rsha)
            labels = {v[0] for v in latest.values()}
            if len(labels) == 1:
                labeled_flows[flow_id] = next(iter(labels))
    
    if any(v == 1 for v in labeled_flows.values()):
        final_label = "BLOCK"
    elif len(labeled_flows) == len(flow_ids) and all(v == 0 for v in labeled_flows.values()) and flow_ids:
        final_label = "ALLOW"
    else:
        if labeled_flows:
            final_label = f"PARTIAL ({len(labeled_flows)}/{len(flow_ids)} flows labeled)"
        else:
            final_label = "NOT LABELED"
    
    print(f"  {event_id[:20]}... flows={len(flow_ids)}, labeled={len(labeled_flows)} -> {final_label}")

print()
total_allow = 0
total_block = 0
total_partial = 0
total_none = 0

for event_id, snap_sha, snap_json in events:
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
            revs = review_map[key]
            latest = {}
            for reviewer, label, rsha in revs:
                latest[reviewer] = label
            labels = set(latest.values())
            if len(labels) == 1:
                labeled_flows[flow_id] = next(iter(labels))
    
    if any(v == 1 for v in labeled_flows.values()):
        total_block += 1
    elif len(labeled_flows) == len(flow_ids) and all(v == 0 for v in labeled_flows.values()):
        total_allow += 1
    elif labeled_flows:
        total_partial += 1
    else:
        total_none += 1

print(f"=== From last {len(events)} events ===")
print(f"  BLOCK (at least 1 malicious): {total_block}")
print(f"  ALLOW (all flows ALLOW):      {total_allow}")
print(f"  PARTIAL (not all flows):      {total_partial}")
print(f"  NOT LABELED:                  {total_none}")
print()
print("KEY INSIGHT: For ALLOW, EVERY flow in the snapshot must be labeled ALLOW.")
print("Even 1 unlabeled flow means the event is excluded from ALLOW training.")

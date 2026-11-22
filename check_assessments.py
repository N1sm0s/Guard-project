import sqlite3, json, sys, io, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

events_db = r"F:\New\integrityguard\data\online\network_events.sqlite"
reviews_db = r"F:\New\integrityguard\data\online\network_label_reviews.sqlite"

with sqlite3.connect(events_db) as c:
    events = c.execute("SELECT event_id, captured_at_utc, snapshot_sha256, snapshot_json, assessment_json FROM events ORDER BY captured_at_utc").fetchall()
with sqlite3.connect(reviews_db) as c:
    reviews_set = {(r[0], r[1]) for r in c.execute("SELECT event_id, flow_id FROM reviews").fetchall()}

unlabeled = []
for event_id, cap, sha, snap_json, assess_json in events:
    try:
        snap = json.loads(snap_json or '{}')
    except: snap = {}
    flow_ids = [str(f.get("id")) for f in (snap.get("remote_endpoints") or []) if isinstance(f,dict) and f.get("id")]
    if not flow_ids: continue
    unlabeled_flows = [f for f in flow_ids if (event_id, f) not in reviews_set]
    if unlabeled_flows:
        unlabeled.append((event_id, cap, sha, snap, assess_json, flow_ids, unlabeled_flows))

print(f"Unlabeled events (some flows missing): {len(unlabeled)}")
print()

# Analyze assessments
assess_actions = collections.Counter()
for event_id, cap, sha, snap, assess_json, flow_ids, unlabeled_flows in unlabeled[:200]:
    try:
        a = json.loads(assess_json or '{}')
    except: a = {}
    action = a.get("action") or a.get("verdict") or a.get("decision") or "none"
    assess_actions[str(action).lower()] += 1

print("Assessment action distribution for unlabeled events:")
for action, count in assess_actions.most_common():
    print(f"  {action}: {count}")

print()
# Show sample assess_json structure
for event_id, cap, sha, snap, assess_json, flow_ids, unlabeled_flows in unlabeled[:3]:
    try:
        a = json.loads(assess_json or '{}')
    except: a = {}
    print(f"Sample ({cap[:16]}): keys={list(a.keys())[:8]}")
    # Show top-level values
    for k, v in list(a.items())[:6]:
        if not isinstance(v, (dict, list)):
            print(f"  {k}: {v}")

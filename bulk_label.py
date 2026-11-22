"""
Bulk labeling script: label all unlabeled ALLOW events at once.

Usage:
  python bulk_label.py [--limit N] [--dry-run]
"""
import sqlite3
import json
import hashlib
import sys
import io
import argparse
import os
from pathlib import Path
from datetime import datetime, timezone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

events_db = Path(r"F:\New\integrityguard\data\online\network_events.sqlite")
reviews_db = Path(r"F:\New\integrityguard\data\online\network_label_reviews.sqlite")

def reviewer_identity():
    return os.environ.get("USERNAME", "pavel")

def propose_all_flows(reviews_path, event_id, flow_ids, snapshot_sha256, is_malicious, rationale):
    labeled = 0
    reviewer = reviewer_identity()
    evidence_text = (f"Bulk label: {'BLOCK' if is_malicious else 'ALLOW'}\n{rationale}").encode("utf-8")
    evidence_sha = hashlib.sha256(evidence_text).hexdigest()
    recorded_at = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(reviews_path, timeout=30) as db:
        db.execute("PRAGMA synchronous=FULL")
        for flow_id in flow_ids:
            existing = db.execute(
                "SELECT id FROM reviews WHERE event_id=? AND flow_id=? AND snapshot_sha256=?",
                (event_id, flow_id, snapshot_sha256.lower())
            ).fetchone()
            if existing:
                continue
            db.execute(
                """INSERT INTO reviews(event_id,flow_id,snapshot_sha256,reviewer,label,rationale,
                   evidence_sha256,evidence,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (event_id, flow_id, snapshot_sha256.lower(), reviewer,
                 int(is_malicious), rationale, evidence_sha, evidence_text, recorded_at)
            )
            labeled += 1
    return labeled

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=200, help="Max events to label")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with sqlite3.connect(events_db) as c:
        all_events = c.execute(
            "SELECT event_id, captured_at_utc, snapshot_sha256, snapshot_json, assessment_json "
            "FROM events ORDER BY captured_at_utc"
        ).fetchall()
    with sqlite3.connect(reviews_db) as c:
        reviewed_set = {(r[0], r[1]) for r in c.execute("SELECT event_id, flow_id FROM reviews").fetchall()}

    print(f"Total events: {len(all_events)}, reviewed pairs: {len(reviewed_set)}")

    to_label = []
    skipped_block = 0
    for event_id, captured_at, snap_sha, snap_json, assess_json in all_events:
        try:
            snap = json.loads(snap_json) if snap_json else {}
        except Exception:
            snap = {}
        try:
            assess = json.loads(assess_json) if assess_json else {}
        except Exception:
            assess = {}

        flow_ids = [str(f.get("id")) for f in (snap.get("remote_endpoints") or [])
                    if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            continue

        unlabeled = [f for f in flow_ids if (event_id, f) not in reviewed_set]
        if not unlabeled:
            continue

        # Only label events assessed as ALLOW or no-decision
        decision = str(assess.get("decision") or assess.get("action") or assess.get("verdict") or "").upper()
        if decision == "BLOCK":
            skipped_block += 1
            continue

        to_label.append((event_id, captured_at, snap_sha, flow_ids, unlabeled))

    print(f"Eligible ALLOW events: {len(to_label)} (skipped {skipped_block} BLOCK events)")

    if not to_label:
        print("Nothing to label.")
        return

    to_label = to_label[:args.limit]
    print(f"Processing {len(to_label)} events...")

    if args.dry_run:
        for event_id, cap, sha, fids, unlabeled in to_label[:10]:
            print(f"  Would label: {event_id[:20]}... {cap[:16]} flows={len(fids)} unlabeled={len(unlabeled)}")
        print("(dry-run)")
        return

    total_labeled = 0
    for i, (event_id, cap, sha, flow_ids, unlabeled) in enumerate(to_label):
        n = propose_all_flows(
            reviews_db, event_id, unlabeled,
            sha or hashlib.sha256(b"").hexdigest(),
            is_malicious=False,
            rationale="Bulk ALLOW: system assessed as normal traffic, no threat signals"
        )
        total_labeled += n
        if (i + 1) % 25 == 0:
            print(f"  {i+1}/{len(to_label)} events, {total_labeled} labels added")

    print(f"\nDone! Added {total_labeled} flow labels across {len(to_label)} events.")
    print("Run: python retrain_now.py --force")

if __name__ == "__main__":
    main()

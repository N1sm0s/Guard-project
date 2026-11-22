"""Детальный аудит: почему из 25118 ревью получилось только 644 образца."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.network_evidence import NetworkEventLog
from integrityguard.network_label_reviews import NetworkLabelReviews

EVENTS = ROOT / "data" / "online" / "network_events.sqlite"
REVIEWS = ROOT / "data" / "online" / "network_label_reviews.sqlite"

event_log = NetworkEventLog(EVENTS)
review_log = NetworkLabelReviews(REVIEWS)

# Статус ревью
counts = review_log.status_counts()
print("Review status counts:", counts)

# Сколько событий всего
all_events = event_log.all_events()
print(f"Total events: {len(all_events)}")

# Уникальные event_id в ревью
import sqlite3
from contextlib import closing
with closing(sqlite3.connect(str(REVIEWS))) as db:
    rows = db.execute("SELECT COUNT(DISTINCT event_id), COUNT(DISTINCT flow_id) FROM reviews").fetchone()
    print(f"Unique event_ids in reviews: {rows[0]}, unique flow_ids: {rows[1]}")
    rows2 = db.execute("SELECT COUNT(DISTINCT event_id || '|' || flow_id) FROM reviews").fetchone()
    print(f"Unique (event_id, flow_id) pairs: {rows2[0]}")

# Вызвать verified_snapshot_labels напрямую
labeled = review_log.verified_snapshot_labels(event_log)
print(f"\nverified_snapshot_labels result: {len(labeled)} samples")
from collections import Counter
lbl_counts = Counter(item["label"] for item in labeled)
print(f"Label distribution: {dict(lbl_counts)}")

# Временной охват ALLOW vs BLOCK
import datetime
allow_times = [item["captured_at_utc"] for item in labeled if item["label"] == "ALLOW"]
block_times = [item["captured_at_utc"] for item in labeled if item["label"] == "BLOCK"]
if allow_times:
    print(f"\nALLOW time range: {min(allow_times)} to {max(allow_times)}")
if block_times:
    print(f"BLOCK time range: {min(block_times)} to {max(block_times)}")

# Почему только 644 из 973 событий? Сколько событий без flow_ids?
no_flow = sum(1 for e in all_events if not (e["snapshot"].get("remote_endpoints") or []))
print(f"\nEvents without remote_endpoints: {no_flow}")
with_flow = len(all_events) - no_flow
print(f"Events with remote_endpoints: {with_flow}")

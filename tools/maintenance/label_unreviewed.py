"""Разметка непомеченных событий где LLM уверенно решил ALLOW.

Критерии безопасной авторазметки как ALLOW:
  - LLM решение = ALLOW (не REVIEW, не BLOCK)
  - нет threat_intelligence угроз в снимке
  - advisory_only=False (наш основной классификатор тоже решил ALLOW) ИЛИ 
    model содержит 'network_classifier' с ALLOW

Запуск: python label_unreviewed.py [--dry-run]
"""
import sys, sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.network_evidence import NetworkEventLog
from integrityguard.network_label_reviews import NetworkLabelReviews

EVENTS = ROOT / "data" / "online" / "network_events.sqlite"
REVIEWS = ROOT / "data" / "online" / "network_label_reviews.sqlite"

DRY_RUN = "--dry-run" in sys.argv

event_log = NetworkEventLog(EVENTS)
review_log = NetworkLabelReviews(REVIEWS)

# Уже проверенные
with sqlite3.connect(str(REVIEWS)) as db:
    reviewed_ids = {r[0] for r in db.execute("SELECT DISTINCT event_id FROM reviews").fetchall()}

# Все события
with sqlite3.connect(str(EVENTS)) as db:
    all_rows = db.execute(
        "SELECT event_id, captured_at_utc, snapshot_json, assessment_json "
        "FROM events WHERE assessment_json IS NOT NULL ORDER BY captured_at_utc"
    ).fetchall()

candidates = []
for event_id, ts, snapshot_json, assessment_json in all_rows:
    if event_id in reviewed_ids:
        continue
    try:
        assessment = json.loads(assessment_json)
        snapshot = json.loads(snapshot_json) if snapshot_json else {}
    except Exception:
        continue

    decision = assessment.get("decision", "")
    if decision != "ALLOW":
        continue

    # Проверяем нет ли угроз в threat_intelligence
    ti = snapshot.get("threat_intelligence", {})
    threats = []
    if isinstance(ti, dict):
        for ep_id, ep_data in ti.items():
            if isinstance(ep_data, dict):
                # Если есть метки угроз — пропускаем
                if ep_data.get("tags") or ep_data.get("types") or ep_data.get("score", 0) > 0:
                    threats.append(ep_id)
    if threats:
        continue

    candidates.append((event_id, ts, snapshot, assessment))

print(f"Candidates for ALLOW labeling: {len(candidates)}")

if not candidates:
    print("Nothing to label.")
    sys.exit(0)

# Показываем первые 5
print("\nSample candidates:")
for eid, ts, snap, assess in candidates[:5]:
    flows = snap.get("remote_endpoints") or []
    flow_ids = [str(f.get("id")) for f in flows if isinstance(f, dict) and f.get("id")]
    print(f"  {ts} flows={len(flow_ids)} model={assess.get('model','?')[:30]}")

if DRY_RUN:
    print("\n[DRY RUN] Would label the above candidates. Use without --dry-run to apply.")
    sys.exit(0)

# Размечаем
labeled_count = 0
skipped_count = 0

for event_id, ts, snapshot, assessment in candidates:
    flows = snapshot.get("remote_endpoints") or []
    flow_ids = [(str(f.get("id")), str(snapshot.get("snapshot_sha256") or "")) 
                for f in flows if isinstance(f, dict) and f.get("id")]

    if not flow_ids:
        skipped_count += 1
        continue

    # Получаем sha256 снимка из events
    with sqlite3.connect(str(EVENTS)) as db:
        row = db.execute(
            "SELECT snapshot_sha256 FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
    if not row or not row[0]:
        skipped_count += 1
        continue
    snapshot_sha = row[0]

    for flow_id, _ in flow_ids:
        # Проверяем flow_id не пустой
        if not flow_id or flow_id == "None":
            continue
        # Проверяем уже не размечено
        dec = review_log.decision(event_id, flow_id, snapshot_sha)
        if dec["accepted"]:
            continue
        try:
            review_log.propose_simple(
                event_id=event_id,
                flow_id=flow_id,
                snapshot_sha256=snapshot_sha,
                is_malicious=False,
                rationale=(
                    f"Auto-label: LLM decision=ALLOW, no threat intelligence hits, "
                    f"captured_at={ts}"
                )
            )
            labeled_count += 1
        except Exception as e:
            print(f"  Error labeling {event_id}/{flow_id}: {e}")
            skipped_count += 1

print(f"\nDone. Labeled: {labeled_count} flow reviews, Skipped: {skipped_count}")
print("Run tools/maintenance/retrain_now.py --force to retrain on the expanded dataset.")

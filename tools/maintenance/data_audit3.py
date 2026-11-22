"""Анализ непомеченных событий и рекомендации по разметке."""
import sys, sqlite3, json
from pathlib import Path
from collections import Counter
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

EVENTS = ROOT / "data" / "online" / "network_events.sqlite"
REVIEWS = ROOT / "data" / "online" / "network_label_reviews.sqlite"

# Все event_id с ревью
with sqlite3.connect(str(REVIEWS)) as db:
    reviewed_ids = {r[0] for r in db.execute("SELECT DISTINCT event_id FROM reviews").fetchall()}

# Все события
with sqlite3.connect(str(EVENTS)) as db:
    all_events = db.execute(
        "SELECT event_id, captured_at_utc, assessment_json FROM events ORDER BY captured_at_utc"
    ).fetchall()

not_reviewed = [(eid, ts, aj) for eid, ts, aj in all_events if eid not in reviewed_ids]
print(f"Total events: {len(all_events)}")
print(f"Reviewed events: {len(reviewed_ids)}")
print(f"NOT reviewed: {len(not_reviewed)}")

# Решения LLM по непомеченным
llm_decisions = Counter()
for eid, ts, aj in not_reviewed:
    if aj:
        try:
            d = json.loads(aj)
            llm_decisions[d.get("decision", "?")] += 1
        except Exception:
            pass

print(f"\nLLM decisions on unreviewed events: {dict(llm_decisions)}")

# Временной охват непомеченных
if not_reviewed:
    times = [r[1] for r in not_reviewed]
    print(f"Unreviewed time range: {min(times)} to {max(times)}")

# Найдём события ПОСЛЕ последней ревью (новые данные для разметки)
last_review_time = "2026-11-14T21:38:01+00:00"
new_events = [(eid, ts, aj) for eid, ts, aj in all_events
              if ts > last_review_time and eid not in reviewed_ids]
print(f"\nNew events after last review: {len(new_events)}")
if new_events:
    for eid, ts, aj in new_events[:5]:
        d = json.loads(aj) if aj else {}
        print(f"  {ts} decision={d.get('decision','?')} id={eid[:16]}...")

# Суммарная картина по временным окнам
print("\nEvents by hour (all reviewed):")
from datetime import datetime, timezone
hour_counts = Counter()
for eid in reviewed_ids:
    pass  # skip
# По всем событиям с ревью
with sqlite3.connect(str(EVENTS)) as db:
    reviewed_events = db.execute(
        "SELECT event_id, captured_at_utc FROM events WHERE event_id IN ({})".format(
            ",".join("?" * len(reviewed_ids))
        ), list(reviewed_ids)
    ).fetchall()
for eid, ts in reviewed_events:
    hour = ts[:13]  # YYYY-MM-DDTHH
    hour_counts[hour] += 1

for hour, count in sorted(hour_counts.items()):
    print(f"  {hour}: {count} events")

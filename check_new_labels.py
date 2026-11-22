import sqlite3
from datetime import datetime

rev_db = r"F:\New\integrityguard\data\online\network_label_reviews.sqlite"
evt_db = r"F:\New\integrityguard\data\online\network_events.sqlite"

# Смотрим последние метки
c = sqlite3.connect(rev_db)
rows = c.execute("""
    SELECT event_id, label, reviewer_id, created_at, rationale
    FROM reviews
    ORDER BY created_at DESC
    LIMIT 20
""").fetchall()
c.close()

print("=== Последние 20 меток ===")
for r in rows:
    print(f"  event={r[0][:16]}  label={r[1]}  reviewer={r[2]}  at={r[3]}  rationale={r[4][:30]}")

# Проверяем сколько событий с метками но без снапшота
c = sqlite3.connect(rev_db)
labeled_events = set(r[0] for r in c.execute("SELECT DISTINCT event_id FROM reviews").fetchall())
c.close()

c = sqlite3.connect(evt_db)
all_events = set(r[0] for r in c.execute("SELECT event_id FROM events").fetchall())
c.close()

matched = labeled_events & all_events
print(f"\n=== Статистика ===")
print(f"  Всего меток (уникальных event_id): {len(labeled_events)}")
print(f"  Всего событий в БД: {len(all_events)}")
print(f"  Меток с соответствующим снапшотом: {len(matched)}")

# Проверяем распределение меток
c = sqlite3.connect(rev_db)
dist = c.execute("SELECT label, COUNT(*) FROM reviews GROUP BY label").fetchall()
c.close()
print(f"  Распределение: {dict(dist)}")

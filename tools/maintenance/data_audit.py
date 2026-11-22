"""Аудит данных для обучения нейросети."""
import sqlite3
import json
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime

BASE = Path("F:/New/integrityguard/data/online")

# --- network_label_reviews.sqlite ---
print("=" * 60)
print("REVIEWS DB")
print("=" * 60)
conn_r = sqlite3.connect(str(BASE / "network_label_reviews.sqlite"))
cur = conn_r.cursor()
cur.execute("SELECT COUNT(*) FROM reviews")
total = cur.fetchone()[0]
print(f"Total reviews: {total}")

cur.execute("SELECT label, COUNT(*) FROM reviews GROUP BY label ORDER BY label")
by_label = cur.fetchall()
print(f"By label (raw): {by_label}")

cur.execute("SELECT reviewer, COUNT(*) FROM reviews GROUP BY reviewer")
print(f"By reviewer: {cur.fetchall()}")

cur.execute("SELECT MIN(recorded_at), MAX(recorded_at) FROM reviews")
mn, mx = cur.fetchone()
print(f"Date range: {mn} to {mx}")

# Проверим содержимое label (может быть строка ALLOW/BLOCK или 0/1)
cur.execute("SELECT label FROM reviews LIMIT 5")
print(f"Sample labels: {[r[0] for r in cur.fetchall()]}")

conn_r.close()

# --- network_events.sqlite ---
print()
print("=" * 60)
print("EVENTS DB")
print("=" * 60)
conn_e = sqlite3.connect(str(BASE / "network_events.sqlite"))
cur = conn_e.cursor()
cur.execute("SELECT COUNT(*) FROM events")
print(f"Total events: {cur.fetchone()[0]}")

cur.execute("SELECT MIN(captured_at_utc), MAX(captured_at_utc) FROM events")
print(f"Date range: {cur.fetchone()}")

# Считаем решения
cur.execute("SELECT assessment_json FROM events WHERE assessment_json IS NOT NULL")
decisions = Counter()
models = Counter()
for (aj,) in cur.fetchall():
    try:
        d = json.loads(aj)
        decisions[d.get("decision", "?")] += 1
        models[d.get("model", "?")] += 1
    except Exception:
        pass
print(f"Decisions: {dict(decisions)}")
print(f"Models: {dict(models)}")

# Проверим snapshot_json для признаков
cur.execute("SELECT snapshot_json FROM events WHERE snapshot_json IS NOT NULL LIMIT 1")
row = cur.fetchone()
if row:
    sj = json.loads(row[0])
    print(f"Snapshot keys: {list(sj.keys())}")

conn_e.close()

# --- network_autoblock.sqlite ---
print()
print("=" * 60)
print("AUTOBLOCK DB")
print("=" * 60)
ab_path = BASE / "network_autoblock.sqlite"
if ab_path.exists():
    conn_ab = sqlite3.connect(str(ab_path))
    cur = conn_ab.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print(f"Tables: {tables}")
    for t in tables:
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        print(f"  {t}: {cur.fetchone()[0]} rows")
    conn_ab.close()
else:
    print("File not found")

# --- label_reviews из retrain (что реально использовалось) ---
print()
print("=" * 60)
print("LABEL REGISTRY (data/label_registry.sqlite)")
print("=" * 60)
lr_path = Path("F:/New/integrityguard/data/label_registry.sqlite")
if lr_path.exists():
    conn_lr = sqlite3.connect(str(lr_path))
    cur = conn_lr.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print(f"Tables: {tables}")
    for t in tables:
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        print(f"  {t}: {cur.fetchone()[0]} rows")
    conn_lr.close()
else:
    print("Not found")

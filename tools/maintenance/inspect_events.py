"""Inspect real event distributions: columns and feature stats per class."""
import sys
sys.path.insert(0, 'F:/New/integrityguard')
import sqlite3, statistics, json
from collections import Counter

db_path = 'F:/New/integrityguard/data/online/network_events.sqlite'
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

# Schema
cols = [r[1] for r in con.execute("PRAGMA table_info(events)").fetchall()]
print("Columns:", cols)

# Sample rows
rows = con.execute("SELECT * FROM events LIMIT 3").fetchall()
for r in rows:
    print(dict(r))

# Class distribution
counts = con.execute("SELECT model_decision, COUNT(*) FROM events GROUP BY model_decision").fetchall()
print("\nClass counts:", {r[0]: r[1] for r in counts})

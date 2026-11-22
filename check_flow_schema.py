import sqlite3
from pathlib import Path

db = sqlite3.connect("data/online/network_runtime_metrics.sqlite")
c = db.cursor()

# flow_inference_samples schema
c.execute("PRAGMA table_info(flow_inference_samples)")
print("flow_inference_samples columns:")
for row in c.fetchall():
    print(" ", row)

print()
c.execute("SELECT * FROM flow_inference_samples LIMIT 3")
rows = c.fetchall()
c.execute("PRAGMA table_info(flow_inference_samples)")
cols = [r[1] for r in c.fetchall()]
for row in rows:
    print(dict(zip(cols, row)))

print()
# captured_flows schema
c.execute("PRAGMA table_info(captured_flows)")
print("captured_flows columns:")
for row in c.fetchall():
    print(" ", row)

print()
c.execute("SELECT * FROM captured_flows LIMIT 2")
rows = c.fetchall()
c.execute("PRAGMA table_info(captured_flows)")
cols = [r[1] for r in c.fetchall()]
for row in rows:
    print(dict(zip(cols, row)))

db.close()

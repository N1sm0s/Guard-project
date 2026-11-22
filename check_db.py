import sqlite3, pathlib
db = pathlib.Path("data/online/network_events.sqlite")
con = sqlite3.connect(str(db))
# Check table structure
cols = con.execute("PRAGMA table_info(events)").fetchall()
print("Columns:", [c[1] for c in cols])
# Sample last 3 events
sample = con.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT 3").fetchall()
for r in sample:
    print(r[:3])
con.close()

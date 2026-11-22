import sqlite3

db = sqlite3.connect(r"F:\New\integrityguard\data\security_audit.sqlite")
cols = [r[1] for r in db.execute("PRAGMA table_info(turns)").fetchall()]
print("columns:", cols)
rows = db.execute("SELECT * FROM turns ORDER BY seq DESC LIMIT 3").fetchall()
for r in rows:
    print(dict(zip(cols, r)))

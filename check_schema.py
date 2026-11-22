import sqlite3

c = sqlite3.connect(r"F:\New\integrityguard\data\online\network_label_reviews.sqlite")
cols = c.execute("PRAGMA table_info(reviews)").fetchall()
print("Columns:", [col[1] for col in cols])
rows = c.execute("SELECT * FROM reviews ORDER BY rowid DESC LIMIT 5").fetchall()
print("\nLast 5 rows:")
for r in rows:
    print(" ", r[:6])
c.close()

import sqlite3, json, collections

c = sqlite3.connect(r"F:\New\integrityguard\data\online\network_events.sqlite")
rows = c.execute("select assessment_json from events").fetchall()
dec = collections.Counter()
final_dec = collections.Counter()
for (raw,) in rows:
    try:
        obj = json.loads(raw)
    except Exception:
        continue
    dec[obj.get("model_decision", "?")] += 1
    final_dec[obj.get("decision", "?")] += 1
print("model_decision (raw teacher label):", dict(dec))
print("decision (after safety downgrades):", dict(final_dec))
print("total rows:", len(rows))

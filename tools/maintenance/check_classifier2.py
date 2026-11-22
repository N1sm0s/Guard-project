import sqlite3, json
from pathlib import Path

db_path = Path("F:/New/integrityguard/data/security_audit.sqlite")
with sqlite3.connect(str(db_path)) as db:
    cols = [r[1] for r in db.execute("PRAGMA table_info(turns)").fetchall()]
    print("turns columns:", cols)

    rows = db.execute("SELECT * FROM turns ORDER BY rowid DESC LIMIT 5").fetchall()
    for row in rows:
        d = dict(zip(cols, row))
        tc_json = d.get("tool_calls") or d.get("tool_calls_json") or ""
        if tc_json:
            try:
                tc = json.loads(tc_json)
                for entry in (tc if isinstance(tc, list) else []):
                    if "classifier" in str(entry.get("tool","")).lower():
                        print(f"\nFound classifier entry at rowid:")
                        print(json.dumps(entry, indent=2, ensure_ascii=False)[:600])
            except Exception:
                pass
        # Print short summary
        summary_key = next((k for k in d if "summary" in k.lower() or "note" in k.lower()), None)
        if summary_key:
            print(f"[{d.get('created_at','')}] {summary_key}: {str(d[summary_key])[:200]}")
        else:
            # print first few fields
            short = {k: str(v)[:80] for k, v in d.items() if v and k not in ('tool_calls','tool_calls_json')}
            print(f"row: {short}")

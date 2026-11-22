import sqlite3, json
from pathlib import Path

db_path = Path("F:/New/integrityguard/data/security_audit.sqlite")
with sqlite3.connect(str(db_path)) as db:
    rows = db.execute("SELECT seq, timestamp_utc, tools_json FROM turns ORDER BY rowid DESC LIMIT 20").fetchall()
    found = 0
    for seq, ts, tj in rows:
        if not tj:
            continue
        try:
            tools = json.loads(tj)
        except Exception:
            continue
        for t in (tools if isinstance(tools, list) else []):
            tool_name = t.get("tool") or t.get("name") or ""
            if "classifier" in tool_name.lower() or "classifier" in str(t).lower():
                print(f"[seq={seq} {ts}] tool={tool_name}")
                print(json.dumps(t, ensure_ascii=False, indent=2)[:800])
                found += 1
        # Also check if model_decision is BLOCK anywhere
        for t in (tools if isinstance(tools, list) else []):
            if t.get("model_decision") == "BLOCK":
                print(f"[seq={seq}] BLOCK decision in tools: {str(t)[:300]}")

    if found == 0:
        # Print the full tools_json of the latest entry to understand structure
        print("No classifier entries found. Latest tools_json sample:")
        row = db.execute("SELECT seq, tools_json FROM turns ORDER BY rowid DESC LIMIT 1").fetchone()
        if row:
            print(f"seq={row[0]}")
            try:
                tools = json.loads(row[1])
                print(json.dumps(tools, ensure_ascii=False, indent=2)[:1200])
            except Exception as e:
                print(f"parse error: {e}\nraw: {row[1][:400]}")

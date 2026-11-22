"""Check that the shadow classifier is writing entries into security audit database."""
import sqlite3, json, sys, os
from pathlib import Path

data_dir = Path(os.environ.get("APPDATA", "C:/Users")) / "IntegrityGuard"
if not data_dir.exists():
    # Try common locations
    for candidate in [
        Path("C:/Users") / os.environ.get("USERNAME", "User") / "AppData/Roaming/IntegrityGuard",
        Path("F:/New/integrityguard/data"),
    ]:
        if candidate.exists():
            data_dir = candidate
            break

print(f"Data dir: {data_dir}")

audit_db = data_dir / "security audit database"
classifier_pt = data_dir / "models" / "network_classifier.pt"

print(f"Audit DB exists: {audit_db.exists()}")
print(f"Classifier checkpoint exists: {classifier_pt.exists()}")

if classifier_pt.exists():
    import torch
    cp = torch.load(str(classifier_pt), weights_only=False)
    print(f"Checkpoint: n_samples={cp.get('n_samples')}, trained_at={cp.get('trained_at_utc')}")
    print(f"  class_counts={cp.get('class_counts')}")
    print(f"  caveat={cp.get('caveat','')[:100]}")

if audit_db.exists():
    with sqlite3.connect(str(audit_db)) as db:
        # Look for recent network_classifier_shadow entries
        try:
            rows = db.execute("""
                SELECT id, created_at, tool_calls_json
                FROM audit_log
                ORDER BY id DESC LIMIT 10
            """).fetchall()
        except Exception as e:
            print(f"audit_log query error: {e}")
            # Try alternate schema
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            print(f"Tables: {tables}")
            rows = []

        shadow_count = 0
        for row_id, created_at, tc_json in rows:
            if not tc_json:
                continue
            try:
                tc = json.loads(tc_json)
            except Exception:
                continue
            for entry in (tc if isinstance(tc, list) else []):
                if entry.get("tool") == "network_classifier_shadow":
                    shadow_count += 1
                    result = entry.get("result", {})
                    print(f"\n[{created_at}] shadow verdict: decision={result.get('decision')}, "
                          f"model_decision={result.get('model_decision')}, "
                          f"advisory_only={result.get('advisory_only')}")

        if shadow_count == 0:
            print("No network_classifier_shadow entries yet (GUI may not have completed a cycle).")
        else:
            print(f"\nTotal shadow entries in last 10 audit rows: {shadow_count}")
else:
    print("Audit DB not found — GUI may not have started yet or uses a different data path.")

"""Current state of neural net training data and checkpoint."""
import sqlite3, json, sys
from pathlib import Path
from collections import Counter

data_dir = Path("F:/New/integrityguard/data")

# 1. Checkpoint info
cp_path = data_dir / "models" / "network_classifier.pt"
if cp_path.exists():
    import torch
    cp = torch.load(str(cp_path), weights_only=False)
    print("=== CHECKPOINT ===")
    print(f"n_samples      : {cp.get('n_samples')}")
    print(f"class_counts   : {cp.get('class_counts')}")
    print(f"train_accuracy : {cp.get('train_accuracy_not_heldout', 'n/a'):.3f}" if isinstance(cp.get('train_accuracy_not_heldout'), float) else f"train_accuracy : {cp.get('train_accuracy_not_heldout','n/a')}")
    print(f"feature_version: {cp.get('feature_version')}")
    print(f"trained_at     : {cp.get('trained_at_utc')}")
    print(f"caveat         : {cp.get('caveat','')[:120]}")
else:
    print("No checkpoint found.")

# 2. Raw events DB
events_db = data_dir / "network_events.sqlite"
if events_db.exists():
    print("\n=== EVENTS DB ===")
    with sqlite3.connect(str(events_db)) as db:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"Tables: {tables}")
        for t in tables:
            cnt = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  {t}: {cnt} rows")
            # Try to get label distribution
            try:
                rows = db.execute(f"SELECT assessment_json FROM {t} WHERE assessment_json IS NOT NULL").fetchall()
                decisions = Counter()
                for (aj,) in rows:
                    try:
                        a = json.loads(aj)
                        decisions[a.get("model_decision","?")] += 1
                    except Exception:
                        pass
                print(f"    model_decision dist: {dict(decisions)}")
            except Exception:
                pass
else:
    print("\nNo events DB found.")

# 3. Audit turns — what has the AI been seeing?
audit_db = data_dir / "security_audit.sqlite"
if audit_db.exists():
    print("\n=== AUDIT TURNS (last 200) ===")
    with sqlite3.connect(str(audit_db)) as db:
        rows = db.execute("SELECT tools_json FROM turns ORDER BY rowid DESC LIMIT 200").fetchall()
        all_model_decisions = Counter()
        shadow_decisions = Counter()
        for (tj,) in rows:
            if not tj: continue
            try:
                tools = json.loads(tj)
            except Exception:
                continue
            for t in (tools if isinstance(tools, list) else []):
                name = t.get("name","")
                md = t.get("model_decision","")
                st = t.get("status","")
                if name == "historical_network_model_assessment":
                    all_model_decisions[md] += 1
                elif name == "network_classifier_shadow":
                    shadow_decisions[f"model={md}/status={st}"] += 1
        print(f"Historical model decisions (last 200 turns): {dict(all_model_decisions)}")
        print(f"Shadow classifier (last 200 turns): {dict(shadow_decisions)}")

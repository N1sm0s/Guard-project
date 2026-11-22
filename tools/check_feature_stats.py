"""Compare feature statistics between train attacks and test capture 53 attacks."""
import csv
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"

def load_capture_stats(path, max_attack=5000, max_benign=5000):
    attack_feats = []
    benign_feats = []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            is_attack = "From-Botnet-" in lbl
            is_benign = "From-Normal-" in lbl
            if not is_attack and not is_benign:
                continue
            try:
                feat = from_ctu_row(row)
            except ValueError:
                continue
            if is_attack and len(attack_feats) < max_attack:
                attack_feats.append(feat)
            elif is_benign and len(benign_feats) < max_benign:
                benign_feats.append(feat)
            if len(attack_feats) >= max_attack and len(benign_feats) >= max_benign:
                break
    return np.array(attack_feats, dtype=np.float32) if attack_feats else None, \
           np.array(benign_feats, dtype=np.float32) if benign_feats else None

print("=== Feature stats for TRAIN attack flows (sample from 51: Sogou) ===")
x_train51_a, _ = load_capture_stats(DATA / "official-ctu13" / "capture20110818_ctu51.binetflow")
if x_train51_a is not None:
    for i, name in enumerate(FEATURE_NAMES[:8]):
        vals = x_train51_a[:, i]
        print(f"  {name}: mean={vals.mean():.4f} std={vals.std():.4f} min={vals.min():.4f} max={vals.max():.4f}")

print("\n=== Feature stats for TEST capture 53 attack flows (Rbot) ===")
x_53_a, _ = load_capture_stats(DATA / "official-ctu13" / "capture20110819_ctu53.binetflow")
if x_53_a is not None:
    for i, name in enumerate(FEATURE_NAMES[:8]):
        vals = x_53_a[:, i]
        print(f"  {name}: mean={vals.mean():.4f} std={vals.std():.4f} min={vals.min():.4f} max={vals.max():.4f}")

print("\n=== Feature stats for VAL capture 49 attack flows (Neris) ===")
x_49_a, _ = load_capture_stats(DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow")
if x_49_a is not None:
    for i, name in enumerate(FEATURE_NAMES[:8]):
        vals = x_49_a[:, i]
        print(f"  {name}: mean={vals.mean():.4f} std={vals.std():.4f} min={vals.min():.4f} max={vals.max():.4f}")

print(f"\nFeature names: {list(FEATURE_NAMES)}")

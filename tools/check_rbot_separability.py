"""Check if Rbot (capture 53) attack flows are separable from benign using all features."""
import csv
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"

def load_capture(path, max_attack=5000, max_benign=5000):
    attack_feats, benign_feats = [], []
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
    return (np.array(attack_feats, dtype=np.float32) if attack_feats else None,
            np.array(benign_feats, dtype=np.float32) if benign_feats else None)

print("Loading capture 53 (Rbot)...")
x53_a, x53_b = load_capture(DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", 2168, 5000)
print(f"  Attack: {len(x53_a)}, Benign: {len(x53_b)}")

print("\n=== Rbot attack vs benign -- ALL FEATURES ===")
print(f"{'Feature':<35} {'attack_mean':>12} {'benign_mean':>12} {'diff':>10} {'separable?':>12}")
print("-" * 85)
for i, name in enumerate(FEATURE_NAMES):
    a_mean = x53_a[:, i].mean()
    b_mean = x53_b[:, i].mean()
    diff = abs(a_mean - b_mean)
    a_std = x53_a[:, i].std()
    b_std = x53_b[:, i].std()
    # Cohen's d
    pooled = np.sqrt((a_std**2 + b_std**2) / 2) + 1e-9
    cohen_d = abs(a_mean - b_mean) / pooled
    sep = "GOOD" if cohen_d > 0.5 else ("SOME" if cohen_d > 0.2 else "WEAK")
    print(f"  {name:<33} {a_mean:12.4f} {b_mean:12.4f} {diff:10.4f} {sep:>12} (d={cohen_d:.2f})")

# Check a simple rule: does the model have ANYTHING to work with?
print("\n=== Top separating features (by Cohen's d) ===")
ds = []
for i, name in enumerate(FEATURE_NAMES):
    a_mean, a_std = x53_a[:, i].mean(), x53_a[:, i].std()
    b_mean, b_std = x53_b[:, i].mean(), x53_b[:, i].std()
    pooled = np.sqrt((a_std**2 + b_std**2) / 2) + 1e-9
    ds.append((abs(a_mean - b_mean) / pooled, name, a_mean, b_mean))
ds.sort(reverse=True)
for d, name, am, bm in ds[:10]:
    print(f"  d={d:.3f}  {name}: attack={am:.4f} vs benign={bm:.4f}")

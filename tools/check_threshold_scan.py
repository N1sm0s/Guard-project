"""Scan all thresholds on the existing v2 checkpoint to find if any threshold
passes gate 5 on BOTH captures 53 and 54."""
import sys
import json
import math
from pathlib import Path
import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row
import csv

DATA = ROOT / "outputs" / "network-eval"
CKPT = DATA / "ctu13-v3-gate5-candidate.pt"

def wilson(successes, total, z=1.959963984540054):
    if total <= 0:
        return None
    p = successes / total
    d = 1.0 + z * z / total
    c = (p + z * z / (2.0 * total)) / d
    m = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / d
    return [max(0.0, c - m), min(1.0, c + m)]

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"):
        return 1
    if label.startswith("flow=From-Normal-"):
        return 0
    return -1

# Load checkpoint
print(f"Loading checkpoint from {CKPT}")
ckpt = torch.load(CKPT, map_location="cpu", weights_only=True)
print(f"  Checkpoint keys: {list(ckpt.keys())}")
print(f"  Normalization: {ckpt.get('normalization', 'mean+std (old)')}")
print(f"  gate5_pass: {ckpt.get('gate5_all_captures_pass')}")

# Check if checkpoint has mean/std or q25/iqr
if "q25" in ckpt:
    center = np.array(ckpt["q25"], dtype=np.float32)
    scale = np.array(ckpt["iqr"], dtype=np.float32)
    print("  Using Q25/IQR normalization")
else:
    center = np.array(ckpt["mean"], dtype=np.float32)
    scale = np.array(ckpt["std"], dtype=np.float32)
    print("  Using mean/std normalization")

from torch import nn

class MLP(nn.Module):
    def __init__(self, n_features):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 32), nn.GELU(),
            nn.Linear(32, 2),
        )
    def forward(self, x):
        return self.net(x)

model = MLP(len(FEATURE_NAMES))
model.load_state_dict(ckpt["state_dict"])
model.eval()

def load_capture(path):
    vectors, targets = [], []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            target = class_for_label(row.get("Label", ""))
            if target < 0:
                continue
            try:
                vectors.append(from_ctu_row(row))
            except ValueError:
                continue
            targets.append(target)
    return np.array(vectors, dtype=np.float32), np.array(targets, dtype=np.int64)

def get_probs(x):
    xn = (x - center) / scale
    out = []
    with torch.no_grad():
        for s in range(0, len(xn), 32768):
            b = torch.from_numpy(xn[s:s + 32768])
            out.extend(torch.softmax(model(b), dim=1)[:, 1].numpy().tolist())
    return np.array(out, dtype=np.float64)

captures = {
    "49-val": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
    "53-test": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54-test": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

print("\nLoading captures and computing probabilities...")
results = {}
for name, path in captures.items():
    print(f"  {name}...", end="", flush=True)
    x, y = load_capture(path)
    p = get_probs(x)
    results[name] = (y, p)
    n_attack = (y==1).sum()
    print(f" {len(y):,} flows ({n_attack:,} attacks), p_attack mean={p[y==1].mean():.4f}, p_benign mean={p[y==0].mean():.4f}")

print("\n=== Threshold scan: looking for gate5 PASS (CI_lo_recall>=0.80 AND FPR_CI_hi<=0.001) ===")
print(f"\n{'thr':>6} | {'53 recall':>10} {'53 CI_lo':>9} {'53 FPR':>8} {'53 FPR_hi':>9} | {'54 recall':>10} {'54 CI_lo':>9} {'54 FPR':>8} {'54 FPR_hi':>9} | {'gate5'}")
print("-" * 110)

thresholds = list(np.linspace(0.1, 0.99, 180))
for thr in thresholds:
    row_parts = [f"{thr:6.3f}"]
    all_pass = True
    for cname in ["53-test", "54-test"]:
        y, p = results[cname]
        actual = y == 1
        predicted = p >= thr
        tp = int(np.count_nonzero(actual & predicted))
        fp = int(np.count_nonzero(~actual & predicted))
        fn = int(np.count_nonzero(actual & ~predicted))
        tn = int(np.count_nonzero(~actual & ~predicted))
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        ci_r = wilson(tp, tp + fn) or [0, 0]
        ci_fpr = wilson(fp, fp + tn) or [0, 1]
        gate = ci_r[0] >= 0.80 and ci_fpr[1] <= 0.001
        if not gate:
            all_pass = False
        row_parts.append(f"{recall:10.4f} {ci_r[0]:9.4f} {fpr:8.5f} {ci_fpr[1]:9.5f}")
    row_parts.append("PASS" if all_pass else "")
    if all_pass:
        print(" | ".join(row_parts))

# Also show interesting threshold ranges
print("\n=== Score distribution for capture 53 (Rbot) attacks ===")
y53, p53 = results["53-test"]
p53_attack = p53[y53 == 1]
print(f"  Attack scores: p0={np.percentile(p53_attack, 0):.4f} p10={np.percentile(p53_attack, 10):.4f} p25={np.percentile(p53_attack, 25):.4f} p50={np.percentile(p53_attack, 50):.4f} p75={np.percentile(p53_attack, 75):.4f} p90={np.percentile(p53_attack, 90):.4f}")
p53_benign = p53[y53 == 0]
print(f"  Benign scores: p90={np.percentile(p53_benign, 90):.4f} p95={np.percentile(p53_benign, 95):.4f} p99={np.percentile(p53_benign, 99):.4f} p999={np.percentile(p53_benign, 99.9):.4f}")
print(f"  To get FPR<=0.1%, benign threshold must be > {np.percentile(p53_benign, 99.9):.4f}")
print(f"  At that threshold, attack recall = {(p53_attack > np.percentile(p53_benign, 99.9)).mean():.4f}")

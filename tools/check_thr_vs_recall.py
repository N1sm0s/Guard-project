"""
Check: at what threshold do we get 80% recall on CTU-53 and CTU-54?
Load the best checkpoint and analyze the full score distribution.
"""
import sys
from pathlib import Path
import numpy as np
import torch
import csv

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
CKPT = DATA / "ctu13-v10-gate5-candidate.pt"

def load_cap(path):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("Label","").startswith("flow=From-Botnet-"): y=1
            elif row.get("Label","").startswith("flow=From-Normal-"): y=0
            else: continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(y)
    return np.array(xs, np.float32), np.array(ys, np.int64)

# Load normalization stats
train_caps_info = [
    ("capture20110812_ctu44","capture20110815-2_ctu46",
     "capture20110816_ctu47","capture20110816-2_ctu48",
     "capture20110818_ctu51","capture20110818-2_ctu52",
     "capture20110819_ctu53","capture20110815-3_ctu54"),
]
all_x = []
for fname in train_caps_info[0]:
    p = DATA / "official-ctu13" / f"{fname}.binetflow"
    if p.exists():
        x, y = load_cap(p)
        all_x.append(x)
for n in ["42","43"]:
    p = DATA / f"ctu-{n}.binetflow"
    if p.exists():
        x, y = load_cap(p)
        all_x.append(x)

all_x = np.vstack(all_x)
q25 = np.percentile(all_x, 25, axis=0)
q75 = np.percentile(all_x, 75, axis=0)
iqr = np.maximum(q75 - q25, 0.1)
iqr[15] = max(iqr[15], 0.5)

def norm(x): return np.clip((x - q25) / iqr, -10.0, 10.0)

# Load model from checkpoint
if not CKPT.exists():
    print(f"Checkpoint not found: {CKPT}")
    sys.exit(1)

ckpt = torch.load(str(CKPT), map_location='cpu')
print(f"Checkpoint epoch: {ckpt.get('epoch', '?')}")
best_val = ckpt.get('best_val', '?')
print(f"Best val: {best_val}")

# Load model
n_feat = len(FEATURE_NAMES)
class MLP(torch.nn.Module):
    def __init__(self, n):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(n, 512), torch.nn.BatchNorm1d(512), torch.nn.GELU(), torch.nn.Dropout(0.3),
            torch.nn.Linear(512, 256), torch.nn.BatchNorm1d(256), torch.nn.GELU(), torch.nn.Dropout(0.25),
            torch.nn.Linear(256, 128), torch.nn.BatchNorm1d(128), torch.nn.GELU(), torch.nn.Dropout(0.2),
            torch.nn.Linear(128, 64), torch.nn.BatchNorm1d(64), torch.nn.GELU(), torch.nn.Dropout(0.1),
            torch.nn.Linear(64, 2))
    def forward(self, x): return self.net(x)

model = MLP(n_feat)
model.load_state_dict(ckpt['state_dict'])
model.eval()

def get_scores(xn):
    with torch.no_grad():
        logits = model(torch.tensor(xn, dtype=torch.float32))
        return torch.softmax(logits, dim=1)[:,1].numpy()

IDX_UDP=5; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14
IDX_UDP_DUR=15; IDX_NO_RESP=16; IDX_DIR_ASYM=10; IDX_PKTS=1; IDX_BYTES=2

def apply_rule_override(raw_scores, xn):
    scores = raw_scores.copy()
    is_sustained = xn[:,IDX_SUSTAINED] > 0.5
    is_very_eph = xn[:,IDX_VERY_EPH] > 0.5
    is_no_resp = xn[:,IDX_NO_RESP] > 0.5
    has_pkts_gt4 = xn[:,IDX_PKTS] > 0.603
    has_dir_asym_r = xn[:,IDX_DIR_ASYM] > -0.40
    is_small_bytes = xn[:,IDX_BYTES] < -0.5
    r1c = is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r
    r2 = is_very_eph & is_no_resp & is_small_bytes
    scores[r1c | r2] = 1.0
    return scores

def wilson_hi(n, k, z=1.96):
    if n == 0: return 1.0
    p = k/n
    return (p + z*z/(2*n) + z*np.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1 + z*z/n)

for cap_name, cap_file in [
    ("CTU-53", DATA/"official-ctu13"/"capture20110819_ctu53.binetflow"),
    ("CTU-54", DATA/"official-ctu13"/"capture20110815-3_ctu54.binetflow"),
]:
    x, y = load_cap(cap_file)
    xn = norm(x)
    is_udp = xn[:,IDX_UDP] > 0.5
    scores_raw = get_scores(xn)
    scores = apply_rule_override(scores_raw, xn)
    
    n_ben_udp = (is_udp & (y==0)).sum()
    n_atk = (y==1).sum()
    
    print(f"\n=== {cap_name}: {n_atk} attacks, {n_ben_udp} UDP benign ===")
    print(f"  {'thr':>6} {'recall':>8} {'FP_UDP':>8} {'CI_hi':>8} {'pass?':>6}")
    
    for thr in [0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.88, 0.90, 0.92, 0.95]:
        pred_atk = scores >= thr
        recall = (pred_atk & (y==1)).sum() / n_atk
        fp_udp = (pred_atk & is_udp & (y==0)).sum()
        ci_hi = wilson_hi(n_ben_udp, fp_udp) * 100
        ok = "PASS" if (recall >= 0.80 and ci_hi <= 0.1) else "FAIL"
        print(f"  {thr:>6.2f} {recall:>8.4f} {fp_udp:>8} {ci_hi:>7.3f}% {ok:>6}")
    
    # Find the threshold where we get max recall with 0 FP
    ben_udp_scores = scores[is_udp & (y==0)]
    max_ben_score = ben_udp_scores.max()
    min_ben_score = ben_udp_scores.min()
    # Threshold just above max benign score = 0 FP
    thr_zero_fp = max_ben_score + 1e-6
    recall_zero_fp = (scores[y==1] >= thr_zero_fp).mean()
    print(f"\n  Max UDP benign score: {max_ben_score:.4f}")
    print(f"  At thr={thr_zero_fp:.4f} (0 FP): recall={recall_zero_fp:.4f}")
    
    # Score distribution of UDP attacks
    atk_scores = scores[y==1]
    print(f"\n  Attack score distribution:")
    for pct in [50, 60, 70, 75, 80, 85, 90, 95]:
        p = np.percentile(atk_scores, pct)
        print(f"    p{pct:02d} = {p:.4f}")
    
    print(f"  % attacks scoring >= 0.80: {(atk_scores >= 0.80).mean()*100:.1f}%")
    print(f"  % attacks scoring >= 0.85: {(atk_scores >= 0.85).mean()*100:.1f}%")
    print(f"  % attacks scoring >= 0.90: {(atk_scores >= 0.90).mean()*100:.1f}%")
    print(f"  % attacks scoring >= 0.92: {(atk_scores >= 0.92).mean()*100:.1f}%")
    
    # UDP benign score distribution
    print(f"\n  UDP benign score p99.9={np.percentile(ben_udp_scores, 99.9):.4f} p999={np.percentile(ben_udp_scores, 99.9):.4f}")
    print(f"  UDP benign scores > 0.80: {(ben_udp_scores > 0.80).sum()}")
    print(f"  UDP benign scores > 0.85: {(ben_udp_scores > 0.85).sum()}")
    print(f"  UDP benign scores > 0.90: {(ben_udp_scores > 0.90).sum()}")
    print(f"  UDP benign scores > 0.92: {(ben_udp_scores > 0.92).sum()}")

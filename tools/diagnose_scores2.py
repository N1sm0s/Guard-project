"""
Diagnose score distributions - standalone version that reuses train_v7 internals directly.
"""
import csv, math, sys, os
sys.path.insert(0, r"F:\New\integrityguard")

import numpy as np
import torch
import torch.nn as nn

from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

# ---- mirror the core from train_v7 ----
IDX_UDP    = 5
IDX_PKTS   = 1
IDX_BYTES  = 2
IDX_DIR_ASYM = 10
IDX_VERY_EPH = 11
IDX_SUSTAINED = 13
IDX_UDP_MED = 14
IDX_UDP_DUR = 15
IDX_NO_RESP = 16

CKPT = r"F:\New\integrityguard\outputs\network-eval\ctu13-v10-gate5-candidate.pt"
DATA_53 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110819_ctu53.binetflow"
DATA_54 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110815-3_ctu54.binetflow"

class MLP(nn.Module):
    def __init__(self, n):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(512, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 2))
    def forward(self, x): return self.net(x)

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    return 0

def load_cap(path, bg_sample_rate=1.0):
    xs, ys, lbls = [], [], []
    rng = np.random.default_rng(42)
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            target = class_for_label(lbl)
            is_background = not (lbl.startswith("flow=From-Botnet-") or lbl.startswith("flow=From-Normal-"))
            if is_background and rng.random() > bg_sample_rate:
                continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(target)
            lbls.append(lbl)
    return np.array(xs, np.float32), np.array(ys, np.int64), lbls

def wilson_hi(k, n, z=1.96):
    if n == 0: return 0.0
    p = k/n
    return (p + z*z/(2*n) + z*np.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1 + z*z/n)

def get_scores(model, xn, q25, iqr):
    xn_norm = np.clip((xn - q25) / iqr, -10.0, 10.0)
    model.eval()
    with torch.no_grad():
        t = torch.FloatTensor(xn_norm)
        probs = []
        for s in range(0, len(t), 32768):
            b = t[s:s+32768]
            probs.extend(torch.softmax(model(b), dim=1)[:,1].numpy().tolist())
    return np.array(probs)

def apply_rule_override(raw_scores, x_raw):
    scores = raw_scores.copy()
    is_sustained = x_raw[:, IDX_SUSTAINED] > 0.5
    is_very_eph = x_raw[:, IDX_VERY_EPH] > 0.5
    has_pkts_gt4 = x_raw[:, IDX_PKTS] > 0.603
    is_no_resp = x_raw[:, IDX_NO_RESP] > 0.5
    has_dir_asym_r = x_raw[:, IDX_DIR_ASYM] > -0.40
    scores[is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r] = 1.0
    is_small_bytes = x_raw[:, IDX_BYTES] < -0.5
    scores[is_very_eph & is_no_resp & is_small_bytes] = 1.0
    return scores

if not os.path.exists(CKPT):
    print(f"ERROR: No checkpoint at {CKPT}")
    sys.exit(1)

ckpt = torch.load(CKPT, map_location='cpu')
print(f"Checkpoint epoch={ckpt.get('epoch','?')}, val_recall={ckpt.get('val_recall','?'):.4f}")
q25 = ckpt['q25']
iqr = ckpt['iqr']
print(f"Loaded scaler: q25 shape={q25.shape}, iqr shape={iqr.shape}")

model = MLP(len(FEATURE_NAMES))
model.load_state_dict(ckpt['model_state_dict'])
model.eval()

for cap_name, cap_path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*60}")
    print(f"=== {cap_name} ===")
    if not os.path.exists(cap_path):
        print(f"  ERROR: {cap_path} not found!")
        continue
    
    x, y, lbls = load_cap(cap_path, bg_sample_rate=1.0)
    is_udp = x[:, IDX_UDP] > 0.5
    is_atk = y == 1
    is_ben = y == 0
    
    print(f"  Total flows: {len(y)}")
    print(f"  UDP flows: {is_udp.sum()} (atk={is_atk[is_udp].sum()}, ben={is_ben[is_udp].sum()})")
    
    raw = get_scores(model, x, q25, iqr)
    scores = apply_rule_override(raw, x)
    
    udp_ben_mask = is_ben & is_udp
    udp_atk_mask = is_atk & is_udp
    
    s_udp_ben = scores[udp_ben_mask]
    s_udp_atk = scores[udp_atk_mask]
    
    print(f"\n  Attack UDP scores (n={len(s_udp_atk)}):")
    print(f"    mean={s_udp_atk.mean():.4f}, median={np.median(s_udp_atk):.4f}")
    print(f"    pct>=0.5: {(s_udp_atk>=0.5).mean():.2%}")
    
    print(f"\n  Benign UDP scores (n={len(s_udp_ben)}):")
    print(f"    mean={s_udp_ben.mean():.4f}, median={np.median(s_udp_ben):.4f}")
    print(f"    max={s_udp_ben.max():.4f}")
    print(f"    pct>=0.1: {(s_udp_ben>=0.1).mean():.4%}")
    print(f"    pct>=0.5: {(s_udp_ben>=0.5).mean():.4%}")
    print(f"    pct>=0.9: {(s_udp_ben>=0.9).mean():.4%}")
    print(f"    pct>=0.99: {(s_udp_ben>=0.99).mean():.4%}")
    
    n_ben = len(s_udp_ben)
    print(f"\n  Threshold FPR analysis:")
    print(f"  {'thr':>8} {'TP_rate':>8} {'FP':>7} {'WilsonHi%':>12} {'pass?':>6}")
    for thr in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999]:
        tp = int((s_udp_atk >= thr).sum())
        fp = int((s_udp_ben >= thr).sum())
        tp_rate = tp / len(s_udp_atk) if len(s_udp_atk) > 0 else 0
        whi = wilson_hi(fp, n_ben) * 100  # as percent
        ok = "YES" if whi <= 0.1 else "no"
        print(f"  {thr:>8.3f} {tp_rate:>8.4f} {fp:>7d} {whi:>12.4f}% {ok:>6}")
    
    # Feature breakdown of high-scoring benign UDP
    high_ben = udp_ben_mask & (scores >= 0.5)
    n_high = high_ben.sum()
    if n_high > 0:
        hb = x[high_ben]
        hs = scores[high_ben]
        print(f"\n  High-scoring benign UDP (score>=0.5): n={n_high}")
        print(f"    very_eph: {(hb[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    sustained: {(hb[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"    no_resp: {(hb[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"    udp_medium: {(hb[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"    score: mean={hs.mean():.4f}, max={hs.max():.4f}")
        # Label breakdown
        high_lbls = [lbls[i] for i in range(len(y)) if high_ben[i]]
        from collections import Counter
        lbl_counts = Counter(lbl.split('-')[1] if '-' in lbl else lbl for lbl in high_lbls)
        print(f"    Label types: {dict(lbl_counts.most_common(5))}")

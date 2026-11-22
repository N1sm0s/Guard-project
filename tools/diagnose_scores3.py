"""
Diagnose score distributions - uses existing checkpoint.
"""
import csv, math, sys, os
sys.path.insert(0, r"F:\New\integrityguard")

import numpy as np
import torch
import torch.nn as nn

from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_UDP = 5; IDX_PKTS = 1; IDX_BYTES = 2; IDX_DIR_ASYM = 10
IDX_VERY_EPH = 11; IDX_SUSTAINED = 13; IDX_UDP_MED = 14; IDX_NO_RESP = 16

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

def load_cap(path):
    xs, ys, lbls = [], [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(class_for_label(lbl))
            lbls.append(lbl)
    return np.array(xs, np.float32), np.array(ys, np.int64), lbls

def wilson_hi(k, n, z=1.96):
    if n == 0: return 0.0
    p = k / n
    return (p + z*z/(2*n) + z*np.sqrt(max(0, p*(1-p)/n) + z*z/(4*n*n))) / (1 + z*z/n)

def get_scores(model, x_raw, q25, iqr):
    xn = np.clip((x_raw - q25) / iqr, -10.0, 10.0).astype(np.float32)
    model.eval()
    with torch.no_grad():
        t = torch.FloatTensor(xn)
        probs = []
        for s in range(0, len(t), 32768):
            probs.extend(torch.softmax(model(t[s:s+32768]), dim=1)[:,1].numpy().tolist())
    return np.array(probs)

def apply_rule_override(scores, x):
    s = scores.copy()
    is_sust = x[:,IDX_SUSTAINED]>0.5; is_veph = x[:,IDX_VERY_EPH]>0.5
    pkts_gt4 = x[:,IDX_PKTS]>0.603; is_no_resp = x[:,IDX_NO_RESP]>0.5
    dir_asym = x[:,IDX_DIR_ASYM]>-0.40; small_bytes = x[:,IDX_BYTES]<-0.5
    s[is_sust & (pkts_gt4 | is_no_resp) & dir_asym] = 1.0
    s[is_veph & is_no_resp & small_bytes] = 1.0
    return s

ckpt = torch.load(CKPT, map_location='cpu')
q25 = np.array(ckpt['q25'], dtype=np.float32)
iqr = np.array(ckpt['iqr'], dtype=np.float32)
model = MLP(len(FEATURE_NAMES))
model.load_state_dict(ckpt['state_dict'])
model.eval()
print(f"Checkpoint loaded. Gate5 pass: {ckpt.get('gate5_all_captures_pass','?')}")
print(f"Stored thresholds: UDP={ckpt.get('thr_udp','?')}, TCP={ckpt.get('thr_tcp','?')}")

for name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*55}")
    print(f"=== {name} ===")
    if not os.path.exists(path):
        print(f"  NOT FOUND: {path}"); continue
    x, y, lbls = load_cap(path)
    is_udp = x[:,IDX_UDP]>0.5
    is_ben = y==0; is_atk = y==1
    
    raw = get_scores(model, x, q25, iqr)
    scores = apply_rule_override(raw, x)
    
    s_ben = scores[is_ben & is_udp]; s_atk = scores[is_atk & is_udp]
    n_ben = len(s_ben)
    
    print(f"  UDP flows: atk={len(s_atk)}, ben={n_ben}")
    print(f"  Atk UDP: mean={s_atk.mean():.4f} pct>=0.5={( s_atk>=0.5).mean():.2%}")
    print(f"  Ben UDP: mean={s_ben.mean():.4f} max={s_ben.max():.4f}")
    print(f"    pct>=0.1: {(s_ben>=0.1).sum():7d} ({(s_ben>=0.1).mean():.4%})")
    print(f"    pct>=0.5: {(s_ben>=0.5).sum():7d} ({(s_ben>=0.5).mean():.4%})")
    print(f"    pct>=0.9: {(s_ben>=0.9).sum():7d} ({(s_ben>=0.9).mean():.4%})")
    print(f"    pct>=0.99:{(s_ben>=0.99).sum():7d} ({(s_ben>=0.99).mean():.4%})")
    
    print(f"\n  Threshold FPR analysis:")
    print(f"  {'thr':>8} {'TP_rate':>8} {'FP_UDP':>8} {'WilsonHi%':>12} {'OK?':>5}")
    for thr in [0.3,0.5,0.7,0.8,0.9,0.95,0.98,0.99,0.999]:
        tp = int((s_atk>=thr).sum()); fp = int((s_ben>=thr).sum())
        tp_r = tp/max(1,len(s_atk))
        whi = wilson_hi(fp, n_ben)*100
        ok = "YES" if whi<=0.1 else "no"
        print(f"  {thr:>8.3f} {tp_r:>8.4f} {fp:>8d} {whi:>12.4f}% {ok:>5}")
    
    # Feature analysis of high-scoring benign
    high_mask = (is_ben & is_udp) & (scores>=0.5)
    n_hi = int(high_mask.sum())
    if n_hi > 0:
        hb = x[high_mask]; hs = scores[high_mask]
        print(f"\n  High-scoring benign UDP (>=0.5): n={n_hi}")
        print(f"    very_eph: {(hb[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    sustained: {(hb[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"    no_resp: {(hb[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"    udp_medium: {(hb[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"    score stats: mean={hs.mean():.4f}, max={hs.max():.4f}")
        from collections import Counter
        lbl_types = [l.split('=')[1].split('-')[0] if '=' in l else l for l in [lbls[i] for i in range(len(y)) if high_mask[i]]]
        print(f"    Label prefix: {Counter(lbl_types).most_common(5)}")

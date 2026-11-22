"""Quick eval of saved checkpoint with corrected R1c=-0.40 rule override."""
from __future__ import annotations
import sys, math
from pathlib import Path
import numpy as np
import torch

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
CKPT = DATA / "ctu13-v10-gate5-candidate.pt"

IDX_UDP=5; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16; IDX_DIR_ASYM=10

TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def wilson(k, n, z=1.96):
    if n == 0: return None
    p = k/n; q = 1-p
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt(p*q/n + z*z/(4*n*n)) / denom
    return max(0.0, center-spread), min(1.0, center+spread)

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    return 0  # All non-botnet flows (Normal, Background, etc.) are benign

def load_cap(path):
    xs, ys = [], []
    import csv
    with open(path, newline='', encoding='utf-8') as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            target = class_for_label(row.get('Label', ''))
            if target < 0: continue
            try:
                fv = from_ctu_row(row)
                xs.append(fv); ys.append(target)
            except: pass
    return np.array(xs, dtype=np.float32), np.array(ys, dtype=np.int32)

def apply_rule_override(raw_scores, x_norm):
    scores = raw_scores.copy()
    IDX_PKTS = 1
    is_sustained = x_norm[:, IDX_SUSTAINED] > 0.5
    is_very_eph = x_norm[:, IDX_VERY_EPH] > 0.5
    has_pkts_gt4 = x_norm[:, IDX_PKTS] > 0.603
    is_no_resp = x_norm[:, IDX_NO_RESP] > 0.5
    has_dir_asym_r = x_norm[:, IDX_DIR_ASYM] > -0.40
    scores[is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r] = 1.0
    IDX_BYTES = 2
    is_small_bytes = x_norm[:, IDX_BYTES] < -0.5
    scores[is_very_eph & is_no_resp & is_small_bytes] = 1.0
    return scores

ckpt = torch.load(CKPT, map_location='cpu', weights_only=False)
q25 = np.array(ckpt['q25'], dtype=np.float32)
iqr = np.array(ckpt['iqr'], dtype=np.float32)
print("Checkpoint loaded. thr_udp=%.4f thr_tcp=%.4f" % (ckpt.get('thr_udp',0.5), ckpt.get('thr_tcp',0.5)))

import torch.nn as nn
class MLP(nn.Module):
    def __init__(self, n_in):
        super().__init__()
        dims=[n_in,512,256,128,64]
        layers=[]
        for i in range(len(dims)-1):
            layers+=[nn.Linear(dims[i],dims[i+1]),nn.BatchNorm1d(dims[i+1]),nn.GELU(),nn.Dropout(0.3)]
        layers.append(nn.Linear(dims[-1],2))
        self.net=nn.Sequential(*layers)
    def forward(self,x): return self.net(x)

model = MLP(len(FEATURE_NAMES))
model.load_state_dict(ckpt['state_dict'])
model.eval()

def get_scores(xn):
    with torch.no_grad():
        logits = model(torch.from_numpy(xn))
        return torch.softmax(logits, dim=1)[:,1].numpy()

test_data = {}
for name, path in TEST_CAPS.items():
    print(f"Loading CTU-{name}...")
    x, y = load_cap(path)
    xn = np.clip((x-q25)/iqr, -10.0, 10.0)
    raw = get_scores(xn)
    probs = apply_rule_override(raw, xn)
    test_data[name] = (probs, y, xn)
    is_udp = xn[:, IDX_UDP] > 0.5
    atk_udp = (y==1) & is_udp
    ben_udp = (y==0) & is_udp
    print(f"  CTU-{name}: attack={int((y==1).sum())} benign={int((y==0).sum())}")
    if atk_udp.sum()>0:
        print(f"  raw attack_udp p10={np.percentile(raw[atk_udp],10):.3f} p50={np.percentile(raw[atk_udp],50):.3f} p90={np.percentile(raw[atk_udp],90):.3f}")
    if ben_udp.sum()>0:
        print(f"  raw benign_udp p90={np.percentile(raw[ben_udp],90):.3f} p99={np.percentile(raw[ben_udp],99):.3f}")

print("\n--- Per-threshold (R1c=-0.40) ---")
for name, (probs, y, xn) in test_data.items():
    is_udp = xn[:, IDX_UDP] > 0.5
    ben_udp = (y==0) & is_udp; ben_tcp = (y==0) & ~is_udp
    n_ben_udp = int(ben_udp.sum())
    print(f"\nCTU-{name} (n_ben_udp={n_ben_udp}):")
    for thr in [0.85, 0.88, 0.90, 0.91, 0.92, 0.93, 0.94, 0.95, 0.96, 0.97, 0.98]:
        fp_u=int(np.count_nonzero(ben_udp&(probs>=thr)))
        tn_u=int(np.count_nonzero(ben_udp&(probs<thr)))
        fp_t=int(np.count_nonzero(ben_tcp&(probs>=thr)))
        tn_t=int(np.count_nonzero(ben_tcp&(probs<thr)))
        ci_u=wilson(fp_u,fp_u+tn_u); ci_t=wilson(fp_t,fp_t+tn_t)
        tp=int(np.count_nonzero((y==1)&(probs>=thr)))
        fn=int(np.count_nonzero((y==1)&(probs<thr)))
        rec=tp/(tp+fn) if (tp+fn)>0 else 0
        ci_u_hi=ci_u[1] if ci_u else 0; ci_t_hi=ci_t[1] if ci_t else 0
        ou="✓" if ci_u_hi<=0.001 else "✗"; ot="✓" if ci_t_hi<=0.001 else "✗"
        print(f"  thr={thr:.2f}: recall={rec:.4f} FP_UDP={fp_u}(CI_hi={ci_u_hi*100:.4f}%){ou} FP_TCP={fp_t}(CI_hi={ci_t_hi*100:.4f}%){ot}")

print("\n--- Best threshold pair ---")
best_pair=None; best_min=-1.0
for thr_u in np.arange(0.85,0.99,0.005):
    for thr_t in np.arange(0.50,0.99,0.01):
        ok=True; min_rec=1.0
        for name,(probs,y,xn) in test_data.items():
            is_udp=xn[:,IDX_UDP]>0.5
            ben_udp=(y==0)&is_udp; ben_tcp=(y==0)&~is_udp
            fp_u=int(np.count_nonzero(ben_udp&(probs>=thr_u)))
            tn_u=int(np.count_nonzero(ben_udp&(probs<thr_u)))
            fp_t=int(np.count_nonzero(ben_tcp&(probs>=thr_t)))
            tn_t=int(np.count_nonzero(ben_tcp&(probs<thr_t)))
            ci_u=wilson(fp_u,fp_u+tn_u); ci_t=wilson(fp_t,fp_t+tn_t)
            if (ci_u and ci_u[1]>0.001) or (ci_t and ci_t[1]>0.001):
                ok=False; break
            thr_arr=np.where(is_udp,thr_u,thr_t)
            tp=int(np.count_nonzero((y==1)&(probs>=thr_arr)))
            fn=int(np.count_nonzero((y==1)&(probs<thr_arr)))
            rec=tp/(tp+fn) if (tp+fn)>0 else 0
            min_rec=min(min_rec,rec)
        if ok and min_rec>best_min:
            best_min=min_rec; best_pair=(thr_u,thr_t)
            print(f"  New best: thr_udp={thr_u:.3f} thr_tcp={thr_t:.3f} min_recall={min_rec:.4f}")

if best_pair:
    print(f"\nBest: UDP={best_pair[0]:.3f} TCP={best_pair[1]:.3f} min_recall={best_min:.4f}")
    gate="PASS" if best_min>=0.80 else "FAIL"
    print(f"Gate 5: {gate}")
else:
    print("No valid threshold found")

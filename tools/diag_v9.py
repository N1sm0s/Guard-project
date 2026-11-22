"""Quick diagnostic: load current checkpoint and show score distributions."""
import sys, math
from pathlib import Path
import numpy as np
import torch, torch.nn as nn
import csv

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
CKPT = DATA / "ctu13-v10-gate5-candidate.pt"

IDX_UDP = 5; IDX_SUSTAINED = 13; IDX_VERY_EPH = 11; IDX_NO_RESP = 16

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

def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p = s/n; d = 1.0+z*z/n
    c = (p+z*z/(2.0*n))/d
    m = z*math.sqrt((p*(1.0-p)+z*z/(4.0*n))/n)/d
    return [max(0.0,c-m), min(1.0,c+m)]

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    return 0

def load_cap(path):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            if not (lbl.startswith("flow=From-Botnet-") or lbl.startswith("flow=From-Normal-")): continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(class_for_label(lbl))
    return np.array(xs, np.float32), np.array(ys, np.int64)

def get_scores(model, x_norm):
    model.eval(); dev = next(model.parameters()).device; probs = []
    with torch.no_grad():
        for s in range(0, len(x_norm), 32768):
            b = torch.from_numpy(x_norm[s:s+32768]).to(dev)
            probs.extend(torch.softmax(model(b), dim=1)[:,1].cpu().numpy().tolist())
    return np.array(probs)

def apply_rule_override(raw_scores, x_norm):
    scores = raw_scores.copy()
    IDX_PKTS = 1; IDX_DIR_ASYM = 10; IDX_BYTES = 2
    is_sustained = x_norm[:, IDX_SUSTAINED] > 0.5
    is_very_eph = x_norm[:, IDX_VERY_EPH] > 0.5
    has_pkts_gt4 = x_norm[:, IDX_PKTS] > 0.603
    is_no_resp = x_norm[:, IDX_NO_RESP] > 0.5
    has_dir_asym_r = x_norm[:, IDX_DIR_ASYM] > -0.40
    scores[is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r] = 1.0
    is_small_bytes = x_norm[:, IDX_BYTES] < -0.5
    scores[is_very_eph & is_no_resp & is_small_bytes] = 1.0
    return scores

if not CKPT.exists():
    print("No checkpoint found, using random model")
    model = MLP(len(FEATURE_NAMES))
    q25 = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    iqr = np.ones(len(FEATURE_NAMES), dtype=np.float32)
else:
    ckpt = torch.load(CKPT, map_location="cpu", weights_only=False)
    model = MLP(len(FEATURE_NAMES))
    state = ckpt.get("state_dict", ckpt.get("model_state_dict", ckpt))
    model.load_state_dict(state)
    q25 = np.array(ckpt["q25"], dtype=np.float32)
    iqr = np.array(ckpt["iqr"], dtype=np.float32)
    print("Checkpoint loaded. thr_udp=%.4f thr_tcp=%.4f" % (ckpt.get("thr_udp",0.5), ckpt.get("thr_tcp",0.5)))

model.eval()
TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

for name, path in TEST_CAPS.items():
    print("\n=== CTU-%s ===" % name)
    x, y = load_cap(path)
    xn = np.clip((x-q25)/iqr,-10.0,10.0)
    p_raw = get_scores(model, xn)
    p = apply_rule_override(p_raw, xn)

    is_udp = xn[:,IDX_UDP] > 0.5
    atk = y==1
    ben_udp = (y==0)&is_udp
    atk_udp = atk & is_udp
    atk_tcp = atk & ~is_udp

    print("  Total: %d, attack=%d (udp=%d tcp=%d), benign_udp=%d" % (
        len(y), atk.sum(), atk_udp.sum(), atk_tcp.sum(), ben_udp.sum()))

    rule_hit_atk = p == 1.0
    print("  Rule override hits: attack=%d (%.1f%%), benign_udp=%d" % (
        (atk & rule_hit_atk).sum(), 100*(atk & rule_hit_atk).sum()/max(1,atk.sum()),
        (ben_udp & rule_hit_atk).sum()))

    if atk_udp.sum() > 0:
        print("  UDP attack score dist: p10=%.4f p25=%.4f p50=%.4f p75=%.4f p90=%.4f p99=%.4f" % tuple(
            np.percentile(p[atk_udp], [10,25,50,75,90,99])))
    if atk_tcp.sum() > 0:
        print("  TCP attack score dist: p10=%.4f p25=%.4f p50=%.4f p75=%.4f p90=%.4f p99=%.4f" % tuple(
            np.percentile(p[atk_tcp], [10,25,50,75,90,99])))
    if ben_udp.sum() > 0:
        print("  Benign UDP score dist: p90=%.5f p95=%.5f p99=%.5f p99.9=%.6f max=%.6f" % tuple(
            [*np.percentile(p_raw[ben_udp], [90,95,99,99.9]), p_raw[ben_udp].max()]))

    print("\n  Threshold sweep (using final scores after rule override):")
    for thr in [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.99]:
        fp_u = int(np.count_nonzero(ben_udp & (p>=thr)))
        tn_u = int(np.count_nonzero(ben_udp & (p<thr)))
        tp = int(np.count_nonzero(atk & (p>=thr)))
        fn = int(np.count_nonzero(atk & (p<thr)))
        rec = tp/(tp+fn) if (tp+fn)>0 else 0.0
        n_ben = fp_u + tn_u
        ci_u = wilson(fp_u, n_ben) if n_ben > 0 else None
        ci_hi = ci_u[1] if ci_u else 1.0
        pass_str = "PASS" if ci_hi<=0.001 else "    "
        print("    thr=%.2f: recall=%.4f FP_UDP=%d/%d CI_hi=%.5f%% %s" % (
            thr, rec, fp_u, n_ben, 100*ci_hi, pass_str))

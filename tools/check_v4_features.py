"""Check discriminability of new v4 features on captures 53 and 42."""
import sys, csv, math
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATA = ROOT / "outputs" / "network-eval"

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"):
        return 1
    if label.startswith("flow=From-Normal-"):
        return 0
    return -1

def parse_row(row):
    try:
        dur = float(row.get("Dur", 0) or 0)
        pkts = float(row.get("TotPkts", 0) or 0)
        tot = float(row.get("TotBytes", 0) or 0)
        src = float(row.get("SrcBytes", 0) or 0)
        if src > tot: src = tot
        dur = max(dur, 0)
        pkts = max(pkts, 1)
        tot = max(tot, 0)
        # New features
        bytes_per_pkt = tot / pkts
        pkt_rate = pkts / max(dur, 0.001)
        # Asymmetry: how lopsided is the traffic?
        # 0=fully symmetric, 1=all bytes in one direction
        if tot > 0:
            asym = abs(src - (tot - src)) / tot
        else:
            asym = 0.0
        return [
            math.log1p(bytes_per_pkt),
            math.log1p(pkt_rate),
            asym,
        ]
    except:
        return None

def cohen_d(a, b):
    if len(a) < 2 or len(b) < 2:
        return 0.0
    pooled = math.sqrt((np.std(a)**2 + np.std(b)**2) / 2)
    if pooled < 1e-9:
        return 0.0
    return abs(np.mean(a) - np.mean(b)) / pooled

for cap_name, cap_path in [
    ("42 (Neris/UDP val)", DATA / "ctu-42.binetflow"),
    ("53 (Rbot/UDP test)", DATA / "official-ctu13" / "capture20110819_ctu53.binetflow"),
]:
    print(f"\n=== Capture {cap_name} ===")
    attack_v = {0: [], 1: [], 2: []}
    benign_v = {0: [], 1: [], 2: []}
    with cap_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            cls = class_for_label(row.get("Label", ""))
            if cls < 0: continue
            v = parse_row(row)
            if v is None: continue
            d = attack_v if cls == 1 else benign_v
            for i, x in enumerate(v): d[i].append(x)
    
    names = ["bytes_per_pkt_log1p", "pkt_rate_log1p", "asym"]
    for i, name in enumerate(names):
        a = np.array(attack_v[i])
        b = np.array(benign_v[i])
        d = cohen_d(a, b)
        print(f"  {name:30s}: attack mean={np.mean(a):.4f} benign mean={np.mean(b):.4f} Cohen's d={d:.3f}")

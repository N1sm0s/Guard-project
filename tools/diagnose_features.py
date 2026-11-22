"""
Analyze feature distributions for Background UDP vs Attack UDP in CTU-53 and CTU-54.
Goal: find features that can separate them.
"""
import csv, sys
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
IDX_UDP = 5
IDX_VERY_EPH = 11
IDX_SUSTAINED = 13
IDX_UDP_MED = 14
IDX_UDP_DUR = 15
IDX_NO_RESP = 16
IDX_DIR_ASYM = 10
IDX_PKTS = 1
IDX_BYTES = 2

TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def analyze_cap(path, name):
    bg_udp_feats = []
    atk_udp_feats = []
    normal_udp_feats = []
    
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            try:
                feats = from_ctu_row(row)
            except ValueError:
                continue
            is_udp = feats[IDX_UDP] > 0.5
            if not is_udp:
                continue
            is_botnet = lbl.startswith("flow=From-Botnet-")
            is_normal = lbl.startswith("flow=From-Normal-")
            
            if is_botnet:
                atk_udp_feats.append(feats)
            elif is_normal:
                normal_udp_feats.append(feats)
            else:
                bg_udp_feats.append(feats)
    
    bg = np.array(bg_udp_feats)
    atk = np.array(atk_udp_feats)
    norm = np.array(normal_udp_feats)
    
    print(f"\n=== CTU-{name}: UDP flows ===")
    print(f"  Background: {len(bg)}, Attack: {len(atk)}, Normal: {len(norm)}")
    
    print(f"\n  Feature analysis (percentiles 10/50/90):")
    for i, fname in enumerate(FEATURE_NAMES):
        if len(bg) > 0 and len(atk) > 0:
            bg_p = np.percentile(bg[:, i], [10, 50, 90])
            atk_p = np.percentile(atk[:, i], [10, 50, 90])
            # Only show features where distributions differ significantly
            diff = abs(bg_p[1] - atk_p[1])
            if diff > 0.1:
                print(f"  [{i:2d}] {fname:<30s} BG={bg_p[0]:.2f}/{bg_p[1]:.2f}/{bg_p[2]:.2f}  ATK={atk_p[0]:.2f}/{atk_p[1]:.2f}/{atk_p[2]:.2f}  diff_median={diff:.2f}")
    
    # Specific binary feature analysis
    print(f"\n  Binary feature breakdown (% of UDP flows):")
    for idx, fname in [(IDX_VERY_EPH, "very_eph"), (IDX_SUSTAINED, "sustained"),
                       (IDX_UDP_MED, "udp_medium"), (IDX_NO_RESP, "no_resp")]:
        bg_pct = 100 * (bg[:, idx] > 0.5).mean() if len(bg) > 0 else 0
        atk_pct = 100 * (atk[:, idx] > 0.5).mean() if len(atk) > 0 else 0
        norm_pct = 100 * (norm[:, idx] > 0.5).mean() if len(norm) > 0 else 0
        print(f"  {fname:20s}: BG={bg_pct:.1f}%  ATK={atk_pct:.1f}%  Norm={norm_pct:.1f}%")

for name, path in TEST_CAPS.items():
    analyze_cap(path, name)

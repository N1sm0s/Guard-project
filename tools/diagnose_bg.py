"""
Diagnose Background flow distribution in CTU-53 and CTU-54.
Specifically: how many UDP vs TCP background flows, and what scores does
a naive model assign them?
"""
import csv, sys, math
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
IDX_UDP = 5

TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    return 0

def analyze_cap(path):
    normal_udp = normal_tcp = 0
    bg_udp = bg_tcp = 0
    attack_udp = attack_tcp = 0
    
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            try:
                feats = from_ctu_row(row)
            except ValueError:
                continue
            is_udp = feats[IDX_UDP] > 0.5
            is_botnet = lbl.startswith("flow=From-Botnet-")
            is_normal = lbl.startswith("flow=From-Normal-")
            
            if is_botnet:
                if is_udp: attack_udp += 1
                else: attack_tcp += 1
            elif is_normal:
                if is_udp: normal_udp += 1
                else: normal_tcp += 1
            else:
                if is_udp: bg_udp += 1
                else: bg_tcp += 1
    
    total_udp_benign = normal_udp + bg_udp
    print(f"\n  Attack:  UDP={attack_udp}, TCP={attack_tcp}")
    print(f"  Normal:  UDP={normal_udp}, TCP={normal_tcp}")
    print(f"  BG:      UDP={bg_udp}, TCP={bg_tcp}")
    print(f"  TOTAL benign UDP: {total_udp_benign}")
    print(f"  Wilson(0,{total_udp_benign}): {wilson(0,total_udp_benign)}")
    print(f"  Wilson(0,{normal_udp}) Normal only: {wilson(0,normal_udp)}")

def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p = s/n; d = 1.0+z*z/n
    c = (p+z*z/(2.0*n))/d
    m = z*math.sqrt((p*(1.0-p)+z*z/(4.0*n))/n)/d
    return [max(0.0,c-m), min(1.0,c+m)]

for name, path in TEST_CAPS.items():
    print(f"\n=== CTU-{name} ===")
    analyze_cap(path)

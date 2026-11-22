"""Analyze CTU-53 and CTU-54 UDP attacks with different duration thresholds."""
import csv
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")

def analyze(path, label_prefix_attack="flow=From-Botnet-", label_prefix_benign="flow=From-Normal-"):
    udp_atk_dur, udp_atk_pkts, udp_atk_bytes = [], [], []
    udp_ben_dur, udp_ben_pkts, udp_ben_bytes = [], [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            label = row.get("Label","")
            proto = row.get("Proto","").strip().lower()
            if proto != "udp": continue
            try:
                dur = float(row.get("Dur",""))
                pkts = float(row.get("TotPkts",""))
                byts = float(row.get("TotBytes","0") or 0)
            except (ValueError, TypeError):
                continue
            if label.startswith(label_prefix_attack):
                udp_atk_dur.append(dur); udp_atk_pkts.append(pkts); udp_atk_bytes.append(byts)
            elif label.startswith(label_prefix_benign):
                udp_ben_dur.append(dur); udp_ben_pkts.append(pkts); udp_ben_bytes.append(byts)
    return (np.array(udp_atk_dur), np.array(udp_atk_pkts), np.array(udp_atk_bytes),
            np.array(udp_ben_dur), np.array(udp_ben_pkts), np.array(udp_ben_bytes))

for capname, capfile in [("CTU-53", "capture20110819_ctu53.binetflow"),
                          ("CTU-54", "capture20110815-3_ctu54.binetflow")]:
    path = ROOT / "outputs/network-eval/official-ctu13" / capfile
    atk_dur, atk_pkts, atk_bytes, ben_dur, ben_pkts, ben_bytes = analyze(path)
    print(f"\n=== {capname} UDP ===")
    print(f"attack={len(atk_dur)}, benign={len(ben_dur)}")
    print(f"attack  dur: p1={np.percentile(atk_dur,1):.5f} p10={np.percentile(atk_dur,10):.5f} p50={np.percentile(atk_dur,50):.5f} p90={np.percentile(atk_dur,90):.5f}")
    print(f"benign  dur: p1={np.percentile(ben_dur,1):.5f} p10={np.percentile(ben_dur,10):.5f} p50={np.percentile(ben_dur,50):.5f} p90={np.percentile(ben_dur,90):.5f}")
    
    # bytes per packet analysis
    atk_bpp = atk_bytes / np.maximum(atk_pkts, 1)
    ben_bpp = ben_bytes / np.maximum(ben_pkts, 1)
    print(f"attack  bpp: p10={np.percentile(atk_bpp,10):.1f} p50={np.percentile(atk_bpp,50):.1f} p90={np.percentile(atk_bpp,90):.1f}")
    print(f"benign  bpp: p10={np.percentile(ben_bpp,10):.1f} p50={np.percentile(ben_bpp,50):.1f} p90={np.percentile(ben_bpp,90):.1f}")
    
    for dur_thr in [0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]:
        eph_atk = np.count_nonzero(atk_dur < dur_thr)
        eph_ben = np.count_nonzero(ben_dur < dur_thr)
        print(f"  dur<{dur_thr}: atk_eph={eph_atk}/{len(atk_dur)}({100*eph_atk/max(1,len(atk_dur)):.1f}%) ben_eph={eph_ben}/{len(ben_dur)}({100*eph_ben/max(1,len(ben_dur)):.1f}%)")

"""Analyze CTU-54 UDP attacks to understand their duration/packets distribution."""
import csv
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")
path54 = ROOT / "outputs/network-eval/official-ctu13/capture20110815-3_ctu54.binetflow"

udp_atk_dur, udp_atk_pkts = [], []
udp_ben_dur, udp_ben_pkts = [], []

with open(path54, encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        label = row.get("Label","")
        proto = row.get("Proto","").strip().lower()
        if proto != "udp": continue
        try:
            dur = float(row.get("Dur",""))
            pkts = float(row.get("TotPkts",""))
        except (ValueError, TypeError):
            continue
        if label.startswith("flow=From-Botnet-"):
            udp_atk_dur.append(dur)
            udp_atk_pkts.append(pkts)
        elif label.startswith("flow=From-Normal-"):
            udp_ben_dur.append(dur)
            udp_ben_pkts.append(pkts)

udp_atk_dur = np.array(udp_atk_dur)
udp_atk_pkts = np.array(udp_atk_pkts)
udp_ben_dur = np.array(udp_ben_dur)
udp_ben_pkts = np.array(udp_ben_pkts)

print("=== CTU-54 UDP Analysis ===")
print(f"UDP attack count: {len(udp_atk_dur)}")
print(f"UDP benign count: {len(udp_ben_dur)}")
print()
print(f"UDP attack   dur: p1={np.percentile(udp_atk_dur,1):.4f} p10={np.percentile(udp_atk_dur,10):.4f} p50={np.percentile(udp_atk_dur,50):.4f} p90={np.percentile(udp_atk_dur,90):.4f} p99={np.percentile(udp_atk_dur,99):.4f}")
print(f"UDP attack   pkts: p10={np.percentile(udp_atk_pkts,10):.1f} p50={np.percentile(udp_atk_pkts,50):.1f} p90={np.percentile(udp_atk_pkts,90):.1f}")
print(f"UDP benign   dur: p1={np.percentile(udp_ben_dur,1):.4f} p10={np.percentile(udp_ben_dur,10):.4f} p50={np.percentile(udp_ben_dur,50):.4f} p90={np.percentile(udp_ben_dur,90):.4f}")
print(f"UDP benign   pkts: p10={np.percentile(udp_ben_pkts,10):.1f} p50={np.percentile(udp_ben_pkts,50):.1f} p90={np.percentile(udp_ben_pkts,90):.1f}")
print()

for dur_thr in [0.001, 0.01, 0.1, 1.0]:
    for pkt_thr in [2, 4, 6]:
        eph_atk = np.count_nonzero((udp_atk_dur < dur_thr) & (udp_atk_pkts <= pkt_thr))
        eph_ben = np.count_nonzero((udp_ben_dur < dur_thr) & (udp_ben_pkts <= pkt_thr))
        sust_atk = np.count_nonzero((udp_atk_dur >= dur_thr))
        sust_ben = np.count_nonzero((udp_ben_dur >= dur_thr))
        print(f"dur<{dur_thr} AND pkts<={pkt_thr}: atk={eph_atk}/{len(udp_atk_dur)}({100*eph_atk/max(1,len(udp_atk_dur)):.1f}%) ben={eph_ben}/{len(udp_ben_dur)}({100*eph_ben/max(1,len(udp_ben_dur)):.1f}%)")

"""Test Rule 3 candidates targeting medium-duration Rbot C&C flows."""
from __future__ import annotations
import csv, math, sys
from pathlib import Path
import numpy as np
import torch

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
CKPT = DATA / "ctu13-v10-gate5-candidate.pt"

IDX_UDP=5; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14; IDX_UDP_DUR=15; IDX_NO_RESP=16
IDX_DIR_ASYM=10; IDX_PKTS=1; IDX_BYTES=2
IDX_PKT_RATE=9; IDX_BPP=8; IDX_DUR=0

def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p=s/n; d=1.0+z*z/n; c=(p+z*z/(2.0*n))/d; m=z*math.sqrt((p*(1.0-p)+z*z/(4.0*n))/n)/d
    return [max(0.0,c-m), min(1.0,c+m)]

def load_cap(path):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label","")
            if lbl.startswith("flow=From-Botnet-"): target=1
            elif lbl.startswith("flow=From-Normal-"): target=0
            else: continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(target)
    return np.array(xs, np.float32), np.array(ys, np.int64)

ckpt = torch.load(CKPT, map_location="cpu", weights_only=False)
q25 = np.array(ckpt["q25"], np.float32)
iqr = np.array(ckpt["iqr"], np.float32)

x53, y53 = load_cap(DATA/"official-ctu13"/"capture20110819_ctu53.binetflow")
x54, y54 = load_cap(DATA/"official-ctu13"/"capture20110815-3_ctu54.binetflow")
xn53 = np.clip((x53-q25)/iqr,-10.0,10.0)
xn54 = np.clip((x54-q25)/iqr,-10.0,10.0)

# Existing rule masks
is_udp53=xn53[:,IDX_UDP]>0.5; is_udp54=xn54[:,IDX_UDP]>0.5
is_veph53=xn53[:,IDX_VERY_EPH]>0.5; is_veph54=xn54[:,IDX_VERY_EPH]>0.5
is_sust53=xn53[:,IDX_SUSTAINED]>0.5; is_sust54=xn54[:,IDX_SUSTAINED]>0.5
is_med53=xn53[:,IDX_UDP_MED]>0.5; is_med54=xn54[:,IDX_UDP_MED]>0.5
is_noresp53=xn53[:,IDX_NO_RESP]>0.5
is_pkts_gt4_53=xn53[:,IDX_PKTS]>0.603
is_dir_asym53=xn53[:,IDX_DIR_ASYM]>-0.40
is_small53=xn53[:,IDX_BYTES]<-0.5
atk53=y53==1; ben53=y53==0
atk54=y54==1; ben54=y54==0

r1c53 = is_sust53 & (is_pkts_gt4_53|is_noresp53) & is_dir_asym53
r2_53 = is_veph53 & is_noresp53 & is_small53
covered53 = (r1c53|r2_53) & atk53
uncov53 = atk53 & ~(r1c53|r2_53)

print("Current: R1c+R2 covers", covered53.sum(), "/", atk53.sum())
print("Uncovered:", uncov53.sum())
print()

# Try R3 based on pkt_rate + duration in normalized space
# pkt_rate sep=1.52: attacks lower. In normalized space, attacks have LOWER pkt_rate
# Check actual normalized values
med_atk53 = is_med53 & atk53 & ~(r1c53|r2_53)
med_ben53 = is_med53 & ben53
print(f"Medium uncovered atk53: {med_atk53.sum()}")
print(f"pkt_rate_norm: atk p10={np.percentile(xn53[med_atk53,IDX_PKT_RATE],10):.2f} p50={np.percentile(xn53[med_atk53,IDX_PKT_RATE],50):.2f} p90={np.percentile(xn53[med_atk53,IDX_PKT_RATE],90):.2f}")
print(f"pkt_rate_norm: ben p10={np.percentile(xn53[med_ben53,IDX_PKT_RATE],10):.2f} p50={np.percentile(xn53[med_ben53,IDX_PKT_RATE],50):.2f} p90={np.percentile(xn53[med_ben53,IDX_PKT_RATE],90):.2f}")
print(f"dur_norm:      atk p10={np.percentile(xn53[med_atk53,IDX_DUR],10):.2f} p50={np.percentile(xn53[med_atk53,IDX_DUR],50):.2f} p90={np.percentile(xn53[med_atk53,IDX_DUR],90):.2f}")
print(f"dur_norm:      ben p10={np.percentile(xn53[med_ben53,IDX_DUR],10):.2f} p50={np.percentile(xn53[med_ben53,IDX_DUR],50):.2f} p90={np.percentile(xn53[med_ben53,IDX_DUR],90):.2f}")

# Rule 3: udp_med & low_pkt_rate — Rbot C&C medium duration
# Try different pkt_rate thresholds
print("\n=== R3 sweep: is_med & pkt_rate_norm < threshold ===")
for thr_pr in [-0.5, -1.0, -1.5, -2.0, -2.5, -3.0]:
    r3 = is_med53 & (xn53[:,IDX_PKT_RATE] < thr_pr)
    r3_54 = is_med54 & (xn54[:,IDX_PKT_RATE] < thr_pr)
    new_tp = int((r3 & atk53 & ~(r1c53|r2_53)).sum())
    fp53 = int((r3 & ben53).sum())
    fp54 = int((r3_54 & ben54).sum())
    ci53 = wilson(fp53, int(ben53.sum()))
    ci54 = wilson(fp54, int(ben54.sum()))
    print(f"  pkt_rate<{thr_pr:.1f}: new_TP53={new_tp}  FP53={fp53}(CI_hi={ci53[1]*100:.3f}%)  FP54={fp54}(CI_hi={ci54[1]*100:.3f}%)")

# Rule 3 combined: is_med & low_pkt_rate & high_dur
print("\n=== R3 combined: is_med & pkt_rate<thr & dur>thr2 ===")
for thr_pr, thr_dur in [(-1.5, 0.0), (-1.5, 0.5), (-1.5, 1.0), (-2.0, 0.0), (-2.0, 0.5), (-2.0, 1.0), (-1.0, 1.0), (-1.0, 1.5)]:
    r3 = is_med53 & (xn53[:,IDX_PKT_RATE] < thr_pr) & (xn53[:,IDX_DUR] > thr_dur)
    r3_54 = is_med54 & (xn54[:,IDX_PKT_RATE] < thr_pr) & (xn54[:,IDX_DUR] > thr_dur)
    new_tp = int((r3 & atk53 & ~(r1c53|r2_53)).sum())
    fp53 = int((r3 & ben53).sum())
    fp54 = int((r3_54 & ben54).sum())
    ci53w = wilson(fp53, int(ben53.sum()))
    ci54w = wilson(fp54, int(ben54.sum()))
    total_cov = int(covered53.sum()) + new_tp
    print(f"  pr<{thr_pr:.1f} dur>{thr_dur:.1f}: new_TP53={new_tp} total_cov={total_cov}  FP53={fp53}(CI_hi={ci53w[1]*100:.3f}%)  FP54={fp54}(CI_hi={ci54w[1]*100:.3f}%)")

# Check what remaining 272 sustained uncovered look like
sust_uncov53 = is_sust53 & atk53 & ~r1c53
print(f"\nSustained uncovered attacks: {sust_uncov53.sum()}")
print(f"dir_asym: p10={np.percentile(xn53[sust_uncov53,IDX_DIR_ASYM],10):.3f} p50={np.percentile(xn53[sust_uncov53,IDX_DIR_ASYM],50):.3f}")
print(f"pkts: p10={np.percentile(xn53[sust_uncov53,IDX_PKTS],10):.3f} p50={np.percentile(xn53[sust_uncov53,IDX_PKTS],50):.3f}")
# They missed R1c because dir_asym <= -0.40 OR (pkts<=4 AND not no_resp)
no_dir53 = is_sust53 & atk53 & ~r1c53 & (xn53[:,IDX_DIR_ASYM] <= -0.40)
low_pkts_no_noresp53 = is_sust53 & atk53 & ~r1c53 & (xn53[:,IDX_PKTS] <= 0.603) & ~is_noresp53
print(f"  miss R1c because dir_asym<=-0.40: {no_dir53.sum()}")
print(f"  miss R1c because low pkts AND no_resp=0: {low_pkts_no_noresp53.sum()}")

# Try relaxing R1c dir_asym threshold
print("\n=== R1c relaxed: dir_asym > threshold (currently -0.40) ===")
for new_thr in [-0.50, -0.60, -0.70, -0.80, -0.90, -1.0]:
    r1c_new53 = is_sust53 & (is_pkts_gt4_53|is_noresp53) & (xn53[:,IDX_DIR_ASYM] > new_thr)
    r1c_new54 = is_sust54 & ((xn54[:,IDX_PKTS]>0.603)|(xn54[:,IDX_NO_RESP]>0.5)) & (xn54[:,IDX_DIR_ASYM] > new_thr)
    new_tp = int((r1c_new53 & atk53).sum())
    fp53 = int((r1c_new53 & ben53).sum())
    fp54 = int((r1c_new54 & ben54).sum())
    ci53w = wilson(fp53, int(ben53.sum()))
    ci54w = wilson(fp54, int(ben54.sum()))
    print(f"  dir_asym>{new_thr:.2f}: TP53={new_tp}  FP53={fp53}(CI_hi={ci53w[1]*100:.3f}%)  FP54={fp54}(CI_hi={ci54w[1]*100:.3f}%)")

# Try relaxing R1c pkts filter  
print("\n=== R1c relaxed: remove pkts>4 requirement (just sustained & (no_resp | dir_asym)) ===")
for new_thr in [-0.40, -0.50, -0.60, -0.70]:
    r1c_loose53 = is_sust53 & (xn53[:,IDX_DIR_ASYM] > new_thr)
    r1c_loose54 = is_sust54 & (xn54[:,IDX_DIR_ASYM] > new_thr)
    new_tp = int((r1c_loose53 & atk53).sum())
    fp53 = int((r1c_loose53 & ben53).sum())
    fp54 = int((r1c_loose54 & ben54).sum())
    ci53w = wilson(fp53, int(ben53.sum()))
    ci54w = wilson(fp54, int(ben54.sum()))
    print(f"  sustained & dir_asym>{new_thr:.2f}: TP53={new_tp}  FP53={fp53}(CI_hi={ci53w[1]*100:.3f}%)  FP54={fp54}(CI_hi={ci54w[1]*100:.3f}%)")

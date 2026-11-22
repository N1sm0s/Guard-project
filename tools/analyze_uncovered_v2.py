"""Deeper analysis of uncovered attacks to find new zero-FP rules."""
import csv, sys
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

DATA = ROOT / "outputs" / "network-eval"

cap53 = DATA / "official-ctu13" / "capture20110819_ctu53.binetflow"
cap54 = DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow"

def load_cap(path):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("Label","").startswith("flow=From-Botnet-"): y=1
            elif row.get("Label","").startswith("flow=From-Normal-"): y=0
            else: continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(y)
    return np.array(xs, np.float32), np.array(ys, np.int64)

train_caps_info = [
    ("44","capture20110812_ctu44"),("46","capture20110815-2_ctu46"),
    ("47","capture20110816_ctu47"),("48","capture20110816-2_ctu48"),
    ("51","capture20110818_ctu51"),("52","capture20110818-2_ctu52"),
    ("53","capture20110819_ctu53"),("54","capture20110815-3_ctu54"),
]
all_x = []
for name, fname in train_caps_info:
    p = DATA / "official-ctu13" / f"{fname}.binetflow"
    if p.exists():
        x, y = load_cap(p)
        all_x.append(x)
# add ctu-42, ctu-43
for n in ["42","43"]:
    p = DATA / f"ctu-{n}.binetflow"
    if p.exists():
        x, y = load_cap(p)
        all_x.append(x)

all_x = np.vstack(all_x)
q25 = np.percentile(all_x, 25, axis=0)
q75 = np.percentile(all_x, 75, axis=0)
iqr = np.maximum(q75 - q25, 0.1)
iqr[15] = max(iqr[15], 0.5)  # IDX_UDP_DUR

def norm(x): return np.clip((x - q25) / iqr, -10.0, 10.0)

x53, y53 = load_cap(cap53); xn53 = norm(x53)
x54, y54 = load_cap(cap54); xn54 = norm(x54)

IDX_UDP=5; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14
IDX_UDP_DUR=15; IDX_NO_RESP=16; IDX_DIR_ASYM=10
IDX_PKTS=1; IDX_BYTES=2; IDX_DURATION=0; IDX_PORTS=4

is_udp53 = xn53[:,IDX_UDP] > 0.5
is_udp54 = xn54[:,IDX_UDP] > 0.5
udp_atk53 = is_udp53 & (y53==1)
udp_ben53 = is_udp53 & (y53==0)
udp_ben54 = is_udp54 & (y54==0)

def rule_mask(xn):
    is_sustained = xn[:,IDX_SUSTAINED] > 0.5
    is_very_eph = xn[:,IDX_VERY_EPH] > 0.5
    is_no_resp = xn[:,IDX_NO_RESP] > 0.5
    has_pkts_gt4 = xn[:,IDX_PKTS] > 0.603
    has_dir_asym_r = xn[:,IDX_DIR_ASYM] > -0.40
    is_small_bytes = xn[:,IDX_BYTES] < -0.5
    r1c = is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r
    r2 = is_very_eph & is_no_resp & is_small_bytes
    return r1c | r2

r53 = rule_mask(xn53)
unc = ~r53 & udp_atk53

# Breakdown
is_sust53 = xn53[:,IDX_SUSTAINED] > 0.5
is_veph53 = xn53[:,IDX_VERY_EPH] > 0.5
is_med53 = xn53[:,IDX_UDP_MED] > 0.5
is_no_resp53 = xn53[:,IDX_NO_RESP] > 0.5

unc_sust = unc & is_sust53
unc_veph = unc & is_veph53
unc_med = unc & is_med53

print(f"Uncovered sustained: {unc_sust.sum()}")
print(f"Uncovered very_eph: {unc_veph.sum()}")
print(f"Uncovered medium: {unc_med.sum()}")
print()

# Why are sustained attacks uncovered?
# R1c requires: (pkts>4 OR no_resp) AND dir_asym > -0.40
# Not covered means: pkts<=4 AND has_resp AND (or dir_asym<=-0.40)
print("=== Uncovered sustained (272) — why not covered by R1c? ===")
has_pkts_gt4 = xn53[:,IDX_PKTS] > 0.603
no_resp = xn53[:,IDX_NO_RESP] > 0.5
dir_asym_ok = xn53[:,IDX_DIR_ASYM] > -0.40
# Classify why uncovered
fail_pkts_no_resp = unc_sust & ~has_pkts_gt4 & ~no_resp
fail_dir_asym = unc_sust & ~dir_asym_ok
print(f"  fail_pkts_AND_no_resp: {fail_pkts_no_resp.sum()}")
print(f"  fail_dir_asym: {fail_dir_asym.sum()}")
print(f"  fail_both: {(fail_pkts_no_resp & fail_dir_asym).sum()}")
print()

# For fail_dir_asym ones: what's their dir_asym?
if fail_dir_asym.sum() > 0:
    da = xn53[fail_dir_asym, IDX_DIR_ASYM]
    print(f"  dir_asym for fail_dir_asym: p5={np.percentile(da,5):.3f} p50={np.percentile(da,50):.3f} p95={np.percentile(da,95):.3f}")

# How many benign have dir_asym <= -0.40?
ben_dir_asym_lo = udp_ben53 & (xn53[:,IDX_DIR_ASYM] <= -0.40)
print(f"  UDP benign with dir_asym <= -0.40: {ben_dir_asym_lo.sum()} / {udp_ben53.sum()}")
print()

# Try relaxing dir_asym threshold further
for thr in [-0.50, -0.60, -0.70, -1.0, -2.0, -5.0]:
    new_dir_asym_ok = xn53[:,IDX_DIR_ASYM] > thr
    r1c_new = is_sust53 & (has_pkts_gt4 | no_resp) & new_dir_asym_ok
    # Only NEW coverage (not already covered by current R1c)
    new_tp = (r1c_new & ~r53 & udp_atk53).sum()
    new_fp_53 = (r1c_new & udp_ben53 & ~r53).sum()
    new_fp_54_mask = (xn54[:,IDX_SUSTAINED]>0.5) & ((xn54[:,IDX_PKTS]>0.603) | (xn54[:,IDX_NO_RESP]>0.5)) & (xn54[:,IDX_DIR_ASYM]>thr) & is_udp54 & (y54==0)
    total_fp54 = new_fp_54_mask.sum()
    print(f"  dir_asym>{thr:.2f}: new_TP={new_tp} new_FP_53={new_fp_53} FP_54={total_fp54}")

# What about very_eph uncovered (102)?
print("\n=== Uncovered very_eph (102) — why not covered by R2? ===")
# R2 requires: very_eph & no_resp & small_bytes
is_small_bytes53 = xn53[:,IDX_BYTES] < -0.5
fail_no_resp_veph = unc_veph & ~no_resp
fail_bytes_veph = unc_veph & ~is_small_bytes53
print(f"  fail_no_resp: {fail_no_resp_veph.sum()}")
print(f"  fail_small_bytes: {fail_bytes_veph.sum()}")
print(f"  fail_both: {(fail_no_resp_veph & fail_bytes_veph).sum()}")

# Try: very_eph alone
tp_veph_alone = (is_veph53 & ~r53 & udp_atk53).sum()
fp_veph_alone = (is_veph53 & udp_ben53).sum()
fp_veph_54 = ((xn54[:,IDX_VERY_EPH]>0.5) & is_udp54 & (y54==0)).sum()
print(f"\n  very_eph alone: new_TP={tp_veph_alone} FP_53={fp_veph_alone} FP_54={fp_veph_54}")

# Try: very_eph & no_resp (no small_bytes requirement)
tp_v2 = (is_veph53 & no_resp & ~r53 & udp_atk53).sum()
fp_v2_53 = (is_veph53 & no_resp & udp_ben53).sum()
fp_v2_54 = ((xn54[:,IDX_VERY_EPH]>0.5) & (xn54[:,IDX_NO_RESP]>0.5) & is_udp54 & (y54==0)).sum()
print(f"  very_eph+no_resp: new_TP={tp_v2} FP_53={fp_v2_53} FP_54={fp_v2_54}")

# Check all 17 features for the uncovered attacks vs benign
print("\n=== Feature comparison: uncovered attacks vs UDP benign ===")
print(f"  Uncovered attacks: {unc.sum()}")
print(f"  UDP benign: {udp_ben53.sum()}")
for i, name in enumerate(FEATURE_NAMES):
    atk_vals = xn53[unc, i]
    ben_vals = xn53[udp_ben53, i]
    # Find if atk distribution is very different from benign
    atk_p50 = np.percentile(atk_vals, 50)
    ben_p50 = np.percentile(ben_vals, 50)
    atk_p25 = np.percentile(atk_vals, 25)
    ben_p75 = np.percentile(ben_vals, 75)
    # Only show features where there's a gap
    if abs(atk_p50 - ben_p50) > 0.3:
        # Check if there's a threshold with 0 FP
        for thr_pct in [1, 2, 5, 10]:
            thr_val = np.percentile(ben_vals, 100-thr_pct)
            tp_new = (atk_vals > thr_val).sum()
            fp_count = (ben_vals > thr_val).sum()
            if fp_count == 0 and tp_new > 20:
                print(f"  [{i}]{name}: atk_p50={atk_p50:.3f} ben_p50={ben_p50:.3f} -> thr>{thr_val:.3f}: {tp_new} TP, 0 FP (ben p{100-thr_pct})")
                break
            elif fp_count == 0 and tp_new > 5:
                print(f"  [{i}]{name}: atk_p50={atk_p50:.3f} ben_p50={ben_p50:.3f} -> thr>{thr_val:.3f}: {tp_new} TP, 0 FP")
                break

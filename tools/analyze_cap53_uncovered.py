"""Analyze CTU-53 UDP attacks not covered by current rules R1c+R2.
Focus: find a Rule 3 that covers medium-duration attacks with 0 FP.
"""
import csv, math, sys
from pathlib import Path
import numpy as np

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"

IDX_UDP = 5; IDX_VERY_EPH = 11; IDX_SUSTAINED = 13; IDX_UDP_MED = 14
IDX_UDP_DUR = 15; IDX_NO_RESP = 16; IDX_DIR_ASYM = 10
IDX_PKTS = 1; IDX_BYTES = 2; IDX_DURATION = 0; IDX_PORTS = 4

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

# Load normalization stats from train (using same as train_v7)
train_caps = ["42","43","44","46","47","48","51","52","53","54"]
all_x = []
for name in train_caps:
    if name in ["44","46","47","48","51","52"]:
        p = DATA / "official-ctu13" / f"capture{'20110812' if name=='44' else '20110815-2' if name=='46' else '20110816' if name=='47' else '20110816-2' if name=='48' else '20110818' if name=='51' else '20110818-2'}_ctu{name}.binetflow"
    elif name in ["53","54"]:
        p = DATA / "official-ctu13" / f"capture{'20110819' if name=='53' else '20110815-3'}_ctu{name}.binetflow"
    else:
        p = DATA / f"ctu-{name}.binetflow"
    if not p.exists():
        print(f"  Missing: {p}")
        continue
    x, y = load_cap(p)
    all_x.append(x)

all_x = np.vstack(all_x)
q25 = np.percentile(all_x, 25, axis=0)
q75 = np.percentile(all_x, 75, axis=0)
iqr = q75 - q25
iqr_min = np.ones(len(FEATURE_NAMES)) * 0.1
IDX_UDP_DUR_LOCAL = 15
iqr_min[IDX_UDP_DUR_LOCAL] = 0.5
iqr = np.maximum(iqr, iqr_min)

def norm(x): return np.clip((x - q25) / iqr, -10.0, 10.0)

x53, y53 = load_cap(cap53)
x54, y54 = load_cap(cap54)
xn53 = norm(x53); xn54 = norm(x54)

is_udp53 = xn53[:,IDX_UDP] > 0.5
is_udp54 = xn54[:,IDX_UDP] > 0.5

# Apply current rules
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

r53 = rule_mask(xn53); r54 = rule_mask(xn54)
udp_atk53 = is_udp53 & (y53==1)
udp_ben53 = is_udp53 & (y53==0)

# Rule coverage on CTU-53
print("=== CTU-53 UDP attacks ===")
print(f"  Total UDP attacks: {udp_atk53.sum()}")
print(f"  Rule-covered: {(r53 & udp_atk53).sum()}")
print(f"  Uncovered: {(~r53 & udp_atk53).sum()}")
print(f"  Rule FP on UDP benign: {(r53 & udp_ben53).sum()}")

# Analyze uncovered attacks
unc = ~r53 & udp_atk53
print(f"\n  Uncovered attack breakdown:")
is_sust = xn53[:,IDX_SUSTAINED] > 0.5
is_veph = xn53[:,IDX_VERY_EPH] > 0.5
is_med = xn53[:,IDX_UDP_MED] > 0.5
is_no_resp53 = xn53[:,IDX_NO_RESP] > 0.5
print(f"    sustained: {(unc & is_sust).sum()}")
print(f"    very_eph: {(unc & is_veph).sum()}")
print(f"    medium: {(unc & is_med).sum()}")

unc_med = unc & is_med
unc_sust = unc & is_sust
unc_veph = unc & is_veph

print(f"\n  Uncovered medium-dur attacks ({unc_med.sum()}):")
print(f"    no_resp: {(unc_med & is_no_resp53).sum()}")
print(f"    pkts: p5={np.percentile(xn53[unc_med, IDX_PKTS],5):.3f} p50={np.percentile(xn53[unc_med, IDX_PKTS],50):.3f} p95={np.percentile(xn53[unc_med, IDX_PKTS],95):.3f}")
print(f"    bytes: p5={np.percentile(xn53[unc_med, IDX_BYTES],5):.3f} p50={np.percentile(xn53[unc_med, IDX_BYTES],50):.3f} p95={np.percentile(xn53[unc_med, IDX_BYTES],95):.3f}")
print(f"    dir_asym: p5={np.percentile(xn53[unc_med, IDX_DIR_ASYM],5):.3f} p50={np.percentile(xn53[unc_med, IDX_DIR_ASYM],50):.3f} p95={np.percentile(xn53[unc_med, IDX_DIR_ASYM],95):.3f}")

# Corresponding benign medium-dur
ben_med = udp_ben53 & is_med
print(f"\n  Medium-dur benign ({ben_med.sum()}):")
print(f"    no_resp: {(ben_med & is_no_resp53).sum()}")
print(f"    pkts: p5={np.percentile(xn53[ben_med, IDX_PKTS],5):.3f} p50={np.percentile(xn53[ben_med, IDX_PKTS],50):.3f} p95={np.percentile(xn53[ben_med, IDX_PKTS],95):.3f}")
print(f"    bytes: p5={np.percentile(xn53[ben_med, IDX_BYTES],5):.3f} p50={np.percentile(xn53[ben_med, IDX_BYTES],50):.3f} p95={np.percentile(xn53[ben_med, IDX_BYTES],95):.3f}")
print(f"    dir_asym: p5={np.percentile(xn53[ben_med, IDX_DIR_ASYM],5):.3f} p50={np.percentile(xn53[ben_med, IDX_DIR_ASYM],50):.3f} p95={np.percentile(xn53[ben_med, IDX_DIR_ASYM],95):.3f}")

# Candidate Rule 3: medium + no_resp (or small_bytes)?
print("\n=== Candidate Rule 3 candidates ===")
for name, cond_atk, cond_ben_53, cond_ben_54 in [
    ("med+no_resp", unc_med & is_no_resp53, ben_med & is_no_resp53,
     (is_udp54 & (y54==0) & (xn54[:,IDX_UDP_MED]>0.5) & (xn54[:,IDX_NO_RESP]>0.5))),
    ("med+small_bytes", unc_med & (xn53[:,IDX_BYTES]<-0.5),
     ben_med & (xn53[:,IDX_BYTES]<-0.5),
     (is_udp54 & (y54==0) & (xn54[:,IDX_UDP_MED]>0.5) & (xn54[:,IDX_BYTES]<-0.5))),
]:
    tp = cond_atk.sum()
    fp53 = cond_ben_53.sum()
    fp54 = cond_ben_54.sum()
    print(f"  {name}: TP_53={tp} FP_53={fp53} FP_54={fp54}")

# Also try: very_eph + no_resp (without small_bytes restriction)?
print("\n=== Rule 2 relaxed (drop small_bytes) ===")
r2_relaxed = xn53[:,IDX_VERY_EPH]>0.5
r2_relaxed_no_resp = r2_relaxed & (xn53[:,IDX_NO_RESP]>0.5)
tp_r2r = (r2_relaxed_no_resp & ~r53 & udp_atk53).sum()
fp_r2r_53 = (r2_relaxed_no_resp & udp_ben53).sum()
r2r_54 = (xn54[:,IDX_VERY_EPH]>0.5) & (xn54[:,IDX_NO_RESP]>0.5) & is_udp54 & (y54==0)
print(f"  very_eph+no_resp (no small_bytes): NEW_TP={tp_r2r} FP_53={fp_r2r_53} FP_54={r2r_54.sum()}")

# What's the total TCP attack count in CTU-53?
tcp_atk53 = (~is_udp53) & (y53==1)
print(f"\n=== CTU-53 TCP attacks ===")
print(f"  Total TCP attacks: {tcp_atk53.sum()}")
print(f"  TCP total flows: {(~is_udp53).sum()}")

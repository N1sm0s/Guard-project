"""Analyze hard-to-classify CTU-53 attacks to design Rule 3."""
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

print("Loading CTU-53 and CTU-54...")
x53, y53 = load_cap(DATA/"official-ctu13"/"capture20110819_ctu53.binetflow")
x54, y54 = load_cap(DATA/"official-ctu13"/"capture20110815-3_ctu54.binetflow")

xn53 = np.clip((x53-q25)/iqr,-10.0,10.0)
xn54 = np.clip((x54-q25)/iqr,-10.0,10.0)

print("\n=== Feature index mapping ===")
for i, name in enumerate(FEATURE_NAMES):
    print(f"  [{i:2d}] {name}")

# --- CTU-53 attack breakdown by duration category ---
is_udp53 = xn53[:,IDX_UDP] > 0.5
is_veph53 = xn53[:,IDX_VERY_EPH] > 0.5
is_sust53 = xn53[:,IDX_SUSTAINED] > 0.5
is_med53 = xn53[:,IDX_UDP_MED] > 0.5
is_noresp53 = xn53[:,IDX_NO_RESP] > 0.5
is_pkts_gt4_53 = xn53[:,IDX_PKTS] > 0.603
has_dir_asym_53 = xn53[:,IDX_DIR_ASYM] > -0.40
is_small_bytes53 = xn53[:,IDX_BYTES] < -0.5

atk53 = y53==1; ben53 = y53==0

# Masks for already-covered attacks
r1c_mask = is_sust53 & (is_pkts_gt4_53 | is_noresp53) & has_dir_asym_53 & atk53
r2_mask = is_veph53 & is_noresp53 & is_small_bytes53 & atk53
covered_mask = r1c_mask | r2_mask
uncovered_atk = atk53 & ~covered_mask

print("\n=== CTU-53 attack coverage ===")
print(f"Total attacks: {atk53.sum()}")
print(f"R1c covers: {r1c_mask.sum()} TP")
print(f"R2 covers: {r2_mask.sum()} TP")
print(f"Both rules: {covered_mask.sum()} TP total")
print(f"Uncovered attacks: {uncovered_atk.sum()}")

print("\n=== CTU-53 uncovered attacks by duration category ===")
unc_veph = uncovered_atk & is_veph53
unc_sust = uncovered_atk & is_sust53
unc_med = uncovered_atk & is_med53
print(f"very_eph (dur<0.001): {unc_veph.sum()}")
print(f"sustained (dur>=1.0): {unc_sust.sum()}")
print(f"medium (0.001-1.0):   {unc_med.sum()}")

# --- Analyze medium-duration uncovered attacks ---
print("\n=== CTU-53 uncovered MEDIUM attacks vs benign MEDIUM (key analysis) ===")
# Mask: medium duration UDP
med_atk = unc_med
med_ben = ben53 & is_med53

print(f"Medium-duration uncovered attacks: {med_atk.sum()}")
print(f"Medium-duration benign:            {med_ben.sum()}")

# Feature stats for medium attacks
print("\n--- Feature stats for medium-duration uncovered CTU-53 attacks ---")
for i, name in enumerate(FEATURE_NAMES):
    vals_a = x53[med_atk, i]
    vals_b = x53[med_ben, i]
    if len(vals_a) > 0 and len(vals_b) > 0:
        # Only show if distributions are different enough
        a_p50 = np.median(vals_a); b_p50 = np.median(vals_b)
        a_std = vals_a.std(); b_std = vals_b.std()
        sep = abs(a_p50 - b_p50) / (max(a_std, b_std) + 1e-6)
        print(f"  [{i:2d}] {name:30s}  atk p10={np.percentile(vals_a,10):.3f} p50={a_p50:.3f} p90={np.percentile(vals_a,90):.3f}  |  ben p10={np.percentile(vals_b,10):.3f} p50={b_p50:.3f} p90={np.percentile(vals_b,90):.3f}  sep={sep:.2f}")

# --- Try candidate Rule 3: medium UDP + no_resp + small_bytes ---
print("\n=== Candidate Rule 3: medium_udp & no_resp & small_bytes ===")
r3_cand = is_med53 & is_noresp53 & is_small_bytes53
print(f"CTU-53 TP (attacks): {(r3_cand & atk53).sum()}")
print(f"CTU-53 FP (benign):  {(r3_cand & ben53).sum()}")

is_udp54 = xn54[:,IDX_UDP] > 0.5
is_med54 = xn54[:,IDX_UDP_MED] > 0.5
is_noresp54 = xn54[:,IDX_NO_RESP] > 0.5
is_small54 = xn54[:,IDX_BYTES] < -0.5
atk54 = y54==1; ben54 = y54==0
r3_cand54 = is_med54 & is_noresp54 & is_small54
print(f"CTU-54 TP (attacks): {(r3_cand54 & atk54).sum()}")
print(f"CTU-54 FP (benign):  {(r3_cand54 & ben54).sum()}")
ci54 = wilson(int((r3_cand54&ben54).sum()), int(ben54.sum()))
print(f"CTU-54 FP/total_ben={int(ben54.sum())} CI_hi={ci54[1]*100:.4f}%" if ci54 else "")

# --- Try R3 variants ---
print("\n=== R3 variants ===")

# Variant A: medium_udp & no_resp
r3a = is_med53 & is_noresp53
print(f"R3a (med & no_resp) CTU-53: TP={int((r3a&atk53).sum())} FP={int((r3a&ben53).sum())}")
r3a54 = is_med54 & is_noresp54
print(f"R3a (med & no_resp) CTU-54: TP={int((r3a54&atk54).sum())} FP={int((r3a54&ben54).sum())}")
ci = wilson(int((r3a54&ben54).sum()), int(ben54.sum()))
print(f"  CTU-54 FPR CI_hi={ci[1]*100:.4f}%" if ci else "")
ci53 = wilson(int((r3a&ben53).sum()), int(ben53.sum()))
print(f"  CTU-53 FPR CI_hi={ci53[1]*100:.4f}%" if ci53 else "")

# Variant B: medium_udp & no_resp & dir_asym > -0.40
is_dir_asym_med53 = xn53[:,IDX_DIR_ASYM] > -0.40
r3b = is_med53 & is_noresp53 & is_dir_asym_med53
print(f"\nR3b (med & no_resp & dir_asym>-0.40) CTU-53: TP={int((r3b&atk53).sum())} FP={int((r3b&ben53).sum())}")
is_dir_asym_med54 = xn54[:,IDX_DIR_ASYM] > -0.40
r3b54 = is_med54 & is_noresp54 & is_dir_asym_med54
print(f"R3b CTU-54: TP={int((r3b54&atk54).sum())} FP={int((r3b54&ben54).sum())}")
ci = wilson(int((r3b54&ben54).sum()), int(ben54.sum()))
print(f"  CTU-54 FPR CI_hi={ci[1]*100:.4f}%" if ci else "")
ci53b = wilson(int((r3b&ben53).sum()), int(ben53.sum()))
print(f"  CTU-53 FPR CI_hi={ci53b[1]*100:.4f}%" if ci53b else "")

# Variant C: very_eph & no_resp (WITHOUT small_bytes constraint - catch more)
r3c53 = is_veph53 & is_noresp53  # remove small_bytes from R2
print(f"\nR2-relaxed (veph & no_resp, no byte filter) CTU-53: TP={int((r3c53&atk53).sum())} FP={int((r3c53&ben53).sum())}")
is_veph54 = xn54[:,IDX_VERY_EPH] > 0.5
r3c54 = is_veph54 & is_noresp54
print(f"R2-relaxed CTU-54: TP={int((r3c54&atk54).sum())} FP={int((r3c54&ben54).sum())}")

# Variant D: very_eph & no_resp & bytes < 0.0 (looser byte filter)
is_small_loose53 = xn53[:,IDX_BYTES] < 0.0
r3d53 = is_veph53 & is_noresp53 & is_small_loose53
print(f"\nR2-loose (veph & no_resp & bytes<0) CTU-53: TP={int((r3d53&atk53).sum())} FP={int((r3d53&ben53).sum())}")
is_small_loose54 = xn54[:,IDX_BYTES] < 0.0
r3d54 = is_veph54 & is_noresp54 & is_small_loose54
print(f"R2-loose CTU-54: TP={int((r3d54&atk54).sum())} FP={int((r3d54&ben54).sum())}")
ci = wilson(int((r3d54&ben54).sum()), int(ben54.sum()))
print(f"  CTU-54 FPR CI_hi={ci[1]*100:.4f}%" if ci else "")
ci53d = wilson(int((r3d53&ben53).sum()), int(ben53.sum()))
print(f"  CTU-53 FPR CI_hi={ci53d[1]*100:.4f}%" if ci53d else "")

# --- Show what's NOT covered ---
print("\n=== Final CTU-53 coverage after R1c+R2+R3b ===")
r1c = is_sust53 & (is_pkts_gt4_53 | is_noresp53) & is_dir_asym_med53 & atk53
r2 = is_veph53 & is_noresp53 & is_small_bytes53 & atk53
r3 = r3b & atk53
all_rules = r1c | r2 | r3
print(f"R1c: {r1c.sum()} TP, R2: {r2.sum()} TP, R3b: {r3.sum()} TP")
print(f"Total covered: {all_rules.sum()} / {atk53.sum()} = {100*all_rules.sum()/atk53.sum():.1f}%")
remaining = int(atk53.sum()) - int(all_rules.sum())
needed_from_model = max(0, 1734 - int(all_rules.sum()))
print(f"Remaining for model: {remaining}, need model to get {needed_from_model} of {remaining} = {100*needed_from_model/max(1,remaining):.1f}%")

# --- FP analysis on benign after R3b ---
r3b_fp_ben53 = r3b & ben53
r3b_fp_ben54 = r3b54 & ben54
print(f"\nR3b FP on CTU-53 benign: {r3b_fp_ben53.sum()}")
if r3b_fp_ben53.sum() > 0:
    for idx_fp in np.where(r3b_fp_ben53)[0][:20]:
        print(f"  FP sample: {x53[idx_fp, :8]}")
print(f"R3b FP on CTU-54 benign: {r3b_fp_ben54.sum()}")

"""Analyze the 1210 MLP-only attacks on CTU-53 that rules don't cover."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch, torch.nn as nn
import math

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

from tools.train_v7 import load_cap, TEST_CAPS, IDX_UDP, IDX_SUSTAINED, IDX_VERY_EPH, IDX_NO_RESP, IDX_UDP_MED
from integrityguard.network_flow_schema import FEATURE_NAMES

IDX_PKTS = 1; IDX_BYTES = 2; IDX_DIR_ASYM = 10; IDX_UDP_DUR = 15

x53, y53 = load_cap(TEST_CAPS['53'])
xn = np.clip((x53 - q25) / iqr, -10, 10)

is_sustained = xn[:, IDX_SUSTAINED] > 0.5
is_very_eph = xn[:, IDX_VERY_EPH] > 0.5
is_no_resp = xn[:, IDX_NO_RESP] > 0.5
has_pkts_gt4 = xn[:, IDX_PKTS] > 0.603
has_dir_asym = xn[:, IDX_DIR_ASYM] > -0.25
is_small_bytes = xn[:, IDX_BYTES] < -0.5
is_med = xn[:, IDX_UDP_MED] > 0.5

r1c = is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym
r2 = is_very_eph & is_no_resp & is_small_bytes
rule_covered = r1c | r2

# MLP-only attacks
mlp_only = (y53 == 1) & ~rule_covered
print(f"MLP-only attacks on CTU-53: {mlp_only.sum()}")
print(f"  Sustained: {(mlp_only & is_sustained).sum()}")
print(f"  Very_eph: {(mlp_only & is_very_eph).sum()}")
print(f"  Medium: {(mlp_only & is_med).sum()}")
print(f"  None of above (non-UDP?): {(mlp_only & ~is_sustained & ~is_very_eph & ~is_med).sum()}")

# Analyze uncovered sustained attacks
unc_sust = mlp_only & is_sustained
print(f"\n=== Uncovered SUSTAINED attacks: {unc_sust.sum()} ===")
if unc_sust.sum() > 0:
    xn_s = xn[unc_sust]
    print(f"  no_resp: {(xn_s[:,IDX_NO_RESP]>0.5).sum()}")
    print(f"  pkts>4: {(xn_s[:,IDX_PKTS]>0.603).sum()}")
    print(f"  dir_asym>-0.25: {(xn_s[:,IDX_DIR_ASYM]>-0.25).sum()}")
    print(f"  dir_asym p10/p50/p90: {np.percentile(xn_s[:,IDX_DIR_ASYM],[10,50,90])}")
    print(f"  So these fail: (pkts>4 OR no_resp) AND dir_asym>-0.25")
    # How many fail only on dir_asym (dir_asym <= -0.25)?
    no_resp_or_pkts = (xn_s[:,IDX_NO_RESP]>0.5) | (xn_s[:,IDX_PKTS]>0.603)
    print(f"  Have (no_resp OR pkts>4): {no_resp_or_pkts.sum()}")
    print(f"    Of those, dir_asym <= -0.25: {(no_resp_or_pkts & (xn_s[:,IDX_DIR_ASYM]<=-0.25)).sum()}")
    # What about with relaxed dir_asym?
    for thr in [-0.5, -0.4, -0.3, -0.25, -0.2, -0.1, 0.0]:
        mask = is_sustained & (has_pkts_gt4 | is_no_resp) & (xn[:, IDX_DIR_ASYM] > thr)
        tp = int((y53==1)[mask].sum()); fp = int((y53==0)[mask].sum())
        print(f"  R1c with dir_asym>{thr:.2f}: TP={tp} FP={fp}")
    
    # What about removing dir_asym entirely?
    mask_no_asym = is_sustained & (has_pkts_gt4 | is_no_resp)
    tp = int((y53==1)[mask_no_asym].sum()); fp = int((y53==0)[mask_no_asym].sum())
    print(f"  R1c without dir_asym: TP={tp} FP={fp}")
    
    # Completely relax - all sustained
    mask_all_sust = is_sustained
    tp = int((y53==1)[mask_all_sust].sum()); fp = int((y53==0)[mask_all_sust].sum())
    print(f"  All sustained: TP={tp} FP={fp}")

# Analyze uncovered very_eph attacks  
unc_veph = mlp_only & is_very_eph
print(f"\n=== Uncovered VERY_EPH attacks: {unc_veph.sum()} ===")
if unc_veph.sum() > 0:
    xn_v = xn[unc_veph]
    print(f"  no_resp=1: {(xn_v[:,IDX_NO_RESP]>0.5).sum()}")
    print(f"  small_bytes (<-0.5): {(xn_v[:,IDX_BYTES]<-0.5).sum()}")
    print(f"  bytes p10/p50/p90: {np.percentile(xn_v[:,IDX_BYTES],[10,50,90])}")
    print(f"  dir_asym p10/p50/p90: {np.percentile(xn_v[:,IDX_DIR_ASYM],[10,50,90])}")
    # Very eph attacks with no_resp=1 but NOT small bytes
    no_resp_no_small = (xn_v[:,IDX_NO_RESP]>0.5) & ~(xn_v[:,IDX_BYTES]<-0.5)
    print(f"  no_resp=1 but bytes >= -0.5: {no_resp_no_small.sum()}")
    # Try rule: very_eph + no_resp (without small_bytes requirement)
    mask_veph_noresp = is_very_eph & is_no_resp
    tp53 = int((y53==1)[mask_veph_noresp].sum()); fp53 = int((y53==0)[mask_veph_noresp].sum())
    print(f"  Rule: very_eph+no_resp (no byte constraint): TP={tp53} FP={fp53} on CTU-53")
    # Check on CTU-54
    x54, y54 = load_cap(TEST_CAPS['54'])
    xn54 = np.clip((x54 - q25) / iqr, -10, 10)
    is_veph54 = xn54[:,IDX_VERY_EPH] > 0.5; is_nr54 = xn54[:,IDX_NO_RESP] > 0.5
    mask54 = is_veph54 & is_nr54
    tp54 = int((y54==1)[mask54].sum()); fp54 = int((y54==0)[mask54].sum())
    print(f"  Rule: very_eph+no_resp (no byte constraint): TP={tp54} FP={fp54} on CTU-54")

# Analyze uncovered medium attacks
unc_med = mlp_only & is_med
print(f"\n=== Uncovered MEDIUM attacks: {unc_med.sum()} ===")
if unc_med.sum() > 0:
    xn_m = xn[unc_med]
    print(f"  no_resp: {(xn_m[:,IDX_NO_RESP]>0.5).sum()}")
    print(f"  pkts>4: {(xn_m[:,IDX_PKTS]>0.603).sum()}")
    print(f"  dir_asym p10/p50/p90: {np.percentile(xn_m[:,IDX_DIR_ASYM],[10,50,90])}")
    # Medium benign stats
    med_ben = (y53==0) & is_med
    xn_mb = xn[med_ben]
    print(f"\n  Medium BENIGN on CTU-53: {med_ben.sum()}")
    print(f"    no_resp=0: {(xn_mb[:,IDX_NO_RESP]<0.5).sum()} (all)")
    print(f"    pkts<=4: {(xn_mb[:,IDX_PKTS]<=0.603).sum()} (all)")
    print(f"    dir_asym p10/p50/p90: {np.percentile(xn_mb[:,IDX_DIR_ASYM],[10,50,90])}")
    
    # Direction-based thresholds for medium
    print(f"\n  dir_asym thresholds for medium attacks vs benign:")
    for thr in [0.0, 0.1, 0.2, 0.3, 0.4, 0.45, 0.5]:
        mask = is_med & (xn[:, IDX_DIR_ASYM] > thr)
        tp = int((y53==1)[mask].sum()); fp = int((y53==0)[mask].sum())
        x54, y54 = load_cap(TEST_CAPS['54'])
        xn54 = np.clip((x54-q25)/iqr,-10,10); is_med54 = xn54[:,IDX_UDP_MED]>0.5
        mask54 = is_med54 & (xn54[:,IDX_DIR_ASYM]>thr)
        tp54 = int((y54==1)[mask54].sum()); fp54 = int((y54==0)[mask54].sum())
        print(f"    medium+dir_asym>{thr:.2f}: CTU53 TP={tp} FP={fp} | CTU54 TP={tp54} FP={fp54}")
        if fp==0 and fp54 <= 2:
            print(f"      *** SAFE RULE FOUND ***")

"""
Analyze uncovered benign UDP flows (not very_eph, have sustained/medium/no_resp)
vs attack UDP to find other discriminating features.
"""
import csv, sys, os
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14; IDX_NO_RESP=16
IDX_TCP=4; IDX_OTHER=6

DATA_53 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110819_ctu53.binetflow"
DATA_54 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110815-3_ctu54.binetflow"

def class_for_label(lbl):
    return 1 if lbl.startswith("flow=From-Botnet-") else 0

def load_cap(path):
    xs, ys, lbls = [], [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            lbl = row.get("Label","")
            ys.append(class_for_label(lbl))
            lbls.append(lbl)
    return np.array(xs, np.float32), np.array(ys, np.int64), lbls

for name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*60}")
    print(f"=== {name} ===")
    if not os.path.exists(path):
        print("  NOT FOUND"); continue
    x, y, lbls = load_cap(path)
    is_udp = x[:,IDX_UDP]>0.5
    is_ben = y==0; is_atk = y==1
    is_veph = x[:,IDX_VERY_EPH]>0.5; is_sust = x[:,IDX_SUSTAINED]>0.5
    is_med = x[:,IDX_UDP_MED]>0.5; is_no_resp = x[:,IDX_NO_RESP]>0.5
    
    # "uncovered" benign = NOT (very_eph AND NOT sustained AND NOT no_resp AND NOT medium)
    # i.e., benign UDP that has at least one attack-like feature
    benign_rule = is_veph & ~is_sust & ~is_no_resp & ~is_med
    uncovered = is_ben & is_udp & ~benign_rule
    attack_udp = is_atk & is_udp
    
    ub = x[uncovered]; au = x[attack_udp]
    print(f"  Uncovered benign UDP: {len(ub)}")
    print(f"  Attack UDP: {len(au)}")
    
    print(f"\n  Feature comparison (uncovered benign vs attack UDP):")
    print(f"  {'Feature':25} {'Ben_mean':10} {'Atk_mean':10} {'Ben_std':10} {'Atk_std':10}")
    for i, fname in enumerate(FEATURE_NAMES):
        if i == IDX_UDP: continue  # all UDP
        bm = ub[:,i].mean(); am = au[:,i].mean()
        bs = ub[:,i].std(); as_ = au[:,i].std()
        # Highlight features with large separation
        sep = abs(bm - am) / max(0.01, (bs + as_) / 2)
        marker = "  <<==" if sep > 1.0 else ("  <" if sep > 0.5 else "")
        print(f"  {fname:25} {bm:10.4f} {am:10.4f} {bs:10.4f} {as_:10.4f}{marker}")
    
    # Look at specific flow types in uncovered benign
    print(f"\n  Uncovered benign breakdown by feature type:")
    n = len(ub)
    sust_only = is_sust[uncovered]
    med_only = is_med[uncovered]
    no_resp_only = is_no_resp[uncovered]
    veph_rem = is_veph[uncovered]
    print(f"    sustained (dur>=1):  {sust_only.sum():8d} ({100*sust_only.mean():.1f}%)")
    print(f"    udp_medium (0.001-1): {med_only.sum():8d} ({100*med_only.mean():.1f}%)")
    print(f"    no_resp:             {no_resp_only.sum():8d} ({100*no_resp_only.mean():.1f}%)")
    print(f"    very_eph (residual): {veph_rem.sum():8d} ({100*veph_rem.mean():.1f}%)")
    
    # For sustained uncovered benign vs attack:
    sust_ben_ub = ub[sust_only]
    sust_atk = au[is_sust[attack_udp]]
    if len(sust_ben_ub) > 0 and len(sust_atk) > 0:
        print(f"\n  Sustained benign (n={len(sust_ben_ub)}) vs sustained attack (n={len(sust_atk)}):")
        for i, fname in enumerate(FEATURE_NAMES):
            if i == IDX_UDP: continue
            bm = sust_ben_ub[:,i].mean(); am = sust_atk[:,i].mean()
            if abs(bm - am) > 0.3:
                print(f"    {fname:25} ben={bm:.4f}  atk={am:.4f}  diff={bm-am:.4f}")

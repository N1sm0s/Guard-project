"""
Test duration-based rules for sustained benign UDP.
Key insight: benign sustained UDP has much longer duration than attack sustained UDP.
"""
import csv, sys, os, math
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14; IDX_NO_RESP=16
IDX_DUR=0; IDX_UDP_DUR_LOG=15

DATA_53 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110819_ctu53.binetflow"
DATA_54 = r"F:\New\integrityguard\outputs\network-eval\official-ctu13\capture20110815-3_ctu54.binetflow"

def class_for_label(lbl):
    return 1 if lbl.startswith("flow=From-Botnet-") else 0

def load_cap(path):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(class_for_label(row.get("Label","")))
    return np.array(xs, np.float32), np.array(ys, np.int64)

def wilson_hi(k, n, z=1.96):
    if n == 0: return 0.0
    p = k/n
    return (p + z*z/(2*n) + z*np.sqrt(max(0,p*(1-p)/n) + z*z/(4*n*n))) / (1 + z*z/n)

for name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*55}")
    print(f"=== {name} ===")
    if not os.path.exists(path):
        print("  NOT FOUND"); continue
    x, y = load_cap(path)
    is_udp = x[:,IDX_UDP]>0.5
    is_ben = y==0; is_atk = y==1
    is_sust = x[:,IDX_SUSTAINED]>0.5
    is_veph = x[:,IDX_VERY_EPH]>0.5
    is_med = x[:,IDX_UDP_MED]>0.5
    is_no_resp = x[:,IDX_NO_RESP]>0.5
    
    n_ben_udp = int((is_ben & is_udp).sum())
    n_atk_udp = int((is_atk & is_udp).sum())
    
    # Duration distribution for sustained UDP
    sust_ben = x[is_ben & is_udp & is_sust, IDX_DUR]  # duration_log1p
    sust_atk = x[is_atk & is_udp & is_sust, IDX_DUR]
    
    print(f"  Sustained benign UDP duration_log1p: n={len(sust_ben)}")
    if len(sust_ben) > 0:
        for p in [0,10,25,50,75,90,95,99,100]:
            v = np.percentile(sust_ben, p)
            dur = math.exp(v) - 1
            print(f"    p{p:3d}: log1p={v:.3f} -> dur={dur:.1f}s")
    
    print(f"  Sustained attack UDP duration_log1p: n={len(sust_atk)}")
    if len(sust_atk) > 0:
        for p in [0,10,25,50,75,90,95,99,100]:
            v = np.percentile(sust_atk, p)
            dur = math.exp(v) - 1
            print(f"    p{p:3d}: log1p={v:.3f} -> dur={dur:.1f}s")
    
    # Test various duration thresholds for rule: sustained AND dur > T -> benign (score=0)
    print(f"\n  Testing rule: sustained UDP AND duration_log1p > T -> benign (score=0)")
    print(f"  {'T':>8} {'Ben_clear':>12} {'Atk_missed':>12} {'Ben_clear%':>12} {'Atk_missed%':>12}")
    for T in [3.0, 4.0, 5.0, 5.5, 6.0, 6.5, 7.0]:
        ben_clr = int((is_ben & is_udp & is_sust & (x[:,IDX_DUR]>T)).sum())
        atk_msd = int((is_atk & is_udp & is_sust & (x[:,IDX_DUR]>T)).sum())
        print(f"  {T:>8.1f} {ben_clr:>12d} {atk_msd:>12d} {100*ben_clr/max(1,n_ben_udp):>12.2f}% {100*atk_msd/max(1,n_atk_udp):>12.2f}%")
    
    # Also test for medium UDP (0.001 <= dur < 1)
    med_ben = x[is_ben & is_udp & is_med, IDX_DUR]
    med_atk = x[is_atk & is_udp & is_med, IDX_DUR]
    print(f"\n  Medium benign UDP duration_log1p: n={len(med_ben)}")
    if len(med_ben) > 0:
        for p in [0,25,50,75,90,99]:
            v = np.percentile(med_ben, p)
            dur = math.exp(v) - 1
            print(f"    p{p:3d}: log1p={v:.3f} -> dur={dur:.3f}s")
    print(f"  Medium attack UDP: n={len(med_atk)}")
    if len(med_atk) > 0:
        for p in [0,25,50,75,90,99]:
            v = np.percentile(med_atk, p)
            dur = math.exp(v) - 1
            print(f"    p{p:3d}: log1p={v:.3f} -> dur={dur:.3f}s")
    
    # Combining very_eph rule + sustained-long rule
    # Rule A: very_eph AND NOT sustained AND NOT no_resp AND NOT medium -> benign
    rule_A = is_veph & ~is_sust & ~is_no_resp & ~is_med & is_udp
    # Rule B: sustained AND duration_log1p > 5.0 -> benign
    rule_B_T = 5.0
    rule_B = is_sust & (x[:,IDX_DUR] > rule_B_T) & is_udp
    # Combined rule (force to 0):
    combined = rule_A | rule_B
    
    ben_clr_combined = int((is_ben & combined).sum())
    atk_msd_combined = int((is_atk & combined).sum())
    remaining_ben = n_ben_udp - ben_clr_combined
    remaining_atk = n_atk_udp - atk_msd_combined  # recall still possible
    
    print(f"\n  Combined rule (A: very_eph basic + B: sustained>5.0):")
    print(f"    Benign cleared: {ben_clr_combined}/{n_ben_udp} = {100*ben_clr_combined/max(1,n_ben_udp):.1f}%")
    print(f"    Attacks missed: {atk_msd_combined}/{n_atk_udp} = {100*atk_msd_combined/max(1,n_atk_udp):.1f}%")
    print(f"    Remaining benign to handle (need model): {remaining_ben}")
    max_fp = 0
    while True:
        p = max_fp/n_ben_udp; z=1.96
        ci_hi = (p + z*z/(2*n_ben_udp) + z*np.sqrt(max(0,p*(1-p)/n_ben_udp) + z*z/(4*n_ben_udp*n_ben_udp))) / (1 + z*z/n_ben_udp)
        if ci_hi > 0.001: break
        max_fp += 1
    print(f"    Max FPs to pass Wilson: {max_fp-1}")
    print(f"    Model needs to get <={max_fp-1} FPs from {remaining_ben} remaining benign UDP")
    
    # What do remaining benign flows look like?
    rem_ben = x[is_ben & is_udp & ~combined]
    if len(rem_ben) > 0:
        print(f"    Remaining benign features:")
        print(f"      very_eph: {(rem_ben[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"      sustained: {(rem_ben[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"      medium: {(rem_ben[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"      no_resp: {(rem_ben[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"      duration mean: {rem_ben[:,IDX_DUR].mean():.4f}")

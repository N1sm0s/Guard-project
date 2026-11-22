"""
Final rule design - correct indices.
Focus: What can we zero-FP rule out as benign from medium UDP?
Key: medium+no_resp benign (865/0 in CTU-53, 3652/0 in CTU-54)
     medium+high_pkt_rate rules
"""
import csv, sys, os, math
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

# Correct indices from FEATURE_NAMES
IDX_DUR=0; IDX_PKTS=1; IDX_BYTES=2; IDX_MAX_DIR_BYTES=3
IDX_TCP=4; IDX_UDP=5
IDX_BYTES_PER_PKT=8; IDX_PKT_RATE=9; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_LOG_PKT_DUR=12; IDX_SUSTAINED=13
IDX_UDP_MED=14; IDX_UDP_DUR=15; IDX_NO_RESP=16

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

for cap_name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*60}")
    print(f"=== {cap_name} ===")
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
    
    # --- RULE CANDIDATES ---
    
    # Rule A: very_eph + NOT sustained + NOT no_resp + NOT medium -> benign
    rule_A = is_veph & ~is_sust & ~is_no_resp & ~is_med & is_udp
    
    # Rule B: sustained + long_duration -> benign (use T=5.0 on IDX_DUR)
    rule_B = is_sust & (x[:,IDX_DUR] > 5.0) & is_udp
    
    # Rule C: medium + no_resp -> benign (CTU-54: 0 attacks!)
    rule_C = is_med & is_no_resp & is_udp
    
    # Rule D: medium + NOT no_resp + pkt_rate_log1p > T -> benign?
    # Let's test various T
    print(f"\n  Medium benign pkt_rate distribution:")
    med_ben = x[is_ben & is_udp & is_med]
    med_atk = x[is_atk & is_udp & is_med]
    print(f"    n_ben={len(med_ben)}, n_atk={len(med_atk)}")
    for pct in [10,25,50,75,90,95,99]:
        bv = np.percentile(med_ben[:,IDX_PKT_RATE], pct) if len(med_ben)>0 else 0
        av = np.percentile(med_atk[:,IDX_PKT_RATE], pct) if len(med_atk)>0 else 0
        print(f"    p{pct:2d}: ben={bv:.3f} atk={av:.3f}")
    
    print(f"\n  Testing pkt_rate_log1p threshold for medium+NOT no_resp benign rule:")
    for T in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0]:
        rule_D = is_med & ~is_no_resp & (x[:,IDX_PKT_RATE] > T) & is_udp
        bc = int((is_ben & rule_D).sum())
        am = int((is_atk & rule_D).sum())
        print(f"    T={T:.1f}: ben_clr={bc}({100*bc/n_ben_udp:.1f}%), atk_msd={am}({100*am/n_atk_udp:.1f}%)")
    
    # Combined: A + B + C + D(best)
    # Find best T for D that misses 0 attacks
    best_T = None
    best_bc = 0
    for T_candidate in np.arange(0.5, 7.0, 0.1):
        rule_D = is_med & ~is_no_resp & (x[:,IDX_PKT_RATE] > T_candidate) & is_udp
        am = int((is_atk & rule_D).sum())
        if am == 0:
            bc = int((is_ben & rule_D).sum())
            if bc > best_bc:
                best_bc = bc
                best_T = T_candidate
    
    if best_T is not None:
        print(f"\n  Best zero-FP pkt_rate threshold for medium: T={best_T:.1f}")
        rule_D_best = is_med & ~is_no_resp & (x[:,IDX_PKT_RATE] > best_T) & is_udp
        bc_D = int((is_ben & rule_D_best).sum())
        am_D = int((is_atk & rule_D_best).sum())
        print(f"    Rule D (pkt>{best_T:.1f}): ben_clr={bc_D}, atk_msd={am_D}")
    else:
        print(f"\n  No zero-attack pkt_rate threshold found for medium")
        rule_D_best = is_med & (x[:,IDX_PKT_RATE] > 999) & is_udp  # empty rule
    
    # Rule E: total_packets_log1p analysis for medium UDP
    print(f"\n  Testing total_packets threshold for medium+NOT no_resp:")
    for T in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5]:
        # benign has more packets than attack?
        rule_E = is_med & ~is_no_resp & (x[:,IDX_PKTS] > T) & is_udp
        bc = int((is_ben & rule_E).sum())
        am = int((is_atk & rule_E).sum())
        print(f"    pkts>{T:.1f}: ben_clr={bc}({100*bc/n_ben_udp:.1f}%), atk_msd={am}({100*am/n_atk_udp:.1f}%)")
    
    # Combined final
    combined = rule_A | rule_B | rule_C | rule_D_best
    bc_total = int((is_ben & combined).sum())
    am_total = int((is_atk & combined).sum())
    rem_ben = n_ben_udp - bc_total
    rem_atk = n_atk_udp - am_total
    
    print(f"\n  === FINAL COMBINED RULE (A+B+C+D) ===")
    print(f"  Rule A (very_eph basic):   ben={int((is_ben&rule_A).sum())}  atk={int((is_atk&rule_A).sum())}")
    print(f"  Rule B (sustained>5.0dur): ben={int((is_ben&rule_B).sum())}  atk={int((is_atk&rule_B).sum())}")
    print(f"  Rule C (medium+no_resp):   ben={int((is_ben&rule_C).sum())}  atk={int((is_atk&rule_C).sum())}")
    print(f"  Rule D (medium+pkt>{best_T:.1f}):  ben={int((is_ben&rule_D_best).sum())}  atk={int((is_atk&rule_D_best).sum())}")
    print(f"  TOTAL cleared: {bc_total}/{n_ben_udp} = {100*bc_total/n_ben_udp:.1f}%")
    print(f"  TOTAL missed:  {am_total}/{n_atk_udp} = {100*am_total/n_atk_udp:.1f}%")
    print(f"  REMAINING benign: {rem_ben}")
    print(f"  REMAINING attack: {rem_atk}")
    
    # What max FPs can model make?
    max_fp = 0
    while True:
        p = max_fp/n_ben_udp; z=1.96
        ci_hi = (p + z*z/(2*n_ben_udp) + z*np.sqrt(max(0,p*(1-p)/n_ben_udp) + z*z/(4*n_ben_udp*n_ben_udp))) / (1 + z*z/n_ben_udp)
        if ci_hi > 0.001: break
        max_fp += 1
    print(f"  Max total FPs to pass Wilson (global): {max_fp-1}")
    
    # What features characterize remaining benign?
    rem_ben_x = x[is_ben & is_udp & ~combined]
    rem_atk_x = x[is_atk & is_udp & ~combined]
    if len(rem_ben_x) > 0:
        print(f"\n  Remaining {len(rem_ben_x)} benign features:")
        print(f"    very_eph:  {(rem_ben_x[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    sustained: {(rem_ben_x[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"    medium:    {(rem_ben_x[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"    no_resp:   {(rem_ben_x[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"    pkt_rate mean: {rem_ben_x[:,IDX_PKT_RATE].mean():.4f}")
        print(f"    duration mean: {rem_ben_x[:,IDX_DUR].mean():.4f}")
        print(f"    pkts mean:     {rem_ben_x[:,IDX_PKTS].mean():.4f}")
    if len(rem_atk_x) > 0:
        print(f"\n  Remaining {len(rem_atk_x)} attack features:")
        print(f"    pkt_rate mean: {rem_atk_x[:,IDX_PKT_RATE].mean():.4f}")
        print(f"    duration mean: {rem_atk_x[:,IDX_DUR].mean():.4f}")

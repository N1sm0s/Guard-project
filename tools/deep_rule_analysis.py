"""
Deep analysis of medium-duration UDP flows for benign rule design.
Focus: CTU-53 medium benign (52K) vs CTU-53 medium attack (431)
Key question: can we find rules that clear most medium benign with <=0 attacks missed?
"""
import csv, sys, os, math
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14; IDX_NO_RESP=16
IDX_DUR=0; IDX_UDP_DUR_LOG=15; IDX_PKT_RATE=3

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

def show_feature_dist(label, x_ben, x_atk, feat_names):
    print(f"\n  Feature distributions for {label}:")
    for i, name in enumerate(feat_names):
        b = x_ben[:,i]; a = x_atk[:,i]
        print(f"    {name:35s}: ben={b.mean():7.4f}(±{b.std():5.3f}) atk={a.mean():7.4f}(±{a.std():5.3f})")

for cap_name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*60}")
    print(f"=== {cap_name} Deep Medium-UDP Analysis ===")
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
    
    # Focus on medium UDP
    med_ben_mask = is_ben & is_udp & is_med
    med_atk_mask = is_atk & is_udp & is_med
    x_mben = x[med_ben_mask]
    x_matk = x[med_atk_mask]
    
    print(f"\n  Medium UDP: {len(x_mben)} benign, {len(x_matk)} attacks")
    
    # Feature names for display
    feat_names = FEATURE_NAMES[:17] if len(FEATURE_NAMES)>=17 else FEATURE_NAMES
    
    show_feature_dist("Medium UDP", x_mben, x_matk, feat_names)
    
    # Test rules for medium benign:
    # Rule: medium AND pkt_rate < threshold -> benign
    print(f"\n  Testing pkt_rate threshold for medium UDP:")
    print(f"  {'T':>8} {'Ben_clr':>10} {'Atk_msd':>10} {'Ben%':>8} {'Atk%':>8}")
    for T in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0]:
        pkt = x[:,IDX_PKT_RATE]
        bc = int((med_ben_mask & (pkt < T)).sum())
        am = int((med_atk_mask & (pkt < T)).sum())
        print(f"  {T:>8.1f} {bc:>10d} {am:>10d} {100*bc/max(1,n_ben_udp):>8.2f}% {100*am/max(1,n_atk_udp):>8.2f}%")
    
    # Rule: medium AND no_resp -> attack (force score 1?)
    # Or: medium AND NOT no_resp -> benign?
    bc_noresp = int((med_ben_mask & is_no_resp).sum())
    am_noresp = int((med_atk_mask & is_no_resp).sum())
    bc_resp = int((med_ben_mask & ~is_no_resp).sum())
    am_resp = int((med_atk_mask & ~is_no_resp).sum())
    print(f"\n  Medium + no_resp: {bc_noresp} benign, {am_noresp} attacks")
    print(f"  Medium + has_resp: {bc_resp} benign, {am_resp} attacks")
    
    # What pkt_rate dist looks like for medium+no_resp benign vs attack
    mr_ben = x[med_ben_mask & is_no_resp]
    mr_atk = x[med_atk_mask & is_no_resp]
    if len(mr_ben) > 0 and len(mr_atk) > 0:
        print(f"  Medium+no_resp benign pkt_rate: {mr_ben[:,IDX_PKT_RATE].mean():.4f}")
        print(f"  Medium+no_resp attack pkt_rate: {mr_atk[:,IDX_PKT_RATE].mean():.4f}")
    
    # Comprehensive rule test: very_eph + sustained>5 + medium+pkt<2
    rule_veph = is_veph & ~is_sust & ~is_no_resp & ~is_med & is_udp
    rule_sust_long = is_sust & (x[:,IDX_DUR] > 5.0) & is_udp
    # Various thresholds for medium pkt_rate rule
    for PKT_T in [1.0, 1.5, 2.0, 2.5, 3.0, 4.0]:
        rule_med_low_pkt = is_med & (x[:,IDX_PKT_RATE] < PKT_T) & is_udp
        combined = rule_veph | rule_sust_long | rule_med_low_pkt
        
        bc_comb = int((is_ben & combined).sum())
        am_comb = int((is_atk & combined).sum())
        rem_ben = n_ben_udp - bc_comb
        
        p=am_comb/n_atk_udp if n_atk_udp else 0
        ci_hi_fpr_ben = wilson_hi(bc_comb - bc_comb + max(0, rem_ben - rem_ben), rem_ben)  # placeholder
        
        print(f"\n  Rule: very_eph + sustained>5 + medium(pkt<{PKT_T:.1f}):")
        print(f"    Ben cleared: {bc_comb}/{n_ben_udp} = {100*bc_comb/n_ben_udp:.1f}%")
        print(f"    Atk missed: {am_comb}/{n_atk_udp} = {100*am_comb/n_atk_udp:.1f}%")
        print(f"    Remaining benign: {rem_ben}")
        
        # What % of remaining benign are no_resp or have high pkt_rate?
        rem_ben_mask = is_ben & is_udp & ~combined
        rem_atk_mask = is_atk & is_udp & ~combined
        rem_b = x[rem_ben_mask]
        rem_a = x[rem_atk_mask]
        if len(rem_b) > 0:
            print(f"    Remaining ben no_resp: {(rem_b[:,IDX_NO_RESP]>0.5).mean():.2%}")
            print(f"    Remaining ben dur mean: {rem_b[:,IDX_DUR].mean():.4f}")
            print(f"    Remaining ben pkt_rate mean: {rem_b[:,IDX_PKT_RATE].mean():.4f}")
        if len(rem_a) > 0:
            print(f"    Remaining atk: {len(rem_a)}, pkt_rate mean={rem_a[:,IDX_PKT_RATE].mean():.4f}")

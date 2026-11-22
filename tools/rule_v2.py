"""
Rule v2: test log_total_pkts_x_dur and other interactions.
Key insight: for medium UDP, attacks have higher log_total_pkts_x_dur than benign.
Also test: total_bytes, bytes_per_pkt thresholds.
"""
import csv, sys, os
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_DUR=0; IDX_PKTS=1; IDX_BYTES=2; IDX_MAX_DIR=3
IDX_UDP=5; IDX_BPP=8; IDX_PKT_RATE=9; IDX_DIR_ASYM=10
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

def test_benign_threshold(label, feat_idx, threshold, comparison, x, y, is_udp, n_ben_udp, n_atk_udp, extra_mask=None):
    """Test a threshold rule for benign classification."""
    if comparison == '<':
        rule = x[:,feat_idx] < threshold
    else:
        rule = x[:,feat_idx] > threshold
    if extra_mask is not None:
        rule = rule & extra_mask
    rule = rule & is_udp
    bc = int(((y==0) & rule).sum())
    am = int(((y==1) & rule).sum())
    return bc, am, 100*bc/max(1,n_ben_udp), 100*am/max(1,n_atk_udp)

for cap_name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n{'='*55}")
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
    
    print(f"  Total benign UDP: {n_ben_udp}, attack UDP: {n_atk_udp}")
    
    # Test log_total_pkts_x_dur < T for medium UDP
    print(f"\n  log_total_pkts_x_dur < T (medium UDP) -> benign rule:")
    for T in [0.0, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5]:
        bc, am, bcp, amp = test_benign_threshold(
            f"log_pkt_x_dur<{T}", IDX_LOG_PKT_DUR, T, '<', 
            x, y, is_udp & is_med, n_ben_udp, n_atk_udp)
        print(f"    T={T:.2f}: ben_clr={bc}({bcp:.1f}%), atk_msd={am}({amp:.1f}%)")
    
    # Test for medium (not just all UDP)
    print(f"\n  pkt_rate_log1p dist for medium UDP:")
    mb = x[is_ben & is_udp & is_med]; ma = x[is_atk & is_udp & is_med]
    for pct in [1,5,10,25,50,75,90,95,99]:
        bv = np.percentile(mb[:,IDX_PKT_RATE], pct) if len(mb)>0 else 0
        av = np.percentile(ma[:,IDX_PKT_RATE], pct) if len(ma)>0 else 0
        print(f"    p{pct:2d}: ben={bv:.3f} atk={av:.3f}")
    
    # Find best zero-FP threshold for each feature for medium UDP
    for feat_idx, feat_name in [(IDX_LOG_PKT_DUR, 'log_pkts_x_dur<'), (IDX_PKT_RATE, 'pkt_rate<'), 
                                  (IDX_BYTES, 'bytes<'), (IDX_BPP, 'bpp<'), (IDX_DIR_ASYM, 'dir_asym<')]:
        # Scan for best zero-FP threshold
        vals_ben = x[(is_ben & is_udp & is_med), feat_idx]
        vals_atk = x[(is_atk & is_udp & is_med), feat_idx]
        if len(vals_ben) == 0 or len(vals_atk) == 0:
            continue
        atk_min = vals_atk.min()
        # Test thresholds below min attack value
        thresholds = np.linspace(vals_ben.min(), min(atk_min, np.percentile(vals_ben, 50)), 20)
        best_bc = 0; best_T = None
        for T in thresholds:
            bc = int(((is_ben & is_udp & is_med) & (x[:,feat_idx] < T)).sum())
            am = int(((is_atk & is_udp & is_med) & (x[:,feat_idx] < T)).sum())
            if am == 0 and bc > best_bc:
                best_bc = bc; best_T = T
        if best_T is not None:
            print(f"  Zero-FP rule: {feat_name}{best_T:.4f} -> clears {best_bc} benign, 0 attacks (medium)")
    
    # Also test for sustained UDP
    print(f"\n  Sustained UDP zero-FP rules:")
    for feat_idx, feat_name, direction in [(IDX_DUR, 'dur<', '<'), (IDX_PKT_RATE, 'pkt_rate>', '>'),
                                             (IDX_LOG_PKT_DUR, 'log_pkt_dur<', '<')]:
        vals_ben = x[(is_ben & is_udp & is_sust), feat_idx]
        vals_atk = x[(is_atk & is_udp & is_sust), feat_idx]
        if len(vals_ben) == 0 or len(vals_atk) == 0:
            continue
        if direction == '<':
            atk_min = vals_atk.min()
            thresholds = np.linspace(vals_ben.min(), min(atk_min, np.percentile(vals_ben, 90)), 20)
        else:
            atk_max = vals_atk.max()
            thresholds = np.linspace(max(atk_max, np.percentile(vals_ben, 10)), vals_ben.max(), 20)
        best_bc = 0; best_T = None
        for T in thresholds:
            if direction == '<':
                bc = int(((is_ben & is_udp & is_sust) & (x[:,feat_idx] < T)).sum())
                am = int(((is_atk & is_udp & is_sust) & (x[:,feat_idx] < T)).sum())
            else:
                bc = int(((is_ben & is_udp & is_sust) & (x[:,feat_idx] > T)).sum())
                am = int(((is_atk & is_udp & is_sust) & (x[:,feat_idx] > T)).sum())
            if am == 0 and bc > best_bc:
                best_bc = bc; best_T = T
        if best_T is not None:
            print(f"    Zero-FP: {feat_name}{best_T:.4f} -> clears {best_bc} benign, 0 attacks (sustained)")
    
    # What would a full scan of ALL UDP zero-FP rules give?
    print(f"\n  ALL UDP zero-FP rules (scanning all features, both directions):")
    total_zero_fp = set()
    for feat_idx, feat_name in enumerate(FEATURE_NAMES[:17]):
        vals_ben = x[(is_ben & is_udp), feat_idx]
        vals_atk = x[(is_atk & is_udp), feat_idx]
        if len(vals_atk) == 0: continue
        for direction in ['<', '>']:
            if direction == '<':
                atk_lim = vals_atk.min()
                thresholds = np.linspace(vals_ben.min(), min(atk_lim, np.percentile(vals_ben, 50)), 15)
            else:
                atk_lim = vals_atk.max()
                thresholds = np.linspace(max(atk_lim, np.percentile(vals_ben, 50)), vals_ben.max(), 15)
            for T in thresholds:
                if direction == '<':
                    bc = int(((is_ben & is_udp) & (x[:,feat_idx] < T)).sum())
                    am = int(((is_atk & is_udp) & (x[:,feat_idx] < T)).sum())
                else:
                    bc = int(((is_ben & is_udp) & (x[:,feat_idx] > T)).sum())
                    am = int(((is_atk & is_udp) & (x[:,feat_idx] > T)).sum())
                if am == 0 and bc > 500:
                    key = f"{feat_name}{direction}{T:.4f}"
                    if key not in total_zero_fp:
                        total_zero_fp.add(key)
                        print(f"    {feat_name}{direction}{T:.4f}: clears {bc} benign, 0 attacks")
                        break  # only show best T per direction per feature

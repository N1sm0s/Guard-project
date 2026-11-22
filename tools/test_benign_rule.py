"""
Test proposed benign override rule: very_eph AND NOT sustained AND NOT no_resp AND NOT udp_medium -> 0.0
Check: how many benign UDP would be forced to 0 (good - FP reduction)
       how many attack UDP would be wrongly forced to 0 (bad - FN creation)
"""
import csv, sys, os
sys.path.insert(0, r"F:\New\integrityguard")
import numpy as np
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_UDP_MED=14; IDX_NO_RESP=16

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

for name, path in [("CTU-53", DATA_53), ("CTU-54", DATA_54)]:
    print(f"\n=== {name} ===")
    if not os.path.exists(path):
        print("  NOT FOUND"); continue
    x, y = load_cap(path)
    is_udp = x[:,IDX_UDP]>0.5
    is_ben = y==0; is_atk = y==1
    
    is_veph = x[:,IDX_VERY_EPH]>0.5
    is_sust = x[:,IDX_SUSTAINED]>0.5
    is_med  = x[:,IDX_UDP_MED]>0.5
    is_no_resp = x[:,IDX_NO_RESP]>0.5
    
    # Proposed benign rule: very_eph AND NOT (any attack indicator)
    benign_rule = is_veph & ~is_sust & ~is_no_resp & ~is_med
    # Only applies to UDP
    benign_rule_udp = benign_rule & is_udp
    
    n_udp_ben = int((is_ben & is_udp).sum())
    n_udp_atk = int((is_atk & is_udp).sum())
    
    # Benign flows forced to 0 by rule (TRUE NEGATIVES = good)
    ben_ruled = int((is_ben & benign_rule_udp).sum())
    # Attack flows wrongly forced to 0 by rule (FALSE NEGATIVES = BAD!)
    atk_ruled = int((is_atk & benign_rule_udp).sum())
    
    print(f"  UDP benign={n_udp_ben}, UDP attack={n_udp_atk}")
    print(f"  Benign UDP covered by rule: {ben_ruled}/{n_udp_ben} = {100*ben_ruled/max(1,n_udp_ben):.1f}%")
    print(f"  Attack UDP wrongly covered: {atk_ruled}/{n_udp_atk} = {100*atk_ruled/max(1,n_udp_atk):.1f}%")
    print(f"  Net: removes {ben_ruled} FPs, creates {atk_ruled} FNs")
    
    # Also try more relaxed rule: very_eph AND NOT sustained AND NOT no_resp (allow medium)
    benign_rule2 = is_veph & ~is_sust & ~is_no_resp
    benign_rule2_udp = benign_rule2 & is_udp
    ben_ruled2 = int((is_ben & benign_rule2_udp).sum())
    atk_ruled2 = int((is_atk & benign_rule2_udp).sum())
    print(f"\n  Alt rule (allow udp_medium): covers {ben_ruled2} benign ({100*ben_ruled2/max(1,n_udp_ben):.1f}%), hits {atk_ruled2} attack ({100*atk_ruled2/max(1,n_udp_atk):.1f}%)")
    
    # Feature stats for attack UDP that would be wrongly scored 0
    if atk_ruled > 0:
        atk_wrongly = x[is_atk & benign_rule_udp]
        print(f"  Wrongly-covered attacks features:")
        print(f"    very_eph: {(atk_wrongly[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    udp_medium: {(atk_wrongly[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"    no_resp: {(atk_wrongly[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"    sustained: {(atk_wrongly[:,IDX_SUSTAINED]>0.5).mean():.2%}")
    
    # How many benign remain uncovered (still need model to handle these)
    # With rule, remaining FPs come from benign NOT covered by rule
    uncovered_ben = int((is_ben & is_udp & ~benign_rule_udp).sum())
    print(f"\n  Benign UDP NOT covered by rule: {uncovered_ben}")
    if uncovered_ben > 0:
        ub = x[is_ben & is_udp & ~benign_rule_udp]
        print(f"    very_eph: {(ub[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    sustained: {(ub[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"    udp_medium: {(ub[:,IDX_UDP_MED]>0.5).mean():.2%}")
        print(f"    no_resp: {(ub[:,IDX_NO_RESP]>0.5).mean():.2%}")
        # If we apply rule to ALL remaining (force 0), what % of attacks are missed?
        # i.e. if we set threshold = infinity for the uncovered benign group
        # We need to know if uncovered_ben is small enough to satisfy Wilson CI
        
    # Wilson CI for uncovered benign (if we have 0 FPs from them)
    # What's the max FPs we can tolerate to pass?
    n_total_ben_udp = n_udp_ben
    # If rule clears ben_ruled, remaining = uncovered_ben
    # We need Wilson(fp_remaining, n_total_ben_udp) CI_hi <= 0.001
    # With ALL remaining benign uncovered but model outputs 0: fp=0, CI_hi = Wilson(0, n) 
    max_fp = 0
    while True:
        p = max_fp/n_total_ben_udp
        z = 1.96
        ci_hi = (p + z*z/(2*n_total_ben_udp) + z*np.sqrt(max(0,p*(1-p)/n_total_ben_udp) + z*z/(4*n_total_ben_udp*n_total_ben_udp))) / (1 + z*z/n_total_ben_udp)
        if ci_hi > 0.001:
            break
        max_fp += 1
    print(f"\n  Wilson analysis on FULL benign UDP ({n_total_ben_udp}):")
    print(f"  Max FP to pass CI_hi<=0.1%: {max_fp-1}")
    print(f"  Rule clears {ben_ruled} benign FPs")
    print(f"  Still need model to get <=0 FPs on remaining {uncovered_ben} benign UDP")

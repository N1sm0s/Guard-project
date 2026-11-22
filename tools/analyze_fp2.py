"""Analyze 2 FP in CTU-53 with R1 no bytes filter, and CTU-54 FP."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])
from tools.train_v7 import load_cap, TEST_CAPS
from integrityguard.network_flow_schema import FEATURE_NAMES

x53, y53 = load_cap(TEST_CAPS['53'])
x53n = np.clip((x53-q25)/iqr,-10,10)
x54, y54 = load_cap(TEST_CAPS['54'])
x54n = np.clip((x54-q25)/iqr,-10,10)

IDX_UDP=5; IDX_SUSTAINED=13; IDX_PKTS=1; IDX_BYTES=2; IDX_NO_RESP=16; IDX_VERY_EPH=11

for xn, y, name in [(x53n,y53,'CTU-53'), (x54n,y54,'CTU-54')]:
    is_udp = xn[:,IDX_UDP]>0.5
    is_sustained = xn[:,IDX_SUSTAINED]>0.5
    has_pkts_gt4 = xn[:,IDX_PKTS]>0.603
    udp_ben = (y==0)&is_udp
    udp_atk = (y==1)&is_udp
    
    r1_nob = is_sustained & has_pkts_gt4
    fp_mask = udp_ben & r1_nob
    tp_mask = udp_atk & r1_nob
    
    print(f'\n=== {name} R1 no bytes filter ===')
    print(f'TP={tp_mask.sum()} FP={fp_mask.sum()} total_udp_ben={udp_ben.sum()}')
    
    # Print FP details
    fp_rows = xn[fp_mask]
    print(f'FP details (all features):')
    for i, row in enumerate(fp_rows):
        print(f'  FP#{i+1}: ', end='')
        for j, (name_f, val) in enumerate(zip(FEATURE_NAMES, row)):
            if abs(val) > 0.1 or j in [1,2,5,11,13,16]:
                print(f'{name_f}={val:.3f}', end=' ')
        print()
    
    # Print TP stats for comparison
    tp_rows = xn[tp_mask]
    if len(tp_rows)>0:
        print(f'TP feature stats (mean):')
        for j, name_f in enumerate(FEATURE_NAMES):
            tp_mean = tp_rows[:,j].mean()
            if fp_mask.sum()>0:
                fp_mean = fp_rows[:,j].mean()
                if abs(tp_mean - fp_mean) > 0.5:
                    print(f'  {name_f}: TP_mean={tp_mean:.3f} FP_mean={fp_mean:.3f}')
    
    # Try to find filter that eliminates FP without hurting TP
    if fp_mask.sum()>0:
        print(f'\nTrying additional filters to eliminate FP:')
        for idx in range(xn.shape[1]):
            fp_vals = fp_rows[:,idx]
            tp_vals = tp_rows[:,idx] if len(tp_rows)>0 else np.array([])
            # Can we set threshold that eliminates all FP?
            for thresh in np.arange(-2, 5, 0.25):
                elim_fp = (fp_vals < thresh).all()
                if elim_fp and len(tp_vals)>0:
                    kept_tp = (tp_vals >= thresh).sum()
                    if kept_tp >= len(tp_vals)*0.9:
                        print(f'  Feature[{idx}]={FEATURE_NAMES[idx]} < {thresh:.2f}: elim all FP, keep {kept_tp}/{len(tp_vals)} TP')
                        break

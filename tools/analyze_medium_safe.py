"""Analyze medium-duration UDP attacks to find safe rule with 0 FP on CTU-53 and <3 FP on CTU-54."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch, torch.nn as nn

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

from tools.train_v7 import load_cap, TEST_CAPS, IDX_UDP, IDX_SUSTAINED, IDX_VERY_EPH, IDX_NO_RESP, IDX_UDP_MED
IDX_PKTS = 1; IDX_BYTES = 2; IDX_DIR_ASYM = 10

def analyze_cap(cap_id):
    x, y = load_cap(TEST_CAPS[cap_id])
    xn = np.clip((x - q25) / iqr, -10, 10)
    is_med = xn[:, IDX_UDP_MED] > 0.5
    is_no_resp = xn[:, IDX_NO_RESP] > 0.5
    has_dir_asym = xn[:, IDX_DIR_ASYM] > -0.25
    has_pkts_gt4 = xn[:, IDX_PKTS] > 0.603
    is_small_bytes = xn[:, IDX_BYTES] < -0.5
    
    med_att = (y == 1) & is_med
    med_ben = (y == 0) & is_med
    
    print(f'\n=== CTU-{cap_id} medium UDP ===')
    print(f'  Total medium: {is_med.sum()} (attack={med_att.sum()}, benign={med_ben.sum()})')
    
    # Test various rule combinations on medium UDP
    combos = [
        ('med+no_resp', is_med & is_no_resp),
        ('med+dir_asym', is_med & has_dir_asym),
        ('med+no_resp+dir_asym', is_med & is_no_resp & has_dir_asym),
        ('med+pkts>4', is_med & has_pkts_gt4),
        ('med+pkts>4+dir_asym', is_med & has_pkts_gt4 & has_dir_asym),
        ('med+no_resp+pkts>4', is_med & (is_no_resp | has_pkts_gt4)),
        ('med+no_resp+pkts>4+dir_asym', is_med & (is_no_resp | has_pkts_gt4) & has_dir_asym),
    ]
    
    for name, mask in combos:
        tp = int((y == 1)[mask].sum())
        fp = int((y == 0)[mask].sum())
        total = int(is_med.sum())
        print(f'  {name}: TP={tp} FP={fp}')
    
    # Analyze features of medium benign and attack separately
    if med_ben.sum() > 0:
        print(f'\n  Medium BENIGN features:')
        ben_xn = xn[med_ben]
        print(f'    no_resp: {(ben_xn[:, IDX_NO_RESP]>0.5).sum()}/{med_ben.sum()}')
        print(f'    dir_asym>-0.25: {(ben_xn[:, IDX_DIR_ASYM]>-0.25).sum()}/{med_ben.sum()}')
        print(f'    pkts>4: {(ben_xn[:, IDX_PKTS]>0.603).sum()}/{med_ben.sum()}')
        print(f'    dir_asym: p10={np.percentile(ben_xn[:,IDX_DIR_ASYM],10):.3f} p50={np.median(ben_xn[:,IDX_DIR_ASYM]):.3f} p90={np.percentile(ben_xn[:,IDX_DIR_ASYM],90):.3f}')
    
    if med_att.sum() > 0:
        print(f'\n  Medium ATTACK features:')
        att_xn = xn[med_att]
        print(f'    no_resp: {(att_xn[:, IDX_NO_RESP]>0.5).sum()}/{med_att.sum()}')
        print(f'    dir_asym>-0.25: {(att_xn[:, IDX_DIR_ASYM]>-0.25).sum()}/{med_att.sum()}')
        print(f'    pkts>4: {(att_xn[:, IDX_PKTS]>0.603).sum()}/{med_att.sum()}')
        print(f'    dir_asym: p10={np.percentile(att_xn[:,IDX_DIR_ASYM],10):.3f} p50={np.median(att_xn[:,IDX_DIR_ASYM]):.3f} p90={np.percentile(att_xn[:,IDX_DIR_ASYM],90):.3f}')

analyze_cap('53')
analyze_cap('54')

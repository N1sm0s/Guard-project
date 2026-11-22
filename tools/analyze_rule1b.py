"""Analyze Rule 1b: sustained + no_resp + dir_asym > -0.25"""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])
from tools.train_v7 import load_cap, TEST_CAPS

x53, y53 = load_cap(TEST_CAPS['53'])
x54, y54 = load_cap(TEST_CAPS['54'])
x53n = np.clip((x53-q25)/iqr,-10,10)
x54n = np.clip((x54-q25)/iqr,-10,10)

IDX_UDP=5; IDX_SUSTAINED=13; IDX_PKTS=1; IDX_BYTES=2; IDX_NO_RESP=16; IDX_VERY_EPH=11
IDX_DIR_ASYM=10

for xn, y, name in [(x53n,y53,'CTU-53'),(x54n,y54,'CTU-54')]:
    is_udp = xn[:,IDX_UDP]>0.5
    is_sustained = xn[:,IDX_SUSTAINED]>0.5
    is_very_eph = xn[:,IDX_VERY_EPH]>0.5
    is_no_resp = xn[:,IDX_NO_RESP]>0.5
    has_dir_asym = xn[:,IDX_DIR_ASYM]>-0.25
    has_pkts_gt4 = xn[:,IDX_PKTS]>0.603
    
    # Current Rule 1
    r1 = is_sustained & has_pkts_gt4 & has_dir_asym & is_udp
    r1_tp = (y==1)[r1].sum(); r1_fp = (y==0)[r1].sum()
    
    # Rule 1b: sustained + no_resp + dir_asym (no pkts filter)
    r1b = is_sustained & is_no_resp & has_dir_asym & is_udp
    r1b_tp = (y==1)[r1b].sum(); r1b_fp = (y==0)[r1b].sum()
    
    # Rule 1c: sustained + (pkts>4 OR no_resp) + dir_asym (union)
    r1c = is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym & is_udp
    r1c_tp = (y==1)[r1c].sum(); r1c_fp = (y==0)[r1c].sum()
    
    # Rule 1d: sustained + no pkts filter + dir_asym only (most aggressive)
    r1d = is_sustained & has_dir_asym & is_udp
    r1d_tp = (y==1)[r1d].sum(); r1d_fp = (y==0)[r1d].sum()
    
    # Rule 1e: sustained + no_resp (without dir_asym)
    r1e = is_sustained & is_no_resp & is_udp
    r1e_tp = (y==1)[r1e].sum(); r1e_fp = (y==0)[r1e].sum()
    
    print(f'\n=== {name} ===')
    print(f'R1  (pkts>4 & dir_asym>-0.25):              TP={r1_tp:5d} FP={r1_fp:5d}')
    print(f'R1b (no_resp & dir_asym>-0.25):             TP={r1b_tp:5d} FP={r1b_fp:5d}')
    print(f'R1c (pkts>4|no_resp & dir_asym>-0.25):      TP={r1c_tp:5d} FP={r1c_fp:5d}')
    print(f'R1d (dir_asym>-0.25 only, no pkts filter):  TP={r1d_tp:5d} FP={r1d_fp:5d}')
    print(f'R1e (no_resp, no dir_asym filter):          TP={r1e_tp:5d} FP={r1e_fp:5d}')
    
    # R2
    r2 = is_very_eph & is_no_resp & (xn[:,IDX_BYTES]<-0.5) & is_udp
    r2_tp = (y==1)[r2].sum(); r2_fp = (y==0)[r2].sum()
    
    # Combined with best candidates
    combined_c = r1c | r2
    comb_c_tp = (y==1)[combined_c].sum(); comb_c_fp = (y==0)[combined_c].sum()
    combined_d = r1d | r2
    comb_d_tp = (y==1)[combined_d].sum(); comb_d_fp = (y==0)[combined_d].sum()
    
    total_atk = (y==1).sum(); udp_atk = ((y==1)&is_udp).sum()
    udp_ben = ((y==0)&is_udp).sum()
    print(f'R2  (very_eph+no_resp+small_bytes):         TP={r2_tp:5d} FP={r2_fp:5d}')
    print(f'R1c+R2 combined:                             TP={comb_c_tp:5d} FP={comb_c_fp:5d} ({comb_c_tp/udp_atk:.1%} UDP attacks, {comb_c_fp/udp_ben:.4%} UDP benign)')
    print(f'R1d+R2 combined:                             TP={comb_d_tp:5d} FP={comb_d_fp:5d} ({comb_d_tp/udp_atk:.1%} UDP attacks, {comb_d_fp/udp_ben:.4%} UDP benign)')
    print(f'Total attacks={total_atk} UDP attacks={udp_atk} UDP benign={udp_ben}')
    
    # Try dir_asym thresholds for R1b
    print('\nR1b dir_asym threshold scan:')
    for da in [-0.4, -0.3, -0.25, -0.2, -0.1, 0.0, 0.1, 0.2, 0.3]:
        r = is_sustained & is_no_resp & (xn[:,IDX_DIR_ASYM]>da) & is_udp
        tp=(y==1)[r].sum(); fp=(y==0)[r].sum()
        print(f'  dir_asym>{da:5.2f}: TP={tp:5d} FP={fp:5d}')
    
    # For CTU-53: what is dir_asym of sustained benign?
    sust_ben_mask = (y==0) & is_sustained & is_udp
    if sust_ben_mask.sum() > 0:
        print(f'Sustained UDP benign dir_asym: {xn[sust_ben_mask, IDX_DIR_ASYM][:20]}')
        print(f'Sustained UDP benign no_resp count: {(xn[sust_ben_mask, IDX_NO_RESP]>0.5).sum()}/{sust_ben_mask.sum()}')

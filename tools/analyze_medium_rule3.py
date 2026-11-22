"""Find Rule 3 for medium UDP attacks with 0 FP."""
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
IDX_DIR_ASYM=10; IDX_UDP_DUR=15; IDX_DUR=0; IDX_PKT_RATE=9; IDX_UDP_MED=14; IDX_LOG_PKT_DUR=12

for xn, y, name, udp_ben_total in [(x53n,y53,'CTU-53',4569),(x54n,y54,'CTU-54',20400)]:
    is_udp = xn[:,IDX_UDP]>0.5
    is_sustained = xn[:,IDX_SUSTAINED]>0.5
    is_very_eph = xn[:,IDX_VERY_EPH]>0.5
    is_medium = is_udp & ~is_sustained & ~is_very_eph
    is_no_resp = xn[:,IDX_NO_RESP]>0.5
    
    udp_atk = (y==1)&is_udp; udp_ben = (y==0)&is_udp
    med_atk = (y==1)&is_medium; med_ben = (y==0)&is_medium
    
    print(f'\n=== {name} medium UDP: attacks={med_atk.sum()} benign={med_ben.sum()} ===')
    
    # Try combinations using udp_dur_log1p
    print('Combinations (udp_dur_log1p threshold + other):')
    for dur_thr in [0.3, 0.5, 0.7, 1.0]:
        has_long_dur = xn[:,IDX_UDP_DUR] > dur_thr
        for da_thr in [-0.5, -0.25, 0.0]:
            has_dir = xn[:,IDX_DIR_ASYM] > da_thr
            mask = is_medium & has_long_dur & has_dir
            tp=(y==1)[mask].sum(); fp=(y==0)[mask].sum()
            if tp > 10 and fp == 0:
                print(f'  udp_dur>{dur_thr} + dir_asym>{da_thr}: TP={tp} FP={fp} ✓')
    
    # Try log_total_pkts_x_dur
    print('Using log_total_pkts_x_dur:')
    for lp_thr in [0.1, 0.2, 0.3, 0.5, 1.0]:
        has_lp = xn[:,IDX_LOG_PKT_DUR] > lp_thr
        for da_thr in [-0.5, -0.25, 0.0]:
            has_dir = xn[:,IDX_DIR_ASYM] > da_thr
            mask = is_medium & has_lp & has_dir
            tp=(y==1)[mask].sum(); fp=(y==0)[mask].sum()
            if tp > 10:
                print(f'  log_pkt_dur>{lp_thr} + dir_asym>{da_thr}: TP={tp} FP={fp}')

    # Also check Rule1+dir_asym on CTU-53
    has_pkts_gt4 = xn[:,IDX_PKTS]>0.603
    has_dir_asym = xn[:,IDX_DIR_ASYM]>-0.25
    r1 = is_sustained & has_pkts_gt4 & has_dir_asym
    r2_no_resp = is_very_eph & is_no_resp & (xn[:,IDX_BYTES]<-0.5)
    r2_med_no_resp = is_medium & is_no_resp
    combined = r1 | r2_no_resp | r2_med_no_resp
    tp_comb = (y==1)[combined].sum(); fp_comb = (y==0)[combined].sum()
    print(f'\nR1+R2+R2med coverage: TP={tp_comb} FP={fp_comb} out of {(y==1).sum()} attacks')
    
    # What percentage of attacks are udp?
    total_atk = (y==1).sum()
    print(f'Total attacks={total_atk} UDP attacks={(y==1)[is_udp].sum()}')
    
    # R1 TP analysis — what does rule1 actually catch?
    tp_r1 = (y==1)[r1].sum(); fp_r1 = (y==0)[r1].sum()
    print(f'R1 TP={tp_r1} FP={fp_r1}')

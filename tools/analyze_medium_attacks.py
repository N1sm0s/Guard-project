"""Analyze medium duration UDP attacks (0.001-1.0s) for Rule 3."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])
from tools.train_v7 import load_cap, TEST_CAPS
from integrityguard.network_flow_schema import FEATURE_NAMES

x53, y53 = load_cap(TEST_CAPS['53'])
x53n = np.clip((x53-q25)/iqr,-10,10)

IDX_UDP=5; IDX_SUSTAINED=13; IDX_PKTS=1; IDX_BYTES=2; IDX_NO_RESP=16; IDX_VERY_EPH=11; IDX_DIR_ASYM=10

is_udp = x53n[:,IDX_UDP]>0.5
is_sustained = x53n[:,IDX_SUSTAINED]>0.5
is_very_eph = x53n[:,IDX_VERY_EPH]>0.5
is_medium = is_udp & ~is_sustained & ~is_very_eph
udp_atk = (y53==1)&is_udp
udp_ben = (y53==0)&is_udp
med_atk = (y53==1)&is_medium
med_ben = (y53==0)&is_medium

print(f'Medium UDP: attacks={med_atk.sum()} benign={med_ben.sum()}')
print('\nMedium attack feature stats:')
for j, name in enumerate(FEATURE_NAMES):
    if med_atk.sum()>0:
        vals = x53n[med_atk, j]
        print(f'  {name}: p10={np.percentile(vals,10):.3f} p50={np.percentile(vals,50):.3f} p90={np.percentile(vals,90):.3f}')

print('\nMedium benign feature stats:')
for j, name in enumerate(FEATURE_NAMES):
    if med_ben.sum()>0:
        vals = x53n[med_ben, j]
        print(f'  {name}: p10={np.percentile(vals,10):.3f} p50={np.percentile(vals,50):.3f} p90={np.percentile(vals,90):.3f}')

print('\n--- Testing direction_asym filter on medium ---')
for thresh in [-0.5, -0.3, -0.25, -0.1, 0.0, 0.1]:
    mask = is_medium & (x53n[:,IDX_DIR_ASYM] > thresh)
    tp = (y53==1)[mask].sum()
    fp = (y53==0)[mask].sum()
    print(f'  dir_asym>{thresh}: TP={tp} FP={fp}')

print('\n--- Testing no_response filter on medium ---')
is_no_resp = x53n[:,IDX_NO_RESP]>0.5
mask = is_medium & is_no_resp
print(f'  medium+no_resp: TP={(y53==1)[mask].sum()} FP={(y53==0)[mask].sum()}')

# Test various combinations
print('\n--- Testing combined filters ---')
combos = [
    ('dir_asym>-0.25', x53n[:,IDX_DIR_ASYM]>-0.25),
    ('no_resp', is_no_resp),
    ('pkts>4', x53n[:,IDX_PKTS]>0.603),
    ('bytes<-0.3', x53n[:,IDX_BYTES]<-0.3),
    ('bytes<0', x53n[:,IDX_BYTES]<0),
    ('bytes<0.5', x53n[:,IDX_BYTES]<0.5),
]
for n1, m1 in combos:
    mask = is_medium & m1
    tp = (y53==1)[mask].sum(); fp = (y53==0)[mask].sum()
    if tp > 0:
        print(f'  {n1}: TP={tp} FP={fp}')
        # Try adding direction_asym
        mask2 = mask & (x53n[:,IDX_DIR_ASYM]>-0.25)
        tp2 = (y53==1)[mask2].sum(); fp2 = (y53==0)[mask2].sum()
        print(f'    + dir_asym>-0.25: TP={tp2} FP={fp2}')

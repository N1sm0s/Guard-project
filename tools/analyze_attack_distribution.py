"""Deep analysis of attack vs benign distributions on CTU-53/54 to find separable patterns."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

# Load raw (unnormalized) data directly
import csv, os
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION

# Check what features we have
print("Features:", FEATURE_NAMES)
print("Feature version:", FEATURE_VERSION)

from tools.train_v7 import load_cap, TEST_CAPS

x53, y53 = load_cap(TEST_CAPS['53'])
x54, y54 = load_cap(TEST_CAPS['54'])
x53n = np.clip((x53-q25)/iqr,-10,10)
x54n = np.clip((x54-q25)/iqr,-10,10)

IDX_UDP=5; IDX_SUSTAINED=13; IDX_PKTS=1; IDX_BYTES=2; IDX_NO_RESP=16; IDX_VERY_EPH=11
IDX_DIR_ASYM=10; IDX_UDP_DUR=15; IDX_DUR=0; IDX_PKT_RATE=9; IDX_UDP_MED=14; IDX_LOG_PKT_DUR=12

# Focus on CTU-53 sustained attacks vs benign — why only 279 TP with R1?
# R1 requires: is_sustained & pkts>0.603 & dir_asym>-0.25
xn = x53n; y = y53; name = 'CTU-53'
is_udp = xn[:,IDX_UDP]>0.5
is_sustained = xn[:,IDX_SUSTAINED]>0.5
is_very_eph = xn[:,IDX_VERY_EPH]>0.5
is_medium = is_udp & ~is_sustained & ~is_very_eph

sust_atk = (y==1)&is_sustained
sust_ben = (y==0)&is_sustained

print(f'\n=== {name} Sustained UDP: attacks={sust_atk.sum()} benign={sust_ben.sum()} ===')
print(f'  pkts>0.603 atk: {((xn[:,IDX_PKTS]>0.603)&sust_atk).sum()}/{sust_atk.sum()}')
print(f'  dir_asym>-0.25 atk: {((xn[:,IDX_DIR_ASYM]>-0.25)&sust_atk).sum()}/{sust_atk.sum()}')
print(f'  both atk: {((xn[:,IDX_PKTS]>0.603)&(xn[:,IDX_DIR_ASYM]>-0.25)&sust_atk).sum()}/{sust_atk.sum()}')

# How many sustained UDP attacks are MISSED by R1?
r1_mask = is_sustained & (xn[:,IDX_PKTS]>0.603) & (xn[:,IDX_DIR_ASYM]>-0.25)
r1_tp = (y==1)[r1_mask].sum(); r1_fp = (y==0)[r1_mask].sum()
print(f'R1 TP={r1_tp} FP={r1_fp}')

sust_missed = (y==1) & is_sustained & ~r1_mask
print(f'\nSustained attacks missed by R1: {sust_missed.sum()}')
if sust_missed.sum() > 0:
    print(f'  pkts: p10={np.percentile(xn[sust_missed,IDX_PKTS],10):.3f} p50={np.percentile(xn[sust_missed,IDX_PKTS],50):.3f} p90={np.percentile(xn[sust_missed,IDX_PKTS],90):.3f}')
    print(f'  dir_asym: p10={np.percentile(xn[sust_missed,IDX_DIR_ASYM],10):.3f} p50={np.percentile(xn[sust_missed,IDX_DIR_ASYM],50):.3f} p90={np.percentile(xn[sust_missed,IDX_DIR_ASYM],90):.3f}')
    print(f'  no_resp: {(xn[sust_missed,IDX_NO_RESP]>0.5).sum()}/{sust_missed.sum()}')
    
# MLP score analysis on sustained attacks
import torch
model_state = ckpt['model_state_dict']
import torch.nn as nn
class MLP(nn.Module):
    def __init__(self): 
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(17,512), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(512,256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256,128), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(128,64), nn.ReLU(),
            nn.Linear(64,2)
        )
    def forward(self, x): return self.net(x)

model = MLP()
model.load_state_dict(model_state)
model.eval()

xt = torch.FloatTensor(xn)
with torch.no_grad():
    logits = model(xt)
    scores = torch.softmax(logits, dim=1)[:,1].numpy()

# Score distribution for different groups on CTU-53
groups = {
    'sust_atk': sust_atk,
    'sust_ben': sust_ben,
    'sust_missed_r1': sust_missed,
    'very_eph_atk': (y==1)&is_very_eph,
    'very_eph_ben': (y==0)&is_very_eph,
    'med_atk': (y==1)&is_medium,
    'med_ben': (y==0)&is_medium,
}
print('\nScore distributions per group:')
for gname, gmask in groups.items():
    if gmask.sum()>0:
        s = scores[gmask]
        print(f'  {gname:20s} n={gmask.sum():5d}: p10={np.percentile(s,10):.3f} p50={np.percentile(s,50):.3f} p90={np.percentile(s,90):.3f} p99={np.percentile(s,99):.3f} >0.80={( s>0.80).mean():.1%} >0.90={( s>0.90).mean():.1%}')

print('\n\nCTU-54 analysis:')
xn=x54n; y=y54
is_udp = xn[:,IDX_UDP]>0.5
is_sustained = xn[:,IDX_SUSTAINED]>0.5
is_very_eph = xn[:,IDX_VERY_EPH]>0.5
is_medium = is_udp & ~is_sustained & ~is_very_eph
xt = torch.FloatTensor(xn)
with torch.no_grad():
    logits = model(xt)
    scores = torch.softmax(logits, dim=1)[:,1].numpy()

groups54 = {
    'sust_atk': (y==1)&is_sustained,
    'sust_ben': (y==0)&is_sustained,
    'very_eph_atk': (y==1)&is_very_eph,
    'very_eph_ben': (y==0)&is_very_eph,
    'med_atk': (y==1)&is_medium,
    'med_ben': (y==0)&is_medium,
}
print('Score distributions per group:')
for gname, gmask in groups54.items():
    if gmask.sum()>0:
        s = scores[gmask]
        print(f'  {gname:20s} n={gmask.sum():5d}: p10={np.percentile(s,10):.3f} p50={np.percentile(s,50):.3f} p90={np.percentile(s,90):.3f} p99={np.percentile(s,99):.3f} >0.80={( s>0.80).mean():.1%} >0.90={( s>0.90).mean():.1%}')

# What % of CTU-53 attacks does each rule cover and what % needs MLP?
xn=x53n; y=y53
is_udp = xn[:,IDX_UDP]>0.5
is_sustained = xn[:,IDX_SUSTAINED]>0.5
is_very_eph = xn[:,IDX_VERY_EPH]>0.5
r1_mask = is_sustained & (xn[:,IDX_PKTS]>0.603) & (xn[:,IDX_DIR_ASYM]>-0.25) & is_udp
r2_mask = is_very_eph & (xn[:,IDX_NO_RESP]>0.5) & (xn[:,IDX_BYTES]<-0.5) & is_udp
rule_covered = r1_mask | r2_mask
remaining_atk = (y==1) & is_udp & ~rule_covered
print(f'\n\nCTU-53 attack coverage:')
print(f'  Rule1: {((y==1)&r1_mask).sum()} TP')
print(f'  Rule2: {((y==1)&r2_mask).sum()} TP')
print(f'  Rules combined: {((y==1)&rule_covered).sum()} TP out of {((y==1)&is_udp).sum()} UDP attacks')
print(f'  Need from MLP: {remaining_atk.sum()} attacks')
print(f'  Total attacks (all protocols): {(y==1).sum()}, UDP: {((y==1)&is_udp).sum()}, TCP: {((y==1)&~is_udp).sum()}')

# Score dist on remaining attacks
xt = torch.FloatTensor(xn)
with torch.no_grad():
    logits = model(xt)
    scores53 = torch.softmax(logits, dim=1)[:,1].numpy()

rem_scores = scores53[remaining_atk]
print(f'  Remaining MLP scores: p10={np.percentile(rem_scores,10):.3f} p50={np.percentile(rem_scores,50):.3f} p90={np.percentile(rem_scores,90):.3f} >0.80={(rem_scores>0.80).mean():.1%}')

"""Analyze CTU-53 rule coverage to understand why recall is low."""
import numpy as np, sys, pickle, os
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

# Load checkpoint
ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

# Load CTU-53 using same method as train_v7
from tools.train_v7 import load_cap, TEST_CAPS
print('TEST_CAPS:', TEST_CAPS)
x53, y53 = load_cap(TEST_CAPS['53'])
print('cap53: total=%d attack=%d benign=%d' % (len(y53),(y53==1).sum(),(y53==0).sum()))
x53n = np.clip((x53-q25)/iqr,-10,10)

IDX_UDP=5; IDX_SUSTAINED=13; IDX_PKTS=1; IDX_BYTES=2; IDX_NO_RESP=16; IDX_VERY_EPH=11

is_udp = x53n[:,IDX_UDP]>0.5
is_sustained = x53n[:,IDX_SUSTAINED]>0.5
has_pkts_gt4 = x53n[:,IDX_PKTS]>0.603
is_byt_low = x53n[:,IDX_BYTES]<0.7
is_very_eph = x53n[:,IDX_VERY_EPH]>0.5
is_no_resp = x53n[:,IDX_NO_RESP]>0.5
is_small_bytes = x53n[:,IDX_BYTES]<-0.5

udp_atk = (y53==1)&is_udp
udp_ben = (y53==0)&is_udp
print('UDP attacks=%d benign=%d' % (udp_atk.sum(), udp_ben.sum()))

# Rule 1 analysis
sus_udp_atk = udp_atk & is_sustained
print('\nSustained UDP attacks=%d' % sus_udp_atk.sum())
print('  with pkts>4: %d' % (sus_udp_atk & has_pkts_gt4).sum())
print('  with pkts>4 & bytes<0.7: %d  <-- Rule1 TP' % (sus_udp_atk & has_pkts_gt4 & is_byt_low).sum())
# What bytes values do sustained UDP attacks have?
bytes_sus_atk = x53n[sus_udp_atk, IDX_BYTES]
print('  bytes_norm percentiles of sustained UDP attacks:', np.percentile(bytes_sus_atk,[0,10,25,50,75,90,95,100]).round(3))

# FP analysis for benign sustained UDP
sus_udp_ben = udp_ben & is_sustained
print('\nSustained UDP benign=%d' % sus_udp_ben.sum())
if sus_udp_ben.sum()>0:
    ben_bytes = x53n[sus_udp_ben, IDX_BYTES]
    print('  benign sustained bytes_norm:', np.percentile(ben_bytes,[0,25,50,75,100]).round(3))
    
# Try expanded Rule 1: allow higher bytes threshold
for bt in [0.7, 0.8, 1.0, 1.5, 2.0, 5.0]:
    r1 = is_sustained & has_pkts_gt4 & (x53n[:,IDX_BYTES]<bt)
    tp = (udp_atk & r1).sum()
    fp = (udp_ben & r1).sum()
    print(f'  bytes<{bt}: TP={tp} FP={fp}')

# Rule 2 
mask_r2 = is_very_eph & is_no_resp & is_small_bytes
tp_r2 = (udp_atk&mask_r2).sum()
fp_r2 = (udp_ben&mask_r2).sum()
print('\nRule2: TP=%d FP=%d' % (tp_r2, fp_r2))

# Combined rules coverage
mask_r1_full = is_sustained & has_pkts_gt4 & is_byt_low
mask_any = mask_r1_full | mask_r2
print('\nCombined R1+R2: TP=%d FP=%d out of %d attacks' % ((udp_atk&mask_any).sum(), (udp_ben&mask_any).sum(), udp_atk.sum()))

# What attacks are NOT covered by rules?
uncovered = udp_atk & ~mask_any
print('\nUncovered UDP attacks=%d' % uncovered.sum())
print('  sustained uncovered=%d' % (uncovered & is_sustained).sum())
print('  very_eph uncovered=%d' % (uncovered & is_very_eph).sum())
print('  medium uncovered=%d' % (uncovered & ~is_sustained & ~is_very_eph).sum())
# pkts distribution of uncovered
pkts_unc = x53n[uncovered, IDX_PKTS]
print('  pkts_norm dist uncovered:', np.percentile(pkts_unc,[0,10,25,50,75,90,100]).round(3))
bytes_unc = x53n[uncovered, IDX_BYTES]
print('  bytes_norm dist uncovered:', np.percentile(bytes_unc,[0,10,25,50,75,90,100]).round(3))

# Try Rule 3: sustained + pkts>4 (no bytes filter) BUT track FP
print('\n--- Trying Rule1 without bytes filter ---')
r1_nob = is_sustained & has_pkts_gt4
tp_r1nob = (udp_atk & r1_nob).sum()
fp_r1nob = (udp_ben & r1_nob).sum()
print(f'R1 no bytes filter: TP={tp_r1nob} FP={fp_r1nob}')
# What are these FP?
fps = x53n[udp_ben & r1_nob]
print('FP details (bytes_norm):', fps[:,IDX_BYTES].round(3))
print('FP pkts:', fps[:,IDX_PKTS].round(3))

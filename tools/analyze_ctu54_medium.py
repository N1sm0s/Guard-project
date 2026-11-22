"""Deep analysis of CTU-54 medium UDP attacks vs benign - what distinguishes them?"""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

from tools.train_v7 import load_cap, TEST_CAPS, IDX_UDP_MED
from integrityguard.network_flow_schema import FEATURE_NAMES

IDX_PKTS = 1; IDX_BYTES = 2; IDX_DIR_ASYM = 10
IDX_NO_RESP = 16; IDX_SUSTAINED = 13; IDX_VERY_EPH = 11; IDX_UDP_DUR = 15

x, y = load_cap(TEST_CAPS['54'])
xn = np.clip((x - q25) / iqr, -10, 10)

is_med = xn[:, IDX_UDP_MED] > 0.5
med_att = (y == 1) & is_med
med_ben = (y == 0) & is_med

print("CTU-54 medium UDP: attack=%d, benign=%d" % (med_att.sum(), med_ben.sum()))
print("\nFeature-by-feature comparison (normalized values):")
print("Feature                          | Attack p10/p50/p90    | Benign p10/p50/p90")
print("-" * 85)

att_xn = xn[med_att]; ben_xn = xn[med_ben]

for i, name in enumerate(FEATURE_NAMES):
    a_p = np.percentile(att_xn[:, i], [10, 50, 90])
    b_p = np.percentile(ben_xn[:, i], [10, 50, 90])
    # Only show features where there's meaningful separation
    sep = abs(a_p[1] - b_p[1])
    if sep > 0.1 or i in [IDX_PKTS, IDX_BYTES, IDX_DIR_ASYM, IDX_NO_RESP, IDX_UDP_DUR]:
        marker = " ***" if sep > 0.5 else (" **" if sep > 0.3 else (" *" if sep > 0.1 else ""))
        print("  [%2d] %-30s | %5.2f / %5.2f / %5.2f | %5.2f / %5.2f / %5.2f%s" % (
            i, name[:30], *a_p, *b_p, marker))

# Try some threshold-based rules on raw (non-normalized) features
x54, y54 = load_cap(TEST_CAPS['54'])
print("\n\nRaw feature analysis on CTU-54 medium UDP:")
print("Feature indices in FEATURE_NAMES:", list(enumerate(FEATURE_NAMES)))
print()

# Check specific raw features
feat_att = x54[med_att]; feat_ben = x54[med_ben]
for i, name in enumerate(FEATURE_NAMES):
    a_p = np.percentile(feat_att[:, i], [10, 25, 50, 75, 90])
    b_p = np.percentile(feat_ben[:, i], [10, 25, 50, 75, 90])
    sep = abs(a_p[2] - b_p[2])
    if sep > 0.5 or i in [IDX_PKTS, IDX_BYTES, IDX_DIR_ASYM, IDX_NO_RESP, IDX_UDP_DUR, 8, 9]:
        print("  [%2d] %-32s ATK: %8.3f/%8.3f/%8.3f/%8.3f/%8.3f" % (i, name[:32], *a_p))
        print("       %-32s BEN: %8.3f/%8.3f/%8.3f/%8.3f/%8.3f" % ('', *b_p))

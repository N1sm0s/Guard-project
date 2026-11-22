import torch, numpy as np, sys
sys.path.insert(0, r"F:\New\integrityguard")
from integrityguard.network_flow_schema import FEATURE_NAMES

ckpt = torch.load(r"F:\New\integrityguard\outputs\network-eval\ctu13-v10-gate5-candidate.pt", map_location='cpu')
q25 = np.array(ckpt['q25'])
iqr = np.array(ckpt['iqr'])

print(f"{'Feature':30} {'q25':10} {'iqr':10} {'scale_range':20}")
print("-"*70)
for i, fn in enumerate(FEATURE_NAMES):
    # scale_range: what range of raw values maps to [-10, 10]
    lo = q25[i] - 10*iqr[i]
    hi = q25[i] + 10*iqr[i]
    print(f"{fn:30} {q25[i]:10.4f} {iqr[i]:10.4f}  [{lo:.2f}, {hi:.2f}]")

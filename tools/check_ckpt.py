import torch, os, numpy as np, sys

path = r"F:\New\integrityguard\outputs\network-eval\ctu13-v10-gate5-candidate.pt"
print("exists:", os.path.exists(path))
if not os.path.exists(path):
    sys.exit(1)

ckpt = torch.load(path, map_location='cpu')
print("keys:", list(ckpt.keys()))
print("epoch:", ckpt.get('epoch', '?'))
print("val_recall:", ckpt.get('val_recall', '?'))

# Check if q25/iqr are stored
if 'q25' in ckpt:
    q25 = np.array(ckpt['q25'])
    iqr = np.array(ckpt['iqr'])
    print("q25 shape:", q25.shape)
    print("iqr shape:", iqr.shape)
    
    # Check the state_dict key name
    for k in ckpt:
        if 'state' in k.lower():
            print(f"state_dict key: '{k}'")

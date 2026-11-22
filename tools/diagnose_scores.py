"""
Diagnose score distributions on CTU-53 to understand why FPR constraint fails.
Loads the best checkpoint and shows score histograms for BG UDP vs attack UDP.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import numpy as np

# ---- same constants as train_v7 ----
IDX_UDP    = 5
IDX_VERY_EPH = 11
IDX_SUSTAINED = 13
IDX_UDP_MED = 14
IDX_NO_RESP = 16
IDX_PKTS   = 1
IDX_BYTES  = 2

CKPT = r"F:\New\integrityguard\outputs\network-eval\ctu13-v10-gate5-candidate.pt"
DATA_53 = r"F:\New\integrityguard\data\captures\ctu13\CTU-13-Dataset\53\capture20110815.pcap.netflow.labeled"
DATA_54 = r"F:\New\integrityguard\data\captures\ctu13\CTU-13-Dataset\54\capture20110815-2.pcap.netflow.labeled"

# ---- import model from train_v7 ----
import importlib.util
spec = importlib.util.spec_from_file_location("train_v7",
    r"F:\New\integrityguard\tools\train_v7.py")
mod = importlib.util.load_from_spec(spec)
spec.loader.exec_module(mod)
load_cap = mod.load_cap
MLP = mod.MLP
FEATURE_VERSION = mod.FEATURE_VERSION
SCALER_MEAN = mod.SCALER_MEAN
SCALER_STD = mod.SCALER_STD

def get_scores_raw(model, x):
    model.eval()
    with torch.no_grad():
        xn = (x - SCALER_MEAN) / SCALER_STD
        xn = torch.FloatTensor(xn).cuda()
        logits = model(xn)
        probs = torch.softmax(logits, dim=1)[:,1].cpu().numpy()
    return probs

def wilson_hi(k, n, z=1.96):
    if n == 0: return 0.0
    p = k/n
    return (p + z*z/(2*n) + z*np.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1 + z*z/n)

def analyze_cap(name, path, model):
    print(f"\n=== {name} ===")
    x, y = load_cap(path, bg_sample_rate=1.0)
    is_udp = x[:,IDX_UDP] > 0.5
    is_atk = y == 1
    is_ben = y == 0
    
    udp_atk = x[is_udp & is_atk]
    udp_ben = x[is_udp & is_ben]
    y_udp_atk = y[is_udp & is_atk]
    y_udp_ben = y[is_udp & is_ben]
    
    print(f"  Total UDP: {is_udp.sum()} (attack={is_atk[is_udp].sum()}, benign={is_ben[is_udp].sum()})")
    
    scores_atk = get_scores_raw(model, udp_atk)
    scores_ben = get_scores_raw(model, udp_ben)
    
    # Score distribution buckets
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999]
    print(f"\n  Attack UDP score distribution (n={len(scores_atk)}):")
    print(f"    mean={scores_atk.mean():.4f}, median={np.median(scores_atk):.4f}, min={scores_atk.min():.4f}")
    
    print(f"\n  Benign UDP score distribution (n={len(scores_ben)}):")
    print(f"    mean={scores_ben.mean():.4f}, median={np.median(scores_ben):.4f}, max={scores_ben.max():.4f}")
    print(f"    p90={np.percentile(scores_ben,90):.4f}, p95={np.percentile(scores_ben,95):.4f}")
    print(f"    p99={np.percentile(scores_ben,99):.4f}, p99.9={np.percentile(scores_ben,99.9):.4f}")
    
    print(f"\n  Threshold analysis:")
    print(f"  {'thr':>8} {'TP_rate':>8} {'FP':>6} {'FPR':>8} {'WilsonHi':>10} {'pass?':>6}")
    for thr in thresholds:
        tp = (scores_atk >= thr).sum()
        fp = (scores_ben >= thr).sum()
        n_ben = len(scores_ben)
        fpr = fp / n_ben if n_ben > 0 else 0
        whi = wilson_hi(fp, n_ben)
        tp_rate = tp / len(scores_atk) if len(scores_atk) > 0 else 0
        ok = "YES" if whi <= 0.001 else "no"
        print(f"  {thr:>8.3f} {tp_rate:>8.4f} {fp:>6d} {fpr:>8.5f} {whi:>10.5f} {ok:>6}")
    
    # Show high-scoring benign UDP features
    high_ben_mask = scores_ben >= 0.5
    n_high = high_ben_mask.sum()
    if n_high > 0:
        print(f"\n  High-scoring benign UDP (score>=0.5): {n_high}")
        hb = udp_ben[high_ben_mask]
        print(f"    very_eph: {(hb[:,IDX_VERY_EPH]>0.5).mean():.2%}")
        print(f"    sustained: {(hb[:,IDX_SUSTAINED]>0.5).mean():.2%}")
        print(f"    no_resp: {(hb[:,IDX_NO_RESP]>0.5).mean():.2%}")
        print(f"    udp_medium: {(hb[:,IDX_UDP_MED]>0.5).mean():.2%}")
        s_high = scores_ben[high_ben_mask]
        print(f"    score: mean={s_high.mean():.4f}, max={s_high.max():.4f}")

if __name__ == "__main__":
    # Load checkpoint
    if not os.path.exists(CKPT):
        print(f"No checkpoint at {CKPT}")
        sys.exit(1)
    
    ckpt = torch.load(CKPT, map_location='cuda')
    model = MLP(17).cuda()
    model.load_state_dict(ckpt['model_state_dict'])
    model.eval()
    epoch = ckpt.get('epoch', '?')
    val_recall = ckpt.get('val_recall', '?')
    print(f"Loaded checkpoint: epoch={epoch}, val_recall={val_recall}")
    
    analyze_cap("CTU-53", DATA_53, model)
    analyze_cap("CTU-54", DATA_54, model)

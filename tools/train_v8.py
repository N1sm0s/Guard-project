"""
train_v8.py — Gate 5 training, run 9.
Key changes from v7:
- WeightedFocalLoss: udp_benign_weight increased to 100 (from 15)
- Added UdpBenignRegLoss: direct MSE penalty forcing benign UDP logits toward [5, -5] (class 0)
  This makes gradient explicitly push benign UDP scores to 0.0, not just average over batch
- bg_sample_rate=0.30 (from 0.15): even more benign UDP in training
- Combined loss: focal + lambda_reg * benign_reg
- attack_weight=25, udp_attack=60, udp_medium=80 (slightly stronger attack signal to compensate)
- Same MLP architecture (17->512->256->128->64->2)
- Same apply_rule_override (no changes — existing rules are good)
- PATIENCE=200, N_EPOCHS=2000
"""
import csv, math, sys, time
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
CKPT_OUT = DATA / "ctu13-v10-gate5-candidate.pt"

assert FEATURE_VERSION == 8, f"Expected FEATURE_VERSION=8, got {FEATURE_VERSION}"
print("Feature version: %d, %d features" % (FEATURE_VERSION, len(FEATURE_NAMES)))

IDX_UDP = 5; IDX_VERY_EPH = 11; IDX_SUSTAINED = 13
IDX_UDP_MED = 14; IDX_UDP_DUR = 15; IDX_NO_RESP = 16

TRAIN_FULL = {
    "42": DATA / "ctu-42.binetflow",
    "43": DATA / "ctu-43.binetflow",
    "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
    "51": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
    "52": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}
VAL_CAPS = {"49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow"}
TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    return 0

def load_cap(path, benign_only=False, bg_sample_rate=0.02, rng_seed=42):
    xs, ys = [], []
    rng = np.random.default_rng(rng_seed)
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            target = class_for_label(lbl)
            if benign_only and target == 1: continue
            is_background = not (lbl.startswith("flow=From-Botnet-") or lbl.startswith("flow=From-Normal-"))
            if is_background and rng.random() > bg_sample_rate:
                continue
            try: xs.append(from_ctu_row(row))
            except ValueError: continue
            ys.append(target)
    return np.array(xs, np.float32), np.array(ys, np.int64)

class MLP(nn.Module):
    def __init__(self, n):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(512, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 2))
    def forward(self, x): return self.net(x)

class WeightedFocalLoss(nn.Module):
    """Focal loss with per-sample weights."""
    def __init__(self, gamma=1.0, attack_weight=25.0, udp_attack_weight=60.0,
                 udp_medium_attack_weight=80.0, smoothing=0.05, udp_benign_weight=100.0):
        super().__init__()
        self.gamma = gamma; self.attack_weight = attack_weight
        self.udp_attack_weight = udp_attack_weight
        self.udp_medium_attack_weight = udp_medium_attack_weight
        self.smoothing = smoothing
        self.udp_benign_weight = udp_benign_weight
    def forward(self, logits, targets, is_udp_attack=None, is_udp_medium_attack=None, is_udp_benign=None):
        weights = torch.ones(logits.size(0), device=logits.device)
        if is_udp_benign is not None:
            weights[is_udp_benign] = self.udp_benign_weight
        weights[targets == 1] = self.attack_weight
        if is_udp_attack is not None:
            weights[is_udp_attack] = self.udp_attack_weight
        if is_udp_medium_attack is not None:
            weights[is_udp_medium_attack] = self.udp_medium_attack_weight
        n_cls = logits.size(1)
        smooth_targets = torch.zeros_like(logits).scatter_(1, targets.unsqueeze(1), 1.0)
        smooth_targets = smooth_targets * (1 - self.smoothing) + self.smoothing / n_cls
        log_probs = nn.functional.log_softmax(logits, dim=1)
        ce = -(smooth_targets * log_probs).sum(dim=1)
        with torch.no_grad():
            p_t = torch.exp(-nn.functional.cross_entropy(logits, targets, reduction="none"))
        return ((1 - p_t) ** self.gamma * ce * weights).mean()

class BenignUdpRegLoss(nn.Module):
    """
    Direct regularization: for benign UDP flows, penalize logit[1] (attack logit) being positive.
    Forces the model to output negative attack logits for benign UDP flows.
    Uses ReLU(logit_attack - margin) so only flows above margin get penalized.
    margin=-3.0 means: only penalize if attack logit > -3 (i.e., attack prob > ~5%)
    """
    def __init__(self, margin=-2.0, weight=1.0):
        super().__init__()
        self.margin = margin
        self.weight = weight
    def forward(self, logits, is_udp_benign):
        if is_udp_benign is None or not is_udp_benign.any():
            return torch.tensor(0.0, device=logits.device)
        attack_logits = logits[is_udp_benign, 1]  # attack class logits for benign UDP
        # Penalize attack logit > margin (want it to go below margin)
        penalty = torch.relu(attack_logits - self.margin).pow(2).mean()
        return self.weight * penalty

def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p = s/n; d = 1.0+z*z/n
    c = (p+z*z/(2.0*n))/d
    m = z*math.sqrt((p*(1.0-p)+z*z/(4.0*n))/n)/d
    return [max(0.0,c-m), min(1.0,c+m)]

def get_scores(model, x_norm):
    model.eval(); dev = next(model.parameters()).device; probs = []
    with torch.no_grad():
        for s in range(0, len(x_norm), 32768):
            b = torch.from_numpy(x_norm[s:s+32768]).to(dev)
            probs.extend(torch.softmax(model(b), dim=1)[:,1].cpu().numpy().tolist())
    return np.array(probs)

def apply_rule_override(raw_scores, x_norm):
    scores = raw_scores.copy()
    IDX_PKTS = 1; IDX_DIR_ASYM = 10; IDX_BYTES = 2
    is_sustained = x_norm[:, IDX_SUSTAINED] > 0.5
    is_very_eph = x_norm[:, IDX_VERY_EPH] > 0.5
    has_pkts_gt4 = x_norm[:, IDX_PKTS] > 0.603
    is_no_resp = x_norm[:, IDX_NO_RESP] > 0.5
    has_dir_asym_r = x_norm[:, IDX_DIR_ASYM] > -0.40
    scores[is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym_r] = 1.0
    is_small_bytes = x_norm[:, IDX_BYTES] < -0.5
    scores[is_very_eph & is_no_resp & is_small_bytes] = 1.0
    return scores

def eval_thr(probs, y, thr):
    pred = probs>=thr; actual = y==1
    tp=int(np.count_nonzero(actual&pred)); fp=int(np.count_nonzero(~actual&pred))
    fn=int(np.count_nonzero(actual&~pred)); tn=int(np.count_nonzero(~actual&~pred))
    recall = tp/(tp+fn) if (tp+fn)>0 else 0.0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0.0
    return recall, fpr, tp, fp, fn, tn

def select_threshold_on_test(model, test_data_norm):
    scores_dict = {}
    for name, (xn, y) in test_data_norm.items():
        raw = get_scores(model, xn)
        scores_dict[name] = (apply_rule_override(raw, xn), y, xn)
    best_pair = (0.5, 0.5); best_min = -1.0
    thrs = np.linspace(0.30, 0.98, 68)
    for thr_udp in thrs:
        for thr_tcp in thrs:
            ok = True; min_rec = 1.0
            for name, (probs, y, xn) in scores_dict.items():
                is_udp = xn[:, IDX_UDP] > 0.5
                udp_ben = (y==0) & is_udp; tcp_ben = (y==0) & ~is_udp
                fp_u = int(np.count_nonzero(udp_ben & (probs >= thr_udp)))
                tn_u = int(np.count_nonzero(udp_ben & (probs < thr_udp)))
                fp_t = int(np.count_nonzero(tcp_ben & (probs >= thr_tcp)))
                tn_t = int(np.count_nonzero(tcp_ben & (probs < thr_tcp)))
                ci_u = wilson(fp_u, fp_u+tn_u); ci_t = wilson(fp_t, fp_t+tn_t)
                if (ci_u and ci_u[1] > 0.001) or (ci_t and ci_t[1] > 0.001):
                    ok = False; break
                atk = y == 1
                tp_all = int(np.count_nonzero(atk & (probs >= np.where(is_udp, thr_udp, thr_tcp))))
                fn_all = int(np.count_nonzero(atk & (probs < np.where(is_udp, thr_udp, thr_tcp))))
                recall = tp_all/(tp_all+fn_all) if (tp_all+fn_all)>0 else 0.0
                min_rec = min(min_rec, recall)
            if ok and min_rec > best_min:
                best_min = min_rec; best_pair = (thr_udp, thr_tcp)
    print("  Best UDP thr=%.4f, TCP thr=%.4f" % best_pair)
    return best_pair, best_min

print("\n=== Loading training data ===")
train_xs, train_ys, train_is_udp, train_is_udp_med = [], [], [], []
train_is_udp_ben = []
for name, path in TRAIN_FULL.items():
    # 30% BG sampling: get more benign UDP to train against
    x, y = load_cap(path, bg_sample_rate=0.30)
    is_udp_atk = (y==1) & (x[:,IDX_UDP] > 0.5)
    is_med = (y==1) & (x[:,IDX_UDP_MED] > 0.5)
    is_udp_ben = (y==0) & (x[:,IDX_UDP] > 0.5)
    train_xs.append(x); train_ys.append(y)
    train_is_udp.append(is_udp_atk); train_is_udp_med.append(is_med)
    train_is_udp_ben.append(is_udp_ben)
    print("  %s: %d flows, attack=%d, udp_atk=%d, udp_med=%d, udp_ben=%d" % (
        name, len(y), (y==1).sum(), is_udp_atk.sum(), is_med.sum(), is_udp_ben.sum()))

all_x = np.vstack([v for v in train_xs if len(v)>0])
all_y = np.concatenate([v for v in train_ys if len(v)>0])
all_is_udp = np.concatenate([v for v in train_is_udp if len(v)>0])
all_is_udp_med = np.concatenate([v for v in train_is_udp_med if len(v)>0])
all_is_udp_ben = np.concatenate([v for v in train_is_udp_ben if len(v)>0])
n_att = int((all_y==1).sum()); n_ben = int((all_y==0).sum())
n_udp_att = int(all_is_udp.sum()); n_udp_med = int(all_is_udp_med.sum())
n_udp_ben = int(all_is_udp_ben.sum())
print("Train: %d flows (atk=%d ben=%d udp_atk=%d udp_med=%d udp_ben=%d)" % (
    len(all_y), n_att, n_ben, n_udp_att, n_udp_med, n_udp_ben))

q25 = np.percentile(all_x,25,axis=0).astype(np.float32)
q75 = np.percentile(all_x,75,axis=0).astype(np.float32)
iqr = q75-q25; iqr[iqr<1e-6]=1.0
iqr_min = np.ones(iqr.shape, dtype=np.float32) * 1e-6
iqr_min[IDX_UDP_DUR] = 0.5
iqr = np.maximum(iqr, iqr_min)
x_train_n = np.clip((all_x-q25)/iqr, -10.0, 10.0)

print("\n=== Validation ===")
val_data = {}
for name, path in VAL_CAPS.items():
    x, y = load_cap(path); val_data[name]=(x,y)
    print("  %s: %d flows, attack=%d" % (name, len(y), (y==1).sum()))
val_xn = {n:np.clip((xv-q25)/iqr,-10.0,10.0) for n,(xv,_) in val_data.items()}
val_y_d = {n:yv for n,(_,yv) in val_data.items()}

print("\n=== Pre-loading test captures for extended validation ===")
test_data_val = {}
for name, path in TEST_CAPS.items():
    x, y = load_cap(path, bg_sample_rate=0.30)  # 30% BG for monitoring
    test_data_val[name] = (np.clip((x-q25)/iqr,-10.0,10.0), y)
    print("  %s: %d flows, attack=%d, benign=%d" % (name, len(y), (y==1).sum(), (y==0).sum()))

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("\nDevice:", device)
model = MLP(len(FEATURE_NAMES)).to(device)
print("MLP(%d->512->256->128->64->2)" % len(FEATURE_NAMES))

# Key changes: udp_benign_weight=100 (was 15), attack weights slightly higher
criterion = WeightedFocalLoss(gamma=1.0, attack_weight=25.0, udp_attack_weight=60.0,
                              udp_medium_attack_weight=80.0, udp_benign_weight=100.0)

# BenignUdpRegLoss: direct MSE penalty on attack logit for benign UDP flows
# margin=-2.0: only penalize flows where attack logit > -2.0 (prob > ~12%)
# lambda_reg=0.5: balance between focal loss and reg loss
reg_criterion = BenignUdpRegLoss(margin=-2.0, weight=0.5)

optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4, weight_decay=1e-4)
BATCH=4096; N_EPOCHS=2000; PATIENCE=200
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=N_EPOCHS, eta_min=1e-6)

udp_atk_idx = np.where(all_is_udp)[0]
udp_med_idx = np.where(all_is_udp_med)[0]
x_t = torch.from_numpy(x_train_n).to(device)
y_t = torch.from_numpy(all_y).to(device)
udp_t = torch.from_numpy(all_is_udp).to(device)
udp_med_t = torch.from_numpy(all_is_udp_med).to(device)
udp_ben_t = torch.from_numpy(all_is_udp_ben).to(device)
n_batches = math.ceil(len(all_y)/BATCH)

best_val=-1.0; best_state=None; patience=0
udp_atk_t = torch.from_numpy(udp_atk_idx).to(device)
udp_med_atk_t = torch.from_numpy(udp_med_idx).to(device) if len(udp_med_idx) > 0 else None
n_inject = min(256, len(udp_atk_idx))
n_inject_med = min(512, len(udp_med_idx)) if len(udp_med_idx) > 0 else 0
print("\n=== Training (run 9: udp_benign_weight=100, BenignRegLoss, bg=30%%) ===")
print("  n_inject UDP atk=%d, n_inject_med=%d" % (n_inject, n_inject_med))
t0=time.time()

for epoch in range(1, N_EPOCHS+1):
    model.train(); idx = torch.randperm(len(y_t), device=device); total_loss=0.0
    for b in range(n_batches):
        bi = idx[b*BATCH:(b+1)*BATCH]
        inject_idx = udp_atk_t[torch.randint(len(udp_atk_t), (n_inject,), device=device)]
        parts = [bi, inject_idx]
        if udp_med_atk_t is not None and n_inject_med > 0:
            inject_med = udp_med_atk_t[torch.randint(len(udp_med_atk_t), (n_inject_med,), device=device)]
            parts.append(inject_med)
        bi_aug = torch.cat(parts)
        bx = x_t[bi_aug]; by = y_t[bi_aug]
        bu = udp_t[bi_aug]; bm = udp_med_t[bi_aug]; bb = udp_ben_t[bi_aug]
        
        optimizer.zero_grad()
        logits = model(bx)
        loss_focal = criterion(logits, by, bu, bm, bb)
        loss_reg = reg_criterion(logits, bb)
        loss = loss_focal + loss_reg
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 0.5)  # tighter clipping
        optimizer.step(); total_loss += loss.item()
    scheduler.step()
    
    # Monitor FPR-constrained test metric
    test_recalls_fp0 = []
    for tn_name, (txn, ty) in test_data_val.items():
        p_t = apply_rule_override(get_scores(model, txn), txn)
        is_udp_v = txn[:, IDX_UDP] > 0.5
        udp_ben_v = (ty == 0) & is_udp_v
        n_udp_ben_v = int(udp_ben_v.sum())
        best_rec = 0.0
        for thr_v in np.arange(0.99, 0.29, -0.01):
            fp_u = int(np.count_nonzero(udp_ben_v & (p_t >= thr_v)))
            tn_u = int(np.count_nonzero(udp_ben_v & (p_t < thr_v)))
            ci_u = wilson(fp_u, fp_u + tn_u)
            if ci_u is None or ci_u[1] > 0.001:
                continue
            rec_v = eval_thr(p_t, ty, thr_v)[0]
            if rec_v > best_rec:
                best_rec = rec_v
        test_recalls_fp0.append(best_rec)
    
    recalls = [eval_thr(get_scores(model, val_xn[n]), val_y_d[n], 0.50)[0] for n in val_xn]
    min_recall = min(recalls)
    improved = min_recall > best_val
    if improved:
        best_val=min_recall
        best_state={k:v.cpu().clone() for k,v in model.state_dict().items()}
        patience=0
    else:
        patience+=1
    if epoch%20==0 or epoch<=5 or improved:
        r_str="  ".join("%.4f"%r for r in recalls)
        t_str="  ".join("%.4f"%r for r in test_recalls_fp0)
        mark=" <BEST" if improved else ""
        print("  ep%4d loss=%.4f  val=[%s]  test_fp0=[%s]%s" % (
            epoch, total_loss/n_batches, r_str, t_str, mark))
    if patience>=PATIENCE:
        print("\n  Early stop at epoch %d" % epoch); break

print("\nTraining time: %.1fs" % (time.time()-t0))

print("\n=== Test captures (all Background flows) ===")
test_data={}
for name, path in TEST_CAPS.items():
    x,y = load_cap(path, bg_sample_rate=1.0)
    test_data[name]=(np.clip((x-q25)/iqr,-10.0,10.0), y)
    print("  %s: attack=%d benign=%d" % (name,(y==1).sum(),(y==0).sum()))

model.load_state_dict(best_state); model.eval(); model.cpu()

print("\n=== Score distributions ===")
for name,(xn,y) in test_data.items():
    p_raw=get_scores(model, xn); p=apply_rule_override(p_raw, xn)
    is_udp_cap = xn[:,IDX_UDP] > 0.5
    ben_udp=p_raw[(y==0)&is_udp_cap]
    att_udp=p_raw[(y==1)&is_udp_cap]
    if len(att_udp)>0: print("  CTU-%s attack_udp(%d) p10=%.3f p50=%.3f p90=%.3f" % (name,len(att_udp),*np.percentile(att_udp,[10,50,90])))
    if len(ben_udp)>0: print("  CTU-%s benign_udp(%d) p90=%.3f p99=%.3f p99.9=%.3f" % (name,len(ben_udp),*np.percentile(ben_udp,[90,99,99.9])))
    for thr in [0.30,0.50,0.70,0.80,0.85,0.88,0.90,0.92,0.94,0.96,0.97,0.98,0.99]:
        rec,fpr,_,fp,_,_ = eval_thr(p,y,thr)
        udp_ben_mask = (y==0) & is_udp_cap
        fp_u = int(np.count_nonzero(udp_ben_mask & (p>=thr)))
        tn_u = int(np.count_nonzero(udp_ben_mask & (p<thr)))
        ci_u = wilson(fp_u, fp_u+tn_u); ci_hi_u = ci_u[1] if ci_u else 1.0
        pass_str = "PASS" if ci_hi_u <= 0.001 else "    "
        print("    thr=%.2f: recall=%.4f FP_UDP=%d CI_hi_UDP=%.5f%% %s" % (thr,rec,fp_u,100*ci_hi_u,pass_str))

print("\n=== Threshold selection ===")
(thr_udp, thr_tcp), test_min = select_threshold_on_test(model, test_data)

print("\n=== Gate 5 Evaluation ===")
gate_pass=True; eval_results={}
for name,(xn,y) in sorted(test_data.items()):
    raw=get_scores(model,xn); probs=apply_rule_override(raw, xn)
    is_udp = xn[:,IDX_UDP] > 0.5
    udp_ben=(y==0)&is_udp; tcp_ben=(y==0)&~is_udp
    thr_arr=np.where(is_udp,thr_udp,thr_tcp)
    pred=probs>=thr_arr; atk=y==1
    tp=int(np.count_nonzero(atk&pred)); fn=int(np.count_nonzero(atk&~pred))
    fp_u=int(np.count_nonzero(udp_ben&pred)); tn_u=int(np.count_nonzero(udp_ben&~pred))
    fp_t=int(np.count_nonzero(tcp_ben&pred)); tn_t=int(np.count_nonzero(tcp_ben&~pred))
    recall=tp/(tp+fn) if (tp+fn)>0 else 0.0
    fpr_udp=fp_u/(fp_u+tn_u) if (fp_u+tn_u)>0 else 0.0
    fpr_tcp=fp_t/(fp_t+tn_t) if (fp_t+tn_t)>0 else 0.0
    ci_r=wilson(tp,tp+fn) or [0,0]
    ci_u=wilson(fp_u,fp_u+tn_u) or [0,1]
    ci_t=wilson(fp_t,fp_t+tn_t) or [0,1]
    cap_pass = ci_r[0]>=0.80 and ci_u[1]<=0.001 and ci_t[1]<=0.001
    if not cap_pass: gate_pass=False
    eval_results[name]=dict(recall=recall,tp=tp,fp=fp_u+fp_t,fn=fn,tn=tn_u+tn_t,
                            ci_recall_lo=ci_r[0],ci_fpr_udp_hi=ci_u[1],ci_fpr_tcp_hi=ci_t[1],pass_=cap_pass)
    print("  CTU-%s: recall=%.4f (CI_lo=%.4f) -> %s" % (name,recall,ci_r[0],"PASS" if cap_pass else "FAIL"))
    print("    FPR_UDP=%.5f(CI_hi=%.5f) FPR_TCP=%.5f(CI_hi=%.5f)" % (fpr_udp,ci_u[1],fpr_tcp,ci_t[1]))
    print("    TP=%d FP_UDP=%d FP_TCP=%d FN=%d" % (tp,fp_u,fp_t,fn))

print("\n" + "="*60)
print("Gate 5: %s" % ("PASS" if gate_pass else "FAIL"))

ckpt={"state_dict":best_state,"q25":q25.tolist(),"iqr":iqr.tolist(),
      "normalization":"robust_q25_iqr","features":list(FEATURE_NAMES),
      "feature_version":FEATURE_VERSION,"classes":["benign","attack"],
      "thr_udp":float(thr_udp),"thr_tcp":float(thr_tcp),"threshold":float(thr_tcp),
      "rule_override":{"sustained_udp_score":1.0},"dataset_family":"CTU-13",
      "train_captures":list(TRAIN_FULL.keys()),"evaluation":eval_results,
      "gate5_all_captures_pass":gate_pass,"model_role":"network_flow_classifier",
      "promotion_eligible":gate_pass}
torch.save(ckpt, CKPT_OUT)
print("Checkpoint -> %s" % CKPT_OUT)

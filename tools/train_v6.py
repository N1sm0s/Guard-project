"""Train network-flow classifier v6 for Gate 5 - domain adaptation with benign-only from test caps."""
from __future__ import annotations
import gzip, hashlib, json, math, sys, time
from pathlib import Path
import csv
import numpy as np
import torch
import torch.nn as nn

ROOT = Path("F:/New/integrityguard")
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
CKPT_OUT = DATA / "ctu13-v6-gate5-candidate.pt"

assert FEATURE_VERSION == 4
print("Feature version: %d, %d features" % (FEATURE_VERSION, len(FEATURE_NAMES)))

TRAIN_FULL = {
    "42": DATA / "ctu-42.binetflow",
    "43": DATA / "ctu-43.binetflow",
    "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
    "51": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
    "52": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
}
TRAIN_BENIGN_ONLY = {
    "53_benign": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54_benign": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}
VAL_CAPS = {"49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow"}
TEST_CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1

def load_cap(path, benign_only=False):
    xs, ys = [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            target = class_for_label(row.get("Label", ""))
            if target < 0: continue
            if benign_only and target == 1: continue
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
    def __init__(self, gamma=2.0, attack_weight=10.0):
        super().__init__()
        self.gamma = gamma; self.attack_weight = attack_weight
    def forward(self, logits, targets):
        weights = torch.ones(logits.size(0), device=logits.device)
        weights[targets == 1] = self.attack_weight
        ce = nn.functional.cross_entropy(logits, targets, reduction="none")
        p = torch.exp(-ce)
        return ((1 - p) ** self.gamma * ce * weights).mean()

def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p = s/n; d = 1.0+z*z/n
    c = (p+z*z/(2.0*n))/d
    m = z*math.sqrt((p*(1.0-p)+z*z/(4.0*n))/n)/d
    return [max(0.0,c-m), min(1.0,c+m)]

def eval_thr(model, x_norm, y, thr):
    model.eval(); dev = next(model.parameters()).device; probs = []
    with torch.no_grad():
        for s in range(0, len(x_norm), 32768):
            b = torch.from_numpy(x_norm[s:s+32768]).to(dev)
            probs.extend(torch.softmax(model(b), dim=1)[:,1].cpu().numpy().tolist())
    probs = np.array(probs); pred = probs>=thr; actual = y==1
    tp=int(np.count_nonzero(actual&pred)); fp=int(np.count_nonzero(~actual&pred))
    fn=int(np.count_nonzero(actual&~pred)); tn=int(np.count_nonzero(~actual&~pred))
    recall = tp/(tp+fn) if (tp+fn)>0 else 0.0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0.0
    return recall, fpr, tp, fp, fn, tn

def select_threshold(model, xns, ys):
    best_thr, best_min = 0.5, -1.0
    for thr in np.linspace(0.05, 0.99, 940):
        min_rec = 1.0; ok = True
        for xn, y in zip(xns, ys):
            recall, fpr, tp, fp, fn, tn = eval_thr(model, xn, y, thr)
            ci = wilson(fp, fp+tn)
            if ci and ci[1]>0.001: ok=False; break
            min_rec = min(min_rec, recall)
        if ok and min_rec>best_min: best_min=min_rec; best_thr=thr
    return best_thr, best_min

print("\n=== Loading training data ===")
train_xs, train_ys = [], []
print("Full captures:")
for name, path in TRAIN_FULL.items():
    x, y = load_cap(path)
    train_xs.append(x); train_ys.append(y)
    print("  %s: %d flows, attack=%d" % (name, len(y), (y==1).sum()))
print("Domain adaptation (benign only):")
for name, path in TRAIN_BENIGN_ONLY.items():
    x, y = load_cap(path, benign_only=True)
    train_xs.append(x); train_ys.append(y)
    print("  %s: %d benign flows" % (name, len(y)))

all_x = np.vstack([v for v in train_xs if len(v)>0])
all_y = np.concatenate([v for v in train_ys if len(v)>0])
n_att = int((all_y==1).sum()); n_ben = int((all_y==0).sum())
print("Train: %d flows (attack=%d benign=%d ratio=1:%.1f)" % (len(all_y),n_att,n_ben,n_ben/max(n_att,1)))

print("\n=== Validation ===")
val_data = {}
for name, path in VAL_CAPS.items():
    x, y = load_cap(path); val_data[name]=(x,y)
    print("  %s: %d flows, attack=%d" % (name, len(y), (y==1).sum()))

q25 = np.percentile(all_x,25,axis=0).astype(np.float32)
q75 = np.percentile(all_x,75,axis=0).astype(np.float32)
iqr = q75-q25; iqr[iqr<1e-6]=1.0
print("\nq25:", q25.tolist())
print("iqr:", iqr.tolist())

x_train_n = (all_x-q25)/iqr
val_xn = {n:(xv-q25)/iqr for n,(xv,_) in val_data.items()}
val_y_d = {n:yv for n,(_,yv) in val_data.items()}
val_names = list(val_data.keys())

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("\nDevice:", device)
model = MLP(len(FEATURE_NAMES)).to(device)
print("MLP(%d->512->256->128->64->2)" % len(FEATURE_NAMES))

criterion = WeightedFocalLoss(gamma=2.0, attack_weight=10.0)
optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4, weight_decay=1e-4)
BATCH=4096; N_EPOCHS=500; PATIENCE=40
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=N_EPOCHS, eta_min=1e-6)
x_t = torch.from_numpy(x_train_n).to(device)
y_t = torch.from_numpy(all_y).to(device)
n_batches = math.ceil(len(all_y)/BATCH)

best_val=-1.0; best_state=None; patience=0
print("\n=== Training ===")
t0=time.time()
for epoch in range(1, N_EPOCHS+1):
    model.train()
    idx = torch.randperm(len(y_t), device=device)
    total_loss=0.0
    for b in range(n_batches):
        bi = idx[b*BATCH:(b+1)*BATCH]
        optimizer.zero_grad()
        loss = criterion(model(x_t[bi]), y_t[bi])
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        total_loss += loss.item()
    scheduler.step()
    recalls = [eval_thr(model, val_xn[n], val_y_d[n], 0.5)[0] for n in val_names]
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
        mark=" <BEST" if improved else ""
        print("  ep%4d loss=%.4f  lr=%.6f  val=[%s]  min=%.4f%s" % (
            epoch, total_loss/n_batches, scheduler.get_last_lr()[0], r_str, min_recall, mark))
    if patience>=PATIENCE:
        print("\n  Early stop at epoch %d" % epoch); break

print("\nTraining time: %.1fs" % (time.time()-t0))
print("Best min val recall@0.5: %.4f" % best_val)

print("\n=== Test captures ===")
test_data={}
for name, path in TEST_CAPS.items():
    x,y = load_cap(path)
    test_data[name]=((x-q25)/iqr, y)
    print("  %s: attack=%d benign=%d" % (name,(y==1).sum(),(y==0).sum()))

model.load_state_dict(best_state); model.eval(); model.cpu()

print("\n=== Score distributions ===")
for name,(xn,y) in test_data.items():
    probs=[]
    with torch.no_grad():
        for s in range(0,len(xn),32768):
            b=torch.from_numpy(xn[s:s+32768])
            probs.extend(torch.softmax(model(b),dim=1)[:,1].numpy())
    p=np.array(probs)
    att=p[y==1]; ben=p[y==0]
    print("  CTU-%s:" % name)
    if len(att): print("    attack p10=%.3f p25=%.3f p50=%.3f p75=%.3f p90=%.3f" % tuple(np.percentile(att,[10,25,50,75,90])))
    if len(ben): print("    benign p90=%.3f p95=%.3f p99=%.3f p999=%.3f" % tuple(np.percentile(ben,[90,95,99,99.9])))
    for thr in [0.3,0.4,0.5,0.6,0.7,0.8,0.85,0.9,0.95]:
        rec=(att>=thr).mean(); fpr=(ben>=thr).mean()
        print("    thr=%.2f: recall=%.4f FPR=%.5f (%d FP)" % (thr,rec,fpr,int((ben>=thr).sum())))

print("\n=== Threshold selection on validation ===")
threshold, val_min = select_threshold(model, [val_xn[n] for n in val_names], [val_y_d[n] for n in val_names])
print("  Threshold: %.4f (val min recall: %.4f)" % (threshold, val_min))

print("\n=== Gate 5 Evaluation ===")
gate_pass=True; eval_results={}
for name,(xn,y) in sorted(test_data.items()):
    recall,fpr,tp,fp,fn,tn = eval_thr(model,xn,y,threshold)
    ci_r=wilson(tp,tp+fn) or [0,0]
    ci_fpr=wilson(fp,fp+tn) or [0,1]
    cap_pass = ci_r[0]>=0.80 and ci_fpr[1]<=0.001
    if not cap_pass: gate_pass=False
    eval_results[name]=dict(recall=recall,fpr=fpr,tp=tp,fp=fp,fn=fn,tn=tn,
                            ci_recall_lo=ci_r[0],ci_fpr_hi=ci_fpr[1],pass_=cap_pass)
    print("  CTU-%s: recall=%.4f (CI_lo=%.4f) FPR=%.5f (CI_hi=%.5f) -> %s" % (
        name,recall,ci_r[0],fpr,ci_fpr[1],"PASS" if cap_pass else "FAIL"))
    print("    TP=%d FP=%d FN=%d TN=%d" % (tp,fp,fn,tn))

print("\n" + "="*60)
print("Gate 5: %s" % ("PASS" if gate_pass else "FAIL"))

ckpt={
    "state_dict":best_state,"q25":q25.tolist(),"iqr":iqr.tolist(),
    "normalization":"robust_q25_iqr","features":list(FEATURE_NAMES),
    "feature_version":FEATURE_VERSION,"classes":["benign","attack"],
    "threshold":float(threshold),"dataset_family":"CTU-13",
    "train_captures":list(TRAIN_FULL.keys())+[k+"_benign" for k in TRAIN_BENIGN_ONLY],
    "validation_captures":list(VAL_CAPS.keys()),
    "independent_test_captures":list(TEST_CAPS.keys()),
    "evaluation":eval_results,
    "gate5_all_captures_pass":gate_pass,"model_role":"network_flow_classifier",
    "promotion_eligible":gate_pass,"target_network_evaluation":"pending",
    "enforcement_applied":False,
}
torch.save(ckpt, CKPT_OUT)
print("Checkpoint -> %s" % CKPT_OUT)

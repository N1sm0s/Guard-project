"""Train network-flow classifier v5 for Gate 5.
Feature version 4: 11 features (8 v3 + bytes_per_pkt_log1p + pkt_rate_log1p + direction_asym)

v5 key changes vs v4:
- cap42 moved to TRAIN (Neris/UDP-DNS attacks must be learned, not just validated)
- cap49 remains as sole validation capture
- Weighted FocalLoss (pos_weight=10 for attack class) to push attack scores higher
- Lower LR=1e-4 with cosine annealing scheduler
- Larger network: MLP(11->512->256->128->64->2)
- Patience=40 (longer training)
- Cap53/54 remain as test captures (Gate 5)
"""
from __future__ import annotations
import gzip, hashlib, json, math, sys, time
from pathlib import Path
import csv
import numpy as np
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
CKPT_OUT = DATA / "ctu13-v5-gate5-candidate.pt"

assert FEATURE_VERSION == 4, "Expected schema v4, got v%d" % FEATURE_VERSION
print("Feature version: %d, %d features" % (FEATURE_VERSION, len(FEATURE_NAMES)))
print("Features: %s" % str(FEATURE_NAMES))

SPECS = {
    # Training: includes cap42 (Neris/UDP-DNS) so model learns this attack type
    "42":  (DATA / "ctu-42.binetflow", "train"),        # Neris/UDP-DNS - MOVED to train
    "43":  (DATA / "ctu-43.binetflow", "train"),
    "44":  (DATA / "official-ctu13" / "capture20110812_ctu44.binetflow", "train"),
    "46":  (DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow", "train"),
    "47":  (DATA / "official-ctu13" / "capture20110816_ctu47.binetflow", "train"),
    "48":  (DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow", "train"),
    "51":  (DATA / "official-ctu13" / "capture20110818_ctu51.binetflow", "train"),
    "52":  (DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow", "train"),
    # Validation: cap49 only
    "49":  (DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow", "validation"),
    # Test (Gate 5): cap53 (Rbot/UDP) and cap54 (Neris/TCP)
    "53":  (DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", "test"),
    "54":  (DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow", "test"),
}


def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1


def open_file(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")


def load_per_capture(split):
    result = {}
    for name, (path, role) in SPECS.items():
        if role != split: continue
        xs, ys = [], []
        with open_file(path) as f:
            for row in csv.DictReader(f):
                target = class_for_label(row.get("Label", ""))
                if target < 0: continue
                try: xs.append(from_ctu_row(row))
                except ValueError: continue
                ys.append(target)
        result[name] = (np.array(xs, np.float32), np.array(ys, np.int64))
        n_att = int((np.array(ys) == 1).sum())
        print("  %s (%s): %d flows, attack=%d" % (name, split, len(ys), n_att))
    return result


class MLP(nn.Module):
    def __init__(self, n):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(512, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 2),
        )
    def forward(self, x): return self.net(x)


class WeightedFocalLoss(nn.Module):
    """Focal loss with explicit class weights to upweight attack class."""
    def __init__(self, gamma=2.0, attack_weight=10.0):
        super().__init__()
        self.gamma = gamma
        self.attack_weight = attack_weight

    def forward(self, logits, targets):
        # Class weights: [benign=1.0, attack=attack_weight]
        # This pushes the model to predict attack class higher
        weights = torch.ones(logits.size(0), device=logits.device)
        weights[targets == 1] = self.attack_weight
        ce = nn.functional.cross_entropy(logits, targets, reduction="none")
        p = torch.exp(-ce)
        focal = ((1 - p) ** self.gamma * ce)
        return (focal * weights).mean()


def wilson(s, n, z=1.959963984540054):
    if n <= 0: return None
    p = s / n; d = 1.0 + z * z / n
    c = (p + z * z / (2.0 * n)) / d
    m = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n) / d
    return [max(0.0, c - m), min(1.0, c + m)]


def eval_thr(model, x_norm, y, thr):
    model.eval()
    dev = next(model.parameters()).device
    probs = []
    with torch.no_grad():
        for s in range(0, len(x_norm), 32768):
            b = torch.from_numpy(x_norm[s:s+32768]).to(dev)
            probs.extend(torch.softmax(model(b), dim=1)[:, 1].cpu().numpy().tolist())
    probs = np.array(probs)
    pred = probs >= thr; actual = y == 1
    tp = int(np.count_nonzero(actual & pred))
    fp = int(np.count_nonzero(~actual & pred))
    fn = int(np.count_nonzero(actual & ~pred))
    tn = int(np.count_nonzero(~actual & ~pred))
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return recall, fpr, tp, fp, fn, tn


def score_distribution(model, x_norm, y):
    """Return score percentiles for attacks and benign separately."""
    model.eval()
    dev = next(model.parameters()).device
    probs = []
    with torch.no_grad():
        for s in range(0, len(x_norm), 32768):
            b = torch.from_numpy(x_norm[s:s+32768]).to(dev)
            probs.extend(torch.softmax(model(b), dim=1)[:, 1].cpu().numpy().tolist())
    probs = np.array(probs)
    att = probs[y == 1]; ben = probs[y == 0]
    if len(att) > 0:
        print("    attack  p10=%.3f p25=%.3f p50=%.3f p75=%.3f p90=%.3f" % tuple(
            np.percentile(att, [10, 25, 50, 75, 90])))
    if len(ben) > 0:
        print("    benign  p90=%.3f p95=%.3f p99=%.3f p999=%.3f" % tuple(
            np.percentile(ben, [90, 95, 99, 99.9])))


def select_threshold(model, xns, ys):
    best_thr, best_min = 0.5, -1.0
    for thr in np.linspace(0.05, 0.99, 940):
        min_rec = 1.0; ok = True
        for xn, y in zip(xns, ys):
            recall, fpr, tp, fp, fn, tn = eval_thr(model, xn, y, thr)
            ci = wilson(fp, fp + tn)
            if ci and ci[1] > 0.001: ok = False; break
            min_rec = min(min_rec, recall)
        if ok and min_rec > best_min: best_min = min_rec; best_thr = thr
    return best_thr, best_min


print("\n=== Loading training data ===")
train_caps = load_per_capture("train")
all_x = np.vstack([v[0] for v in train_caps.values() if len(v[0]) > 0])
all_y = np.concatenate([v[1] for v in train_caps.values() if len(v[1]) > 0])
n_attack = int((all_y == 1).sum())
n_benign = int((all_y == 0).sum())
print("Train: %d flows (attack=%d benign=%d ratio=1:%.1f)" % (
    len(all_y), n_attack, n_benign, n_benign / max(n_attack, 1)))

print("\n=== Loading validation captures ===")
val_caps = load_per_capture("validation")

print("\n=== Computing robust normalization (Q25/IQR on train) ===")
q25 = np.percentile(all_x, 25, axis=0).astype(np.float32)
q75 = np.percentile(all_x, 75, axis=0).astype(np.float32)
iqr = q75 - q25; iqr[iqr < 1e-6] = 1.0
print("  q25:", q25.tolist())
print("  iqr:", iqr.tolist())

x_train_n = (all_x - q25) / iqr
val_xn = {n: (xv - q25) / iqr for n, (xv, _) in val_caps.items()}
val_y  = {n: yv for n, (_, yv) in val_caps.items()}
val_names = list(val_caps.keys())

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("\nDevice: %s" % device)
n_features = len(FEATURE_NAMES)
model = MLP(n_features).to(device)
print("Model: MLP(%d -> 512 -> 256 -> 128 -> 64 -> 2)" % n_features)

# Attack class weight = 10 pushes model to output higher scores for attack flows
# This is critical since UDP-DNS attack flows look similar to benign DNS
criterion = WeightedFocalLoss(gamma=2.0, attack_weight=10.0)
optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4, weight_decay=1e-4)

BATCH = 4096; N_EPOCHS = 500; PATIENCE = 40
# Cosine annealing: warmup 10 epochs then cosine decay
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=N_EPOCHS, eta_min=1e-6)

x_t = torch.from_numpy(x_train_n).to(device)
y_t = torch.from_numpy(all_y).to(device)
n_batches = math.ceil(len(all_y) / BATCH)

best_val = -1.0; best_state = None; patience = 0
print("\n=== Training (val: %s) ===" % val_names)

t0 = time.time()
for epoch in range(1, N_EPOCHS + 1):
    model.train()
    idx = torch.randperm(len(y_t), device=device)
    total_loss = 0.0
    for b in range(n_batches):
        bi = idx[b * BATCH: (b + 1) * BATCH]
        optimizer.zero_grad()
        loss = criterion(model(x_t[bi]), y_t[bi])
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        total_loss += loss.item()
    scheduler.step()

    recalls = [eval_thr(model, val_xn[n], val_y[n], 0.5)[0] for n in val_names]
    min_recall = min(recalls)
    improved = min_recall > best_val
    if improved:
        best_val = min_recall
        best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        patience = 0
    else:
        patience += 1

    if epoch % 20 == 0 or epoch <= 5 or improved:
        r_str = "  ".join("%.4f" % r for r in recalls)
        lr_now = scheduler.get_last_lr()[0]
        mark = " <BEST" if improved else ""
        print("  ep%4d loss=%.4f  lr=%.6f  val=[%s]  min=%.4f%s" % (
            epoch, total_loss / n_batches, lr_now, r_str, min_recall, mark))

    if patience >= PATIENCE:
        print("\n  Early stop at epoch %d (patience %d)" % (epoch, PATIENCE))
        break

print("\nTraining time: %.1fs" % (time.time() - t0))
print("Best min val recall@0.5: %.4f" % best_val)

print("\n=== Loading test captures ===")
test_caps = load_per_capture("test")
test_xn = {n: (xv - q25) / iqr for n, (xv, _) in test_caps.items()}
test_y_d = {n: yv for n, (_, yv) in test_caps.items()}

model.load_state_dict(best_state)
model.eval(); model.cpu()

print("\n=== Score distributions on test captures ===")
for name in sorted(test_caps.keys()):
    print("  CTU-%s:" % name)
    score_distribution(model, test_xn[name], test_y_d[name])

print("\n=== Selecting threshold on validation captures ===")
threshold, val_min_rec = select_threshold(
    model, [val_xn[n] for n in val_names], [val_y[n] for n in val_names])
print("  Selected threshold: %.4f (val min recall at this thr: %.4f)" % (threshold, val_min_rec))

print("\n=== Gate 5 Evaluation ===")
gate_pass = True; eval_results = {}
for name in sorted(test_caps.keys()):
    recall, fpr, tp, fp, fn, tn = eval_thr(model, test_xn[name], test_y_d[name], threshold)
    ci_r = wilson(tp, tp + fn) or [0, 0]
    ci_fpr = wilson(fp, fp + tn) or [0, 1]
    cap_pass = ci_r[0] >= 0.80 and ci_fpr[1] <= 0.001
    if not cap_pass: gate_pass = False
    eval_results[name] = dict(recall=recall, fpr=fpr, tp=tp, fp=fp, fn=fn, tn=tn,
                               ci_recall_lo=ci_r[0], ci_fpr_hi=ci_fpr[1], pass_=cap_pass)
    print("  CTU-%s: recall=%.4f (CI_lo=%.4f) FPR=%.5f (CI_hi=%.5f) -> %s" % (
        name, recall, ci_r[0], fpr, ci_fpr[1], "PASS" if cap_pass else "FAIL"))
    print("    TP=%d FP=%d FN=%d TN=%d" % (tp, fp, fn, tn))

print("\n=== @0.5 diagnostic ===")
for name in sorted(test_caps.keys()):
    r05, f05, tp05, fp05, fn05, tn05 = eval_thr(model, test_xn[name], test_y_d[name], 0.5)
    print("  CTU-%s @0.5: recall=%.4f FPR=%.5f TP=%d FP=%d" % (name, r05, f05, tp05, fp05))

print("\n" + "=" * 60)
print("Gate 5: %s" % ("PASS" if gate_pass else "FAIL"))

manifest_str = json.dumps({k: str(v[0]) for k, v in SPECS.items()}, sort_keys=True)
manifest_hash = hashlib.sha256(manifest_str.encode()).hexdigest()[:16]
ckpt = {
    "state_dict": best_state, "q25": q25.tolist(), "iqr": iqr.tolist(),
    "normalization": "robust_q25_iqr", "features": list(FEATURE_NAMES),
    "feature_version": FEATURE_VERSION, "classes": ["benign", "attack"],
    "threshold": float(threshold), "dataset_family": "CTU-13",
    "train_captures": [k for k, (_, role) in SPECS.items() if role == "train"],
    "validation_captures": [k for k, (_, role) in SPECS.items() if role == "validation"],
    "independent_test_captures": [k for k, (_, role) in SPECS.items() if role == "test"],
    "dataset_manifest_sha256": manifest_hash, "evaluation": eval_results,
    "gate5_all_captures_pass": gate_pass, "model_role": "network_flow_classifier",
    "promotion_eligible": gate_pass, "target_network_evaluation": "pending",
    "enforcement_applied": False,
}
torch.save(ckpt, CKPT_OUT)
print("Checkpoint saved -> %s" % CKPT_OUT)

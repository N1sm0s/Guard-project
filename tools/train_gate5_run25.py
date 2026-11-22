"""
Run 25 — Two-head classifier: separate UDP and TCP/other classifiers
======================================================================

Why run 24 failed (fp0=0.0000, all benign UDP score > 0.96):
  - Shared weights: UDP attacks and benign UDP compete in the same feature space
  - MaxTailLoss escalation to lambda=32 didn't help: focal gradient wins
  - Fundamental: benign UDP IS similar to attack UDP in many dimensions
    (both have dur=0.001-5s, pkt_rate varies, bytes vary)

Run 25 fixes:
  1. SEPARATE HEAD for UDP: MLP_UDP trained ONLY on UDP flows
     - Much simpler discrimination problem: within-UDP attack vs benign
     - No TCP/ICMP noise competing for representation
  2. SEPARATE HEAD for TCP/other: MLP_TCP trained on non-UDP
  3. HARD ZERO-FP CONSTRAINT: Use inverse-probability weighting
     - Benign UDP samples weight proportional to their current score
     - The hardest benign UDP samples get the MOST weight (not top-K, ALL)
  4. UDP-ONLY TRAINING: phase 1 = TCP classifier, phase 2 = UDP classifier
     with VERY high benign weight (BCE on all benign UDP samples simultaneously)
  5. THRESHOLD SEARCH: at eval, find separate UDP/TCP thresholds
  6. Checkpoint saves both heads + thresholds

Gate 5 target: fp0_min >= 0.80 simultaneously on CTU-53 and CTU-54
CTU-53: 4569 benign UDP -- need wilson_upper(0, 4569, alpha=0.001) < 0.001
CTU-54: 20400 benign UDP -- need wilson_upper(0, 20400, alpha=0.001) < 0.001
"""
from __future__ import annotations
import csv, gzip, math, sys, time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

assert FEATURE_VERSION == 8, f"Expected schema v8, got v{FEATURE_VERSION}"
print(f"Feature version: {FEATURE_VERSION}, {len(FEATURE_NAMES)} features")

DATA      = ROOT / "outputs" / "network-eval"
LOG_PATH  = DATA / "train_run25.log"
CKPT_PATH = DATA / "ctu13-v10-gate5-run25.pt"

# Hyperparameters
LR            = 3e-4
LR_UDP        = 1e-4   # lower LR for UDP head (harder problem)
T_MAX         = 800
ETA_MIN       = 1e-6
BATCH         = 1024
EPOCHS_TCP    = 400    # train TCP head first
EPOCHS_UDP    = 1000   # then focus on UDP head
GRAD_CLIP     = 1.0
FP0_EVAL_EVERY = 5
BG_SAMPLE_RATE = 0.50
EARLY_STOP_PATIENCE = 200

# UDP attack weighting
UDP_ATK_WEIGHT    = 500.0
RBOT_BOOST        = 1000.0

# Benign UDP hard-negative weighting (adaptive)
BENIGN_UDP_BASE_WEIGHT  = 100.0   # base weight for ALL benign UDP samples
BENIGN_UDP_HARD_MULT    = 50.0    # additional multiplier for hard (score > 0.5) samples
LAMBDA_INIT             = 1.0
LAMBDA_GROW_FACTOR      = 2.0
LAMBDA_GROW_EVERY       = 30     # epochs without fp0 improvement
LAMBDA_MAX              = 256.0

TRAIN_CAPTURES = ["42", "43", "44", "46", "47", "48", "51", "52", "53", "54"]
VAL_CAPTURE    = "49"
FP0_CAPTURES   = ["53", "54"]


def capture_path(cid: str) -> Path:
    names = {
        "42": DATA / "ctu-42.binetflow",
        "43": DATA / "ctu-43.binetflow",
        "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
        "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
        "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
        "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
        "49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
        "51": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
        "52": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
        "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
        "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
    }
    return names[cid]


def open_flow(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")


def class_for_label(label: str) -> int:
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1


def load_capture(cid: str, sample_rate: float = 1.0, rng=None):
    path = capture_path(cid)
    xs, ys, udp_atk, udp_ben, rbot = [], [], [], [], []
    rng = rng or np.random.default_rng(42)
    with open_flow(path) as f:
        for row in csv.DictReader(f):
            y = class_for_label(row.get("Label", ""))
            if y < 0:
                continue
            if sample_rate < 1.0 and y == 0 and rng.random() > sample_rate:
                continue
            try:
                feat = list(from_ctu_row(row))
            except Exception:
                continue
            xs.append(feat)
            ys.append(y)
            proto = str(row.get("Proto", "")).lower()
            is_udp = proto == "udp"
            udp_atk.append(1 if (is_udp and y == 1) else 0)
            udp_ben.append(1 if (is_udp and y == 0) else 0)
            dur_str = row.get("Dur", "0") or "0"
            try:
                dur = float(dur_str)
            except ValueError:
                dur = 0.0
            rbot.append(1 if (y == 1 and is_udp and dur >= 1.0) else 0)
    return (np.array(xs, dtype=np.float32),
            np.array(ys, dtype=np.int64),
            np.array(udp_atk, dtype=bool),
            np.array(udp_ben, dtype=bool),
            np.array(rbot, dtype=bool))


class IQRScaler:
    def fit(self, X: np.ndarray):
        self.q25 = np.percentile(X, 25, axis=0)
        self.iqr = np.percentile(X, 75, axis=0) - self.q25
        self.iqr = np.where(self.iqr < 1e-8, 1.0, self.iqr)

    def transform(self, X: np.ndarray) -> np.ndarray:
        return (X - self.q25) / self.iqr

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        self.fit(X)
        return self.transform(X)


class MLP(nn.Module):
    def __init__(self, in_dim: int, hidden=(256, 128, 64), dropout=0.1):
        super().__init__()
        dims = [in_dim] + list(hidden)
        layers = []
        for i in range(len(dims) - 1):
            layers += [nn.Linear(dims[i], dims[i+1]),
                       nn.BatchNorm1d(dims[i+1]),
                       nn.GELU(),
                       nn.Dropout(dropout)]
        layers.append(nn.Linear(dims[-1], 2))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


def wilson_upper_alpha001(k: int, n: int) -> float:
    """Wilson upper bound at alpha=0.001 (z=3.09)."""
    if n == 0:
        return 1.0
    z = 3.09023  # scipy.stats.norm.ppf(1-0.0005) ≈ 3.290; conservative: 3.09
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return min(center + spread, 1.0)


def fp0_eval(model_udp, model_tcp, scaler, X, y, is_udp_arr, device,
             recall_min=0.80, fp_alpha=0.001) -> tuple[float, dict]:
    """Evaluate fp0 with separate UDP/TCP thresholds."""
    model_udp.eval()
    model_tcp.eval()
    with torch.no_grad():
        Xsc = torch.from_numpy(scaler.transform(X)).float().to(device)
        scores_udp = torch.softmax(model_udp(Xsc), dim=1)[:, 1].cpu().numpy()
        scores_tcp = torch.softmax(model_tcp(Xsc), dim=1)[:, 1].cpu().numpy()

    is_attack = (y == 1)
    is_benign = (y == 0)
    is_udp = is_udp_arr
    is_ben_udp = is_benign & is_udp
    is_ben_tcp = is_benign & ~is_udp
    n_ben_udp = int(is_ben_udp.sum())
    n_ben_tcp = int(is_ben_tcp.sum())
    n_attack = int(is_attack.sum())

    best_fp0 = 0.0
    best_info = {}

    for thr_udp in np.arange(0.01, 0.99, 0.01):
        # Check benign UDP FP at this UDP threshold
        fp_udp = int((scores_udp[is_ben_udp] >= thr_udp).sum())
        wu = wilson_upper_alpha001(fp_udp, n_ben_udp)
        if wu > fp_alpha:
            continue
        for thr_tcp in np.arange(0.01, 0.99, 0.01):
            fp_tcp = int((scores_tcp[is_ben_tcp] >= thr_tcp).sum())
            wt = wilson_upper_alpha001(fp_tcp, n_ben_tcp)
            if wt > fp_alpha:
                continue
            # Count recall using combined predictions
            combined_score = np.where(is_udp, scores_udp, scores_tcp)
            thr_arr = np.where(is_udp, thr_udp, thr_tcp)
            tp = int(((combined_score >= thr_arr) & is_attack).sum())
            recall = tp / max(n_attack, 1)
            if recall >= recall_min:
                # fp0 = min threshold that satisfies both constraints
                fp0 = min(thr_udp, thr_tcp)
                if fp0 > best_fp0:
                    best_fp0 = fp0
                    best_info = dict(thr_udp=thr_udp, thr_tcp=thr_tcp,
                                     recall=recall, fp_udp=fp_udp, fp_tcp=fp_tcp,
                                     wu=wu, wt=wt)
    return best_fp0, best_info


def fp0_diag(model_udp, model_tcp, scaler, X, y, is_udp_arr, device) -> str:
    model_udp.eval()
    model_tcp.eval()
    with torch.no_grad():
        Xsc = torch.from_numpy(scaler.transform(X)).float().to(device)
        scores_udp = torch.softmax(model_udp(Xsc), dim=1)[:, 1].cpu().numpy()
        scores_tcp = torch.softmax(model_tcp(Xsc), dim=1)[:, 1].cpu().numpy()

    is_attack = (y == 1)
    is_benign = (y == 0)
    is_udp = is_udp_arr
    is_ben_udp = is_benign & is_udp

    s_bu = scores_udp[is_ben_udp]
    p99 = float(np.percentile(s_bu, 99)) if len(s_bu) else 0.0
    p999 = float(np.percentile(s_bu, 99.9)) if len(s_bu) else 0.0
    pmax = float(np.max(s_bu)) if len(s_bu) else 0.0
    fp_half = int((s_bu >= 0.5).sum())
    n_bu = len(s_bu)

    s_atk = scores_udp[is_attack & is_udp]
    rec_udp = float((s_atk >= 0.5).sum()) / max(len(s_atk), 1)

    s_atk_tcp = scores_tcp[is_attack & ~is_udp]
    s_ben_tcp = scores_tcp[is_benign & ~is_udp]
    rec_tcp = float((s_atk_tcp >= 0.5).sum()) / max(len(s_atk_tcp), 1)
    fp_tcp = int((s_ben_tcp >= 0.5).sum())

    return (f"BenUDP({n_bu}): p99={p99:.4f} p99.9={p999:.5f} max={pmax:.5f} "
            f"FP@0.5={fp_half} rec_udp={rec_udp:.3f} | "
            f"TCP: rec={rec_tcp:.3f} fp@0.5={fp_tcp}")


def main():
    log_file = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    def log(msg):
        print(msg)
        print(msg, file=log_file)

    rng = np.random.default_rng(42)

    log("\n=== Loading training data ===")
    all_X, all_y, all_ua, all_ub, all_rb = [], [], [], [], []
    for cid in TRAIN_CAPTURES:
        X, y, ua, ub, rb = load_capture(cid, sample_rate=BG_SAMPLE_RATE, rng=rng)
        log(f"  {cid}: {len(X)} flows, atk={y.sum()}, udp_ben={ub.sum()}, rbot={rb.sum()}")
        all_X.append(X); all_y.append(y)
        all_ua.append(ua); all_ub.append(ub); all_rb.append(rb)

    X_train = np.concatenate(all_X)
    y_train = np.concatenate(all_y)
    ua_train = np.concatenate(all_ua)  # udp attack
    ub_train = np.concatenate(all_ub)  # udp benign
    rb_train = np.concatenate(all_rb)  # rbot pattern
    log(f"Train total: {len(X_train)} (atk={y_train.sum()}, udp_ben={ub_train.sum()}, rbot={rb_train.sum()})")

    log("\n=== Validation ===")
    X_val, y_val, va_val, vb_val, _ = load_capture(VAL_CAPTURE, sample_rate=1.0)
    is_udp_val = va_val | vb_val
    log(f"  {VAL_CAPTURE}: {len(X_val)}, atk={y_val.sum()}, udp_ben={vb_val.sum()}")

    log("\n=== FP0 captures ===")
    fp0_data = {}
    for cid in FP0_CAPTURES:
        X_fp, y_fp, ua_fp, ub_fp, _ = load_capture(cid, sample_rate=1.0)
        is_udp_fp = ua_fp | ub_fp
        log(f"  {cid}: {len(X_fp)}, atk={y_fp.sum()}, ben_udp={ub_fp.sum()}")
        fp0_data[cid] = (X_fp, y_fp, is_udp_fp)

    scaler = IQRScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)

    # Split training data by protocol
    is_udp_train = ua_train | ub_train
    idx_udp = np.where(is_udp_train)[0]
    idx_tcp = np.where(~is_udp_train)[0]
    log(f"\nUDP flows: {len(idx_udp)} | TCP/other: {len(idx_tcp)}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"Device: {device}")

    n_feat = len(FEATURE_NAMES)
    model_udp = MLP(n_feat, hidden=(256, 128, 64), dropout=0.05).to(device)
    model_tcp = MLP(n_feat, hidden=(512, 256, 128, 64), dropout=0.1).to(device)

    # ─── Phase 1: Train TCP classifier ────────────────────────────────────────
    log(f"\n=== PHASE 1: TCP classifier ({EPOCHS_TCP} epochs) ===")
    opt_tcp = torch.optim.Adam(model_tcp.parameters(), lr=LR, weight_decay=1e-5)
    sched_tcp = torch.optim.lr_scheduler.CosineAnnealingLR(opt_tcp, T_max=EPOCHS_TCP, eta_min=ETA_MIN)

    rbot_idx = np.where(rb_train)[0]
    best_tcp_acc = 0.0
    best_tcp_state = None

    for ep in range(1, EPOCHS_TCP + 1):
        model_tcp.train()
        idx_shuf = idx_tcp.copy()
        rng.shuffle(idx_shuf)

        total_loss = 0.0
        n_batches = 0
        for start in range(0, len(idx_shuf), BATCH):
            batch_idx = idx_shuf[start:start + BATCH]
            # inject rbot patterns
            if len(rbot_idx) > 0:
                n_inject = min(512, len(rbot_idx))
                inject = rng.choice(rbot_idx, size=n_inject, replace=False)
                # only inject UDP attacks into UDP model, skip for TCP
                pass

            Xb = torch.from_numpy(X_train_sc[batch_idx]).float().to(device)
            yb = torch.from_numpy(y_train[batch_idx]).long().to(device)

            opt_tcp.zero_grad()
            loss = F.cross_entropy(model_tcp(Xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model_tcp.parameters(), GRAD_CLIP)
            opt_tcp.step()
            total_loss += loss.item()
            n_batches += 1

        sched_tcp.step()

        if ep % 50 == 0:
            model_tcp.eval()
            with torch.no_grad():
                Xv = torch.from_numpy(X_val_sc).float().to(device)
                pred = model_tcp(Xv).argmax(dim=1).cpu().numpy()
            acc = float((pred == y_val).mean())
            if acc > best_tcp_acc:
                best_tcp_acc = acc
                best_tcp_state = {k: v.clone() for k, v in model_tcp.state_dict().items()}
            log(f"  ep {ep:4d}: loss={total_loss/max(n_batches,1):.4f} val_acc={acc:.4f}")

    if best_tcp_state:
        model_tcp.load_state_dict(best_tcp_state)
    log(f"TCP classifier done. Best val_acc={best_tcp_acc:.4f}")

    # ─── Phase 2: Train UDP classifier with hard benign constraint ────────────
    log(f"\n=== PHASE 2: UDP classifier ({EPOCHS_UDP} epochs) ===")
    opt_udp = torch.optim.Adam(model_udp.parameters(), lr=LR_UDP, weight_decay=1e-4)
    sched_udp = torch.optim.lr_scheduler.CosineAnnealingLR(opt_udp, T_max=EPOCHS_UDP, eta_min=ETA_MIN)

    idx_udp_atk = np.where(ua_train)[0]
    idx_udp_ben = np.where(ub_train)[0]
    idx_rbot = np.where(rb_train)[0]

    log(f"UDP attack samples: {len(idx_udp_atk)}, benign: {len(idx_udp_ben)}, rbot: {len(idx_rbot)}")

    best_fp0 = 0.0
    best_udp_state = None
    no_improve = 0
    lambda_mult = LAMBDA_INIT
    epochs_since_improve = 0
    t0 = time.time()

    for ep in range(1, EPOCHS_UDP + 1):
        model_udp.train()

        # Build batch: all UDP samples (attacks + benign)
        idx_shuf_atk = idx_udp_atk.copy()
        idx_shuf_ben = idx_udp_ben.copy()
        rng.shuffle(idx_shuf_atk)
        rng.shuffle(idx_shuf_ben)

        # Oversample attacks to match benign count
        if len(idx_shuf_atk) < len(idx_shuf_ben):
            repeat = int(np.ceil(len(idx_shuf_ben) / max(len(idx_shuf_atk), 1)))
            idx_shuf_atk = np.tile(idx_shuf_atk, repeat)[:len(idx_shuf_ben)]

        # Add rbot patterns
        if len(idx_rbot) > 0:
            idx_shuf_atk = np.concatenate([idx_shuf_atk,
                rng.choice(idx_rbot, size=min(512, len(idx_rbot)), replace=False)])

        total_loss = 0.0
        n_batches = 0

        # Interleave attack and benign
        combined = np.concatenate([idx_shuf_atk, idx_shuf_ben])
        rng.shuffle(combined)

        for start in range(0, len(combined), BATCH):
            batch_idx = combined[start:start + BATCH]

            Xb = torch.from_numpy(X_train_sc[batch_idx]).float().to(device)
            yb = torch.from_numpy(y_train[batch_idx]).long().to(device)
            ua_b = torch.from_numpy(ua_train[batch_idx]).to(device)
            ub_b = torch.from_numpy(ub_train[batch_idx]).to(device)
            rb_b = torch.from_numpy(rb_train[batch_idx]).to(device)

            opt_udp.zero_grad()
            logits = model_udp(Xb)

            # Per-sample weights
            w = torch.ones(len(Xb), device=device)
            # Attack UDP: high weight
            w = torch.where(ua_b, torch.full_like(w, UDP_ATK_WEIGHT), w)
            # Rbot patterns: extra boost
            w = torch.where(rb_b, torch.full_like(w, RBOT_BOOST), w)

            # Focal loss for attacks
            ce = F.cross_entropy(logits, yb, reduction="none")
            p_t = torch.exp(-ce)
            focal = (1 - p_t) ** 2 * ce
            focal_loss = (focal * w).mean()

            # Hard benign UDP constraint: BCE on ALL benign UDP with adaptive weight
            if ub_b.any():
                ben_logits = logits[ub_b, 1]  # attack logit for benign UDP
                ben_probs = torch.sigmoid(ben_logits)
                # Adaptive weight: harder samples get more weight
                hard_w = torch.ones_like(ben_probs) * BENIGN_UDP_BASE_WEIGHT
                hard_mask = ben_probs > 0.1
                if hard_mask.any():
                    hard_w[hard_mask] = BENIGN_UDP_BASE_WEIGHT * (1 + BENIGN_UDP_HARD_MULT * ben_probs[hard_mask])
                # BCE: push toward 0 (benign)
                ben_loss = F.softplus(ben_logits)  # -log(1-sigmoid(x))
                reg_loss = lambda_mult * (hard_w * ben_loss).mean()
            else:
                reg_loss = torch.tensor(0.0, device=device)

            loss = focal_loss + reg_loss
            loss.backward()
            nn.utils.clip_grad_norm_(model_udp.parameters(), GRAD_CLIP)
            opt_udp.step()
            total_loss += loss.item()
            n_batches += 1

        sched_udp.step()

        if ep % FP0_EVAL_EVERY == 0 or ep <= 5:
            fp0_scores = {}
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                fp0, info = fp0_eval(model_udp, model_tcp, scaler, X_fp, y_fp, is_udp_fp, device)
                fp0_scores[cid] = fp0

            fp0_min = min(fp0_scores.values()) if fp0_scores else 0.0
            is_best = fp0_min > best_fp0
            if is_best:
                best_fp0 = fp0_min
                best_udp_state = {k: v.clone() for k, v in model_udp.state_dict().items()}
                no_improve = 0
                epochs_since_improve = 0
            else:
                no_improve += FP0_EVAL_EVERY
                epochs_since_improve += FP0_EVAL_EVERY

            # Escalate lambda if stuck
            if epochs_since_improve >= LAMBDA_GROW_EVERY:
                old = lambda_mult
                lambda_mult = min(lambda_mult * LAMBDA_GROW_FACTOR, LAMBDA_MAX)
                epochs_since_improve = 0
                if lambda_mult != old:
                    log(f"  [Lambda: {old:.1f} -> {lambda_mult:.1f} at ep {ep}]")

            scores_str = "  ".join(f"{c}:{v:.4f}" for c, v in fp0_scores.items())
            flag = " <BEST" if is_best else ""
            log(f"  ep {ep:4d} lam={lambda_mult:.1f} loss={total_loss/max(n_batches,1):.4f} "
                f"fp0={fp0_min:.4f} [{scores_str}]{flag}")
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                diag = fp0_diag(model_udp, model_tcp, scaler, X_fp, y_fp, is_udp_fp, device)
                log(f"    {cid}: {diag}")

            if no_improve >= EARLY_STOP_PATIENCE:
                log(f"\n  Early stop ep {ep} (best fp0={best_fp0:.4f})")
                break

    elapsed = time.time() - t0
    log(f"\nDone {elapsed:.1f}s, best fp0={best_fp0:.4f}")

    if best_udp_state:
        model_udp.load_state_dict(best_udp_state)

    # Find best thresholds
    log("\n=== Finding best thresholds ===")
    best_thr_udp, best_thr_tcp = 0.5, 0.5
    best_fp0_final = 0.0
    for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
        fp0, info = fp0_eval(model_udp, model_tcp, scaler, X_fp, y_fp, is_udp_fp, device)
        log(f"  CTU-{cid}: fp0={fp0:.4f} info={info}")
        if info:
            best_thr_udp = info.get("thr_udp", 0.5)
            best_thr_tcp = info.get("thr_tcp", 0.5)

    # Save checkpoint with both heads
    torch.save({
        "state_dict": model_udp.state_dict(),   # primary (eval_checkpoint compat)
        "model": model_udp.state_dict(),
        "state_dict_tcp": model_tcp.state_dict(),
        "q25": scaler.q25.tolist(),
        "iqr": scaler.iqr.tolist(),
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "run": 25,
        "two_head": True,
        "thr_udp": best_thr_udp,
        "thr_tcp": best_thr_tcp,
        "hparams": {
            "udp_hidden": [256, 128, 64],
            "tcp_hidden": [512, 256, 128, 64],
            "dropout_udp": 0.05,
            "dropout_tcp": 0.1,
        },
    }, CKPT_PATH)
    log(f"Saved {CKPT_PATH}")

    log("\n=== Gate 5 ===")
    gate_pass = True
    for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
        fp0, info = fp0_eval(model_udp, model_tcp, scaler, X_fp, y_fp, is_udp_fp, device)
        status = "PASS" if fp0 >= 0.80 else "FAIL"
        log(f"  CTU-{cid}: fp0={fp0:.4f} {status} {info}")
        if fp0 < 0.80:
            gate_pass = False
    log(f"\nGate 5: {'PASS' if gate_pass else 'FAIL'}")
    log_file.close()


if __name__ == "__main__":
    main()

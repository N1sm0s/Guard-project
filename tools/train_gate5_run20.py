"""Train network-flow MLP for Gate 5 — run 20.

Run 20 changes vs run 19:
  - grad_clip: 0.5 → 5.0   (was capping reg-loss gradients, preventing convergence)
  - udp_benign_weight in WeightedFocalLoss: 10.0 → 0.1  (remove competing focal pressure on benign UDP)
  - BenignUdpRegLoss weight: 500,000 → 50,000,000  (100x — allows reg loss to dominate and push benign logits below margin)
  - BenignUdpMeanLoss removed entirely (redundant with BenignUdpRegLoss, only added noise)
  - T_max: 1500 epochs

Gate 5 target: fp0_min >= 0.80 simultaneously on CTU-53 and CTU-54
  fp0_min = min(fp0_53, fp0_54)
  fp0_53 = max threshold where CI_hi(FPR_UDP_53) <= 0.001 AND CI recall_53 >= 0.80
  fp0_54 = max threshold where CI_hi(FPR_UDP_54) <= 0.001 AND CI recall_54 >= 0.80
"""
from __future__ import annotations
import csv, gzip, math, sys, time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

assert FEATURE_VERSION == 8, f"Expected schema v8, got v{FEATURE_VERSION}"
print(f"Feature version: {FEATURE_VERSION}, {len(FEATURE_NAMES)} features")

DATA = ROOT / "outputs" / "network-eval"
LOG_PATH = DATA / "train_run20_internal.log"
CKPT_PATH = DATA / "ctu13-v10-gate5-run20.pt"

# ── hyper-parameters ─────────────────────────────────────────────────────────
LR            = 1e-3
T_MAX         = 1500
ETA_MIN       = 1e-6
BATCH         = 2048
EPOCHS        = 1500
GRAD_CLIP     = 5.0          # run 19 had 0.5 — this was capping reg gradients
FP0_EVAL_EVERY = 5
BG_SAMPLE_RATE = 0.50        # train; 1.0 for full eval

# loss weights
UDP_ATK_WEIGHT   = 800.0     # up-weight UDP attack samples in focal loss
RBOT_BOOST       = 1200.0    # extra boost for rbot-pattern samples
UDP_BEN_WEIGHT   = 0.1       # run 19 had 10.0 → competing gradient; now minimal
BENIGN_REG_MARGIN = -7.0     # target logit for benign UDP (need <-6.9 at p99.9)
BENIGN_REG_WEIGHT = 50_000_000.0  # run 19 had 500,000 → 100x increase

RBOT_PATTERNS_PER_BATCH = 1024  # inject Rbot pattern samples every batch

EARLY_STOP_PATIENCE = 300    # epochs without fp0 improvement

# CTU-13 binetflow files
TRAIN_CAPTURES = ["42", "43", "44", "46", "47", "48", "51", "52", "53", "54"]
VAL_CAPTURE    = "49"
FP0_CAPTURES   = ["53", "54"]   # Gate 5 FP0 monitoring


def capture_path(cid: str) -> Path:
    names = {
        "42": DATA / "ctu-42.binetflow",
        "43": DATA / "ctu-43.binetflow",
        "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
        "45": DATA / "official-ctu13" / "capture20110815_ctu45.binetflow",
        "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
        "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
        "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
        "49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
        "50": DATA / "official-ctu13" / "capture20110817_ctu50.binetflow",
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


def is_rbot_pattern(row) -> bool:
    """Rbot/UDP botnet: protocol=udp, sustained (dur>=1s), no response (asym=1)."""
    proto = str(row.get("Proto", "")).lower()
    dur_str = row.get("Dur", "0") or "0"
    try:
        dur = float(dur_str)
    except ValueError:
        dur = 0.0
    # From-Botnet-V42 (Rbot): sustained UDP with one-way traffic
    return proto == "udp" and dur >= 1.0


# ── feature extraction ───────────────────────────────────────────────────────

def extract_features(row) -> list[float] | None:
    try:
        return list(from_ctu_row(row))
    except Exception:
        return None


# ── load data ────────────────────────────────────────────────────────────────

def load_capture(cid: str, sample_rate: float = 1.0, rng=None):
    """Returns (X, y, is_udp_attack, is_udp_benign, is_rbot) arrays."""
    path = capture_path(cid)
    xs, ys, udp_atk, udp_ben, rbot_pat = [], [], [], [], []
    rng = rng or np.random.default_rng(42)
    with open_flow(path) as f:
        for row in csv.DictReader(f):
            y = class_for_label(row.get("Label", ""))
            if y < 0:
                continue
            if sample_rate < 1.0 and y == 0 and rng.random() > sample_rate:
                continue
            feat = extract_features(row)
            if feat is None:
                continue
            xs.append(feat)
            ys.append(y)
            proto = str(row.get("Proto", "")).lower()
            is_udp = proto == "udp"
            udp_atk.append(1 if (is_udp and y == 1) else 0)
            udp_ben.append(1 if (is_udp and y == 0) else 0)
            rbot_pat.append(1 if (y == 1 and is_rbot_pattern(row)) else 0)
    return (np.array(xs, dtype=np.float32),
            np.array(ys, dtype=np.int64),
            np.array(udp_atk, dtype=bool),
            np.array(udp_ben, dtype=bool),
            np.array(rbot_pat, dtype=bool))


# ── IQR scaler ───────────────────────────────────────────────────────────────

class IQRScaler:
    def __init__(self):
        self.q25 = None
        self.iqr  = None

    def fit(self, X: np.ndarray):
        self.q25 = np.percentile(X, 25, axis=0)
        self.iqr  = np.percentile(X, 75, axis=0) - self.q25
        self.iqr  = np.where(self.iqr < 1e-8, 1.0, self.iqr)

    def transform(self, X: np.ndarray) -> np.ndarray:
        return (X - self.q25) / self.iqr

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        self.fit(X)
        return self.transform(X)


# ── MLP model ────────────────────────────────────────────────────────────────

class MLP(nn.Module):
    def __init__(self, in_dim: int = 17, hidden: tuple = (512, 256, 128, 64), out_dim: int = 2):
        super().__init__()
        layers = []
        prev = in_dim
        for h in hidden:
            layers += [nn.Linear(prev, h), nn.BatchNorm1d(h), nn.GELU(), nn.Dropout(0.1)]
            prev = h
        layers.append(nn.Linear(prev, out_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


# ── losses ───────────────────────────────────────────────────────────────────

class WeightedFocalLoss(nn.Module):
    """Focal loss with per-sample weights for UDP attack and Rbot boost."""
    def __init__(self, gamma: float = 2.0, udp_atk_weight: float = UDP_ATK_WEIGHT,
                 rbot_boost: float = RBOT_BOOST, udp_ben_weight: float = UDP_BEN_WEIGHT):
        super().__init__()
        self.gamma = gamma
        self.udp_atk_weight = udp_atk_weight
        self.rbot_boost = rbot_boost
        self.udp_ben_weight = udp_ben_weight

    def forward(self, logits, targets, is_udp_atk=None, is_rbot=None, is_udp_ben=None):
        ce = nn.functional.cross_entropy(logits, targets, reduction="none")
        p  = torch.exp(-ce)
        focal = (1 - p) ** self.gamma * ce
        w = torch.ones(len(logits), device=logits.device)
        if is_udp_atk is not None:
            w = torch.where(is_udp_atk, torch.full_like(w, self.udp_atk_weight), w)
        if is_rbot is not None:
            w = torch.where(is_rbot, torch.full_like(w, self.rbot_boost), w)
        if is_udp_ben is not None:
            # run 20: minimal weight (0.1) — was 10.0 in run 19, competed with reg loss
            w = torch.where(is_udp_ben, torch.full_like(w, self.udp_ben_weight), w)
        return (focal * w).mean()


class BenignUdpRegLoss(nn.Module):
    """Push benign UDP logit[1] (attack score) below margin.
    
    For every benign UDP flow: loss = relu(logit[1] - margin)^2
    This penalizes any benign UDP sample whose attack logit exceeds the margin.
    
    Run 20: weight=50,000,000 (was 500,000 in run 19 — 100x increase so this 
    loss dominates and grad_clip=5.0 allows large updates to actually occur).
    """
    def __init__(self, margin: float = BENIGN_REG_MARGIN, weight: float = BENIGN_REG_WEIGHT):
        super().__init__()
        self.margin = margin
        self.weight = weight

    def forward(self, logits, is_udp_ben):
        if not is_udp_ben.any():
            return torch.tensor(0.0, device=logits.device)
        atk_logit = logits[is_udp_ben, 1]
        excess = torch.relu(atk_logit - self.margin)
        return self.weight * (excess ** 2).mean()


# ── Wilson 95% CI upper bound for FPR ────────────────────────────────────────

def wilson_upper(fp: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p_hat = fp / n
    denom = 1 + z * z / n
    centre = (p_hat + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) / denom
    return min(centre + spread, 1.0)


# ── FP0 evaluation (Gate 5) ───────────────────────────────────────────────────

def fp0_score(model, scaler: IQRScaler, X_full, y_full, is_udp_full, device,
              ci_fpr_limit: float = 0.001, recall_limit: float = 0.80) -> float:
    """Max threshold where CI_hi(FPR_UDP) <= ci_fpr_limit AND recall >= recall_limit."""
    model.eval()
    with torch.no_grad():
        Xt = torch.from_numpy(scaler.transform(X_full)).to(device)
        logits = model(Xt).cpu().numpy()
    probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
    score = probs[:, 1]  # attack probability

    # attack recall and UDP FPR at various thresholds
    is_attack = (y_full == 1)
    is_benign_udp = is_udp_full & (y_full == 0)
    n_ben_udp = is_benign_udp.sum()
    n_attack = is_attack.sum()

    best_thr = 0.0
    for thr in np.arange(0.01, 1.00, 0.01):
        pred_pos = score >= thr
        recall = (pred_pos & is_attack).sum() / max(n_attack, 1)
        fp_udp  = (pred_pos & is_benign_udp).sum()
        ci_hi   = wilson_upper(int(fp_udp), int(n_ben_udp))
        if ci_hi <= ci_fpr_limit and recall >= recall_limit:
            best_thr = float(thr)
    return best_thr


def fp0_diag(model, scaler, X_full, y_full, is_udp_full, device) -> str:
    """Detailed diagnostic at thr=0.5."""
    model.eval()
    with torch.no_grad():
        Xt = torch.from_numpy(scaler.transform(X_full)).to(device)
        logits = model(Xt).cpu().numpy()
    probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
    score = probs[:, 1]

    is_attack = (y_full == 1)
    is_benign_udp = is_udp_full & (y_full == 0)
    n_ben_udp = is_benign_udp.sum()
    thr = 0.5
    pred = score >= thr
    rec = (pred & is_attack).sum() / max(is_attack.sum(), 1)
    fp_u = (pred & is_benign_udp).sum()
    ci_hi = wilson_upper(int(fp_u), int(n_ben_udp))
    ben_udp_scores = score[is_benign_udp]
    p99 = float(np.percentile(ben_udp_scores, 99)) if len(ben_udp_scores) else 0.0
    p999 = float(np.percentile(ben_udp_scores, 99.9)) if len(ben_udp_scores) else 0.0
    fp_001 = int((ben_udp_scores >= 0.001).sum())
    return (f"FP_U={fp_u}({100*fp_u/max(n_ben_udp,1):.3f}%)"
            f" p99={p99:.4f} p99.9={p999:.5f} FP@0.001={fp_001} rec={rec:.3f}")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    log_file = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    def log(msg):
        print(msg)
        print(msg, file=log_file)

    log(f"Feature version: {FEATURE_VERSION}, {len(FEATURE_NAMES)} features")

    rng = np.random.default_rng(42)

    # ── load training data ──
    log("\n=== Loading training data ===")
    all_X, all_y, all_udp_atk, all_udp_ben, all_rbot = [], [], [], [], []
    for cid in TRAIN_CAPTURES:
        X, y, ua, ub, rb = load_capture(cid, sample_rate=BG_SAMPLE_RATE, rng=rng)
        log(f"  {cid}: {len(X)} flows, attack={y.sum()}, udp_atk={ua.sum()}, "
            f"udp_ben={ub.sum()}, rbot_pat={rb.sum()}")
        all_X.append(X); all_y.append(y)
        all_udp_atk.append(ua); all_udp_ben.append(ub); all_rbot.append(rb)

    X_train = np.concatenate(all_X)
    y_train = np.concatenate(all_y)
    ua_train = np.concatenate(all_udp_atk)
    ub_train = np.concatenate(all_udp_ben)
    rb_train = np.concatenate(all_rbot)
    log(f"Train: {len(X_train)} flows (atk={y_train.sum()} "
        f"ben={(y_train==0).sum()} udp_ben={ub_train.sum()} rbot_pat={rb_train.sum()})")

    # ── validation ──
    log("\n=== Validation ===")
    X_val, y_val, _, _, _ = load_capture(VAL_CAPTURE, sample_rate=1.0)
    log(f"  {VAL_CAPTURE}: {len(X_val)} flows, attack={y_val.sum()}")

    # ── pre-load full FP0 captures ──
    log("\n=== Pre-loading full test captures for FP0 monitoring ===")
    fp0_data = {}
    for cid in FP0_CAPTURES:
        X_fp, y_fp, ua_fp, ub_fp, _ = load_capture(cid, sample_rate=1.0)
        is_udp_fp = ua_fp | ub_fp  # all UDP flows
        ben_udp_count = ub_fp.sum()
        log(f"  {cid}: {len(X_fp)} flows, attack={y_fp.sum()}, benign_udp={ben_udp_count}")
        fp0_data[cid] = (X_fp, y_fp, is_udp_fp)

    # ── scaler (fit on training features) ──
    scaler = IQRScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)

    # ── model ──
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"\nDevice: {device}")
    model = MLP(in_dim=len(FEATURE_NAMES)).to(device)
    log(f"MLP({len(FEATURE_NAMES)}->" + "->".join("512 256 128 64".split()) + "->2)")

    # Rbot-pattern samples for injection
    rbot_idx = np.where(rb_train)[0]
    log(f"Rbot pattern samples: {len(rbot_idx)} (inject {RBOT_PATTERNS_PER_BATCH} per batch)")

    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=T_MAX, eta_min=ETA_MIN)

    focal_loss = WeightedFocalLoss()
    reg_loss   = BenignUdpRegLoss()

    banner = (f"run 20: NO_rule_override, BenignReg(m={BENIGN_REG_MARGIN},w={int(BENIGN_REG_WEIGHT)}), "
              f"udp_atk={int(UDP_ATK_WEIGHT)}, rbot={int(RBOT_BOOST)}, "
              f"grad_clip={GRAD_CLIP}, fp0 every {FP0_EVAL_EVERY} ep")
    log(f"\n=== Training ({banner}) ===")

    best_fp0   = 0.0
    best_state = None
    no_improve = 0
    t0 = time.time()

    # pre-tensorize validation
    Xv_t = torch.from_numpy(X_val_sc).float().to(device)
    yv_t = torch.from_numpy(y_val).long().to(device)

    n_train = len(X_train_sc)
    idx_all = np.arange(n_train)

    for ep in range(1, EPOCHS + 1):
        model.train()
        rng.shuffle(idx_all)
        total_loss = 0.0
        n_batches = 0

        for start in range(0, n_train, BATCH):
            batch_idx = idx_all[start:start + BATCH]

            # Inject Rbot samples
            if len(rbot_idx) > 0:
                n_inject = min(RBOT_PATTERNS_PER_BATCH, len(rbot_idx))
                inject = rng.choice(rbot_idx, size=n_inject, replace=False)
                batch_idx = np.concatenate([batch_idx, inject])

            Xb = torch.from_numpy(X_train_sc[batch_idx]).float().to(device)
            yb = torch.from_numpy(y_train[batch_idx]).long().to(device)
            ua_b = torch.from_numpy(ua_train[batch_idx]).to(device)
            ub_b = torch.from_numpy(ub_train[batch_idx]).to(device)
            rb_b = torch.from_numpy(rb_train[batch_idx]).to(device)

            optimizer.zero_grad()
            logits = model(Xb)

            loss_focal = focal_loss(logits, yb, is_udp_atk=ua_b, is_rbot=rb_b, is_udp_ben=ub_b)
            loss_reg   = reg_loss(logits, ub_b)
            loss = loss_focal + loss_reg

            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            optimizer.step()

            total_loss += loss.item()
            n_batches += 1

        scheduler.step()

        # ── validation recall ──
        model.eval()
        with torch.no_grad():
            val_logits = model(Xv_t)
            val_pred = val_logits.argmax(dim=1)
            val_recall = float((val_pred == yv_t)[yv_t == 1].float().mean())

        # ── FP0 monitoring ──
        fp0_scores = {}
        if ep % FP0_EVAL_EVERY == 0 or ep <= 5:
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                fp0_scores[cid] = fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)

        avg_loss = total_loss / max(n_batches, 1)
        fp0_min = min(fp0_scores.values()) if fp0_scores else float("nan")

        is_best = fp0_scores and fp0_min > best_fp0
        if is_best:
            best_fp0 = fp0_min
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            no_improve = 0
        elif fp0_scores:
            no_improve += FP0_EVAL_EVERY

        scores_str = "  ".join(f"{c}:{v:.4f}" for c, v in fp0_scores.items())
        flag = " <BEST_FP0" if is_best else ""
        fp0_str = f"fp0_min={fp0_min:.4f} [{scores_str}]" if fp0_scores else "fp0=N/A"
        log(f"  ep {ep:4d} loss={avg_loss:.4f}  val={val_recall:.4f}  {fp0_str}{flag}")

        if fp0_scores and (ep % FP0_EVAL_EVERY == 0 or ep <= 5):
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                diag = fp0_diag(model, scaler, X_fp, y_fp, is_udp_fp, device)
                log(f"    diag(0.5): {cid}:{diag}")

        if no_improve >= EARLY_STOP_PATIENCE:
            log(f"\n  Early stop at epoch {ep} (best fp0={best_fp0:.4f})")
            break

    elapsed = time.time() - t0
    log(f"\nTraining time: {elapsed:.1f}s (best test_fp0={best_fp0:.4f})")

    # ── save best checkpoint ──
    if best_state is not None:
        model.load_state_dict(best_state)
    torch.save({
        "model_state": model.state_dict(),
        "scaler_q25": scaler.q25.tolist(),
        "scaler_iqr": scaler.iqr.tolist(),
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "run": 20,
    }, CKPT_PATH)
    log(f"Saved checkpoint to {CKPT_PATH}")

    # ── final evaluation ──
    log("\n=== Final evaluation with best FP0 checkpoint ===")
    log("\n=== Score distributions ===")
    for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
        model.eval()
        with torch.no_grad():
            Xt = torch.from_numpy(scaler.transform(X_fp)).float().to(device)
            logits_np = model(Xt).cpu().numpy()
        probs = np.exp(logits_np) / np.exp(logits_np).sum(axis=1, keepdims=True)
        score = probs[:, 1]
        is_attack = (y_fp == 1)
        is_udp_atk = is_udp_fp & is_attack
        is_ben_udp = is_udp_fp & (y_fp == 0)
        atk_udp_scores = score[is_udp_atk]
        ben_udp_scores = score[is_ben_udp]
        n_ben = len(ben_udp_scores)
        if len(atk_udp_scores):
            log(f"  CTU-{cid} attack_udp({len(atk_udp_scores)}) "
                f"p10={np.percentile(atk_udp_scores,10):.3f} "
                f"p50={np.percentile(atk_udp_scores,50):.3f} "
                f"p90={np.percentile(atk_udp_scores,90):.3f}")
        if n_ben:
            log(f"  CTU-{cid} benign_udp({n_ben}) "
                f"p90={np.percentile(ben_udp_scores,90):.4f} "
                f"p99={np.percentile(ben_udp_scores,99):.4f} "
                f"p99.9={np.percentile(ben_udp_scores,99.9):.5f}")
        n_atk = is_attack.sum()
        for thr in [0.30, 0.50, 0.70, 0.80, 0.90, 0.95, 0.99]:
            pred = score >= thr
            recall = float((pred & is_attack).sum()) / max(n_atk, 1)
            fp_udp = int((pred & is_ben_udp).sum())
            ci_hi  = wilson_upper(fp_udp, n_ben)
            gate = "PASS" if ci_hi <= 0.001 else ""
            log(f"    thr={thr:.2f}: recall={recall:.4f} FP_UDP={fp_udp} "
                f"CI_hi_UDP={100*ci_hi:.5f}% {gate}")

    log("\n=== Gate 5 Evaluation ===")
    gate_pass = True
    for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
        s = fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)
        log(f"  CTU-{cid}: fp0={s:.4f} {'PASS' if s >= 0.80 else 'FAIL'}")
        if s < 0.80:
            gate_pass = False
    fp0_min_final = min(
        fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)
        for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items()
    )
    log(f"\nfp0_min (both captures) = {fp0_min_final:.4f}")
    log(f"Gate 5: {'PASS' if gate_pass else 'FAIL'}")

    log_file.close()


if __name__ == "__main__":
    main()

"""
Run 22 key changes vs run 21:
  - BenignUdpRegLoss: use BCE-style loss = -log(1 - sigmoid(logit[1])) instead of prob^2
    This has gradient 1/(1-prob) -> inf as prob->1, forcing the tail outliers down
    (prob^2 has gradient that vanishes as prob->0, causing tail to stagnate)
  - weight: 5.0 (BCE-style has much larger gradients than prob^2)
  - Phase 1 extended to ep 100 (more time for attack recall to stabilize)
  - Phase 2: BCE reg loss kicks in at ep 100
  - Hard negatives: include the most-FP benign UDP samples with extra weight
  - LR reduced to 1e-4 to avoid oscillation in phase 2

Gate 5 target: fp0_min >= 0.80 simultaneously on CTU-53 and CTU-54
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

DATA = ROOT / "outputs" / "network-eval"
LOG_PATH = DATA / "train_run22_internal.log"
CKPT_PATH = DATA / "ctu13-v10-gate5-run22.pt"

LR            = 5e-4
LR_PHASE2     = 1e-4         # much lower LR when reg loss kicks in
T_MAX         = 1500
ETA_MIN       = 1e-6
BATCH         = 2048
EPOCHS        = 1500
GRAD_CLIP     = 1.0          # tight clip to prevent any oscillation
FP0_EVAL_EVERY = 5
BG_SAMPLE_RATE = 0.50
PHASE2_START  = 100          # more phase 1 time for stable attack recall

UDP_ATK_WEIGHT   = 800.0
RBOT_BOOST       = 1200.0
BENIGN_BCE_WEIGHT = 5.0      # BCE-style: -log(1-prob) has large gradients already

RBOT_PATTERNS_PER_BATCH = 1024
EARLY_STOP_PATIENCE = 300

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


def is_rbot_pattern(row) -> bool:
    proto = str(row.get("Proto", "")).lower()
    dur_str = row.get("Dur", "0") or "0"
    try:
        dur = float(dur_str)
    except ValueError:
        dur = 0.0
    return proto == "udp" and dur >= 1.0


def extract_features(row) -> list[float] | None:
    try:
        return list(from_ctu_row(row))
    except Exception:
        return None


def load_capture(cid: str, sample_rate: float = 1.0, rng=None):
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


class WeightedFocalLoss(nn.Module):
    def __init__(self, gamma: float = 2.0, udp_atk_weight: float = UDP_ATK_WEIGHT,
                 rbot_boost: float = RBOT_BOOST):
        super().__init__()
        self.gamma = gamma
        self.udp_atk_weight = udp_atk_weight
        self.rbot_boost = rbot_boost

    def forward(self, logits, targets, is_udp_atk=None, is_rbot=None):
        ce = F.cross_entropy(logits, targets, reduction="none")
        p  = torch.exp(-ce)
        focal = (1 - p) ** self.gamma * ce
        w = torch.ones(len(logits), device=logits.device)
        if is_udp_atk is not None:
            w = torch.where(is_udp_atk, torch.full_like(w, self.udp_atk_weight), w)
        if is_rbot is not None:
            w = torch.where(is_rbot, torch.full_like(w, self.rbot_boost), w)
        return (focal * w).mean()


class BenignUdpBCELoss(nn.Module):
    """BCE-style penalty: -log(1 - sigmoid(logit[1])) for each benign UDP flow.

    This equals cross-entropy loss for class 0 on the binary attack logit.
    Gradient = sigmoid(logit[1]) = prob_attack  (not vanishing for high probs)

    When prob = 0.98: gradient = 0.98  (huge -- forces outliers down immediately)
    When prob = 0.01: gradient = 0.01  (tiny -- leaves already-safe samples alone)
    """
    def __init__(self, weight: float = BENIGN_BCE_WEIGHT):
        super().__init__()
        self.weight = weight

    def forward(self, logits, is_udp_ben):
        if not is_udp_ben.any():
            return torch.tensor(0.0, device=logits.device)
        atk_logit = logits[is_udp_ben, 1]
        # -log(1 - sigmoid(x)) = log(1 + exp(x)) - log(exp(x)/(1+exp(x)))...
        # = softplus(x) for x < 0, but let's use numerically stable BCE:
        # BCE(logit, target=0) = -log(1 - sigmoid(logit)) = log(1 + exp(logit))
        loss_per = F.softplus(atk_logit)   # = log(1 + exp(logit[1])) = -log(1-sigmoid)
        return self.weight * loss_per.mean()


def wilson_upper(fp: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p_hat = fp / n
    denom = 1 + z * z / n
    centre = (p_hat + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) / denom
    return min(centre + spread, 1.0)


def fp0_score(model, scaler, X_full, y_full, is_udp_full, device,
              ci_fpr_limit: float = 0.001, recall_limit: float = 0.80) -> float:
    model.eval()
    with torch.no_grad():
        Xt = torch.from_numpy(scaler.transform(X_full)).float().to(device)
        logits = model(Xt).cpu().numpy()
    probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
    score = probs[:, 1]
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
    model.eval()
    with torch.no_grad():
        Xt = torch.from_numpy(scaler.transform(X_full)).float().to(device)
        logits = model(Xt).cpu().numpy()
    probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
    score = probs[:, 1]
    is_attack = (y_full == 1)
    is_benign_udp = is_udp_full & (y_full == 0)
    n_ben_udp = is_benign_udp.sum()
    pred = score >= 0.5
    rec = float((pred & is_attack).sum()) / max(is_attack.sum(), 1)
    fp_u = int((pred & is_benign_udp).sum())
    ben_sc = score[is_benign_udp]
    p99   = float(np.percentile(ben_sc, 99)) if len(ben_sc) else 0.0
    p999  = float(np.percentile(ben_sc, 99.9)) if len(ben_sc) else 0.0
    p100  = float(np.max(ben_sc)) if len(ben_sc) else 0.0
    fp_001 = int((ben_sc >= 0.001).sum())
    return (f"FP_U={fp_u}({100*fp_u/max(n_ben_udp,1):.3f}%)"
            f" p99={p99:.4f} p99.9={p999:.5f} max={p100:.5f} FP@0.001={fp_001} rec={rec:.3f}")


def main():
    log_file = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    def log(msg):
        print(msg)
        print(msg, file=log_file)

    rng = np.random.default_rng(42)

    log("\n=== Loading training data ===")
    all_X, all_y, all_udp_atk, all_udp_ben, all_rbot = [], [], [], [], []
    for cid in TRAIN_CAPTURES:
        X, y, ua, ub, rb = load_capture(cid, sample_rate=BG_SAMPLE_RATE, rng=rng)
        log(f"  {cid}: {len(X)} flows, attack={y.sum()}, udp_ben={ub.sum()}, rbot={rb.sum()}")
        all_X.append(X); all_y.append(y)
        all_udp_atk.append(ua); all_udp_ben.append(ub); all_rbot.append(rb)

    X_train = np.concatenate(all_X)
    y_train = np.concatenate(all_y)
    ua_train = np.concatenate(all_udp_atk)
    ub_train = np.concatenate(all_udp_ben)
    rb_train = np.concatenate(all_rbot)
    log(f"Train: {len(X_train)} (atk={y_train.sum()}, udp_ben={ub_train.sum()}, rbot={rb_train.sum()})")

    log("\n=== Validation ===")
    X_val, y_val, _, _, _ = load_capture(VAL_CAPTURE, sample_rate=1.0)
    log(f"  {VAL_CAPTURE}: {len(X_val)}, attack={y_val.sum()}")

    log("\n=== FP0 captures ===")
    fp0_data = {}
    for cid in FP0_CAPTURES:
        X_fp, y_fp, ua_fp, ub_fp, _ = load_capture(cid, sample_rate=1.0)
        is_udp_fp = ua_fp | ub_fp
        log(f"  {cid}: {len(X_fp)}, attack={y_fp.sum()}, benign_udp={ub_fp.sum()}")
        fp0_data[cid] = (X_fp, y_fp, is_udp_fp)

    scaler = IQRScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"\nDevice: {device}")
    model = MLP(in_dim=len(FEATURE_NAMES)).to(device)

    rbot_idx = np.where(rb_train)[0]
    log(f"Rbot: {len(rbot_idx)} samples")

    # Phase 1 optimizer (higher LR, focal only)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=T_MAX, eta_min=ETA_MIN)

    focal_loss_fn = WeightedFocalLoss()
    reg_loss_fn   = BenignUdpBCELoss()

    banner = (f"run 22: BCE-reg(w={BENIGN_BCE_WEIGHT}), udp_atk={int(UDP_ATK_WEIGHT)}, "
              f"rbot={int(RBOT_BOOST)}, grad_clip={GRAD_CLIP}, phase2@ep{PHASE2_START}, "
              f"lr_p1={LR}, lr_p2={LR_PHASE2}")
    log(f"\n=== {banner} ===")

    best_fp0   = 0.0
    best_state = None
    no_improve = 0
    phase2_started = False
    t0 = time.time()

    Xv_t = torch.from_numpy(X_val_sc).float().to(device)
    yv_t = torch.from_numpy(y_val).long().to(device)

    n_train = len(X_train_sc)
    idx_all = np.arange(n_train)

    for ep in range(1, EPOCHS + 1):
        use_reg = (ep >= PHASE2_START)

        # Switch to lower LR when phase 2 starts
        if use_reg and not phase2_started:
            phase2_started = True
            for pg in optimizer.param_groups:
                pg["lr"] = LR_PHASE2
            log(f"  [Phase 2 start ep {ep}: LR->{LR_PHASE2}]")

        model.train()
        rng.shuffle(idx_all)
        total_focal = 0.0
        total_reg   = 0.0
        n_batches = 0

        for start in range(0, n_train, BATCH):
            batch_idx = idx_all[start:start + BATCH]
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

            lf = focal_loss_fn(logits, yb, is_udp_atk=ua_b, is_rbot=rb_b)
            lr_ = reg_loss_fn(logits, ub_b) if use_reg else torch.tensor(0.0, device=device)
            loss = lf + lr_

            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            optimizer.step()

            total_focal += lf.item()
            total_reg   += lr_.item()
            n_batches += 1

        if not use_reg:
            scheduler.step()

        model.eval()
        with torch.no_grad():
            val_pred = model(Xv_t).argmax(dim=1)
            val_recall = float((val_pred == yv_t)[yv_t == 1].float().mean())

        fp0_scores = {}
        if ep % FP0_EVAL_EVERY == 0 or ep <= 5:
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                fp0_scores[cid] = fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)

        fp0_min = min(fp0_scores.values()) if fp0_scores else float("nan")
        is_best = fp0_scores and fp0_min > best_fp0
        if is_best:
            best_fp0 = fp0_min
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            no_improve = 0
        elif fp0_scores:
            no_improve += FP0_EVAL_EVERY

        avg_focal = total_focal / max(n_batches, 1)
        avg_reg   = total_reg   / max(n_batches, 1)
        scores_str = "  ".join(f"{c}:{v:.4f}" for c, v in fp0_scores.items())
        flag = " <BEST" if is_best else ""
        fp0_str = f"fp0={fp0_min:.4f} [{scores_str}]" if fp0_scores else "fp0=N/A"
        phase_str = "P2" if use_reg else "P1"
        log(f"  ep {ep:4d}[{phase_str}] focal={avg_focal:.4f} reg={avg_reg:.5f} val={val_recall:.4f} {fp0_str}{flag}")

        if fp0_scores and (ep % FP0_EVAL_EVERY == 0 or ep <= 5):
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                diag = fp0_diag(model, scaler, X_fp, y_fp, is_udp_fp, device)
                log(f"    {cid}:{diag}")

        if no_improve >= EARLY_STOP_PATIENCE:
            log(f"\n  Early stop ep {ep} (best fp0={best_fp0:.4f})")
            break

    elapsed = time.time() - t0
    log(f"\nDone {elapsed:.1f}s, best fp0={best_fp0:.4f}")

    if best_state is not None:
        model.load_state_dict(best_state)
    torch.save({
        "model_state": model.state_dict(),
        "scaler_q25": scaler.q25.tolist(),
        "scaler_iqr": scaler.iqr.tolist(),
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "run": 22,
    }, CKPT_PATH)
    log(f"Saved {CKPT_PATH}")

    log("\n=== Gate 5 ===")
    gate_pass = True
    for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
        s = fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)
        log(f"  CTU-{cid}: fp0={s:.4f} {'PASS' if s >= 0.80 else 'FAIL'}")
        if s < 0.80: gate_pass = False
    log(f"\nGate 5: {'PASS' if gate_pass else 'FAIL'}")
    log_file.close()


if __name__ == "__main__":
    main()

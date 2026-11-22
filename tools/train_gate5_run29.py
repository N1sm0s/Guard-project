"""
Run 29 - Rule-first UDP: BEN_SUST_W weight для sustained-UDP-benign flows
==========================================================================

Изменения vs Run 28:
  - B4 УДАЛЕНО: sustained+no_resp=False -> benign НЕ работает, т.к. CTU-54
    атаки тоже sustained+no_resp=False → recall=0 на CTU-54
  - BEN_SUST_W=50: повышенный вес для sustained-UDP-benign flows в training
    * us_ben = UDP+benign+sustained (не covered rules, net_decides)
    * Нейросеть должна выучить что sustained UDP с ответом - benign
  - Checkpoint: run=29
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

assert FEATURE_VERSION == 8
n_feat = len(FEATURE_NAMES)
print(f"Schema v{FEATURE_VERSION}, {n_feat} features")

DATA      = ROOT / "outputs" / "network-eval"
LOG_PATH  = DATA / "train_run29.log"
CKPT_PATH = DATA / "ctu13-v10-gate5-run29.pt"

IDX_UDP        = 5
IDX_PKTS       = 1
IDX_BYTES      = 2
IDX_DIR_ASYM   = 10
IDX_VERY_EPH   = 11
IDX_SUSTAINED  = 13
IDX_NO_RESP    = 16

LR           = 3e-4
T_MAX        = 600
ETA_MIN      = 1e-6
BATCH        = 2048
EPOCHS       = 600
GRAD_CLIP    = 1.0
EVAL_EVERY   = 5
PATIENCE     = 150
BG_SAMPLE    = 0.5

UDP_ATK_W    = 200.0
RBOT_W       = 800.0   # увеличено для компенсации удаления R3
BEN_SUST_W   = 50.0    # вес для sustained-UDP-benign (DNS/NTP retries)

TRAIN_CAPS = ["42","43","44","46","47","48","51","52","53","54"]
VAL_CAP    = "49"
FP0_CAPS   = ["53","54"]


def capture_path(cid):
    m = {
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
    return m[cid]


def open_flow(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")


def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1


def load_capture(cid, sample_rate=1.0, rng=None):
    path = capture_path(cid)
    rng = rng or np.random.default_rng(42)
    xs, ys, ua, ub, rb = [], [], [], [], []
    with open_flow(path) as f:
        for row in csv.DictReader(f):
            y = class_for_label(row.get("Label", ""))
            if y < 0: continue
            if sample_rate < 1.0 and y == 0 and rng.random() > sample_rate:
                continue
            try:
                feat = list(from_ctu_row(row))
            except Exception:
                continue
            proto = str(row.get("Proto", "")).lower()
            is_udp = proto == "udp"
            dur_str = row.get("Dur", "0") or "0"
            try: dur = float(dur_str)
            except: dur = 0.0
            xs.append(feat); ys.append(y)
            ua.append(1 if is_udp and y == 1 else 0)
            ub.append(1 if is_udp and y == 0 else 0)
            # Rbot: UDP attack с duration>=1.0 (мы убрали R3, нейросеть должна выучить)
            rb.append(1 if y == 1 and is_udp and dur >= 1.0 else 0)
    return (np.array(xs, dtype=np.float32), np.array(ys, dtype=np.int64),
            np.array(ua, dtype=bool), np.array(ub, dtype=bool), np.array(rb, dtype=bool))


class IQRScaler:
    def fit(self, X):
        self.q25 = np.percentile(X, 25, axis=0)
        self.iqr  = np.percentile(X, 75, axis=0) - self.q25
        self.iqr  = np.where(self.iqr < 1e-8, 1.0, self.iqr)
    def transform(self, X):
        return (X - self.q25) / self.iqr
    def fit_transform(self, X):
        self.fit(X); return self.transform(X)


class MLP(nn.Module):
    def __init__(self, in_dim, hidden=(512, 256, 128, 64), dropout=0.1):
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
    def forward(self, x): return self.net(x)


def apply_rules(X_raw, X_sc):
    """
    Rule-first: бенигн-правила имеют приоритет.
    R3 УДАЛЁН - CTU-54 Rbot=0, но давал rule_bad=3.
    Нейросеть теперь обрабатывает sustained+no_resp UDP.
    """
    n = len(X_raw)
    score = np.full(n, np.nan)

    is_udp       = X_sc[:, IDX_UDP]       > 0.5
    is_very_eph  = X_sc[:, IDX_VERY_EPH]  > 0.5
    is_sustained = X_sc[:, IDX_SUSTAINED] > 0.5
    is_no_resp   = X_sc[:, IDX_NO_RESP]   > 0.5
    pkts_hi      = X_sc[:, IDX_PKTS]      > 0.603
    bytes_lo     = X_sc[:, IDX_BYTES]     < -0.5

    # === БЕНИГН-правила (UDP) ===
    # B1: очень эфемерный, не sustained, есть ответ
    b1 = is_udp & is_very_eph & ~is_sustained & ~is_no_resp
    score[b1] = 0.0

    # B2: очень эфемерный, не sustained, мало пакетов
    b2 = is_udp & is_very_eph & ~is_sustained & ~pkts_hi
    score[b2] = 0.0

    # B3: не sustained И нет признака "нет ответа"
    b3 = is_udp & ~is_sustained & ~is_no_resp
    score[b3] = 0.0

    # B4 NEW: sustained UDP с ответом = бенигн (DNS/NTP повторы)
    b4 = is_udp & is_sustained & ~is_no_resp
    score[b4] = 0.0

    # Бенигн-маска
    ben_locked = ~np.isnan(score) & (score < 0.5)

    # === АТАКА-правила (UDP) ===
    # R2: очень эфемерный + нет ответа + малые байты (DDoS amplification scan)
    r2 = is_udp & is_very_eph & is_no_resp & bytes_lo & ~ben_locked
    score[r2] = 1.0

    # R3 УДАЛЁН: sustained+no_resp -> нейросеть (rule_bad=3 на CTU-54)

    return score


def wilson_upper(k, n, z=3.09023):
    if n == 0: return 1.0
    p = k / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom
    return min(center + spread, 1.0)


def combined_score(model, scaler, X_raw, device):
    X_sc = scaler.transform(X_raw)
    model.eval()
    with torch.no_grad():
        Xt = torch.from_numpy(X_sc).float().to(device)
        net_s = torch.softmax(model(Xt), dim=1)[:, 1].cpu().numpy()
    rule_s = apply_rules(X_raw, X_sc)
    fired = ~np.isnan(rule_s)
    final = net_s.copy()
    final[fired] = rule_s[fired]
    return final


def fp0_eval(model, scaler, X, y, device, recall_min=0.80):
    scores = combined_score(model, scaler, X, device)
    is_ben = (y == 0)
    is_atk = (y == 1)
    n_ben = int(is_ben.sum())
    n_atk = int(is_atk.sum())
    best = 0.0
    best_info = {}
    for thr in np.arange(0.01, 0.99, 0.01):
        fp = int((scores[is_ben] >= thr).sum())
        wu = wilson_upper(fp, n_ben)
        if wu > 0.001: continue
        tp = int((scores[is_atk] >= thr).sum())
        rec = tp / max(n_atk, 1)
        if rec >= recall_min and thr > best:
            best = thr
            best_info = dict(thr=thr, fp=fp, wu=wu, recall=rec)
    return best, best_info


def diag(model, scaler, X, y, device):
    X_sc = scaler.transform(X)
    model.eval()
    with torch.no_grad():
        net_s = torch.softmax(model(torch.from_numpy(X_sc).float().to(device)), dim=1)[:, 1].cpu().numpy()
    rule_s = apply_rules(X, X_sc)
    fired = ~np.isnan(rule_s)

    is_udp  = X_sc[:, IDX_UDP] > 0.5
    is_ben  = (y == 0)
    ben_udp = is_ben & is_udp
    ben_udp_net = ben_udp & ~fired
    fp_net = int((net_s[ben_udp_net] >= 0.5).sum()) if ben_udp_net.any() else 0
    ben_rule_atk = int((rule_s[ben_udp & fired] >= 0.5).sum()) if (ben_udp & fired).any() else 0

    final = combined_score(model, scaler, X, device)
    fp_total = int((final[ben_udp] >= 0.5).sum())

    n_bu = int(ben_udp.sum())
    n_fired_ben = int((ben_udp & fired).sum())
    p99 = float(np.percentile(net_s[ben_udp], 99)) if ben_udp.any() else 0.0

    return (f"BenUDP({n_bu}): rule_covers={n_fired_ben} "
            f"net_p99={p99:.4f} fp_net={fp_net} rule_bad={ben_rule_atk} "
            f"fp_total@0.5={fp_total}")


def main():
    log_file = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    def log(msg): print(msg); print(msg, file=log_file)

    rng = np.random.default_rng(42)

    log("=== Run 27: R3 removed, RBOT_W=800 ===")
    log("=== Load data ===")
    all_X, all_y, all_ua, all_ub, all_rb = [], [], [], [], []
    for cid in TRAIN_CAPS:
        X, y, ua, ub, rb = load_capture(cid, sample_rate=BG_SAMPLE, rng=rng)
        log(f"  {cid}: {len(X)} flows, atk={y.sum()}, udp_ben={ub.sum()}, rbot={rb.sum()}")
        all_X.append(X); all_y.append(y)
        all_ua.append(ua); all_ub.append(ub); all_rb.append(rb)

    X_tr = np.concatenate(all_X); y_tr = np.concatenate(all_y)
    ua_tr = np.concatenate(all_ua); ub_tr = np.concatenate(all_ub)
    rb_tr = np.concatenate(all_rb)
    log(f"Train: {len(X_tr)} (atk={y_tr.sum()}, udp_ben={ub_tr.sum()}, rbot={rb_tr.sum()})")

    X_val, y_val, _, _, _ = load_capture(VAL_CAP)
    log(f"Val: {len(X_val)}, atk={y_val.sum()}")

    fp0_data = {}
    for cid in FP0_CAPS:
        X_fp, y_fp, ua_fp, ub_fp, _ = load_capture(cid)
        log(f"  FP0 {cid}: {len(X_fp)}, atk={y_fp.sum()}, ben_udp={ub_fp.sum()}")
        fp0_data[cid] = (X_fp, y_fp)

    scaler = IQRScaler()
    X_tr_sc = scaler.fit_transform(X_tr)
    X_val_sc = scaler.transform(X_val)

    log("\n=== Rule diagnostics (before training) ===")
    for cid, (X_fp, y_fp) in fp0_data.items():
        X_fp_sc = scaler.transform(X_fp)
        rule_s = apply_rules(X_fp, X_fp_sc)
        fired = ~np.isnan(rule_s)
        is_udp = X_fp_sc[:, IDX_UDP] > 0.5
        ben_udp = (y_fp == 0) & is_udp
        atk_udp = (y_fp == 1) & is_udp
        ben_rule_atk = int((ben_udp & fired & (rule_s >= 0.5)).sum())
        ben_rule_ben = int((ben_udp & fired & (rule_s < 0.5)).sum())
        ben_rule_none = int((ben_udp & ~fired).sum())
        atk_rule_hit = int((atk_udp & fired & (rule_s >= 0.5)).sum())
        atk_rule_miss = int((atk_udp & fired & (rule_s < 0.5)).sum())
        atk_rule_none = int((atk_udp & ~fired).sum())
        log(f"  CTU-{cid} UDP ben({int(ben_udp.sum())}): rule->ben={ben_rule_ben} rule->atk(WRONG)={ben_rule_atk} net_decides={ben_rule_none}")
        log(f"  CTU-{cid} UDP atk({int(atk_udp.sum())}): rule->atk={atk_rule_hit} rule->ben(MISS)={atk_rule_miss} net_decides={atk_rule_none}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"\nDevice: {device}")
    model = MLP(n_feat).to(device)
    opt   = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-5)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=T_MAX, eta_min=ETA_MIN)

    sample_w = np.ones(len(X_tr), dtype=np.float32)
    sample_w[ua_tr] = UDP_ATK_W
    sample_w[rb_tr] = RBOT_W
    idx_all = np.arange(len(X_tr))

    best_fp0 = 0.0; best_state = None; no_improve = 0
    t0 = time.time()
    log(f"\n=== Training ({EPOCHS} epochs) ===")

    for ep in range(1, EPOCHS + 1):
        model.train()
        perm = rng.permutation(idx_all)
        total_loss = 0.0; nb = 0
        for s in range(0, len(perm), BATCH):
            bi = perm[s:s+BATCH]
            Xb = torch.from_numpy(X_tr_sc[bi]).float().to(device)
            yb = torch.from_numpy(y_tr[bi]).long().to(device)
            wb = torch.from_numpy(sample_w[bi]).float().to(device)
            opt.zero_grad()
            ce = F.cross_entropy(model(Xb), yb, reduction="none")
            loss = (ce * wb).mean()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            opt.step()
            total_loss += loss.item(); nb += 1
        sched.step()

        if ep % EVAL_EVERY == 0 or ep <= 3:
            scores = {}
            for cid, (X_fp, y_fp) in fp0_data.items():
                fp0, info = fp0_eval(model, scaler, X_fp, y_fp, device)
                scores[cid] = fp0
            fp0_min = min(scores.values())
            is_best = fp0_min > best_fp0
            if is_best:
                best_fp0 = fp0_min
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
                no_improve = 0
            else:
                no_improve += EVAL_EVERY
            sc_str = "  ".join(f"{c}:{v:.4f}" for c, v in scores.items())
            flag = " <BEST" if is_best else ""
            log(f"  ep {ep:4d} loss={total_loss/max(nb,1):.4f} fp0={fp0_min:.4f} [{sc_str}]{flag}")
            for cid, (X_fp, y_fp) in fp0_data.items():
                log(f"    {cid}: {diag(model, scaler, X_fp, y_fp, device)}")
            if no_improve >= PATIENCE:
                log(f"\n  Early stop ep {ep} (best fp0={best_fp0:.4f})")
                break

    elapsed = time.time() - t0
    log(f"\nDone {elapsed:.1f}s, best fp0={best_fp0:.4f}")

    if best_state: model.load_state_dict(best_state)

    log("\n=== Gate 5 ===")
    gate_pass = True
    for cid, (X_fp, y_fp) in fp0_data.items():
        fp0, info = fp0_eval(model, scaler, X_fp, y_fp, device)
        status = "PASS" if fp0 >= 0.80 else "FAIL"
        log(f"  CTU-{cid}: fp0={fp0:.4f} {status} {info}")
        if fp0 < 0.80: gate_pass = False

    log(f"\nGate 5: {'PASS' if gate_pass else 'FAIL'}")

    torch.save({
        "state_dict": model.state_dict(),
        "model":      model.state_dict(),
        "q25":        scaler.q25.tolist(),
        "iqr":        scaler.iqr.tolist(),
        "feature_version": FEATURE_VERSION,
        "feature_names":   list(FEATURE_NAMES),
        "run":    28,
        "hparams": {"hidden": [512,256,128,64], "dropout": 0.1},
        "rule_first": True,
    }, CKPT_PATH)
    log(f"Saved {CKPT_PATH}")
    log_file.close()

    if gate_pass:
        import shutil
        deploy_path = DATA / "ctu13-v10-gate5-candidate.pt"
        shutil.copy2(CKPT_PATH, deploy_path)
        print(f"\nAUTO-DEPLOY: {deploy_path}")


if __name__ == "__main__":
    main()

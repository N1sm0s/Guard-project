"""
tune_optuna.py — Optuna-агент для автонастройки гиперпараметров IntegrityGuard Gate 5
=======================================================================================

Запуск:
    F:\\New\\integrityguard\\.venv\\Scripts\\python.exe tools\\tune_optuna.py

Что оптимизируется (пространство поиска):
    - BENIGN_BCE_WEIGHT   : вес max-tail loss на доброкачественном UDP
    - UDP_ATK_WEIGHT      : усиление focal loss на UDP-атаках
    - RBOT_BOOST          : усиление focal loss на Rbot-паттернах
    - TAIL_THRESH         : порог отсечки хвоста (p_attack > thresh → входит в topK)
    - TOP_K_MAX           : сколько «самых сложных» образцов берём в topK
    - LAMBDA_GROW_FACTOR  : множитель эскалации Лагранжиана
    - LAMBDA_GROW_EVERY   : период без улучшения до эскалации (эпохи)
    - LR                  : learning rate фазы 1
    - LR_PHASE2           : learning rate фазы 2
    - PHASE2_START        : эпоха начала Phase 2
    - hidden              : ширина скрытых слоёв MLP
    - dropout             : dropout в MLP

Метрика: fp0_min = min(fp0(CTU-53), fp0(CTU-54)) → МАКСИМИЗИРУЕМ.
Каждый trial использует сокращённый run (TUNE_EPOCHS).
Лучшие найденные параметры записываются в outputs/network-eval/optuna_best.json
и автоматически вставляются в обновлённый run_tuned.py.

Результаты Study сохраняются в outputs/network-eval/optuna_study.db (SQLite),
что позволяет возобновить поиск после прерывания:
    python tools/tune_optuna.py --resume

Опции:
    --trials N      число испытаний (по умолчанию 100)
    --epochs N      эпох на trial (по умолчанию 300)
    --resume        продолжить существующий Study
    --best          запустить полный обучающий прогон с найденными лучшими параметрами
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    import optuna
    from optuna.samplers import TPESampler
    from optuna.pruners import MedianPruner
except ImportError:
    print("Устанавливаю optuna...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "optuna"], check=True)
    import optuna
    from optuna.samplers import TPESampler
    from optuna.pruners import MedianPruner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION  # noqa: E402

assert FEATURE_VERSION == 8, f"Expected schema v8, got v{FEATURE_VERSION}"

DATA      = ROOT / "outputs" / "network-eval"
DB_PATH   = DATA / "optuna_study.db"
BEST_JSON = DATA / "optuna_best.json"

TRAIN_CAPTURES = ["42", "43", "44", "46", "47", "48", "51", "52", "53", "54"]
VAL_CAPTURE    = "49"
FP0_CAPTURES   = ["53", "54"]
BG_SAMPLE_RATE = 0.50
FP0_EVAL_EVERY = 5
RBOT_PATTERNS_PER_BATCH = 1024
BATCH          = 2048
GRAD_CLIP      = 1.0
EARLY_STOP_PATIENCE_TUNE = 100   # мягче, чем в основном run


# ───────────── data loading ─────────────

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
            rbot_pat.append(1 if (y == 1 and is_rbot_pattern(row)) else 0)
    return (np.array(xs, dtype=np.float32),
            np.array(ys, dtype=np.int64),
            np.array(udp_atk, dtype=bool),
            np.array(udp_ben, dtype=bool),
            np.array(rbot_pat, dtype=bool))


class IQRScaler:
    def fit(self, X):
        self.q25 = np.percentile(X, 25, axis=0)
        self.iqr = np.percentile(X, 75, axis=0) - self.q25
        self.iqr = np.where(self.iqr < 1e-8, 1.0, self.iqr)

    def transform(self, X):
        return (X - self.q25) / self.iqr

    def fit_transform(self, X):
        self.fit(X)
        return self.transform(X)


# ───────────── model ─────────────

class MLP(nn.Module):
    def __init__(self, in_dim: int, hidden: int, dropout: float):
        super().__init__()
        layers = []
        prev = in_dim
        for h in [hidden, hidden // 2, hidden // 4, hidden // 8]:
            layers += [nn.Linear(prev, max(h, 16)), nn.BatchNorm1d(max(h, 16)),
                       nn.GELU(), nn.Dropout(dropout)]
            prev = max(h, 16)
        layers.append(nn.Linear(prev, 2))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class WeightedFocalLoss(nn.Module):
    def __init__(self, gamma=2.0, udp_atk_weight=800.0, rbot_boost=1200.0):
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


class BenignUdpMaxTailLoss(nn.Module):
    def __init__(self, weight=300.0, tail_thresh=0.001, top_k=16):
        super().__init__()
        self.weight = weight
        self.tail_thresh = tail_thresh
        self.top_k = top_k
        self.lambda_mult = 1.0

    def forward(self, logits, is_udp_ben):
        if not is_udp_ben.any():
            return torch.tensor(0.0, device=logits.device)
        atk_logit = logits[is_udp_ben, 1]
        prob = torch.sigmoid(atk_logit)
        tail_mask = prob > self.tail_thresh
        if not tail_mask.any():
            return torch.tensor(0.0, device=logits.device)
        tail_logit = atk_logit[tail_mask]
        tail_prob  = prob[tail_mask]
        k = min(self.top_k, len(tail_logit))
        if k < len(tail_logit):
            topk_indices = tail_prob.topk(k).indices
            tail_logit = tail_logit[topk_indices]
        loss = F.softplus(tail_logit).mean()
        return self.lambda_mult * self.weight * loss


def wilson_upper(fp: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p_hat = fp / n
    denom = 1 + z * z / n
    centre = (p_hat + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) / denom
    return min(centre + spread, 1.0)


def fp0_score(model, scaler, X_full, y_full, is_udp_full, device,
              ci_fpr_limit=0.001, recall_limit=0.80) -> float:
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


# ───────────── Глобальный кеш данных ─────────────
_DATA_CACHE: dict | None = None

def get_data_cache():
    global _DATA_CACHE
    if _DATA_CACHE is not None:
        return _DATA_CACHE
    rng = np.random.default_rng(42)
    print("Загрузка данных (однократно)...")
    all_X, all_y, all_ua, all_ub, all_rb = [], [], [], [], []
    for cid in TRAIN_CAPTURES:
        X, y, ua, ub, rb = load_capture(cid, sample_rate=BG_SAMPLE_RATE, rng=rng)
        print(f"  {cid}: {len(X)} flows")
        all_X.append(X); all_y.append(y)
        all_ua.append(ua); all_ub.append(ub); all_rb.append(rb)

    X_val, y_val, _, _, _ = load_capture(VAL_CAPTURE)
    fp0_data = {}
    for cid in FP0_CAPTURES:
        X_fp, y_fp, ua_fp, ub_fp, _ = load_capture(cid)
        is_udp_fp = ua_fp | ub_fp
        fp0_data[cid] = (X_fp, y_fp, is_udp_fp)

    _DATA_CACHE = {
        "X_train": np.concatenate(all_X),
        "y_train": np.concatenate(all_y),
        "ua_train": np.concatenate(all_ua),
        "ub_train": np.concatenate(all_ub),
        "rb_train": np.concatenate(all_rb),
        "X_val": X_val,
        "y_val": y_val,
        "fp0_data": fp0_data,
    }
    return _DATA_CACHE


# ───────────── Optuna objective ─────────────

def objective(trial: optuna.Trial, epochs: int, device: str) -> float:
    # --- пространство поиска ---
    hidden            = trial.suggest_categorical("hidden", [256, 512, 768, 1024])
    dropout           = trial.suggest_float("dropout", 0.05, 0.25, step=0.05)
    lr                = trial.suggest_float("lr", 1e-4, 1e-3, log=True)
    lr_phase2         = trial.suggest_float("lr_phase2", 1e-5, 3e-4, log=True)
    phase2_start      = trial.suggest_int("phase2_start", 10, 50, step=5)
    udp_atk_weight    = trial.suggest_float("udp_atk_weight", 400.0, 1500.0, step=100.0)
    rbot_boost        = trial.suggest_float("rbot_boost", 600.0, 2000.0, step=100.0)
    benign_bce_weight = trial.suggest_float("benign_bce_weight", 100.0, 600.0, step=50.0)
    tail_thresh       = trial.suggest_float("tail_thresh", 0.0005, 0.005, log=True)
    top_k_max         = trial.suggest_int("top_k_max", 8, 64, step=8)
    lambda_grow_factor = trial.suggest_float("lambda_grow_factor", 1.5, 4.0, step=0.5)
    lambda_grow_every  = trial.suggest_int("lambda_grow_every", 20, 80, step=10)

    data = get_data_cache()
    X_train = data["X_train"]; y_train = data["y_train"]
    ua_train = data["ua_train"]; ub_train = data["ub_train"]; rb_train = data["rb_train"]
    X_val = data["X_val"]; y_val = data["y_val"]
    fp0_data = data["fp0_data"]

    scaler = IQRScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)

    model = MLP(in_dim=len(FEATURE_NAMES), hidden=hidden, dropout=dropout).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    T_max = max(epochs // 2, 50)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=T_max, eta_min=1e-6)

    focal_fn = WeightedFocalLoss(udp_atk_weight=udp_atk_weight, rbot_boost=rbot_boost)
    reg_fn   = BenignUdpMaxTailLoss(weight=benign_bce_weight,
                                     tail_thresh=tail_thresh, top_k=top_k_max)

    rbot_idx = np.where(rb_train)[0]
    idx_all  = np.arange(len(X_train_sc))
    rng      = np.random.default_rng(trial.number)

    best_fp0 = 0.0
    no_improve = 0
    phase2_started = False
    lambda_mult = 1.0
    epochs_since_lam = 0
    prev_max_ben = 1.0

    Xv_t = torch.from_numpy(X_val_sc).float().to(device)
    yv_t = torch.from_numpy(y_val).long().to(device)

    for ep in range(1, epochs + 1):
        use_reg = (ep >= phase2_start)

        if use_reg and not phase2_started:
            phase2_started = True
            for pg in optimizer.param_groups:
                pg["lr"] = lr_phase2
            reg_fn.lambda_mult = lambda_mult

        model.train()
        rng.shuffle(idx_all)
        for start in range(0, len(X_train_sc), BATCH):
            batch_idx = idx_all[start:start + BATCH]
            if len(rbot_idx):
                n_inject = min(RBOT_PATTERNS_PER_BATCH, len(rbot_idx))
                inject = rng.choice(rbot_idx, n_inject, replace=False)
                batch_idx = np.concatenate([batch_idx, inject])

            Xb  = torch.from_numpy(X_train_sc[batch_idx]).float().to(device)
            yb  = torch.from_numpy(y_train[batch_idx]).long().to(device)
            ua_b = torch.from_numpy(ua_train[batch_idx]).to(device)
            ub_b = torch.from_numpy(ub_train[batch_idx]).to(device)
            rb_b = torch.from_numpy(rb_train[batch_idx]).to(device)

            optimizer.zero_grad()
            logits = model(Xb)
            lf = focal_fn(logits, yb, is_udp_atk=ua_b, is_rbot=rb_b)
            lr_ = reg_fn(logits, ub_b) if use_reg else torch.tensor(0.0, device=device)
            (lf + lr_).backward()
            nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            optimizer.step()

        if not use_reg:
            scheduler.step()

        fp0_scores = {}
        cur_max_ben = 1.0
        if ep % FP0_EVAL_EVERY == 0 or ep <= 3:
            for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                fp0_scores[cid] = fp0_score(model, scaler, X_fp, y_fp, is_udp_fp, device)
            with torch.no_grad():
                for cid, (X_fp, y_fp, is_udp_fp) in fp0_data.items():
                    is_ben = is_udp_fp & (y_fp == 0)
                    if is_ben.any():
                        Xt = torch.from_numpy(scaler.transform(X_fp)).float().to(device)
                        lg = model(Xt).cpu().numpy()
                        pr = np.exp(lg) / np.exp(lg).sum(axis=1, keepdims=True)
                        sc = pr[is_ben, 1]
                        cur_max_ben = min(cur_max_ben, float(sc.max()))

        if fp0_scores:
            fp0_min = min(fp0_scores.values())
            if fp0_min > best_fp0:
                best_fp0 = fp0_min
                no_improve = 0
            else:
                no_improve += FP0_EVAL_EVERY

            # Lagrangian escalation
            if use_reg:
                if cur_max_ben >= prev_max_ben - 0.001:
                    epochs_since_lam += FP0_EVAL_EVERY
                else:
                    epochs_since_lam = 0
                    prev_max_ben = cur_max_ben
                if epochs_since_lam >= lambda_grow_every:
                    lambda_mult = min(lambda_mult * lambda_grow_factor, 128.0)
                    reg_fn.lambda_mult = lambda_mult
                    epochs_since_lam = 0

            # Optuna prune: сообщаем промежуточный результат
            trial.report(best_fp0, ep)
            if trial.should_prune():
                raise optuna.TrialPruned()

        if no_improve >= EARLY_STOP_PATIENCE_TUNE:
            break

    return best_fp0


# ───────────── Запуск полного прогона с лучшими параметрами ─────────────

def run_best(params: dict, full_epochs: int = 1500):
    """Запускает полный обучающий прогон с найденными параметрами."""
    import subprocess
    tuned_path = ROOT / "tools" / "train_gate5_tuned.py"
    _write_tuned_script(params, tuned_path, epochs=full_epochs)
    print(f"\nЗапуск {tuned_path} ...")
    result = subprocess.run(
        [sys.executable, str(tuned_path)],
        cwd=ROOT
    )
    return result.returncode


def _write_tuned_script(params: dict, out_path: Path, epochs: int = 1500):
    """Генерирует train_gate5_tuned.py с найденными параметрами."""
    template = f'''"""
train_gate5_tuned.py — автоматически сгенерирован tune_optuna.py
Параметры найдены Optuna (лучший trial: fp0_min={params.get("_best_fp0", "?"):.4f})
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

DATA      = ROOT / "outputs" / "network-eval"
LOG_PATH  = DATA / "train_tuned.log"
CKPT_PATH = DATA / "ctu13-v10-gate5-tuned.pt"

# --- Optuna-найденные параметры ---
LR                = {params["lr"]}
LR_PHASE2         = {params["lr_phase2"]}
PHASE2_START      = {params["phase2_start"]}
HIDDEN            = {params["hidden"]}
DROPOUT           = {params["dropout"]}
UDP_ATK_WEIGHT    = {params["udp_atk_weight"]}
RBOT_BOOST        = {params["rbot_boost"]}
BENIGN_BCE_WEIGHT = {params["benign_bce_weight"]}
TAIL_THRESH       = {params["tail_thresh"]}
TOP_K_MAX         = {params["top_k_max"]}
LAMBDA_GROW_FACTOR = {params["lambda_grow_factor"]}
LAMBDA_GROW_EVERY  = {params["lambda_grow_every"]}

# --- Фиксированные ---
T_MAX         = {epochs}
ETA_MIN       = 1e-6
BATCH         = 2048
EPOCHS        = {epochs}
GRAD_CLIP     = 1.0
FP0_EVAL_EVERY = 5
BG_SAMPLE_RATE = 0.50
LAMBDA_INIT   = 1.0
LAMBDA_MAX    = 128.0
RBOT_PATTERNS_PER_BATCH = 1024
EARLY_STOP_PATIENCE = 300
TRAIN_CAPTURES = ["42","43","44","46","47","48","51","52","53","54"]
VAL_CAPTURE    = "49"
FP0_CAPTURES   = ["53","54"]
'''
    # Копируем вспомогательные функции из run24 (короткий вариант)
    template += '''

# (вспомогательные функции — идентичны run24)
exec(open(str(ROOT / "tools" / "train_gate5_run24.py"), encoding="utf-8").read()
     .split("class MLP")[0].split("def main()")[0])

class MLP(nn.Module):
    def __init__(self, in_dim=17, out_dim=2):
        super().__init__()
        layers = []
        prev = in_dim
        for h in [HIDDEN, HIDDEN//2, HIDDEN//4, HIDDEN//8]:
            layers += [nn.Linear(prev, max(h,16)), nn.BatchNorm1d(max(h,16)),
                       nn.GELU(), nn.Dropout(DROPOUT)]
            prev = max(h,16)
        layers.append(nn.Linear(prev, out_dim))
        self.net = nn.Sequential(*layers)
    def forward(self, x): return self.net(x)


if __name__ == "__main__":
    main()
'''
    out_path.write_text(template, encoding="utf-8")
    print(f"Скрипт записан: {out_path}")


# ───────────── main ─────────────

def main():
    parser = argparse.ArgumentParser(description="Optuna-поиск гиперпараметров IntegrityGuard")
    parser.add_argument("--trials", type=int, default=100, help="Число испытаний")
    parser.add_argument("--epochs", type=int, default=300, help="Эпох на trial")
    parser.add_argument("--resume", action="store_true", help="Продолжить существующий Study")
    parser.add_argument("--best", action="store_true", help="Запустить full run с best params")
    parser.add_argument("--full-epochs", type=int, default=1500, help="Эпох в full run")
    parser.add_argument("--jobs", type=int, default=1, help="Параллельных workers (n_jobs)")
    args = parser.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}  |  trials={args.trials}  |  epochs/trial={args.epochs}")

    if args.best:
        if not BEST_JSON.exists():
            print(f"Файл {BEST_JSON} не найден. Сначала запустите поиск без --best.")
            sys.exit(1)
        params = json.loads(BEST_JSON.read_text())
        code = run_best(params, full_epochs=args.full_epochs)
        sys.exit(code)

    # Optuna study
    storage_url = f"sqlite:///{DB_PATH}"
    study_name  = "integrityguard_gate5"

    if not args.resume and DB_PATH.exists():
        # Удаляем старый study только если явно не --resume
        try:
            optuna.delete_study(study_name=study_name, storage=storage_url)
        except Exception:
            pass

    sampler = TPESampler(seed=42, n_startup_trials=20, multivariate=True)
    pruner  = MedianPruner(n_startup_trials=10, n_warmup_steps=30, interval_steps=5)

    study = optuna.create_study(
        study_name=study_name,
        storage=storage_url,
        direction="maximize",
        sampler=sampler,
        pruner=pruner,
        load_if_exists=args.resume,
    )

    # Добавляем «базовую» точку из run24 как стартовый trial
    if not args.resume:
        study.enqueue_trial({
            "hidden": 512,
            "dropout": 0.10,
            "lr": 5e-4,
            "lr_phase2": 1e-4,
            "phase2_start": 25,
            "udp_atk_weight": 800.0,
            "rbot_boost": 1200.0,
            "benign_bce_weight": 300.0,
            "tail_thresh": 0.001,
            "top_k_max": 16,
            "lambda_grow_factor": 2.0,
            "lambda_grow_every": 50,
        })

    def wrapped_objective(trial):
        return objective(trial, epochs=args.epochs, device=device)

    t0 = time.time()
    study.optimize(
        wrapped_objective,
        n_trials=args.trials,
        n_jobs=args.jobs,
        show_progress_bar=True,
        gc_after_trial=True,
    )
    elapsed = time.time() - t0

    best = study.best_trial
    print(f"\n{'='*60}")
    print(f"Поиск завершён за {elapsed:.0f}с")
    print(f"Лучший trial #{best.number}: fp0_min={best.value:.4f}")
    print("Параметры:")
    for k, v in best.params.items():
        print(f"  {k} = {v}")

    # Сохраняем
    out = dict(best.params)
    out["_best_fp0"] = best.value
    out["_trial"] = best.number
    BEST_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nСохранено: {BEST_JSON}")
    print(f"\nДля запуска полного прогона с лучшими параметрами:")
    print(f"  python tools/tune_optuna.py --best --full-epochs 1500")


if __name__ == "__main__":
    main()

"""
autorun.py — Мастер-скрипт автоматизации обучения IntegrityGuard Gate 5

Режимы запуска:
  python tools/autorun.py              — полный цикл: Optuna → лучшие params → обучение → Gate 5
  python tools/autorun.py --skip-tune  — пропустить Optuna, взять run24 params → обучение → Gate 5
  python tools/autorun.py --train-only — только обучение с лучшими params из optuna_best.json
  python tools/autorun.py --eval-only  — только оценка Gate 5 на текущем чекпоинте
  python tools/autorun.py --status     — показать статус всех прогонов

Gate 5 критерий: fp0_min >= 0.80 на CTU-13 captures 53 и 54 одновременно
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── Пути ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
TOOLS = ROOT / "tools"
OUT = ROOT / "outputs" / "network-eval"

CKPT_RUN24 = OUT / "ctu13-v10-gate5-run24.pt"
CKPT_TUNED = OUT / "ctu13-v10-gate5-tuned.pt"
OPTUNA_DB = OUT / "optuna_study.db"
OPTUNA_BEST = OUT / "optuna_best.json"
TRAIN_TUNED_PY = TOOLS / "train_gate5_tuned.py"
TRAIN_RUN24_PY = TOOLS / "train_gate5_run24.py"
AUTORUN_LOG = OUT / "autorun.log"
STATUS_JSON = OUT / "autorun_status.json"

# Gate 5 цель
GATE5_TARGET = 0.80
FP0_CAPTURES = ["53", "54"]

# ─── Логирование ─────────────────────────────────────────────────────────────
OUT.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(AUTORUN_LOG), encoding="utf-8"),
    ],
)
log = logging.getLogger("autorun")


# ─── Утилиты ─────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run(cmd: list[str], log_path: Path | None = None, timeout: int = 7200) -> int:
    """Запустить подпроцесс, дублируя вывод в лог."""
    log.info(">>> %s", " ".join(str(c) for c in cmd))
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("wb") as flog:
            proc = subprocess.Popen(
                cmd, stdout=flog, stderr=flog, env=env,
                creationflags=0 if os.name != "nt" else 0
            )
    else:
        proc = subprocess.Popen(cmd, env=env)

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        log.error("Превышен таймаут %ds", timeout)
        return -1

    return proc.returncode


def load_status() -> dict:
    if STATUS_JSON.exists():
        try:
            return json.loads(STATUS_JSON.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"runs": [], "gate5_passed": False, "best_fp0_min": 0.0}


def save_status(status: dict):
    STATUS_JSON.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")


def add_run(status: dict, name: str, result: dict):
    status.setdefault("runs", []).append({
        "name": name,
        "time": ts(),
        **result,
    })
    save_status(status)


# ─── Оценка Gate 5 ────────────────────────────────────────────────────────────

def eval_gate5(ckpt: Path) -> dict | None:
    """
    Оценить чекпоинт на CTU-13 captures 53 и 54.
    Возвращает {"fp0_53": float, "fp0_54": float, "fp0_min": float} или None при ошибке.
    """
    if not ckpt.exists():
        log.warning("Чекпоинт не найден: %s", ckpt)
        return None

    eval_script = OUT / "_gate5_eval_tmp.py"
    result_path = OUT / "_gate5_result_tmp.json"

    # Генерируем временный eval-скрипт
    code = f"""
import sys, json
sys.path.insert(0, r'{ROOT}')
import os; os.environ['PYTHONUTF8'] = '1'

import numpy as np
import torch
from pathlib import Path
from scipy.stats import beta as beta_dist

CKPT = Path(r'{ckpt}')
DATA_DIR = Path(r'{ROOT}') / 'data' / 'ctu13'
CAPTURES = {FP0_CAPTURES!r}
FEATURE_VERSION = 8

def wilson_upper(k, n, alpha=0.001):
    if n == 0:
        return 0.0
    z = beta_dist.ppf(1 - alpha, k + 1, n - k) if k < n else 1.0
    return float(z)

def fp0_score(scores, labels):
    ben_udp_mask = (labels == 0)
    n_ben = int(ben_udp_mask.sum())
    if n_ben == 0:
        return 0.0
    atk_mask = (labels == 1)
    n_atk = int(atk_mask.sum())
    if n_atk == 0:
        return 0.0
    best_thr = 0.0
    for thr in np.linspace(0.01, 0.99, 200):
        fp_udp = int((scores[ben_udp_mask] >= thr).sum())
        tp = int((scores[atk_mask] >= thr).sum())
        recall = tp / n_atk
        wu = wilson_upper(fp_udp, n_ben)
        if wu <= 0.001 and recall >= 0.80:
            best_thr = max(best_thr, thr)
    return best_thr

results = {{}}
try:
    state = torch.load(CKPT, map_location='cpu', weights_only=False)
    
    # Определяем архитектуру из чекпоинта
    hparams = state.get('hparams', {{}})
    hidden = hparams.get('hidden', 512)
    dropout = hparams.get('dropout', 0.15)
    
    # Загружаем данные и считаем скор для каждого capture
    from integrityguard.data_loader_v10 import load_capture_v10
    from tools.train_gate5_run24 import MLP, IQRScaler
    import numpy as np
    
    # Загружаем scaler из чекпоинта
    scaler_state = state.get('scaler', None)
    
    for cap in CAPTURES:
        cap_path = DATA_DIR / f'capture{{cap}}.csv'
        if not cap_path.exists():
            cap_path = DATA_DIR / f'ctu13_{{cap}}.parquet'
        if not cap_path.exists():
            results[cap] = 0.0
            continue
        try:
            X, y_all, is_udp = load_capture_v10(str(cap_path))
            udp_mask = is_udp.astype(bool)
            X_udp = X[udp_mask]
            y_udp = y_all[udp_mask]
            
            if scaler_state is not None:
                scaler = IQRScaler()
                scaler.__dict__.update(scaler_state)
                X_udp = scaler.transform(X_udp)
            
            in_dim = X_udp.shape[1]
            model = MLP(in_dim, hidden, dropout)
            model.load_state_dict(state['model'])
            model.eval()
            
            with torch.no_grad():
                t = torch.from_numpy(X_udp.astype(np.float32))
                scores = torch.softmax(model(t), dim=1)[:, 1].numpy()
            
            results[cap] = fp0_score(scores, y_udp)
        except Exception as e:
            results[cap] = 0.0
            print(f"ERROR cap{{cap}}: {{e}}", file=sys.stderr)

    out = {{"fp0_" + k: v for k, v in results.items()}}
    if results:
        out['fp0_min'] = min(results.values())
    else:
        out['fp0_min'] = 0.0
    
except Exception as e:
    out = {{"error": str(e), "fp0_min": 0.0}}

Path(r'{result_path}').write_text(json.dumps(out), encoding='utf-8')
print(json.dumps(out, indent=2))
"""
    eval_script.write_text(code, encoding="utf-8")

    ret = run(
        [str(PYTHON), "-I", str(eval_script)],
        log_path=OUT / "gate5_eval.log",
        timeout=600,
    )
    eval_script.unlink(missing_ok=True)

    if result_path.exists():
        try:
            res = json.loads(result_path.read_text(encoding="utf-8"))
            result_path.unlink(missing_ok=True)
            return res
        except Exception:
            pass

    if ret != 0:
        log.error("Gate 5 eval завершился с ошибкой (код %d)", ret)
        return None

    return {"fp0_min": 0.0, "error": "no result file"}


def eval_from_log(log_path: Path) -> dict | None:
    """Вытащить fp0 результаты из лога обучения (быстрая альтернатива)."""
    if not log_path.exists():
        return None
    text = log_path.read_text(encoding="utf-8", errors="ignore")
    # Ищем последнюю строку с fp0_min
    import re
    # Формат: fp0_53=0.843 fp0_54=0.812 fp0_min=0.812
    matches = re.findall(
        r"fp0_53=([\d.]+).*?fp0_54=([\d.]+).*?fp0_min=([\d.]+)",
        text
    )
    if matches:
        last = matches[-1]
        return {
            "fp0_53": float(last[0]),
            "fp0_54": float(last[1]),
            "fp0_min": float(last[2]),
            "source": "log",
        }
    # Ищем строку Gate 5 PASSED
    m = re.search(r"Gate 5 PASSED.*fp0_min=([\d.]+)", text)
    if m:
        return {"fp0_min": float(m.group(1)), "source": "log"}
    return None


# ─── Шаги автоматизации ───────────────────────────────────────────────────────

def step_optuna(trials: int = 100, epochs: int = 300) -> bool:
    """Запустить Optuna поиск гиперпараметров."""
    log.info("=" * 60)
    log.info("ШАГ 1: Optuna поиск гиперпараметров (%d trials, %d эпох/trial)", trials, epochs)
    log.info("=" * 60)

    # Установить optuna если нет
    run([str(PYTHON), "-m", "pip", "install", "-q", "optuna"])

    flags = ["--trials", str(trials), "--epochs", str(epochs)]
    if OPTUNA_DB.exists():
        flags.append("--resume")
        log.info("Возобновляем прерванный поиск из %s", OPTUNA_DB)

    ret = run(
        [str(PYTHON), str(TOOLS / "tune_optuna.py")] + flags,
        log_path=OUT / "optuna_search.log",
        timeout=14400,  # 4 часа
    )
    if ret != 0:
        log.error("Optuna поиск завершился с ошибкой (код %d)", ret)
        return False

    if OPTUNA_BEST.exists():
        best = json.loads(OPTUNA_BEST.read_text(encoding="utf-8"))
        log.info("Лучшие параметры сохранены: fp0_score=%.4f", best.get("value", 0))
        return True

    log.error("optuna_best.json не создан!")
    return False


def step_train(use_tuned: bool = True) -> Path | None:
    """Запустить обучение с лучшими или run24 параметрами."""
    log.info("=" * 60)

    if use_tuned and OPTUNA_BEST.exists():
        log.info("ШАГ 2: Обучение с оптимальными параметрами Optuna (1500 эпох)")
        log.info("=" * 60)

        # Генерируем tuned скрипт через tune_optuna.py --best
        log.info("Генерация train_gate5_tuned.py...")
        ret = run(
            [str(PYTHON), str(TOOLS / "tune_optuna.py"), "--best"],
            log_path=OUT / "optuna_best_gen.log",
            timeout=120,
        )
        if ret != 0 or not TRAIN_TUNED_PY.exists():
            log.warning("Генерация tuned скрипта не удалась, используем run24")
            use_tuned = False

    if not use_tuned:
        log.info("ШАГ 2: Обучение с параметрами Run 24 (1500 эпох)")
        log.info("=" * 60)
        train_script = TRAIN_RUN24_PY
        ckpt = CKPT_RUN24
        log_path = OUT / "train_run24.log"
    else:
        train_script = TRAIN_TUNED_PY
        ckpt = CKPT_TUNED
        log_path = OUT / "train_tuned.log"

    if not train_script.exists():
        log.error("Скрипт обучения не найден: %s", train_script)
        return None

    ret = run(
        [str(PYTHON), str(train_script)],
        log_path=log_path,
        timeout=14400,  # 4 часа
    )

    if ret != 0:
        log.warning("Обучение завершилось с кодом %d (возможно early stop)", ret)

    # Проверяем наличие чекпоинта
    if ckpt.exists():
        log.info("Чекпоинт сохранён: %s (%.1f MB)", ckpt.name, ckpt.stat().st_size / 1e6)
        return ckpt

    # Fallback: ищем любой свежий .pt
    pts = sorted(OUT.glob("*.pt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if pts:
        log.info("Используем последний чекпоинт: %s", pts[0].name)
        return pts[0]

    log.error("Чекпоинт не найден после обучения!")
    return None


def step_eval_gate5(ckpt: Path, log_path: Path | None = None) -> dict:
    """Оценить Gate 5 — сначала из лога, потом прямой eval."""
    log.info("=" * 60)
    log.info("ШАГ 3: Оценка Gate 5 (fp0_min >= %.2f на captures %s)", GATE5_TARGET, FP0_CAPTURES)
    log.info("=" * 60)

    # Быстро: вытащить из лога обучения
    if log_path:
        result = eval_from_log(log_path)
        if result and "fp0_min" in result:
            log.info("Gate 5 из лога: fp0_53=%.4f fp0_54=%.4f fp0_min=%.4f",
                     result.get("fp0_53", 0), result.get("fp0_54", 0), result["fp0_min"])
            return result

    # Полный eval
    result = eval_gate5(ckpt)
    if result is None:
        result = {"fp0_min": 0.0, "error": "eval failed"}

    log.info("Gate 5 результат: %s", result)
    return result


def announce_result(result: dict, status: dict):
    """Финальное объявление результата."""
    fp0_min = result.get("fp0_min", 0.0)
    passed = fp0_min >= GATE5_TARGET

    log.info("")
    log.info("╔══════════════════════════════════════════════════╗")
    if passed:
        log.info("║  НЕЙРОСЕТЬ ГОТОВА! Gate 5 ПРОЙДЕН!              ║")
        log.info("║                                                  ║")
        log.info("║  fp0_min = %.4f >= %.2f (цель)                ║", fp0_min, GATE5_TARGET)
        log.info("╚══════════════════════════════════════════════════╝")
        status["gate5_passed"] = True
        status["gate5_passed_at"] = ts()
        status["best_fp0_min"] = fp0_min
    else:
        log.info("║  Gate 5 НЕ ПРОЙДЕН                               ║")
        log.info("║  fp0_min = %.4f < %.2f (цель)                 ║", fp0_min, GATE5_TARGET)
        log.info("╚══════════════════════════════════════════════════╝")
        if fp0_min > status.get("best_fp0_min", 0.0):
            status["best_fp0_min"] = fp0_min

    save_status(status)
    return passed


def show_status():
    """Показать статус всех прогонов."""
    status = load_status()
    print("\n=== СТАТУС AUTORUN ===")
    print(f"Gate 5 пройден: {'ДА' if status.get('gate5_passed') else 'НЕТ'}")
    print(f"Лучший fp0_min: {status.get('best_fp0_min', 0.0):.4f}")
    if status.get("gate5_passed_at"):
        print(f"Пройден в:      {status['gate5_passed_at']}")

    print(f"\nОчередь прогонов ({len(status.get('runs', []))} запусков):")
    for r in status.get("runs", [])[-10:]:
        fp = r.get("fp0_min", "?")
        fp_str = f"{fp:.4f}" if isinstance(fp, float) else str(fp)
        passed_mark = " ГОТОВА!" if isinstance(fp, float) and fp >= GATE5_TARGET else ""
        print(f"  {r['time']}  {r['name']}  fp0_min={fp_str}{passed_mark}")

    # Проверить наличие текущих файлов
    print("\nФайлы:")
    for path, label in [
        (CKPT_RUN24, "Чекпоинт run24"),
        (CKPT_TUNED, "Чекпоинт tuned"),
        (OPTUNA_BEST, "Optuna best params"),
        (OPTUNA_DB, "Optuna study DB"),
        (OUT / "train_run24.log", "Лог run24"),
        (OUT / "train_tuned.log", "Лог tuned"),
    ]:
        exists = "OK" if path.exists() else "--"
        size = f" ({path.stat().st_size / 1e6:.1f} MB)" if path.exists() else ""
        print(f"  [{exists}] {label}: {path.name}{size}")

    # Показать последние строки из лога обучения
    for log_p, name in [(OUT / "train_tuned.log", "tuned"), (OUT / "train_run24.log", "run24")]:
        if log_p.exists():
            lines = log_p.read_text(encoding="utf-8", errors="ignore").splitlines()
            tail = [l for l in lines[-30:] if "fp0" in l.lower() or "epoch" in l.lower() or "gate" in l.lower()]
            if tail:
                print(f"\nПоследние строки из {name}:")
                for l in tail[-5:]:
                    print(f"  {l}")
            break


# ─── Шаг 4: Внедрение модели ──────────────────────────────────────────────────

CKPT_CANDIDATE = OUT / "ctu13-v10-gate5-candidate.pt"


def step_deploy(ckpt: Path):
    """Копирует обученный чекпоинт в live-путь приложения."""
    import shutil
    log.info("=" * 60)
    log.info("ШАГ 4: Внедрение нейросети в приложение")
    log.info("  Источник: %s", ckpt.name)
    log.info("  Цель:     %s", CKPT_CANDIDATE.name)
    log.info("=" * 60)
    if not ckpt.exists():
        log.error("Чекпоинт не найден: %s", ckpt)
        return None
    try:
        shutil.copy2(str(ckpt), str(CKPT_CANDIDATE))
        size_mb = CKPT_CANDIDATE.stat().st_size / 1e6
        log.info("✓ Нейросеть внедрена: %s (%.1f MB)", CKPT_CANDIDATE.name, size_mb)
        return CKPT_CANDIDATE
    except Exception as e:
        log.error("Ошибка при копировании: %s", e)
        return None


# ─── Шаг 5: Тест на атаках ────────────────────────────────────────────────────

def step_attack_test(deployed_ckpt: Path) -> dict:
    """Запускает тест нейросети на реальных атаках из CTU-13 captures 53 и 54."""
    log.info("=" * 60)
    log.info("ШАГ 5: Тест нейросети на атаках (CTU-13 captures 53 и 54)")
    log.info("=" * 60)

    result_path = OUT / "_attack_test_result.json"
    test_script = OUT / "_attack_test_tmp.py"

    code = r"""
import sys, json, os
os.environ['PYTHONUTF8'] = '1'
sys.path.insert(0, r'""" + str(ROOT) + r"""')
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
import csv

CKPT = Path(r'""" + str(deployed_ckpt) + r"""')
DATA_DIR = Path(r'""" + str(OUT) + r"""') / 'official-ctu13'
RESULT_PATH = Path(r'""" + str(result_path) + r"""')
CAPTURES = {
    "53": "capture20110819_ctu53.binetflow",
    "54": "capture20110815-3_ctu54.binetflow",
}

def wilson_upper(k, n, alpha=0.001):
    if n == 0:
        return 0.0
    try:
        from scipy.stats import beta as beta_dist
        return float(beta_dist.ppf(1 - alpha, k + 1, n - k) if k < n else 1.0)
    except Exception:
        # fallback: normal approximation
        import math
        if n == 0:
            return 0.0
        p = k / n
        z = 3.09  # z for alpha=0.001 two-tailed
        denom = 1 + z * z / n
        center = (p + z * z / (2 * n)) / denom
        margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
        return min(1.0, center + margin)

class MLP(nn.Module):
    def __init__(self, n_in, hidden=(512, 256, 128, 64), dropout=0.1):
        super().__init__()
        if isinstance(hidden, int):
            hidden = (hidden, hidden//2, hidden//4, hidden//8)
        dims = [n_in] + list(hidden)
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

try:
    from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row
    state = torch.load(CKPT, map_location='cpu', weights_only=False)
    hparams = state.get('hparams', {})
    hidden = hparams.get('hidden', 512)
    dropout = hparams.get('dropout', 0.15)
    q25 = np.array(state.get('q25', [0.0] * len(FEATURE_NAMES)), dtype=np.float32)
    iqr = np.array(state.get('iqr', [1.0] * len(FEATURE_NAMES)), dtype=np.float32)
    iqr = np.where(iqr < 1e-6, 1.0, iqr)
    model = MLP(len(FEATURE_NAMES), hidden, dropout)
    sd = state.get('state_dict', state.get('model', {}))
    model.load_state_dict(sd)
    model.eval()
except Exception as e:
    json.dump({"error": str(e)}, open(RESULT_PATH, 'w', encoding='utf-8'), ensure_ascii=False)
    sys.exit(1)

results = {}
for cap_id, fname in CAPTURES.items():
    cap_path = DATA_DIR / fname
    if not cap_path.exists():
        results[cap_id] = {"error": f"file not found: {fname}"}
        continue
    xs, ys, is_udp = [], [], []
    with open(cap_path, newline='', encoding='utf-8', errors='ignore') as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            lbl = row.get('Label', '')
            target = 1 if lbl.startswith('flow=From-Botnet-') else 0
            try:
                fv = from_ctu_row(row)
                xs.append(fv)
                ys.append(target)
                proto = str(row.get('Proto', '')).lower()
                is_udp.append(proto == 'udp')
            except Exception:
                pass
    if not xs:
        results[cap_id] = {"error": "no rows parsed"}
        continue
    X = (np.array(xs, dtype=np.float32) - q25) / iqr
    y = np.array(ys, dtype=np.int32)
    udp = np.array(is_udp, dtype=bool)
    with torch.no_grad():
        logits = model(torch.from_numpy(X))
        scores = torch.softmax(logits, dim=1)[:, 1].numpy()
    thr = 0.5
    preds = (scores >= thr).astype(int)
    atk = y == 1
    ben = y == 0
    ben_udp = ben & udp
    tp = int((preds[atk] == 1).sum())
    fp = int((preds[ben] == 1).sum())
    fp_udp = int((preds[ben_udp] == 1).sum())
    n_atk = int(atk.sum())
    n_ben = int(ben.sum())
    n_ben_udp = int(ben_udp.sum())
    recall = tp / max(n_atk, 1)
    precision = tp / max(tp + fp, 1)
    wu = wilson_upper(fp_udp, n_ben_udp)
    best_fp0 = 0.0
    for t in np.linspace(0.01, 0.99, 200):
        fp_u = int((scores[ben_udp] >= t).sum())
        tp_t = int((scores[atk] >= t).sum())
        r = tp_t / max(n_atk, 1)
        w = wilson_upper(fp_u, n_ben_udp)
        if w <= 0.001 and r >= 0.80:
            best_fp0 = max(best_fp0, t)
    results[cap_id] = {
        "total_flows": len(xs), "attack_flows": n_atk, "benign_flows": n_ben,
        "benign_udp": n_ben_udp, "tp": tp, "fp": fp, "fp_udp": fp_udp,
        "recall": round(recall, 4), "precision": round(precision, 4),
        "fp_rate_udp_wilson_upper": round(wu, 6), "fp0_score": round(best_fp0, 4),
        "threshold": thr,
    }
    print(f"Capture {cap_id}: recall={recall:.3f} precision={precision:.3f} "
          f"fp0={best_fp0:.4f} n_atk={n_atk} fp_udp={fp_udp}/{n_ben_udp}")

fp0_min = min(
    (r.get('fp0_score', 0.0) for r in results.values() if 'fp0_score' in r),
    default=0.0,
)
out = {"captures": results, "fp0_min": round(fp0_min, 4)}
json.dump(out, open(RESULT_PATH, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
print(json.dumps(out, indent=2, ensure_ascii=False))
"""

    test_script.write_text(code, encoding="utf-8")
    ret = run([str(PYTHON), "-I", str(test_script)],
              log_path=OUT / "attack_test.log", timeout=600)
    test_script.unlink(missing_ok=True)

    if result_path.exists():
        try:
            res = json.loads(result_path.read_text(encoding="utf-8"))
            result_path.unlink(missing_ok=True)
            fp0_min = res.get("fp0_min", 0.0)
            log.info("Тест на атаках завершён: fp0_min=%.4f", fp0_min)
            for cap_id, cr in res.get("captures", {}).items():
                if "error" not in cr:
                    log.info(
                        "  Capture %s: recall=%.3f fp0=%.4f атак=%d fp_udp=%d/%d",
                        cap_id, cr.get("recall", 0), cr.get("fp0_score", 0),
                        cr.get("attack_flows", 0), cr.get("fp_udp", 0),
                        cr.get("benign_udp", 0),
                    )
            return res
        except Exception as e:
            log.error("Ошибка чтения результата теста: %s", e)

    return {"fp0_min": 0.0, "error": "attack test failed", "ret": ret}


# ─── Главный цикл ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IntegrityGuard Gate 5 — автоматизация обучения")
    parser.add_argument("--skip-tune", action="store_true", help="Пропустить Optuna, сразу обучение")
    parser.add_argument("--train-only", action="store_true", help="Только обучение (нужен optuna_best.json или run24)")
    parser.add_argument("--eval-only", action="store_true", help="Только оценка Gate 5")
    parser.add_argument("--status", action="store_true", help="Показать статус прогонов")
    parser.add_argument("--trials", type=int, default=100, help="Число trials для Optuna (default: 100)")
    parser.add_argument("--tune-epochs", type=int, default=300, help="Эпох на trial Optuna (default: 300)")
    parser.add_argument("--ckpt", type=str, default=None, help="Путь к чекпоинту для --eval-only")
    args = parser.parse_args()

    if args.status:
        show_status()
        return 0

    status = load_status()
    log.info("IntegrityGuard Gate 5 — Автоматизация обучения")
    log.info("Старт: %s", ts())
    log.info("Цель: fp0_min >= %.2f на captures %s", GATE5_TARGET, FP0_CAPTURES)

    # ── eval-only ──
    if args.eval_only:
        ckpt = Path(args.ckpt) if args.ckpt else (CKPT_TUNED if CKPT_TUNED.exists() else CKPT_RUN24)
        result = step_eval_gate5(ckpt, log_path=OUT / "train_run24.log")
        add_run(status, "eval-only", result)
        announce_result(result, status)
        return 0

    # ── train-only ──
    if args.train_only:
        use_tuned = OPTUNA_BEST.exists()
        ckpt = step_train(use_tuned=use_tuned)
        if ckpt is None:
            log.error("Обучение провалилось")
            return 1
        log_path = OUT / ("train_tuned.log" if use_tuned else "train_run24.log")
        result = step_eval_gate5(ckpt, log_path=log_path)
        add_run(status, "train-only", result)
        announce_result(result, status)
        return 0

    # ── Полный цикл ──

    # Шаг 1: Optuna (если не пропускаем)
    if not args.skip_tune:
        ok = step_optuna(trials=args.trials, epochs=args.tune_epochs)
        add_run(status, f"optuna-{args.trials}trials", {"optuna_ok": ok})
        if not ok:
            log.warning("Optuna завершился с ошибкой, продолжаем с run24 params")

    # Шаг 2: Обучение
    use_tuned = OPTUNA_BEST.exists() and not args.skip_tune
    ckpt = step_train(use_tuned=use_tuned)
    if ckpt is None:
        log.error("Обучение провалилось, останавливаемся")
        return 1

    # Шаг 3: Оценка Gate 5
    log_path = OUT / ("train_tuned.log" if use_tuned else "train_run24.log")
    result = step_eval_gate5(ckpt, log_path=log_path)
    add_run(status, "full-run", result)
    passed = announce_result(result, status)

    if passed:
        # -- Шаг 4: Внедрение модели --
        deployed = step_deploy(ckpt)
        if deployed:
            # -- Шаг 5: Тест на атаках --
            attack_result = step_attack_test(deployed)
            add_run(status, "attack-test", attack_result)
            log.info("")
            log.info("*" * 60)
            log.info("НЕЙРОСЕТЬ ВНЕДРЕНА И ПРОТЕСТИРОВАНА НА АТАКАХ!")
            log.info("Запускайте IntegrityGuard для просмотра прогресса нейросети.")
            log.info("*" * 60)
        else:
            log.error("Внедрение не удалось -- модель не скопирована в candidate.pt")
    else:
        fp0_min = result.get("fp0_min", 0.0)
        gap = GATE5_TARGET - fp0_min
        log.info("")
        log.info("До цели не хватает: %.4f", gap)
        log.info("Рекомендации:")
        if fp0_min < 0.60:
            log.info("  -> Увеличить UDP_ATK_WEIGHT и RBOT_BOOST")
            log.info("  -> Запустить ещё Optuna: python tools/autorun.py --trials 200")
        elif fp0_min < 0.75:
            log.info("  -> Увеличить LAMBDA_GROW_FACTOR или уменьшить TAIL_THRESH")
            log.info("  -> Попробовать: python tools/autorun.py --train-only")
        else:
            log.info("  -> Близко к цели, попробовать ещё одно полное обучение")
            log.info("  -> python tools/autorun.py --train-only")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

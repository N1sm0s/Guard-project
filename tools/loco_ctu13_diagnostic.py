"""Leave-one-capture-out (LOCO) transfer diagnostic on CTU-13 publisher labels.

Development diagnostic only. For each held-out CTU-13 capture H, a model is
trained on every other listed capture (plus benign-only CTU-Normal-12). The
decision threshold is taken from the TRAINING data alone (99.75th percentile
of training benign scores, i.e. about 0.25% training FPR), so H is never used
for selection. Reported per held-out capture: ROC AUC (threshold-free),
recall at the training-derived threshold, observed FPR with its 95% Wilson
bounds. No independent-test or target source is loaded.

Usage:
  python tools/loco_ctu13_diagnostic.py --out <dir> --registration <json> [--epochs 20]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
import train_v9 as tv  # noqa: E402

HELD_OUT = ["42", "43", "44", "46", "47", "48", "49", "50", "51", "52", "53", "54"]
ALWAYS_TRAIN = ["normal12"]
# Profile no_endpoint_port_v10: drop UDP heuristic flags 11, 13-16 and endpoint
# port magnitudes 18-19 (feature-audit artifacts). Keeps 40 - 7 = 33 features.
KEEP = [i for i in range(40) if i not in {11, 13, 14, 15, 16, 18, 19}]
SEED = 1907
Z = 1.959963984540054


def wilson(k: int, n: int):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    s = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return max(c - s, 0.0), min(c + s, 1.0)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_model(x: np.ndarray, y: np.ndarray, epochs: int, device: str) -> tuple[nn.Module, np.ndarray, np.ndarray]:
    median = np.median(x, axis=0)
    q25, q75 = np.percentile(x, [25, 75], axis=0)
    scale = np.maximum(q75 - q25, 1e-6)
    xs = np.clip((x - median) / scale, -10.0, 10.0).astype(np.float32)
    torch.manual_seed(SEED)
    model = tv.MLP(xs.shape[1], hidden_width=64).to(device)
    counts = np.bincount(y, minlength=2).astype(np.float64)
    weights = torch.tensor(len(y) / (2.0 * np.maximum(counts, 1.0)), dtype=torch.float32, device=device)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-4)
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    rng = np.random.default_rng(SEED)
    xt = torch.from_numpy(xs).to(device)
    yt = torch.from_numpy(y).long().to(device)
    for _ in range(epochs):
        model.train()
        order = torch.from_numpy(rng.permutation(len(xs))).to(device)
        for start in range(0, len(order), 2048):
            batch = order[start:start + 2048]
            optimiser.zero_grad()
            loss_fn(model(xt[batch]), yt[batch]).backward()
            optimiser.step()
    return model, median, scale


def score(model: nn.Module, median, scale, x: np.ndarray, device: str) -> np.ndarray:
    xs = np.clip((x - median) / scale, -10.0, 10.0).astype(np.float32)
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(xs).to(device))
        return torch.softmax(logits, dim=1)[:, 1].cpu().numpy()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args(argv)
    torch.set_num_threads(args.threads)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    reg = json.loads(args.registration.read_text(encoding="utf-8"))
    if reg.get("status") != "preregistered_development_only":
        raise SystemExit("registration is not in the pre-registered state")
    if sha256_file(Path(__file__)) != reg["diagnostic_sha256"]:
        raise SystemExit("this script differs from the pre-registered version")

    tv.configure_feature_schema(10)
    caps = {**tv.TRAIN_CAPTURES, **tv.CTU_ADDITIONAL_TRAIN_CAPTURES}
    data = {}
    for cid in HELD_OUT + ALWAYS_TRAIN:
        x, y, _udp, excluded = tv.load_capture(cid, caps[cid])
        data[cid] = (x[:, KEEP], y)
        print(f"loaded {cid}: attack={int(y.sum())} benign={int((y == 0).sum())} excluded={excluded}", flush=True)

    rows = []
    device_note = device
    for held in HELD_OUT:
        started = time.time()
        train_ids = [c for c in HELD_OUT + ALWAYS_TRAIN if c != held]
        x_tr = np.concatenate([data[c][0] for c in train_ids])
        y_tr = np.concatenate([data[c][1] for c in train_ids])
        model, median, scale = train_model(x_tr, y_tr, args.epochs, device)
        s_tr_ben = score(model, median, scale, x_tr[y_tr == 0], device)
        threshold = float(np.quantile(s_tr_ben, 1 - 0.0025))
        x_h, y_h = data[held]
        s_h = score(model, median, scale, x_h, device)
        n_att, n_ben = int((y_h == 1).sum()), int((y_h == 0).sum())
        tp = int(((s_h >= threshold) & (y_h == 1)).sum())
        fp = int(((s_h >= threshold) & (y_h == 0)).sum())
        rec = tp / max(n_att, 1)
        fpr = fp / max(n_ben, 1)
        auc = float(roc_auc_score(y_h, s_h)) if 0 < n_att and 0 < n_ben else None
        row = {"held_out": held, "train_captures": train_ids,
               "train_attack": int(y_tr.sum()), "train_benign": int((y_tr == 0).sum()),
               "threshold_from_train": threshold, "auc": auc,
               "attack": n_att, "benign": n_ben, "tp": tp, "fp": fp,
               "recall": rec, "recall_ci95": list(wilson(tp, n_att)),
               "fpr": fpr, "fpr_ci95_upper": wilson(fp, n_ben)[1],
               "seconds": round(time.time() - started, 1)}
        rows.append(row)
        print(f"held {held}: AUC={auc if auc is None else round(auc, 4)} recall={rec:.4f} "
              f"fpr={fpr:.5f} thr={threshold:.4f} ({row['seconds']}s)", flush=True)

    recalls = [r["recall"] for r in rows]
    aucs = [r["auc"] for r in rows if r["auc"] is not None]
    summary = {"folds": len(rows), "recall_median": float(np.median(recalls)),
               "recall_min": float(min(recalls)), "recall_max": float(max(recalls)),
               "auc_median": float(np.median(aucs)) if aucs else None,
               "auc_min": float(min(aucs)) if aucs else None,
               "folds_recall_ci_lower_ge_0_80": sum(1 for r in rows if r["recall_ci95"][0] >= 0.80),
               "folds_fpr_ci_upper_le_0_0025": sum(1 for r in rows if r["fpr_ci95_upper"] <= 0.0025)}
    report = {"kind": "loco_ctu13_transfer_diagnostic", "research_only": True,
              "promotion_eligible": False, "enforcement_applied": False,
              "registration_sha256": sha256_file(args.registration),
              "script_sha256": sha256_file(Path(__file__)),
              "feature_profile": "no_endpoint_port_v10", "kept_indices": KEEP,
              "epochs": args.epochs, "device": device_note, "seed": SEED,
              "threshold_rule": "99.75th percentile of training benign scores (train-only)",
              "independent_test_loaded": False, "target_loaded": False,
              "summary": summary, "folds": rows}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "loco_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("summary", json.dumps(summary, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

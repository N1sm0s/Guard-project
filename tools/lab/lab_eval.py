"""Pre-registered diagnostic on the own lab shards (research-only, no promotion).

Train: attack shard sess-udp-03 + all benign shards except sess-benign-08.
Test:  attack shards seg-68b743878383 and seg-96dc621453ef (udp-02 window from app capture),
       benign shard sess-benign-08. Test shards are never used for training or threshold choice.
Threshold: 99.75th percentile of training benign scores (train-only).
Model: same MLP and feature profile as tools/loco_ctu13_diagnostic.py.

Usage: python tools/lab/lab_eval.py --registration <json> --out <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
import loco_ctu13_diagnostic as loco  # noqa: E402  (same MLP training and scoring)

SHARDS = ROOT / "outputs" / "lab" / "shards"
TRAIN_ATTACK = ["sess-udp-03"]
TEST_ATTACK = ["seg-68b743878383", "seg-96dc621453ef"]
TEST_BENIGN = ["sess-benign-08"]
MIN_BENIGN_FOR_RELEASE = 3838


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(source_id: str):
    manifest = json.loads((SHARDS / f"{source_id}.manifest.json").read_text(encoding="utf-8"))
    with np.load(SHARDS / f"{source_id}.npz") as data:
        x, y = data["x"], data["y"].astype(np.int64)
    return x[:, loco.KEEP], y, manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    reg = json.loads(args.registration.read_text(encoding="utf-8"))
    if reg.get("status") != "preregistered_development_only":
        raise SystemExit("registration is not pre-registered")
    if sha256_file(Path(__file__)) != reg["script_sha256"]:
        raise SystemExit("script differs from the registered version")

    train_benign = [s for s in sorted(p.stem.replace(".manifest", "") for p in SHARDS.glob("*.manifest.json"))
                    if s not in TEST_BENIGN and s not in TEST_ATTACK and s not in TRAIN_ATTACK]
    parts_x, parts_y, used = [], [], {"train": {}, "test": {}}
    for sid in TRAIN_ATTACK + train_benign:
        x, y, m = load(sid)
        if len(y) == 0:
            continue
        parts_x.append(x); parts_y.append(y)
        used["train"][sid] = {"attack": int((y == 1).sum()), "benign": int((y == 0).sum()),
                              "sha256": sha256_file(SHARDS / f"{sid}.npz")}
    x_tr = np.concatenate(parts_x); y_tr = np.concatenate(parts_y)
    train_benign_n = int((y_tr == 0).sum())

    torch_started = time.time()
    model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
    s_tr_ben = loco.score(model, median, scale, x_tr[y_tr == 0], "cpu")
    threshold = float(np.quantile(s_tr_ben, 1 - 0.0025))

    test_x, test_y = [], []
    for sid in TEST_ATTACK + TEST_BENIGN:
        x, y, m = load(sid)
        test_x.append(x); test_y.append(y)
        used["test"][sid] = {"attack": int((y == 1).sum()), "benign": int((y == 0).sum()),
                             "sha256": sha256_file(SHARDS / f"{sid}.npz")}
    x_te = np.concatenate(test_x); y_te = np.concatenate(test_y)
    s_te = loco.score(model, median, scale, x_te, "cpu")
    n_att, n_ben = int((y_te == 1).sum()), int((y_te == 0).sum())
    tp = int(((s_te >= threshold) & (y_te == 1)).sum())
    fp = int(((s_te >= threshold) & (y_te == 0)).sum())
    auc = float(roc_auc_score(y_te, s_te))
    result = {"kind": "lab_eval_diagnostic", "research_only": True, "promotion_eligible": False,
              "registration_sha256": sha256_file(args.registration), "script_sha256": sha256_file(Path(__file__)),
              "train": used["train"], "test": used["test"], "train_benign": train_benign_n,
              "threshold_from_train_benign": threshold, "auc": auc,
              "test_attack": n_att, "test_benign": n_ben, "tp": tp, "fp": fp,
              "recall": tp / max(n_att, 1), "recall_ci95": list(loco.wilson(tp, n_att)),
              "fpr": fp / max(n_ben, 1), "fpr_ci95_upper": loco.wilson(fp, n_ben)[1],
              "benign_sample_gate_met": train_benign_n >= MIN_BENIGN_FOR_RELEASE and n_ben >= MIN_BENIGN_FOR_RELEASE,
              "seconds": round(time.time() - torch_started, 1)}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "lab_eval_report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("auc", "recall", "recall_ci95", "fpr", "fpr_ci95_upper",
                                             "test_attack", "test_benign", "train_benign",
                                             "benign_sample_gate_met")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

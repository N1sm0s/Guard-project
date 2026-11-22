"""LOCO comparison: benign-only anomaly detector vs. the supervised classifier protocol.

Development diagnostic. For each held-out CTU-13 capture H:
  * the anomaly model (IsolationForest) is fit on BENIGN flows only from the
    other captures plus CTU-Normal-12 (no attack labels are used for fitting);
  * the threshold is the 99.75th percentile of training benign anomaly scores
    (train-only, about 0.25% training false-alarm rate);
  * recall = share of held-out attacks scored above the threshold, FPR = share
    of held-out benign scored above it, both with Wilson 95% bounds.

Uses the same captures, label policy, feature profile and fold design as
loco_ctu13_diagnostic.py, so results are directly comparable. Research-only.

Usage:
  python tools/loco_benign_anomaly.py --out <dir> --registration <json>
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
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
import train_v9 as tv  # noqa: E402
import loco_ctu13_diagnostic as loco  # noqa: E402  (same folds, features, label policy)

SEED = 1907
Z = 1.959963984540054


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    args = parser.parse_args(argv)

    reg = json.loads(args.registration.read_text(encoding="utf-8"))
    if reg.get("status") != "preregistered_development_only":
        raise SystemExit("registration is not in the pre-registered state")
    if sha256_file(Path(__file__)) != reg["diagnostic_sha256"]:
        raise SystemExit("this script differs from the pre-registered version")

    tv.configure_feature_schema(10)
    caps = {**tv.TRAIN_CAPTURES, **tv.CTU_ADDITIONAL_TRAIN_CAPTURES}
    data = {}
    for cid in loco.HELD_OUT + loco.ALWAYS_TRAIN:
        x, y, _udp, _excluded = tv.load_capture(cid, caps[cid])
        data[cid] = (x[:, loco.KEEP], y)

    rows = []
    for held in loco.HELD_OUT:
        started = time.time()
        train_ids = [c for c in loco.HELD_OUT + loco.ALWAYS_TRAIN if c != held]
        # benign only: labels of training flows are used to select benign rows, never as a target
        x_ben = np.concatenate([data[c][0][data[c][1] == 0] for c in train_ids])
        model = IsolationForest(n_estimators=200, max_samples=min(100_000, len(x_ben)),
                                random_state=SEED, n_jobs=4)
        median = np.median(x_ben, axis=0)
        q25, q75 = np.percentile(x_ben, [25, 75], axis=0)
        scale = np.maximum(q75 - q25, 1e-6)
        scaled = lambda x: np.clip((x - median) / scale, -10.0, 10.0)  # noqa: E731
        model.fit(scaled(x_ben))
        # score = negative anomaly score: higher = more anomalous
        s_tr_ben = -model.score_samples(scaled(x_ben))
        threshold = float(np.quantile(s_tr_ben, 1 - 0.0025))
        x_h, y_h = data[held]
        s_h = -model.score_samples(scaled(x_h))
        n_att, n_ben = int((y_h == 1).sum()), int((y_h == 0).sum())
        tp = int(((s_h >= threshold) & (y_h == 1)).sum())
        fp = int(((s_h >= threshold) & (y_h == 0)).sum())
        auc = float(roc_auc_score(y_h, s_h)) if 0 < n_att and 0 < n_ben else None
        rows.append({"held_out": held, "train_benign": int(len(x_ben)),
                     "threshold_from_train_benign": threshold, "auc": auc,
                     "attack": n_att, "benign": n_ben, "tp": tp, "fp": fp,
                     "recall": tp / max(n_att, 1), "recall_ci95": list(loco.wilson(tp, n_att)),
                     "fpr": fp / max(n_ben, 1), "fpr_ci95_upper": loco.wilson(fp, n_ben)[1],
                     "seconds": round(time.time() - started, 1)})
        print(f"held {held}: AUC={auc} recall={tp / max(n_att, 1):.4f} fpr={fp / max(n_ben, 1):.5f} "
              f"({rows[-1]['seconds']}s)", flush=True)

    recalls = [r["recall"] for r in rows]
    aucs = [r["auc"] for r in rows if r["auc"] is not None]
    summary = {"folds": len(rows), "recall_median": float(np.median(recalls)),
               "recall_min": float(min(recalls)),
               "auc_median": float(np.median(aucs)) if aucs else None,
               "auc_min": float(min(aucs)) if aucs else None,
               "folds_recall_ci_lower_ge_0_80": sum(1 for r in rows if r["recall_ci95"][0] >= 0.80),
               "folds_fpr_ci_upper_le_0_0025": sum(1 for r in rows if r["fpr_ci95_upper"] <= 0.0025)}
    report = {"kind": "loco_benign_anomaly_comparison", "research_only": True,
              "promotion_eligible": False, "enforcement_applied": False,
              "registration_sha256": sha256_file(args.registration),
              "script_sha256": sha256_file(Path(__file__)), "seed": SEED,
              "summary": summary, "folds": rows}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "loco_benign_anomaly_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("summary", json.dumps(summary, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

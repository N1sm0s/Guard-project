"""Compare deterministic sklearn baselines on CTU-13 train 42-44 / validation 45.

This research script deliberately never opens independent-test captures.
Unknown/background labels are excluded via train_v9.load_capture.
"""
from __future__ import annotations
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.train_v9 import (OUT, TRAIN_CAPTURES, VALIDATION_CAPTURE, load_capture,
                            score_curve, sha256_file)

SCHEMES = [
    ("hist_gb_balanced", HistGradientBoostingClassifier(
        learning_rate=0.08, max_iter=150, max_leaf_nodes=31, min_samples_leaf=40,
        l2_regularization=1.0, class_weight="balanced", early_stopping=False,
        random_state=1907)),
    ("hist_gb_positive_1_5", HistGradientBoostingClassifier(
        learning_rate=0.08, max_iter=150, max_leaf_nodes=31, min_samples_leaf=40,
        l2_regularization=1.0, class_weight={0: 1.0, 1: 1.5}, early_stopping=False,
        random_state=1907)),
    ("random_forest_balanced", RandomForestClassifier(
        n_estimators=300, max_features="sqrt", min_samples_leaf=3,
        class_weight="balanced_subsample", n_jobs=-1, random_state=1907)),
]


def main():
    started = time.time()
    train_x, train_y = [], []
    train_hashes = {}
    for cid, path in TRAIN_CAPTURES.items():
        x, y, _udp, _excluded = load_capture(cid, path)
        train_x.append(x); train_y.append(y); train_hashes[cid] = sha256_file(path)
    x_train = np.concatenate(train_x); y_train = np.concatenate(train_y)
    val_x, val_y = [], []
    val_hashes = {}
    for cid, path in VALIDATION_CAPTURE.items():
        x, y, _udp, _excluded = load_capture(cid, path)
        val_x.append(x); val_y.append(y); val_hashes[cid] = sha256_file(path)
    x_val = np.concatenate(val_x); y_val = np.concatenate(val_y)
    # Tree split points use raw feature values; no validation statistics are fitted.
    results = []
    for name, model in SCHEMES:
        t0 = time.time()
        model.fit(x_train, y_train)
        prob = model.predict_proba(x_val)[:, 1]
        thresholds, recall, fpr, fpr_hi, tp, fp = score_curve(prob, y_val)
        eligible = np.flatnonzero(fpr_hi <= 0.001)
        chosen = int(eligible[np.argmax(recall[eligible])]) if len(eligible) else None
        point = None if chosen is None else {
            "threshold": float(thresholds[chosen]), "recall": float(recall[chosen]),
            "fpr": float(fpr[chosen]), "fpr_ci95_upper": float(fpr_hi[chosen]),
            "tp": int(tp[chosen]), "fp": int(fp[chosen]),
            "fn": int((y_val == 1).sum() - tp[chosen]),
            "tn": int((y_val == 0).sum() - fp[chosen]),
        }
        results.append({"model": name, "params": model.get_params(deep=False),
                        "validation_operating_point": point,
                        "seconds": round(time.time() - t0, 2)})
        print(name, point, flush=True)
    out = OUT / "model_family_comparison.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_captures": list(TRAIN_CAPTURES), "validation_captures": list(VALIDATION_CAPTURE),
        "independent_test": "not loaded or evaluated",
        "label_policy": "only explicit From-Botnet and From-Normal; background/unknown excluded",
        "sha256": {"train": train_hashes, "validation": val_hashes},
        "results": results,
        "warning": "Validation model selection only; results are not independent-test evidence or deployment approval.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out}; total seconds={time.time()-started:.1f}")


if __name__ == "__main__":
    main()

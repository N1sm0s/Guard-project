"""Pre-registered leave-one-attack-family-out with a separate calibration background (v3).

Per held-out attack family F:
  * train: other attack families + all lab background except the calibration and test backgrounds;
  * threshold: 99.75th percentile of scores on the CALIBRATION background (benign-10), which is not in training;
  * test: family F (recall) and the TEST background benign-08 (FPR).
Feature set chosen by --features: "full" (KEEP profile) or "nonvolume" (drops size and duration magnitudes).
Model: same MLP as tools/loco_ctu13_diagnostic.py.

Usage: python tools/lab/lab_calibrated.py --features full|nonvolume --registration <json> --out <dir>
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
import loco_ctu13_diagnostic as loco  # noqa: E402

SHARDS = ROOT / "outputs" / "lab" / "shards"
FAMILIES = {
    "flood": ["sess-udp-03", "seg-68b743878383", "seg-96dc621453ef", "real-flood-02", "real-flood-03"],
    "scan": ["real-scan-01", "real-scan-02", "real-scan-03", "real-scan-04"],
    "ssh": ["real-ssh-01", "real-ssh-02"],
}
TEST_BENIGN = "sess-benign-08"
CALIBRATION_BENIGN = "real-benign-10"
NONVOLUME_DROP = {0, 1, 2, 3, 8, 9, 12}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(source_id: str, keep: list[int]):
    with np.load(SHARDS / f"{source_id}.npz") as data:
        x, y = data["x"], data["y"].astype(np.int64)
    return x[:, keep], y


def background_shards() -> list[str]:
    names = []
    for path in sorted(SHARDS.glob("*.manifest.json")):
        sid = path.name[: -len(".manifest.json")]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["counts"]["attack"] == 0 and manifest["counts"]["benign"] > 0 and sid not in (TEST_BENIGN, CALIBRATION_BENIGN):
            names.append(sid)
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", choices=("full", "nonvolume"), required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    reg = json.loads(args.registration.read_text(encoding="utf-8"))
    if reg.get("status") != "preregistered_development_only":
        raise SystemExit("registration is not pre-registered")
    if sha256_file(Path(__file__)) != reg["script_sha256"]:
        raise SystemExit("script differs from the registered version")

    keep = loco.KEEP if args.features == "full" else [i for i in loco.KEEP if i not in NONVOLUME_DROP]
    bg = background_shards()
    x_test_bg, _ = load(TEST_BENIGN, keep)
    x_cal, y_cal = load(CALIBRATION_BENIGN, keep)
    assert (y_cal == 0).all(), "calibration shard must be benign only"
    results = []
    for held, held_ids in FAMILIES.items():
        train_attack = [s for fam, ids in FAMILIES.items() if fam != held for s in ids]
        xs, ys = [], []
        for sid in train_attack + bg:
            x, y = load(sid, keep)
            xs.append(x); ys.append(y)
        x_tr = np.concatenate(xs); y_tr = np.concatenate(ys)
        started = time.time()
        model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
        s_cal = loco.score(model, median, scale, x_cal, "cpu")
        threshold = float(np.quantile(s_cal, 1 - 0.0025))
        xh = np.concatenate([load(s, keep)[0] for s in held_ids])
        yh = np.concatenate([load(s, keep)[1] for s in held_ids])
        sh = loco.score(model, median, scale, xh, "cpu")
        s_test_bg = loco.score(model, median, scale, x_test_bg, "cpu")
        tp = int((sh >= threshold).sum())
        fp = int((s_test_bg >= threshold).sum())
        n_att, n_ben = len(sh), len(s_test_bg)
        auc = float(roc_auc_score(np.concatenate([np.ones(n_att), np.zeros(n_ben)]),
                                  np.concatenate([sh, s_test_bg])))
        results.append({"held_out_family": held, "held_out_shards": held_ids,
                        "train_attack": int((y_tr == 1).sum()), "train_background": int((y_tr == 0).sum()),
                        "threshold_from_calibration": threshold, "auc": auc,
                        "test_attack": n_att, "test_background": n_ben, "tp": tp, "fp": fp,
                        "recall": tp / max(n_att, 1), "recall_ci95": list(loco.wilson(tp, n_att)),
                        "fpr": fp / max(n_ben, 1), "fpr_ci95_upper": loco.wilson(fp, n_ben)[1],
                        "seconds": round(time.time() - started, 1)})
        print(f"[{args.features}] held {held}: AUC={auc:.4f} recall={tp / max(n_att, 1):.4f} fpr={fp / max(n_ben, 1):.4f}", flush=True)
    report = {"kind": "lab_calibrated_crossfamily", "features": args.features, "research_only": True,
              "promotion_eligible": False, "registration_sha256": sha256_file(args.registration),
              "script_sha256": sha256_file(Path(__file__)), "calibration_background": CALIBRATION_BENIGN,
              "test_background": TEST_BENIGN, "train_background": bg, "folds": results}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"lab_calibrated_{args.features}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

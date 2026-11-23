"""Pre-registered leave-one-attack-family-out on lab schema v12 with SSH benign background (v12-benign-14b) shards (research-only).

Shards: outputs/lab/shards_v12/v12-<scenario>.npz (53 features: v11 + same-service repetition).
Training background includes benign-13 (two-way UDP). Calibration (benign-10, benign-11) sets the threshold.
Check background (benign-08, benign-12) is scored after the threshold is fixed. The check FPR is reported
overall and split into two strata that are fixed by the feature direction_asym (one-way: > 0.99; the rest),
so the one-way shape of our own UDP noise is visible and not hidden inside the total.

Usage: python tools/lab/lab_v13_crossfamily.py --features full|nonvolume --registration <json> --out <dir>
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
from integrityguard import network_flow_schema_v12 as v12  # noqa: E402

SHARDS = ROOT / "outputs" / "lab" / "shards_v12"
FAMILIES = {
    "flood": ["v12-udp-03", "v12-flood-02", "v12-flood-03"],
    "scan": ["v12-scan-01", "v12-scan-02", "v12-scan-03", "v12-scan-04"],
    "ssh": ["v12-ssh-01", "v12-ssh-02"],
}
TRAIN_BACKGROUND = ["v12-benign-06", "v12-benign-07", "v12-benign-09", "v12-benign-13", "v12-benign-14b"]
CALIBRATION = ["v12-benign-10", "v12-benign-11"]
CHECK = ["v12-benign-08", "v12-benign-12"]
VOLUME_DROP = {0, 1, 2, 3, 8, 9, 12}
DIRECTION = list(v12.FEATURE_NAMES).index("direction_asym")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(sid: str, keep: list[int]):
    with np.load(SHARDS / f"{sid}.npz") as data:
        return data["x"][:, keep], data["y"].astype(np.int64)


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
    all_idx = list(range(len(v12.FEATURE_NAMES)))
    keep = all_idx if args.features == "full" else [i for i in all_idx if i not in VOLUME_DROP]

    x_cal = np.concatenate([load(s, keep)[0] for s in CALIBRATION])
    chk = [load(s, keep) for s in CHECK]
    x_chk = np.concatenate([c[0] for c in chk])
    # direction_asym is kept in both variants; its position inside the kept vector:
    dir_pos = keep.index(DIRECTION)
    one_way_mask = x_chk[:, dir_pos] > 0.99
    results = []
    for held, held_ids in FAMILIES.items():
        train_attack = [s for fam, ids in FAMILIES.items() if fam != held for s in ids]
        xs, ys = [], []
        for sid in train_attack + TRAIN_BACKGROUND:
            x, y = load(sid, keep)
            xs.append(x); ys.append(y)
        x_tr = np.concatenate(xs); y_tr = np.concatenate(ys)
        started = time.time()
        model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
        threshold = float(np.quantile(loco.score(model, median, scale, x_cal, "cpu"), 1 - 0.0025))
        xh = np.concatenate([load(s, keep)[0] for s in held_ids])
        sh = loco.score(model, median, scale, xh, "cpu")
        s_chk = loco.score(model, median, scale, x_chk, "cpu")
        flagged = s_chk >= threshold
        tp = int((sh >= threshold).sum())
        n_att, n_ben = len(sh), len(s_chk)
        auc = float(roc_auc_score(np.concatenate([np.ones(n_att), np.zeros(n_ben)]),
                                  np.concatenate([sh, s_chk])))
        def stratum(mask):
            n = int(mask.sum())
            fp = int(flagged[mask].sum())
            return {"flows": n, "fp": fp, "fpr": fp / max(n, 1), "fpr_ci95_upper": loco.wilson(fp, n)[1]}
        results.append({"held_out_family": held, "held_out_shards": held_ids,
                        "train_attack": int((y_tr == 1).sum()), "train_background": int((y_tr == 0).sum()),
                        "threshold_from_calibration": threshold, "auc": auc,
                        "test_attack": n_att, "recall": tp / max(n_att, 1), "recall_ci95": list(loco.wilson(tp, n_att)),
                        "check_overall": stratum(np.ones(n_ben, dtype=bool)),
                        "check_one_way_udp": stratum(one_way_mask),
                        "check_other": stratum(~one_way_mask),
                        "seconds": round(time.time() - started, 1)})
        print(f"[{args.features}] held {held}: AUC={auc:.4f} recall={tp / max(n_att, 1):.4f} "
              f"fpr_overall={flagged.mean():.4f} fpr_other={flagged[~one_way_mask].mean():.4f}", flush=True)
    report = {"kind": "lab_v13_crossfamily", "features": args.features, "feature_count": len(keep),
              "research_only": True, "promotion_eligible": False,
              "registration_sha256": sha256_file(args.registration), "script_sha256": sha256_file(Path(__file__)),
              "folds": results}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"lab_v13_crossfamily_{args.features}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

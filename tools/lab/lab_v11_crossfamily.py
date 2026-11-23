"""Pre-registered leave-one-attack-family-out on lab schema v11 shards (research-only).

Shards: outputs/lab/shards_v11/v11-<scenario>.npz (51 features: v10 flow features + 5 host-context features).
Families and roles are fixed in the registration. Calibration background (benign-10, benign-11) sets the
threshold, never training. Check background (benign-08, and benign-12 when present) is scored only after the threshold.
Feature variants: "full" (all 51) or "nonvolume" (drops duration, packets, bytes, rates, pkts*dur; keeps context).

Usage: python tools/lab/lab_v11_crossfamily.py --features full|nonvolume --registration <json> --out <dir>
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
from integrityguard import network_flow_schema_v11 as v11  # noqa: E402

SHARDS = ROOT / "outputs" / "lab" / "shards_v11"
FAMILIES = {
    "flood": ["v11-udp-03", "v11-flood-02", "v11-flood-03"],
    "scan": ["v11-scan-01", "v11-scan-02", "v11-scan-03", "v11-scan-04"],
    "ssh": ["v11-ssh-01", "v11-ssh-02"],
}
TRAIN_BACKGROUND = ["v11-benign-06", "v11-benign-07", "v11-benign-09"]
CALIBRATION = ["v11-benign-10", "v11-benign-11"]
CHECK = ["v11-benign-08"]
VOLUME_DROP = {0, 1, 2, 3, 8, 9, 12}


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
    all_idx = list(range(len(v11.FEATURE_NAMES)))
    keep = all_idx if args.features == "full" else [i for i in all_idx if i not in VOLUME_DROP]

    xc, yc = zip(*[load(s, keep) for s in CALIBRATION])
    x_cal = np.concatenate(xc)
    assert (np.concatenate(yc) == 0).all(), "calibration must be benign only"
    check_sets = [load(s, keep) for s in CHECK]
    x_chk = np.concatenate([c[0] for c in check_sets])
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
        s_cal = loco.score(model, median, scale, x_cal, "cpu")
        threshold = float(np.quantile(s_cal, 1 - 0.0025))
        hx = [load(s, keep) for s in held_ids]
        xh = np.concatenate([h[0] for h in hx])
        sh = loco.score(model, median, scale, xh, "cpu")
        s_chk = loco.score(model, median, scale, x_chk, "cpu")
        tp = int((sh >= threshold).sum()); fp = int((s_chk >= threshold).sum())
        n_att, n_ben = len(sh), len(s_chk)
        auc = float(roc_auc_score(np.concatenate([np.ones(n_att), np.zeros(n_ben)]),
                                  np.concatenate([sh, s_chk])))
        results.append({"held_out_family": held, "held_out_shards": held_ids,
                        "train_attack": int((y_tr == 1).sum()), "train_background": int((y_tr == 0).sum()),
                        "threshold_from_calibration": threshold, "auc": auc,
                        "test_attack": n_att, "check_background": n_ben, "tp": tp, "fp": fp,
                        "recall": tp / max(n_att, 1), "recall_ci95": list(loco.wilson(tp, n_att)),
                        "fpr": fp / max(n_ben, 1), "fpr_ci95_upper": loco.wilson(fp, n_ben)[1],
                        "seconds": round(time.time() - started, 1)})
        print(f"[{args.features}] held {held}: AUC={auc:.4f} recall={tp / max(n_att, 1):.4f} "
              f"fpr={fp / max(n_ben, 1):.4f} thr={threshold:.4f}", flush=True)
    report = {"kind": "lab_v11_crossfamily", "features": args.features, "feature_count": len(keep),
              "research_only": True, "promotion_eligible": False,
              "registration_sha256": sha256_file(args.registration), "script_sha256": sha256_file(Path(__file__)),
              "folds": results}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"lab_v11_crossfamily_{args.features}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Pre-registered leave-one-attack-family-out on lab schema v13 shards, with host negatives in training (research-only, advisory).

Shards: outputs/lab/shards_v13/ (57 features: v12 + four packet-size statistics).
Training background: the lab v13 training background (v13-benign-06/07/09/13/14b) PLUS the host training part (HOST_TRAIN):
the first 70% (rounded down) of the 109 host calibration shards, ordered by the minimum first_seen of each shard.
Threshold (calibration): HOST_THRESHOLD, the remaining 33 host calibration shards, i.e. a later part of the same host
traffic that was not used for training. The cut-off timestamp is recorded in the registration.
Check: 20 host background shards (host-chk-*), captured after 2026-11-24T02:00Z, scored after the threshold is fixed.
Host background is unlabelled normal host traffic (lab subnet excluded), NOT confirmed benign, and it is used here as
training negatives. The check result is therefore an alarm rate on unlabelled host traffic, not a labelled FPR, and is
not comparable to the release gate FPR.
Attack families are the lab v13 shards, as in the template.
The check FPR is reported overall and split into two strata fixed by the feature direction_asym (one-way: > 0.99; the rest).
No blocking; no promotion.

Usage: python tools/lab/lab_host_negatives_crossfamily.py --features full|nonvolume --registration <json> --out <dir>
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
from integrityguard import network_flow_schema_v13 as v13  # noqa: E402

SHARDS = ROOT / "outputs" / "lab" / "shards_v13"
FAMILIES = {
    "flood": ["v13-udp-03", "v13-flood-02", "v13-flood-03"],
    "scan": ["v13-scan-01", "v13-scan-02", "v13-scan-03", "v13-scan-04"],
    "ssh": ["v13-ssh-01", "v13-ssh-02"],
}
LAB_TRAIN_BACKGROUND = ["v13-benign-06", "v13-benign-07", "v13-benign-09", "v13-benign-13", "v13-benign-14b"]
HOST_TRAIN = [
    "host-cal-016835341a7a",
    "host-cal-0216f6d00df3",
    "host-cal-03b398562d95",
    "host-cal-11c38f7e0a1e",
    "host-cal-1396c14563da",
    "host-cal-14c03ee4354d",
    "host-cal-183897365aba",
    "host-cal-192233a77cb2",
    "host-cal-198a18204f88",
    "host-cal-1be6d3fb7fff",
    "host-cal-20ed92ac7e60",
    "host-cal-21c326bce96c",
    "host-cal-2762c741365b",
    "host-cal-2cf6a21f5773",
    "host-cal-2e400ee30e79",
    "host-cal-3423054d6567",
    "host-cal-34d1faa179ab",
    "host-cal-37c01cac3bfd",
    "host-cal-38b8a1da53e8",
    "host-cal-3c7a419794c1",
    "host-cal-3d700df49839",
    "host-cal-3da06b93c950",
    "host-cal-40a44af44b2e",
    "host-cal-45ff849bfd8e",
    "host-cal-4968c2583637",
    "host-cal-592d5a29b82c",
    "host-cal-59f56f5d2653",
    "host-cal-5d4fad6154f5",
    "host-cal-637fd2e92b1f",
    "host-cal-6481281b9bc9",
    "host-cal-66739be3c3f7",
    "host-cal-68edca4bd07c",
    "host-cal-6c35b4d3e11b",
    "host-cal-6d2802dfab19",
    "host-cal-6f440cacf0c4",
    "host-cal-755e54056119",
    "host-cal-788fc3bddb8b",
    "host-cal-822204fd8aa9",
    "host-cal-8ad2c9f42a58",
    "host-cal-9267eb9a9391",
    "host-cal-958e8fdf6f5f",
    "host-cal-958eba4486ac",
    "host-cal-96dc621453ef",
    "host-cal-9767a6b957ef",
    "host-cal-9b77e245519f",
    "host-cal-9bb608338cae",
    "host-cal-9c77079403ac",
    "host-cal-9eeef8c5fb0b",
    "host-cal-a25b301c905d",
    "host-cal-a3a42bfe0d3b",
    "host-cal-a3dce53a790d",
    "host-cal-a79696bafe07",
    "host-cal-a82cf9adf77c",
    "host-cal-abca48a02a26",
    "host-cal-b37e1256c1d4",
    "host-cal-b53089998b23",
    "host-cal-b5542e63c917",
    "host-cal-b76fdae154e0",
    "host-cal-bbd742974136",
    "host-cal-bd065e38dba8",
    "host-cal-c148e0bdb98f",
    "host-cal-c76ccf384cc1",
    "host-cal-d05feacc386f",
    "host-cal-d354cafc19b9",
    "host-cal-d3bae83b08ac",
    "host-cal-d83f49591e1a",
    "host-cal-dab47d7ea391",
    "host-cal-df7655278cd7",
    "host-cal-eb5547d4ee1e",
    "host-cal-f0677ec571f4",
    "host-cal-f1ec59a286a3",
    "host-cal-f238892da223",
    "host-cal-f2f205f2ac00",
    "host-cal-f347e83f415b",
    "host-cal-fa758ce326b9",
    "host-cal-fcd418e20277",
]
TRAIN_BACKGROUND = LAB_TRAIN_BACKGROUND + HOST_TRAIN
HOST_THRESHOLD = [
    "host-cal-161b64312478",
    "host-cal-1a556b0c8451",
    "host-cal-1bd86415a029",
    "host-cal-2890adad3dda",
    "host-cal-2c530835994c",
    "host-cal-39ec9adad604",
    "host-cal-4d494e1126cd",
    "host-cal-4ee37ad2e300",
    "host-cal-6f69a97a560b",
    "host-cal-72f2c8c76246",
    "host-cal-7547a7b1936c",
    "host-cal-79d056498f85",
    "host-cal-8484e3a1c20c",
    "host-cal-8d814a20877f",
    "host-cal-8dbf05e65a92",
    "host-cal-9b63a92f2569",
    "host-cal-9cb368e79d92",
    "host-cal-a13423ef5915",
    "host-cal-a2bb84afba3c",
    "host-cal-b322d348e15e",
    "host-cal-b4418090e53d",
    "host-cal-b50c93df7eab",
    "host-cal-c5c1f5cbbea1",
    "host-cal-c6130b732b7a",
    "host-cal-d4bf3b88356b",
    "host-cal-d65dd6f81566",
    "host-cal-e0c059f798c3",
    "host-cal-e68853ebc747",
    "host-cal-ea23b74a782a",
    "host-cal-eb18ae0dfd47",
    "host-cal-ed7d9942bdea",
    "host-cal-ee777a79c619",
    "host-cal-f1aa8253f22f",
]
CALIBRATION = HOST_THRESHOLD
CHECK = [
    "host-chk-08b6c8d38703",
    "host-chk-2470c58a52bd",
    "host-chk-25b118adaeea",
    "host-chk-2b1d5ed46e9d",
    "host-chk-4ae65c9ab2ad",
    "host-chk-4d9a1c4930ef",
    "host-chk-4f69bd1c558c",
    "host-chk-5f999e1615d7",
    "host-chk-6cc9a2eb3ac3",
    "host-chk-6fdd00e747b8",
    "host-chk-7417b3d1d6b3",
    "host-chk-8157dc1f5f89",
    "host-chk-866443c36fec",
    "host-chk-b4a86793429e",
    "host-chk-bbfd84a562da",
    "host-chk-bf52c9c41c1b",
    "host-chk-c7db6efda7a9",
    "host-chk-cfe6c906614d",
    "host-chk-e7e8e7118a9f",
    "host-chk-fe77184aedca",
]
VOLUME_DROP = {0, 1, 2, 3, 8, 9, 12, 53, 54, 55, 56}  # v12 volume + v13 packet-size statistics
DIRECTION = list(v13.FEATURE_NAMES).index("direction_asym")


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
    all_idx = list(range(len(v13.FEATURE_NAMES)))
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
        threshold = float(np.quantile(loco.score(model, median, scale, x_cal, "cpu"), 1 - 0.01))
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
    report = {"kind": "lab_host_negatives_crossfamily", "features": args.features, "feature_count": len(keep),
              "research_only": True, "promotion_eligible": False,
              "registration_sha256": sha256_file(args.registration), "script_sha256": sha256_file(Path(__file__)),
              "folds": results}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"lab_host_negatives_crossfamily_{args.features}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

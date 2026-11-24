"""Pre-registered held-out scan-variant evaluation on lab schema v13 shards (research-only).

Training attack: v13-scan-01..04 (original scans) plus v13-scan-05 and v13-scan-06 (TCP connect, UDP top ports).
Held-out attack: v13-scan-07 (fast SYN 1-10000) and v13-scan-08 (sparse SYN on 12 service ports); never trained on.
Training background: v13-benign-06, 07, 09, 13, 14b (same list as the existing v13 diagnostics).
Host background (unlabeled, y=-1) is never a training negative. Host calibration (threshold) and host check
are read via lab_host_advisory_crossfamily.py, which defines the host lists and loaders.

Threshold: np.quantile(host calibration scores, 1 - 0.01), i.e. the 99th percentile, as in the template.
Host alarm rate is a descriptive rate on unlabeled traffic, NOT a false-positive rate.
Reported: recall on each held-out capture and pooled (Wilson 95%); host alarm rate overall and split by
direction_asym > 0.99 (Wilson 95%, and one-sided 95% upper bound). No blocking; no promotion.

Usage: python tools/lab/lab_scan_variants_crossfamily.py --features full|nonvolume --registration <json> --out <dir>
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tools"), str(HERE)]
import loco_ctu13_diagnostic as loco  # noqa: E402
import lab_host_advisory_crossfamily as base  # noqa: E402
from integrityguard import network_flow_schema_v13 as v13  # noqa: E402

TRAIN_ATTACK = ["v13-scan-01", "v13-scan-02", "v13-scan-03", "v13-scan-04", "v13-scan-05", "v13-scan-06"]
HELD_OUT = ["v13-scan-07", "v13-scan-08"]
TRAIN_BACKGROUND = ["v13-benign-06", "v13-benign-07", "v13-benign-09", "v13-benign-13", "v13-benign-14b"]
CALIBRATION = base.CALIBRATION
CHECK = base.CHECK
DIRECTION = base.DIRECTION
VOLUME_DROP = base.VOLUME_DROP
Z_ONE_SIDED_95 = 1.6448536269514722


def wilson_upper_one_sided(k: int, n: int) -> float:
    """One-sided 95% Wilson score upper bound."""
    if n == 0:
        return 1.0
    z = Z_ONE_SIDED_95
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return float((centre + margin) / denom)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", choices=("full", "nonvolume"), required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    reg = json.loads(args.registration.read_text(encoding="utf-8"))
    if reg.get("status") != "preregistered_development_only":
        raise SystemExit("registration is not pre-registered")
    if base.sha256_file(Path(__file__)) != reg["script_sha256"]:
        raise SystemExit("script differs from the registered version")
    all_idx = list(range(len(v13.FEATURE_NAMES)))
    keep = all_idx if args.features == "full" else [i for i in all_idx if i not in VOLUME_DROP]

    x_cal = np.concatenate([base.load_host(s, keep)[0] for s in CALIBRATION])
    x_chk = np.concatenate([base.load_host(s, keep)[0] for s in CHECK])
    dir_pos = keep.index(DIRECTION)
    one_way_mask = x_chk[:, dir_pos] > 0.99

    xs, ys = [], []
    for sid in TRAIN_ATTACK + TRAIN_BACKGROUND:
        x, y = base.load(sid, keep)
        xs.append(x); ys.append(y)
    x_tr = np.concatenate(xs); y_tr = np.concatenate(ys)
    started = time.time()
    model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
    threshold = float(np.quantile(loco.score(model, median, scale, x_cal, "cpu"), 1 - 0.01))
    s_chk = loco.score(model, median, scale, x_chk, "cpu")
    flagged = s_chk >= threshold

    per_capture = {}
    pooled_hits, pooled_n = 0, 0
    for sid in HELD_OUT:
        x, _ = base.load(sid, keep)
        sc = loco.score(model, median, scale, x, "cpu")
        hits = int((sc >= threshold).sum())
        n = len(sc)
        pooled_hits += hits; pooled_n += n
        per_capture[sid] = {"flows": n, "flagged": hits, "recall": hits / max(n, 1),
                            "recall_ci95": list(loco.wilson(hits, n))}

    def stratum(mask):
        n = int(mask.sum())
        alerts = int(flagged[mask].sum())
        return {"flows": n, "alerts": alerts, "alarm_rate": alerts / max(n, 1),
                "alarm_rate_ci95": list(loco.wilson(alerts, n)),
                "alarm_rate_one_sided_95_upper": wilson_upper_one_sided(alerts, n)}

    overall = stratum(np.ones(len(s_chk), dtype=bool))
    report = {
        "kind": "lab_scan_variants_crossfamily",
        "features": args.features,
        "feature_count": len(keep),
        "seed": int(loco.SEED),
        "epochs": 20,
        "train_attack": TRAIN_ATTACK,
        "train_attack_flows": int((y_tr == 1).sum()),
        "train_background": TRAIN_BACKGROUND,
        "train_background_flows": int((y_tr == 0).sum()),
        "held_out": HELD_OUT,
        "held_out_per_capture": per_capture,
        "held_out_pooled": {"flows": pooled_n, "flagged": pooled_hits,
                            "recall": pooled_hits / max(pooled_n, 1),
                            "recall_ci95": list(loco.wilson(pooled_hits, pooled_n))},
        "threshold_from_unlabeled_host_calibration": threshold,
        "host_labels": "unlabeled (-1); host alarm rates are not FPR",
        "check_overall": overall,
        "check_one_way_udp": stratum(one_way_mask),
        "check_other": stratum(~one_way_mask),
        "seconds": round(time.time() - started, 1),
        "research_only": True,
        "promotion_eligible": False,
        "registration_sha256": base.sha256_file(args.registration),
        "script_sha256": base.sha256_file(Path(__file__)),
    }
    print(json.dumps({k: report[k] for k in ("held_out_per_capture", "held_out_pooled", "check_overall",
                                             "check_one_way_udp", "check_other",
                                             "threshold_from_unlabeled_host_calibration")}, indent=2), flush=True)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"lab_scan_variants_crossfamily_{args.features}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

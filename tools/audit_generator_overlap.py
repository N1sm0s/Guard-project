"""Train on one synthetic seed and measure transfer to a second seed.

This is an internal generator audit, not an external real-world evaluation.
It regenerates both cohorts from explicit seeds, saves metrics and a model,
and keeps the production detector untouched.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from integrityguard.corpus import build_corpus
from integrityguard.model import save_detector
from integrityguard.train import calibrate, evaluate, split_by_project, train_detector


def audit(train_projects: int, holdout_projects: int, train_seed: int,
          holdout_seed: int, epochs: int, target_fpr: float, out_dir: Path):
    if train_seed == holdout_seed:
        raise ValueError("training and holdout seeds must be different")
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[audit] train cohort: n={train_projects}, seed={train_seed}")
    train_samples = build_corpus(train_projects, seed=train_seed)
    print(f"[audit] holdout cohort: n={holdout_projects}, seed={holdout_seed}")
    holdout = build_corpus(holdout_projects, seed=holdout_seed)

    # PID numbering restarts for each corpus. Rebase holdout IDs so an audit
    # can assert disjoint project groups explicitly; PIDs are not model inputs.
    for row in holdout:
        row["pid"] = int(row["pid"]) + 1_000_000_000
    train, val, internal_test = split_by_project(train_samples, seed=train_seed + 1)
    train_pids = {int(row["pid"]) for row in train_samples}
    holdout_pids = {int(row["pid"]) for row in holdout}
    if train_pids & holdout_pids:
        raise AssertionError("train and holdout project groups overlap")

    model = train_detector(train, val, epochs=epochs, seed=train_seed, log=print)
    threshold = calibrate(model, val, target_fpr)
    metrics = evaluate(model, holdout, threshold)
    save_detector(model, out_dir / "detector.pt",
                  {"threshold": threshold, "block_threshold": max(threshold, 0.9)})

    result = {
        "scope": "synthetic second-seed holdout; same generator family, not external data",
        "train": {"projects": len(train_samples), "train_rows": len(train),
                  "validation_rows": len(val), "unused_internal_test_rows": len(internal_test),
                  "seed": train_seed, "class_counts": dict(Counter(x["cls"] for x in train_samples))},
        "holdout": {"projects": len(holdout), "seed": holdout_seed,
                    "project_ids_disjoint": not bool(train_pids & holdout_pids),
                    "class_counts": dict(Counter(x["cls"] for x in holdout))},
        "threshold_calibration": {"target_fpr": target_fpr, "threshold": threshold,
                                  "validation_clean_n": sum(x["y"] == 0 for x in val)},
        "metrics": metrics,
        "model": str((out_dir / "detector.pt").resolve()),
    }
    (out_dir / "metrics.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-projects", type=int, default=300)
    parser.add_argument("--holdout-projects", type=int, default=90)
    parser.add_argument("--train-seed", type=int, default=31011)
    parser.add_argument("--holdout-seed", type=int, default=91207)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--target-fpr", type=float, default=0.02)
    parser.add_argument("--out", type=Path, default=Path("outputs/generator-overlap-audit"))
    args = parser.parse_args()
    audit(args.train_projects, args.holdout_projects, args.train_seed,
          args.holdout_seed, args.epochs, args.target_fpr, args.out)


if __name__ == "__main__":
    main()

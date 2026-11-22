"""Read-only feature-semantics audit for CTU-13 v10 flow features.

Development-only diagnostic. It reads already-used train/dev captures with
their publisher labels (From-Botnet-* / From-Normal-*; Background excluded),
and reports, per feature and per capture:

* univariate ROC AUC attack-vs-benign (direction of separation),
* sign flips of that direction across captures,
* per-class distribution shift of each dev capture vs pooled train (PSI),
* attack label families present in each capture.

No model is trained or scored, no threshold is selected, and independent /
target test sources are refused. Results are not evidence of model quality.

Usage:
  python tools/audit_feature_semantics_v10.py \
      --train 42 43 44 48 50 --dev 49 51 53 --out outputs/network-eval/feature-audit-v10
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import train_v9 as tv  # noqa: E402

CTU13_CAPTURES = {**tv.TRAIN_CAPTURES, **tv.CTU_ADDITIONAL_TRAIN_CAPTURES}
# Publisher scenario families for CTU-13 (scenario number = capture id - 41).
CTU13_FAMILY = {"42": "Neris", "43": "Neris", "44": "Rbot", "45": "Rbot",
                "46": "Virut", "47": "Menti", "48": "Sogou", "49": "Murlo",
                "50": "Neris", "51": "Rbot", "52": "Rbot", "53": "NSIS.ay",
                "54": "Virut"}
# Captures previously scored as independent tests must not be re-read here.
REFUSED = {"45", "46", "47"}
PSI_BINS = 10
MIN_CLASS_SUPPORT = 30


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def label_family(raw: str) -> str:
    """Strip capture-specific numbering so families are comparable."""
    text = raw.removeprefix("flow=")
    text = re.sub(r"-V\d+", "", text)
    text = re.sub(r"-\d+$", "", text)
    return text


def auc(x: np.ndarray, y: np.ndarray) -> float | None:
    if y.min() == y.max():
        return None
    if (y == 1).sum() < MIN_CLASS_SUPPORT or (y == 0).sum() < MIN_CLASS_SUPPORT:
        return None
    if np.all(x == x[0]):
        return 0.5
    return float(roc_auc_score(y, x))


def psi(reference: np.ndarray, sample: np.ndarray) -> float | None:
    if len(reference) < MIN_CLASS_SUPPORT or len(sample) < MIN_CLASS_SUPPORT:
        return None
    edges = np.unique(np.quantile(reference, np.linspace(0, 1, PSI_BINS + 1)))
    if len(edges) < 2:
        # Constant in reference: share of sample that differs from it.
        same = np.mean(sample == reference[0])
        ref = np.array([1.0 - 1e-6, 1e-6]); cur = np.array([same, 1 - same])
    else:
        edges[0], edges[-1] = -np.inf, np.inf
        ref = np.histogram(reference, edges)[0] / len(reference)
        cur = np.histogram(sample, edges)[0] / len(sample)
    ref = np.clip(ref, 1e-6, None); cur = np.clip(cur, 1e-6, None)
    return float(np.sum((cur - ref) * np.log(cur / ref)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--train", nargs="+", required=True)
    parser.add_argument("--dev", nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    ids = list(dict.fromkeys(args.train + args.dev))
    bad = [c for c in ids if c in REFUSED or c not in CTU13_CAPTURES or c not in CTU13_FAMILY]
    if bad:
        raise SystemExit(f"Refusing captures (independent-test or unknown): {bad}")
    if set(args.train) & set(args.dev):
        raise SystemExit("Train and dev captures overlap")

    tv.configure_feature_schema(10)
    names = list(tv.FEATURE_NAMES)
    # CTU NetFlow has no TCP history; v10 indices 40-45 are not observed.
    used = list(range(40))

    data, sources = {}, {}
    for cid in ids:
        path = CTU13_CAPTURES[cid]
        x, y, _udp, excluded, raw = tv.load_capture(cid, path, include_raw_labels=True)
        fam = Counter(label_family(r) for r, t in zip(raw, y) if t == 1)
        data[cid] = (x[:, used], y)
        sources[cid] = {
            "path": str(path.relative_to(ROOT)), "sha256": sha256_file(path),
            "role": "train" if cid in args.train else "dev",
            "publisher_family": CTU13_FAMILY[cid],
            "attack": int(y.sum()), "benign": int((y == 0).sum()), "excluded": int(excluded),
            "attack_label_families": dict(fam.most_common(12)),
        }
        print(f"{cid}: attack={y.sum()} benign={(y == 0).sum()} excluded={excluded}", flush=True)

    tr_x = np.concatenate([data[c][0] for c in args.train])
    tr_y = np.concatenate([data[c][1] for c in args.train])

    features = []
    for j in used:
        per_cap = {c: auc(data[c][0][:, j], data[c][1]) for c in ids}
        pooled = auc(tr_x[:, j], tr_y)
        signs = {c: (0 if a is None or abs(a - 0.5) < 0.1 else (1 if a > 0.5 else -1))
                 for c, a in per_cap.items()}
        strong = [s for s in signs.values() if s]
        flip = bool(strong) and min(strong) != max(strong)
        shift = {}
        for c in args.dev:
            x, y = data[c]
            shift[c] = {
                "benign_psi": psi(tr_x[tr_y == 0, j], x[y == 0, j]),
                "attack_psi": psi(tr_x[tr_y == 1, j], x[y == 1, j]),
            }
        dev_against_train = [c for c in args.dev
                             if pooled is not None and per_cap[c] is not None
                             and abs(pooled - 0.5) >= 0.1 and abs(per_cap[c] - 0.5) >= 0.1
                             and (pooled > 0.5) != (per_cap[c] > 0.5)]
        features.append({
            "index": j, "name": names[j],
            "train_pooled_auc": pooled, "auc_by_capture": per_cap,
            "direction_flip_across_captures": flip,
            "dev_captures_opposite_to_train": dev_against_train,
            "dev_shift_psi": shift,
            "attack_nonzero_rate": {c: float(np.mean(data[c][0][data[c][1] == 1, j] != 0)) for c in ids},
            "benign_nonzero_rate": {c: float(np.mean(data[c][0][data[c][1] == 0, j] != 0)) for c in ids},
        })

    args.out.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": "feature_semantics_audit",
        "research_only": True, "promotion_eligible": False,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "auditor_sha256": sha256_file(Path(__file__)),
        "feature_version": tv.FEATURE_VERSION,
        "features_audited": [names[j] for j in used],
        "features_not_observed_in_ctu": names[40:],
        "train_captures": args.train, "dev_captures": args.dev,
        "sources": sources,
        "method": ("Univariate ROC AUC attack-vs-benign per capture (support >= 30 per class); "
                   "direction counted only when |AUC-0.5| >= 0.1; PSI of each dev capture vs pooled "
                   "train per class with 10 train-quantile bins. Labels: explicit publisher From-Botnet/"
                   "From-Normal only. No model, threshold, or independent test is used."),
        "limitations": ("Univariate statistics ignore feature interactions; flows are not independent "
                        "(host/time clustering); dev captures were already used for development."),
        "features": features,
    }
    out_json = args.out / "feature_semantics_audit.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    def f(v):
        return "—" if v is None else f"{v:.3f}"
    lines = ["| # | feature | train AUC | " + " | ".join(ids) + " | flip | dev vs train | max benign PSI | max attack PSI |",
             "|---|---|---|" + "---|" * len(ids) + "---|---|---|---|"]
    for item in features:
        sh = item["dev_shift_psi"].values()
        bmax = max((s["benign_psi"] or 0) for s in sh); amax = max((s["attack_psi"] or 0) for s in sh)
        lines.append(f"| {item['index']} | {item['name']} | {f(item['train_pooled_auc'])} | "
                     + " | ".join(f(item["auc_by_capture"][c]) for c in ids)
                     + f" | {'yes' if item['direction_flip_across_captures'] else ''} | "
                     + f"{','.join(item['dev_captures_opposite_to_train'])} | {bmax:.2f} | {amax:.2f} |")
    (args.out / "feature_semantics_audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Report: {out_json} sha256={sha256_file(out_json)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Train the lab neural-network candidate (research-only; not loaded by the application).

Training data: all lab attack shards (flood, scan, SSH auth attempts) and all lab background shards
except the calibration shard (real-benign-10) and the test shard (sess-benign-08).
Threshold: 99.75th percentile of calibration-background scores (not in training).
Check: sess-benign-08 false-positive rate. Attack recall on training families is reported only as
training fit, not as generalization. Output: checkpoint + manifest under outputs/lab/candidates.

Usage: python tools/lab/train_lab_candidate.py --registration <json> --out <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
import loco_ctu13_diagnostic as loco  # noqa: E402

SHARDS = ROOT / "outputs" / "lab" / "shards"
CALIBRATION = "real-benign-10"
TEST_BENIGN = "sess-benign-08"
ATTACK_SHARDS = ["sess-udp-03", "seg-68b743878383", "seg-96dc621453ef", "real-flood-02", "real-flood-03",
                 "real-scan-01", "real-scan-02", "real-scan-03", "real-scan-04", "real-ssh-01", "real-ssh-02"]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(source_id: str):
    with np.load(SHARDS / f"{source_id}.npz") as data:
        return data["x"][:, loco.KEEP], data["y"].astype(np.int64)


def background_shards() -> list[str]:
    out = []
    for path in sorted(SHARDS.glob("*.manifest.json")):
        sid = path.name[: -len(".manifest.json")]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["counts"]["attack"] == 0 and manifest["counts"]["benign"] > 0 and sid not in (CALIBRATION, TEST_BENIGN):
            out.append(sid)
    return out


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

    torch.set_num_threads(4)
    bg = background_shards()
    xs, ys = [], []
    for sid in ATTACK_SHARDS + bg:
        x, y = load(sid)
        xs.append(x); ys.append(y)
    x_tr = np.concatenate(xs); y_tr = np.concatenate(ys)

    model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
    x_cal, _ = load(CALIBRATION)
    s_cal = loco.score(model, median, scale, x_cal, "cpu")
    threshold = float(np.quantile(s_cal, 1 - 0.0025))

    x_te, y_te = load(TEST_BENIGN)
    s_te = loco.score(model, median, scale, x_te, "cpu")
    fp = int((s_te >= threshold).sum()); n_ben = len(s_te)

    per_family = {}
    for sid in ATTACK_SHARDS:
        x, y = load(sid)
        s = loco.score(model, median, scale, x, "cpu")
        per_family[sid] = {"flows": len(s), "fit_recall": float((s >= threshold).mean())}

    args.out.mkdir(parents=True, exist_ok=True)
    ckpt = args.out / "lab-mlp-candidate-v1.pt"
    torch.save({"state_dict": model.state_dict(), "median": median.tolist(), "scale": scale.tolist(),
                "threshold": threshold, "kept_indices": loco.KEEP, "hidden_width": 64,
                "research_only": True, "promotion_eligible": False, "enforcement_applied": False}, ckpt)
    manifest = {"kind": "lab_candidate_manifest", "research_only": True, "promotion_eligible": False,
                "enforcement_applied": False, "registration_sha256": sha256_file(args.registration),
                "script_sha256": sha256_file(Path(__file__)), "checkpoint": ckpt.name,
                "checkpoint_sha256": sha256_file(ckpt), "threshold": threshold,
                "training_attack_shards": ATTACK_SHARDS, "training_background_shards": bg,
                "calibration_shard": CALIBRATION, "check_shard": TEST_BENIGN,
                "check_background_flows": n_ben, "check_background_flagged": fp,
                "check_background_fpr": fp / max(n_ben, 1), "check_background_fpr_ci95_upper": loco.wilson(fp, n_ben)[1],
                "training_fit_by_shard": per_family,
                "limitations": ["lab data only; one stand; artificial attacks", "check background is 298 flows",
                                "training-fit recall is not generalization", "not loaded by the application"]}
    (args.out / "lab-mlp-candidate-v1-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("threshold", "check_background_flagged", "check_background_fpr",
                                               "check_background_fpr_ci95_upper")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

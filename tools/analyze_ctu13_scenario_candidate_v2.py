"""Post-hoc error analysis for the frozen CTU-54 holdout of candidate v2.

This script reports aggregate score distributions and protocol-stratified errors.
It never changes the checkpoint or selects a new threshold.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrityguard.network_flow_model import _FlowV3AutoencoderClassifier  # noqa: E402
from integrityguard.network_flow_schema import FEATURE_NAMES  # noqa: E402
from tools.train_ctu13_scenario_candidate_v2 import read_labeled_capture  # noqa: E402

DATA = ROOT / "outputs" / "network-eval"
CHECKPOINT = DATA / "ctu13-scenarios-flow-v3-candidate-v2.pt"
TEST_CAPTURE = DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow"
METRICS = DATA / "ctu13-scenarios-flow-v3-metrics-v2.json"
OUT = DATA / "ctu13-scenarios-flow-v3-error-analysis-v2.json"
PROTOCOLS = {
    "tcp": FEATURE_NAMES.index("protocol_tcp"),
    "udp": FEATURE_NAMES.index("protocol_udp"),
    "icmp": FEATURE_NAMES.index("protocol_icmp"),
    "other": FEATURE_NAMES.index("protocol_other"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quantiles(values: np.ndarray) -> dict:
    if not len(values):
        return {"n": 0}
    probs = np.quantile(values, [0, .1, .25, .5, .75, .9, .95, .99, 1])
    return {"n": int(len(values)), "min": float(probs[0]), "p10": float(probs[1]),
            "p25": float(probs[2]), "median": float(probs[3]), "p75": float(probs[4]),
            "p90": float(probs[5]), "p95": float(probs[6]), "p99": float(probs[7]),
            "max": float(probs[8])}


def main() -> None:
    train_report = json.loads(METRICS.read_text(encoding="utf-8"))
    checkpoint = torch.load(CHECKPOINT, map_location="cpu", weights_only=True)
    model = _FlowV3AutoencoderClassifier()
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    x, y, label_counts = read_labeled_capture(TEST_CAPTURE)
    mean = np.asarray(checkpoint["mean"], dtype=np.float32)
    std = np.asarray(checkpoint["std"], dtype=np.float32)
    normalized = (x - mean) / np.where(std < 1e-6, 1.0, std)
    scores = []
    with torch.no_grad():
        for start in range(0, len(normalized), 32768):
            batch = torch.from_numpy(normalized[start:start + 32768])
            scores.extend(torch.softmax(model(batch)[1], dim=1)[:, 1].numpy().tolist())
    scores = np.asarray(scores, dtype=np.float64)
    threshold = float(train_report["validation"]["selected_threshold"])

    by_class = {name: quantiles(scores[y == target])
                for name, target in (("benign", 0), ("attack", 1))}
    by_protocol = {}
    for protocol, index in PROTOCOLS.items():
        mask = x[:, index] == 1.0
        if not mask.any():
            continue
        actual_attack = y[mask] == 1
        protocol_scores = scores[mask]
        operating_points = {}
        for name, cutoff in (("validation_selected", threshold), ("fixed_0_5", 0.5)):
            flagged = protocol_scores >= cutoff
            tp = int((flagged & actual_attack).sum())
            fp = int((flagged & ~actual_attack).sum())
            operating_points[name] = {
                "threshold": cutoff,
                "detected_attack": tp,
                "missed_attack": int(actual_attack.sum()) - tp,
                "false_positive_benign": fp,
                "attack_recall": tp / int(actual_attack.sum()) if actual_attack.any() else None,
                "benign_false_positive_rate": fp / int((~actual_attack).sum())
                    if (~actual_attack).any() else None,
            }
        by_protocol[protocol] = {
            "n": int(mask.sum()), "attack": int(actual_attack.sum()),
            "benign": int((~actual_attack).sum()),
            "operating_points": operating_points,
            "score_quantiles_attack": quantiles(protocol_scores[actual_attack]),
            "score_quantiles_benign": quantiles(protocol_scores[~actual_attack]),
        }
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "post-hoc error analysis only; no threshold/model selection",
        "candidate_sha256": sha256(CHECKPOINT),
        "test_capture": "official CTU-13 scenario 54",
        "test_capture_sha256": sha256(TEST_CAPTURE),
        "source_labeled_counts": dict(label_counts),
        "validation_selected_threshold": threshold,
        "score_quantiles_by_true_class": by_class,
        "errors_by_protocol_at_validation_threshold": by_protocol,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

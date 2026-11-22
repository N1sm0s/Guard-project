"""Score a frozen flow candidate on the public MCFP CTU-353 capture.

This is a one-shot external transfer benchmark. It never trains, calibrates,
or chooses a threshold from CTU-353. Dataset labels are publisher rule labels;
unassigned/background traffic is excluded and is not treated as benign.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, from_ctu_row  # noqa: E402

DATA = ROOT / "outputs" / "network-eval"
CAPTURE = DATA / "official-mcfp" / "ctu-353-1" / "2018-05-07_capture.binetflow"
LABEL_RULES = DATA / "official-mcfp" / "ctu-353-1" / "ralabel-filters.conf"
CHECKPOINT = ROOT / "models" / "network_flow_v3_candidate.pt"
MODEL_METRICS = ROOT / "models" / "network_flow_v3_candidate_metrics.json"
OUTPUT = DATA / "ctu-353-public-transfer-metrics.json"


class AutoencoderClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 32), nn.ReLU(),
                                     nn.Linear(32, 12), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(12, 32), nn.ReLU(),
                                     nn.Linear(32, len(FEATURE_NAMES)))
        self.classifier = nn.Linear(12, 2)

    def forward(self, values):
        latent = self.encoder(values)
        return self.decoder(latent), self.classifier(latent)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wilson(successes: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    z = 1.959963984540054
    p = successes / total
    den = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / den
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / den
    return [max(0.0, center - margin), min(1.0, center + margin)]


def recall_result(probabilities: np.ndarray, threshold: float) -> dict:
    detected = int(np.count_nonzero(probabilities >= threshold))
    total = int(len(probabilities))
    return {
        "threshold": float(threshold),
        "attack_flows": total,
        "detected": detected,
        "missed": total - detected,
        "attack_recall": detected / total if total else None,
        "attack_recall_ci95_wilson": wilson(detected, total),
    }


def main() -> None:
    for path in (CAPTURE, LABEL_RULES, CHECKPOINT, MODEL_METRICS):
        if not path.is_file():
            raise FileNotFoundError(path)

    # Lock provenance before reading/scoring the frozen capture.
    frozen_at = datetime.now(timezone.utc).isoformat()
    capture_hash = sha256(CAPTURE)
    label_rules_hash = sha256(LABEL_RULES)
    checkpoint_hash = sha256(CHECKPOINT)
    metrics = json.loads(MODEL_METRICS.read_text(encoding="utf-8"))
    threshold = float(metrics["validation"]["selected_threshold"])

    checkpoint = torch.load(CHECKPOINT, map_location="cpu", weights_only=True)
    if (checkpoint.get("feature_version") != FEATURE_VERSION
            or checkpoint.get("features") != list(FEATURE_NAMES)
            or checkpoint.get("classes") != ["benign", "attack"]):
        raise RuntimeError("candidate checkpoint feature schema mismatch")
    model = AutoencoderClassifier()
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    mean = np.asarray(checkpoint["mean"], dtype=np.float32)
    std = np.asarray(checkpoint["std"], dtype=np.float32)
    std[std < 1e-6] = 1.0

    label_counts: Counter[str] = Counter()
    attack_probabilities: list[float] = []
    normal_probabilities: list[float] = []
    malformed = 0
    scored = 0
    with CAPTURE.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        for row in reader:
            label = (row.get("Label") or "").strip()
            label_counts[label or "(empty)"] += 1
            if label.startswith("flow=Malware-"):
                target = attack_probabilities
            elif label.startswith("flow=TCP-Established-To-Microsoft-"):
                target = normal_probabilities
            else:
                # Background and unassigned labels are ambiguous, never benign.
                continue
            try:
                vector = np.asarray(from_ctu_row(row), dtype=np.float32)
            except ValueError:
                malformed += 1
                continue
            with torch.no_grad():
                values = torch.from_numpy(((vector - mean) / std).reshape(1, -1))
                probability = float(torch.softmax(model(values)[1], dim=1)[0, 1].item())
            target.append(probability)
            scored += 1

    attacks = np.asarray(attack_probabilities, dtype=np.float64)
    normals = np.asarray(normal_probabilities, dtype=np.float64)
    if attacks.size == 0:
        raise RuntimeError("No complete publisher-labeled malware flows were scoreable")

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_before_scoring_at_utc": frozen_at,
        "source": "Malware Capture Facility Project, CTU-Malware-Capture-Botnet-353-1",
        "source_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-353-1/",
        "label_rule_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-353-1/ralabel-filters.conf",
        "label_provenance": "publisher flow labels assigned by published ralabel rules; not independent target-network adjudication",
        "capture_sha256": capture_hash,
        "label_rules_sha256": label_rules_hash,
        "checkpoint_sha256": checkpoint_hash,
        "threshold": threshold,
        "threshold_source": "fixed from CTU-45 validation; not tuned on CTU-353",
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "field_mapping": {"duration": "Dur", "total_packets": "TotPkts",
                          "total_bytes": "TotBytes", "direction_a_bytes": "SrcBytes",
                          "direction_b_bytes": "TotBytes - SrcBytes", "protocol": "Proto"},
        "label_mapping": {
            "attack": "flow label starts with flow=Malware-",
            "limited_normal_reference": "flow label starts with flow=TCP-Established-To-Microsoft-",
            "excluded": "Background, DNS background, unassigned, and all other labels; not assumed benign",
        },
        "source_label_counts": dict(label_counts),
        "score_coverage": {"complete_labeled_flows_scored": scored,
                           "incomplete_labeled_flows_excluded": malformed},
        "malware_flow_recall": {
            "fixed_threshold_0_5": recall_result(attacks, 0.5),
            "ctu45_selected_threshold": recall_result(attacks, threshold),
            "score_quantiles": {str(q): float(np.quantile(attacks, q)) for q in (0, .25, .5, .75, .9, .99, 1)},
        },
        "normal_flow_reference": {
            "n": int(normals.size),
            "false_positives_at_ctu45_threshold": int(np.count_nonzero(normals >= threshold)),
            "fpr": None,
            "reason_no_fpr": "only a very small publisher-labeled normal reference set is present; background labels are ambiguous",
            "promotion_eligible": False,
        },
        "limitations": [
            "CTU-353 is a controlled malware-lab capture, not the user's target network.",
            "Published labels are rule-derived and do not establish field performance.",
            "The capture has insufficient reliably labeled benign flows to estimate false-positive rate.",
            "This is a flow-level transfer benchmark, not packet-loss, sensor-completeness, or inference-latency evidence.",
        ],
        "model_role": "external_public_transfer_benchmark_only",
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(OUTPUT.relative_to(ROOT)),
        "checkpoint_sha256": checkpoint_hash,
        "capture_sha256": capture_hash,
        "source_label_counts": dict(label_counts),
        "score_coverage": report["score_coverage"],
        "malware_flow_recall": report["malware_flow_recall"],
        "normal_flow_reference": report["normal_flow_reference"],
        "promotion_eligible": False,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

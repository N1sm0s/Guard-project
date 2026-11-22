"""One-shot external transfer evaluation of a frozen flow candidate on IoT-23 v2.

The script does not train or calibrate the model. It scores the public
publisher-labeled Mirai capture and the clean Somfy capture using the stored
threshold. The optional experimental UDP rules are reported separately.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, feature_vector  # noqa: E402

DATA = ROOT / "outputs" / "network-eval" / "official-iot23v2"
CHECKPOINT = ROOT / "outputs" / "network-eval" / "ctu13-v10-gate5-candidate.pt"
CAPTURES = {
    "mirai_34_1": (DATA / "ctu-iot-malware-34-1-zeek-conn.log.labeled", "mixed"),
    "somfy_7_1": (DATA / "ctu-honeypot-7-1-zeek-conn.log.labeled", "benign"),
}
OUTPUT = ROOT / "outputs" / "network-eval" / "iot23v2-external-transfer-metrics.json"


class MLP(nn.Module):
    def __init__(self, n: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(512, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 2),
        )

    def forward(self, values):
        return self.net(values)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return None
    p = successes / total
    den = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / den
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / den
    return [max(0.0, center - margin), min(1.0, center + margin)]


def metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    actual = labels == 1
    predicted = scores >= threshold
    tp = int(np.count_nonzero(actual & predicted))
    fp = int(np.count_nonzero(~actual & predicted))
    fn = int(np.count_nonzero(actual & ~predicted))
    tn = int(np.count_nonzero(~actual & ~predicted))
    return {
        "n": int(len(labels)), "n_attack": int(actual.sum()), "n_benign": int((~actual).sum()),
        "threshold": float(threshold), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "attack_recall": tp / (tp + fn) if tp + fn else None,
        "benign_fpr": fp / (fp + tn) if fp + tn else None,
        "attack_recall_ci95_wilson": wilson(tp, tp + fn),
        "benign_fpr_ci95_wilson": wilson(fp, fp + tn),
    }


def parse_zeek_flow(line: str):
    columns = line.rstrip("\r\n").split("\t")
    if len(columns) < 21:
        raise ValueError("fewer than 21 Zeek columns")
    # In these published logs, the final three logical fields are written as
    # one tab field containing whitespace-separated tunnel, label and detail.
    tail = columns[-1].strip().split()
    label = tail[-2].strip().lower() if len(tail) >= 3 else ""
    duration = columns[8]
    orig_packets, resp_packets = columns[16], columns[18]
    orig_ip_bytes, resp_ip_bytes = columns[17], columns[19]
    vector = feature_vector(
        duration,
        float(orig_packets) + float(resp_packets),
        float(orig_ip_bytes) + float(resp_ip_bytes),
        orig_ip_bytes,
        resp_ip_bytes,
        columns[6],
    )
    return label, vector


def score_capture(path: Path, scenario_role: str, model, q25, iqr, use_rule_override: bool):
    labels: list[int] = []
    raw_scores: list[float] = []
    counts = {"malicious": 0, "benign": 0, "unknown_excluded": 0, "incomplete_excluded": 0}
    vectors: list[list[float]] = []
    targets: list[int] = []
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not line or line.startswith("#"):
                continue
            try:
                label, vector = parse_zeek_flow(line)
            except (ValueError, IndexError):
                counts["incomplete_excluded"] += 1
                continue
            if label == "malicious":
                target = 1
            elif label == "benign":
                target = 0
            elif scenario_role == "benign" and label == "":
                # The publisher designates this entire capture as a benign
                # clean-device scenario; preserve this weaker provenance.
                target = 0
            else:
                counts["unknown_excluded"] += 1
                continue
            counts["malicious" if target else "benign"] += 1
            vectors.append(vector)
            targets.append(target)

    if not targets:
        raise RuntimeError(f"No scoreable source-labeled flows: {path}")
    x = np.asarray(vectors, dtype=np.float32)
    y = np.asarray(targets, dtype=np.int64)
    x_norm = np.clip((x - q25) / iqr, -10.0, 10.0)
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(x_norm))
        scores = torch.softmax(logits, dim=1)[:, 1].cpu().numpy().astype(np.float64)

    rule_counts = {"sustained_udp_packets_gt4": 0, "ephemeral_udp_no_response_small_bytes": 0}
    rule_scores = scores.copy()
    if use_rule_override:
        is_sustained = x_norm[:, 13] > 0.5
        has_pkts_gt4 = x_norm[:, 1] > 0.6
        rule1 = is_sustained & has_pkts_gt4
        is_very_ephemeral = x_norm[:, 11] > 0.5
        is_no_response = x_norm[:, 16] > 0.5
        is_small_bytes = x_norm[:, 2] < -0.5
        rule2 = is_very_ephemeral & is_no_response & is_small_bytes
        rule_scores[rule1 | rule2] = 1.0
        rule_counts["sustained_udp_packets_gt4"] = int(rule1.sum())
        rule_counts["ephemeral_udp_no_response_small_bytes"] = int(rule2.sum())

    return {
        "source_label_counts_scored": counts,
        "source_file_sha256": sha256(path),
        "model_only_fixed_threshold": metrics(y, scores, 0.5),
        "with_experimental_rule_overrides_fixed_threshold": metrics(y, rule_scores, 0.5),
        "experimental_rule_match_counts": rule_counts,
        "scores": scores,
        "rule_scores": rule_scores,
        "labels": y,
    }


def main() -> None:
    if not CHECKPOINT.is_file():
        raise FileNotFoundError(CHECKPOINT)
    for path, _ in CAPTURES.values():
        if not path.is_file():
            raise FileNotFoundError(path)

    frozen_at = datetime.now(timezone.utc).isoformat()
    checkpoint_hash = sha256(CHECKPOINT)
    input_hashes = {name: sha256(path) for name, (path, _) in CAPTURES.items()}
    checkpoint = torch.load(CHECKPOINT, map_location="cpu", weights_only=True)
    if checkpoint.get("feature_version") != FEATURE_VERSION \
            or checkpoint.get("features") != list(FEATURE_NAMES) \
            or checkpoint.get("classes") != ["benign", "attack"]:
        raise RuntimeError("candidate checkpoint does not match the current feature schema")
    model = MLP(len(FEATURE_NAMES))
    model.load_state_dict(checkpoint["state_dict"])
    q25 = np.asarray(checkpoint["q25"], dtype=np.float32)
    iqr = np.asarray(checkpoint["iqr"], dtype=np.float32)
    iqr[iqr < 1e-6] = 1.0

    results = {}
    combined_y = []
    combined_raw = []
    combined_rules = []
    per_capture_summary = {}
    for name, (path, role) in CAPTURES.items():
        result = score_capture(path, role, model, q25, iqr, use_rule_override=True)
        results[name] = {
            "capture_sha256": input_hashes[name],
            "source_label_counts_scored": result["source_label_counts_scored"],
            "model_only_fixed_threshold": result["model_only_fixed_threshold"],
            "with_experimental_rule_overrides_fixed_threshold": result["with_experimental_rule_overrides_fixed_threshold"],
            "experimental_rule_match_counts": result["experimental_rule_match_counts"],
        }
        combined_y.append(result["labels"])
        combined_raw.append(result["scores"])
        combined_rules.append(result["rule_scores"])
        per_capture_summary[name] = {
            "labels": result["labels"],
            "scores": result["scores"],
            "rule_scores": result["rule_scores"],
        }

    y = np.concatenate(combined_y)
    raw = np.concatenate(combined_raw)
    rules = np.concatenate(combined_rules)
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_before_scoring_at_utc": frozen_at,
        "dataset": "Aposemat IoT-23 v2, MCFP/Stratosphere Laboratory",
        "source_url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/",
        "labeling": "published Zeek flow labels; security-expert analysis and per-scenario labels.config; unknown/background excluded",
        "checkpoint_sha256": checkpoint_hash,
        "checkpoint_path": str(CHECKPOINT.relative_to(ROOT)),
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "threshold": 0.5,
        "threshold_source": "checkpoint fixed threshold; no threshold selection or training on IoT-23",
        "capture_provenance": {
            "mirai_34_1": "malware scenario; row-level Benign/Malicious labels from publisher",
            "somfy_7_1": "clean Somfy device scenario; published per-flow labels",
        },
        "per_capture": results,
        "combined_external_transfer": {
            "model_only_fixed_threshold": metrics(y, raw, 0.5),
            "with_experimental_rule_overrides_fixed_threshold": metrics(y, rules, 0.5),
        },
        "candidate_integrity_notes": [
            "Checkpoint training metadata includes CTU-53 and CTU-54, which were also used for development scoring; those CTU results are not independent.",
            "IoT-23 flows were not used to train the checkpoint or choose its threshold and are held out for this transfer measurement.",
            "The experimental Rule 1/2 overrides were derived from CTU-53/54 and are scored separately from model-only output.",
            "This public controlled-lab IoT evaluation is not the user's target network evaluation.",
            "Model-only features were derived from Zeek IP-byte counters; this schema/tool mapping should be validated against Pktmon-derived flows before deployment.",
        ],
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {
        "output": str(OUTPUT.relative_to(ROOT)),
        "checkpoint_sha256": checkpoint_hash,
        "per_capture": {name: {
            "model_only": value["model_only_fixed_threshold"],
            "rules": value["with_experimental_rule_overrides_fixed_threshold"],
            "counts": value["source_label_counts_scored"],
            "rule_matches": value["experimental_rule_match_counts"],
        } for name, value in results.items()},
        "combined_external_transfer": report["combined_external_transfer"],
        "promotion_eligible": False,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

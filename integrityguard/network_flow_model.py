"""CTU-trained recommendation classifier over live socket metadata."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
import torch
from torch import nn
from .network_flow_schema import FEATURE_VERSION_HISTORY, from_live_flow

# The live candidate is the original eight-feature v3 checkpoint. The shared
# schema has since advanced to v8; use its explicitly preserved v3 prefix.
FLOW_V3_VERSION = 3
FLOW_V3_FEATURE_NAMES = FEATURE_VERSION_HISTORY[FLOW_V3_VERSION]

FEATURE_VERSION = 2
FEATURE_NAMES = ("remote_port_log1p", "local_port_log1p",
                 "protocol_tcp", "protocol_udp", "protocol_other")
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "network_flow_classifier.pt"
_MODEL_CACHE = None
_MODEL_CACHE_SIGNATURE = None


def _load_model(checkpoint_path):
    global _MODEL_CACHE, _MODEL_CACHE_SIGNATURE
    signature = (str(checkpoint_path.resolve()), checkpoint_path.stat().st_mtime_ns)
    if _MODEL_CACHE is not None and signature == _MODEL_CACHE_SIGNATURE:
        return _MODEL_CACHE
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    if checkpoint.get("feature_version") != FEATURE_VERSION \
            or checkpoint.get("features") != list(FEATURE_NAMES) \
            or checkpoint.get("classes") != ["benign", "attack"]:
        raise ValueError("checkpoint schema mismatch")
    if checkpoint.get("promotion_eligible") is False:
        raise ValueError("checkpoint failed its shortcut/leakage audit")
    model = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 16), nn.ReLU(), nn.Linear(16, 8),
                          nn.ReLU(), nn.Linear(8, 2))
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    _MODEL_CACHE, _MODEL_CACHE_SIGNATURE = (checkpoint, model), signature
    return _MODEL_CACHE


def _port(value, name):
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing {name}")
    try:
        port = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {name}") from None
    if not 0 <= port <= 65535:
        raise ValueError(f"Invalid {name}")
    return port


def feature_vector(remote_port, protocol, local_port):
    remote_port = _port(remote_port, "remote port")
    local_port = _port(local_port, "local port")
    protocol = str(protocol).upper()
    return [__import__("math").log1p(remote_port), __import__("math").log1p(local_port),
            float(protocol == "TCP"),
            float(protocol == "UDP"), float(protocol not in {"TCP", "UDP"})]


def assess(snapshot: dict, checkpoint_path: Path = MODEL_PATH) -> dict:
    try:
        checkpoint, model = _load_model(checkpoint_path)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return {"status": "unavailable", "reason": "Нет совместимой обученной модели."}

    if snapshot.get("socket_flow_truncated"):
        return {"status": "insufficient_telemetry",
                "reason": "Часть наблюдаемых сокетов не вошла в ограниченный снимок; оценка пропущена."}
    examples = []
    for connection in snapshot.get("socket_flows", []):
        try:
            examples.append(feature_vector(connection["remote_port"], connection["protocol"],
                                           connection["local_port"]))
        except (KeyError, TypeError, ValueError):
            continue
    if not examples:
        return {"status": "insufficient_telemetry", "reason": "Сенсор не передал метаданные отдельных сокетов."}

    mean = torch.tensor(checkpoint["mean"], dtype=torch.float32)
    std = torch.tensor(checkpoint["std"], dtype=torch.float32)
    values = (torch.tensor(examples, dtype=torch.float32) - mean) / std
    with torch.no_grad():
        attack_probabilities = torch.softmax(model(values), dim=1)[:, 1]
    flagged = int((attack_probabilities >= 0.5).sum().item())
    return {
        "status": "recommendation",
        "model": checkpoint.get("model_name", "IntegrityGuard CTU flow classifier"),
        "scored_connections": len(examples),
        "attack_candidates": flagged,
        "max_attack_probability": round(float(attack_probabilities.max().item()), 4),
        "mean_attack_probability": round(float(attack_probabilities.mean().item()), 4),
        "checkpoint_dataset_sha256": checkpoint.get("dataset_sha256"),
        "feature_version": FEATURE_VERSION,
        "evaluation": checkpoint.get("evaluation", {}),
        "enforcement_applied": False,
    }


class _FlowV3AutoencoderClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        count = len(FLOW_V3_FEATURE_NAMES)
        self.encoder = nn.Sequential(nn.Linear(count, 32), nn.ReLU(),
                                     nn.Linear(32, 12), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(12, 32), nn.ReLU(),
                                     nn.Linear(32, count))
        self.classifier = nn.Linear(12, 2)

    def forward(self, values):
        latent = self.encoder(values)
        return self.decoder(latent), self.classifier(latent)


def assess_completed_packet_flows(flows: list[dict], checkpoint_path: Path) -> dict:
    """Score complete live flows with a publisher-labeled research candidate.

    Labels come from the public capture publisher and are kept distinct from
    unlabeled local observations. This model returns recommendations only; it
    never changes firewall rules.
    """
    checkpoint_path = Path(checkpoint_path)
    try:
        checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
        manifest_path = checkpoint_path.with_name("network_flow_v3_candidate_manifest.json")
        manifest_bytes = manifest_path.read_bytes()
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_hash != checkpoint.get("dataset_manifest_sha256"):
            raise ValueError("dataset provenance manifest hash mismatch")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        metrics_path = checkpoint_path.with_name("network_flow_v3_candidate_metrics.json")
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        checkpoint_hash = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        if checkpoint.get("feature_version") != FLOW_V3_VERSION \
                or checkpoint.get("features") != list(FLOW_V3_FEATURE_NAMES) \
                or checkpoint.get("classes") != ["benign", "attack"] \
                or checkpoint.get("model_role") != "advisory_research_candidate" \
                or checkpoint.get("promotion_eligible") is not False \
                or checkpoint.get("target_network_evaluation") != "not_performed" \
                or metrics.get("dataset_family") != manifest.get("dataset_family") \
                or metrics.get("checkpoint_sha256") != checkpoint_hash:
            raise ValueError("checkpoint schema mismatch")
        threshold = float(checkpoint.get("threshold", 0.5))
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("invalid calibrated threshold")
        model = _FlowV3AutoencoderClassifier()
        model.load_state_dict(checkpoint["state_dict"])
        model.eval()
        mean = torch.tensor(checkpoint["mean"], dtype=torch.float32)
        std = torch.tensor(checkpoint["std"], dtype=torch.float32)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return {"status": "unavailable", "reason": "Нет совместимого кандидата v3."}

    vectors = []
    scored_protocols = []
    scored_flows = []
    incomplete_count = 0
    for flow in flows:
        if not flow.get("complete"):
            incomplete_count += 1
            continue
        try:
            # from_live_flow returns the current schema; v3 was trained on the
            # preserved first eight features only.
            vectors.append(from_live_flow(flow)[:len(FLOW_V3_FEATURE_NAMES)])
            scored_protocols.append(str(flow.get("protocol", "OTHER")).upper())
            scored_flows.append(flow)
        except (ValueError, TypeError):
            incomplete_count += 1
    if not vectors:
        return {"status": "insufficient_complete_flows", "scored_flows": 0,
                "incomplete_flows": incomplete_count,
                "checkpoint_sha256": checkpoint_hash,
                "feature_version": FLOW_V3_VERSION,
                "dataset_manifest_sha256": manifest_hash,
                "threshold": threshold,
                "reason": "В сегменте нет полностью наблюдённых потоков."}
    values = (torch.tensor(vectors, dtype=torch.float32) - mean) / torch.where(
        std.abs() < 1e-6, torch.ones_like(std), std)
    inference_started = time.perf_counter()
    with torch.no_grad():
        probabilities = torch.softmax(model(values)[1], dim=1)[:, 1]
    inference_latency_ms = (time.perf_counter() - inference_started) * 1000.0
    threshold_count = int((probabilities >= threshold).sum().item())
    flow_scores = [
        {"score": float(score), "is_udp": protocol == "UDP",
         "verdict": "REVIEW" if float(score) >= threshold else "ALLOW",
         "completion_reason": flow.get("completion_reason", "complete")}
        for score, protocol, flow in zip(probabilities.tolist(), scored_protocols, scored_flows)
    ]
    evaluation = checkpoint.get("evaluation", {})
    return {
        "status": "recommendation_candidate",
        "model": "IntegrityGuard per-flow classifier v3 (public-source labels)",
        "feature_version": FLOW_V3_VERSION,
        "scored_flows": len(vectors),
        "inference_latency_ms": round(inference_latency_ms, 3),
        "incomplete_flows": incomplete_count,
        "attack_candidates_at_0_5": int((probabilities >= 0.5).sum().item()),
        "attack_candidates_at_threshold": threshold_count,
        "threshold": threshold,
        "mean_attack_probability": round(float(probabilities.mean().item()), 4),
        "max_attack_probability": round(float(probabilities.max().item()), 4),
        "flow_scores": flow_scores,
        "label_provenance": metrics.get("label_provenance"),
        "dataset_family": manifest.get("dataset_family"),
        "training_captures": checkpoint.get("train_captures", []),
        "validation_capture": checkpoint.get("validation_capture"),
        "independent_test_captures": checkpoint.get("independent_test_captures", []),
        "dataset_manifest_sha256": manifest_hash,
        "checkpoint_sha256": checkpoint_hash,
        "independent_test_metrics": evaluation,
        "per_capture_metrics": metrics.get("independent_test", {}).get("per_capture", {}),
        "promotion_eligible": False,
        "advisory_only": True,
        "enforcement_applied": False,
    }


def source_labeled_candidate_status(checkpoint_path: Path) -> dict:
    """Return provenance and independent-capture metrics for the live-flow model."""
    checkpoint_path = Path(checkpoint_path)
    try:
        checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
        manifest_path = checkpoint_path.with_name("network_flow_v3_candidate_manifest.json")
        manifest_bytes = manifest_path.read_bytes()
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        metrics_path = checkpoint_path.with_name("network_flow_v3_candidate_metrics.json")
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        checkpoint_hash = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        if checkpoint.get("feature_version") != FLOW_V3_VERSION \
                or checkpoint.get("features") != list(FLOW_V3_FEATURE_NAMES) \
                or checkpoint.get("classes") != ["benign", "attack"] \
                or checkpoint.get("dataset_manifest_sha256") != manifest_hash \
                or metrics.get("dataset_family") != manifest.get("dataset_family") \
                or metrics.get("checkpoint_sha256") != checkpoint_hash:
            raise ValueError("candidate/provenance mismatch")
        return {
            "status": "available",
            "dataset_family": manifest.get("dataset_family"),
            "label_provenance": metrics.get("label_provenance"),
            "train_captures": checkpoint.get("train_captures", []),
            "validation_capture": checkpoint.get("validation_capture"),
            "independent_test_captures": checkpoint.get("independent_test_captures", []),
            "threshold": checkpoint.get("threshold"),
            "independent_test_metrics": checkpoint.get("evaluation", {}),
            "per_capture_metrics": metrics.get("independent_test", {}).get("per_capture", {}),
            "checkpoint_sha256": checkpoint_hash,
            "dataset_manifest_sha256": manifest_hash,
            "promotion_eligible": checkpoint.get("promotion_eligible") is True,
            "target_network_evaluation": metrics.get(
                "target_network_evaluation", checkpoint.get("target_network_evaluation")),
            "target_network_metrics": metrics.get("target_network_metrics", {}),
            "target_sensor_validation": metrics.get("target_sensor_validation", {}),
            "operational_performance": metrics.get("operational_performance", {}),
            "firewall_validation": metrics.get("firewall_validation", {}),
        }
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"status": "unavailable", "reason": "Модель или provenance manifest не прошли проверку."}

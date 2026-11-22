"""Experimental host-telemetry classifier trained from evidence-attached labels.

The model recommends ALLOW/BLOCK from complete human adjudications. The ledger
checks attached-file integrity but does not authenticate the source; this model
is separate from the packet-flow release candidate. When evidence or a class is
missing, it abstains with REVIEW. It never changes Windows Firewall rules.
"""
from __future__ import annotations

from pathlib import Path

_DECISIONS = ("ALLOW", "BLOCK")
FEATURE_VERSION = 4  # added four threat-signal features
LABEL_SOURCE = "evidence_attached_single_adjudicator_host_snapshot_v1"
# Firewall enforcement is deliberately separate from model recommendations.
FEATURE_NAMES = (
    # --- original 22 features ---
    "active_connection_count", "remote_endpoint_count", "established_count",
    "listen_count", "other_state_count", "new_remote_endpoint_count",
    "new_connection_count", "bytes_received_per_second", "bytes_sent_per_second",
    "distinct_process_count", "mean_connections_per_endpoint",
    "max_connections_per_endpoint", "total_remote_port_diversity",
    "max_remote_port_diversity", "unattributed_endpoint_share", "udp_endpoint_share",
    "non_https_endpoint_share", "syn_sent_count", "time_wait_count", "reset_count",
    "packet_rate_zscore", "byte_rate_zscore",
    # --- 4 new threat-signal features (v4) ---
    "suspicious_port_match_count",   # endpoints hitting known backdoor/C2 ports
    "port_scan_suspected_count",     # endpoints with unusually many distinct ports
    "public_endpoint_share",         # fraction of remote IPs that are globally routable
    "blocked_state_ratio",           # (TIME_WAIT + RESET) / max(active_connections, 1)
)
MODEL_NAME_UNTRAINED = "network_classifier(untrained)"


def extract_features(snapshot: dict) -> dict:
    """Fixed, named feature vector for one NetworkTelemetry.sample()-shaped snapshot
    (the same dict the "network_status" tool returns -- includes threat_intelligence
    once that tool has run). Pure function, no I/O: safe to call every cycle for
    free, and this is exactly the shape a future training table will be built from.
    """
    if not isinstance(snapshot, dict):
        snapshot = {}
    states = snapshot.get("connection_state_counts") or {}
    new_remote = snapshot.get("new_remote_endpoints_since_previous_sample")
    endpoints = [item for item in snapshot.get("remote_endpoints") or [] if isinstance(item, dict)]
    endpoint_count = len(endpoints)
    connection_counts = [float(item.get("connection_count") or 0) for item in endpoints]
    remote_port_counts = [float(item.get("distinct_remote_ports") or 0) for item in endpoints]
    new_connection_count = sum(float(item.get("new_connections_since_previous_sample") or 0)
                               for item in endpoints)
    unattributed = sum(not item.get("process_names") for item in endpoints)
    udp_endpoints = sum("udp" in {str(proto).lower() for proto in item.get("protocols") or []}
                        for item in endpoints)
    non_https = sum(any(int(port) not in (80, 443) for port in (item.get("remote_ports_sample") or [])
                        if str(port).isdigit()) for item in endpoints)
    recv_rate = sent_rate = 0.0
    for interface in snapshot.get("interfaces") or []:
        if not isinstance(interface, dict):
            continue
        rate = interface.get("rate") or {}
        recv_rate += float(rate.get("bytes_received_per_second") or 0)
        sent_rate += float(rate.get("bytes_sent_per_second") or 0)
    anomaly = snapshot.get("traffic_anomaly") or {}
    packet_z = anomaly.get("packet_rate_zscore")
    byte_z = anomaly.get("byte_rate_zscore")
    return {
        "active_connection_count": float(snapshot.get("active_connection_count") or 0),
        "remote_endpoint_count": float(snapshot.get("remote_endpoint_count") or 0),
        "established_count": float(states.get("ESTABLISHED", 0)),
        "listen_count": float(states.get("LISTEN", 0)),
        "other_state_count": float(sum(v for k, v in states.items() if k not in ("ESTABLISHED", "LISTEN"))),
        "new_remote_endpoint_count": float(new_remote) if isinstance(new_remote, (int, float)) else 0.0,
        "new_connection_count": new_connection_count,
        "bytes_received_per_second": recv_rate,
        "bytes_sent_per_second": sent_rate,
        "distinct_process_count": float(snapshot.get("distinct_process_count") or 0),
        "mean_connections_per_endpoint": sum(connection_counts) / max(endpoint_count, 1),
        "max_connections_per_endpoint": max(connection_counts, default=0.0),
        "total_remote_port_diversity": sum(remote_port_counts),
        "max_remote_port_diversity": max(remote_port_counts, default=0.0),
        "unattributed_endpoint_share": unattributed / max(endpoint_count, 1),
        "udp_endpoint_share": udp_endpoints / max(endpoint_count, 1),
        "non_https_endpoint_share": non_https / max(endpoint_count, 1),
        "syn_sent_count": float(states.get("SYN_SENT", 0)),
        "time_wait_count": float(states.get("TIME_WAIT", 0)),
        "reset_count": float(states.get("RESET", 0)),
        "packet_rate_zscore": float(packet_z) if isinstance(packet_z, (int, float)) else 0.0,
        "byte_rate_zscore": float(byte_z) if isinstance(byte_z, (int, float)) else 0.0,
        # v4 threat-signal features
        "suspicious_port_match_count": float(snapshot.get("suspicious_port_match_count") or 0),
        "port_scan_suspected_count": float(snapshot.get("port_scan_suspected_count") or 0),
        "public_endpoint_share": sum(
            1 for item in endpoints if item.get("remote_scope") == "public"
        ) / max(endpoint_count, 1),
        "blocked_state_ratio": (
            float(states.get("TIME_WAIT", 0)) + float(states.get("RESET", 0))
        ) / max(float(snapshot.get("active_connection_count") or 1), 1.0),
    }


ARCH_LEGACY = "mlp16x8"            # checkpoints saved before the "arch" key existed
ARCH_DROPOUT = "mlp16x8_dropout"   # same widths, Dropout(0.3) after each hidden layer
ARCH_WIDE = "mlp64x32x16_dropout"  # wider network for 500+ labeled examples (v4 default)


def build_model(arch: str | None):
    """Single place that defines the student network's shape, shared by the trainer
    and load_checkpoint so the two can never drift apart. Returns None for an
    architecture name this version of the code doesn't know."""
    from torch import nn
    n_in, n_out = len(FEATURE_NAMES), len(_DECISIONS)
    if arch in (None, ARCH_LEGACY):
        return nn.Sequential(nn.Linear(n_in, 16), nn.ReLU(),
                             nn.Linear(16, 8), nn.ReLU(),
                             nn.Linear(8, n_out))
    if arch == ARCH_DROPOUT:
        return nn.Sequential(nn.Linear(n_in, 16), nn.ReLU(), nn.Dropout(0.3),
                             nn.Linear(16, 8), nn.ReLU(), nn.Dropout(0.3),
                             nn.Linear(8, n_out))
    if arch == ARCH_WIDE:
        return nn.Sequential(
            nn.Linear(n_in, 64), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(64, 32), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, n_out),
        )
    return None


def load_checkpoint(path: Path):
    """Returns a loaded, ready-to-use checkpoint dict (with a live torch model under
    "_model"), or None if no checkpoint exists yet, or if one exists but doesn't
    match this module's current FEATURE_VERSION (features changed since it was
    trained -- never silently run a stale-shaped model)."""
    path = Path(path)
    if not path.exists():
        return None
    import torch
    try:
        checkpoint = torch.load(path, weights_only=False)
    except Exception:  # noqa: BLE001 — corrupt/partial checkpoint file
        return None
    if not isinstance(checkpoint, dict) or checkpoint.get("feature_version") != FEATURE_VERSION \
            or checkpoint.get("label_source") != LABEL_SOURCE:
        return None
    if checkpoint.get("feature_names") != list(FEATURE_NAMES):
        return None
    classes = checkpoint.get("classes") or []
    if classes != list(_DECISIONS):
        return None
    counts = checkpoint.get("class_counts") or {}
    if any(not isinstance(counts.get(label), (int, float)) or counts[label] <= 0
           for label in _DECISIONS):
        return None
    model = build_model(checkpoint.get("arch"))
    if model is None:
        return None
    try:
        model.load_state_dict(checkpoint["state_dict"])
    except Exception:  # noqa: BLE001 — shape mismatch despite matching version
        return None
    model.eval()
    checkpoint["_model"] = model
    return checkpoint


def assess_network_with_classifier(snapshot: dict, app_state: dict, checkpoint_path: Path) -> dict:
    """Score one real telemetry snapshot with the local network classifier.

    Returns the model recommendation. It never edits Windows Firewall rules.
    """
    features = extract_features(snapshot)
    evidence_ids = [item["id"] for item in snapshot.get("remote_endpoints", [])
                    if isinstance(item, dict) and isinstance(item.get("id"), str)]
    evidence_ids.append("network_visibility")
    if app_state:
        evidence_ids.append("application_state")
    evidence_ids = list(dict.fromkeys(evidence_ids))[:3]
    checkpoint = load_checkpoint(Path(checkpoint_path))
    if checkpoint is None:
        return {
            "decision": "REVIEW", "model_decision": "REVIEW",
            "summary": ("Локальный классификатор сетевого трафика ещё не обучен (нет подходящего "
                       "чекпойнта для текущей версии признаков). Решение не выносится; "
                       "проверяйте события вручную."),
            "evidence_ids": evidence_ids, "insufficient_evidence": True,
            "model": MODEL_NAME_UNTRAINED, "advisory_only": True,
            "enforcement_applied": False,
            "features": features, "feature_version": FEATURE_VERSION,
        }

    import torch

    mean = checkpoint.get("mean") or [0.0] * len(FEATURE_NAMES)
    std = checkpoint.get("std") or [1.0] * len(FEATURE_NAMES)
    vector = [(features[name] - mean[i]) / (std[i] or 1.0) for i, name in enumerate(FEATURE_NAMES)]
    with torch.no_grad():
        logits = checkpoint["_model"](torch.tensor([vector], dtype=torch.float32))
        probabilities = torch.softmax(logits, dim=1)[0].tolist()
    p_allow, p_block = probabilities
    allow_threshold = float(checkpoint.get("allow_threshold", 0.10))
    block_threshold = float(checkpoint.get("block_threshold", 0.90))
    raw_decision = "BLOCK" if p_block >= block_threshold else \
        "ALLOW" if p_block <= allow_threshold else "REVIEW"
    class_counts = checkpoint.get("class_counts") or {}
    n_samples = checkpoint.get("n_samples", 0)

    decision = raw_decision
    summary = (
        f"Рекомендация сетевого классификатора: {raw_decision} "
        f"(p угрозы {p_block:.0%}; пороги ALLOW≤{allow_threshold:.0%}, BLOCK≥{block_threshold:.0%}). "
        f"Подтверждённые снимки: ALLOW={class_counts.get('ALLOW', 0)}, "
        f"BLOCK={class_counts.get('BLOCK', 0)}. "
        "Рекомендация не меняет правила Windows Firewall. "
        f"{checkpoint.get('caveat', '')}"
    )

    return {
        "decision": decision, "model_decision": raw_decision,
        "summary": summary, "evidence_ids": evidence_ids, "insufficient_evidence": False,
        "model": f"network_classifier(recommendation,n={n_samples})",
        "advisory_only": True,
        "enforcement_applied": False,
        "features": features, "feature_version": FEATURE_VERSION,
        "class_probabilities": {"ALLOW": round(p_allow, 3), "BLOCK": round(p_block, 3)},
        "trained_at_utc": checkpoint.get("trained_at_utc"),
    }

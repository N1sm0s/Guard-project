from integrityguard.network_classifier import (
    FEATURE_NAMES,
    MODEL_NAME_UNTRAINED,
    assess_network_with_classifier,
    extract_features,
    load_checkpoint,
)


def test_extract_features_on_empty_snapshot_is_all_zero():
    features = extract_features({})
    assert set(features) == set(FEATURE_NAMES)
    assert all(v == 0.0 for v in features.values())


def test_extract_features_on_none_does_not_raise():
    features = extract_features(None)
    assert all(v == 0.0 for v in features.values())


def test_extract_features_reads_real_snapshot_shape():
    snapshot = {
        "active_connection_count": 12, "remote_endpoint_count": 3,
        "connection_state_counts": {"ESTABLISHED": 5, "LISTEN": 2, "TIME_WAIT": 1},
        "new_remote_endpoints_since_previous_sample": 1,
        # Threat-intelligence matches are context only and are not model labels/features.
        "threat_intelligence": {"matches": [{"targets_reported": 42}, {"targets_reported": 7}]},
        "interfaces": [{"rate": {"bytes_received_per_second": 100.0, "bytes_sent_per_second": 10.0}},
                       {"rate": {"bytes_received_per_second": 50.0, "bytes_sent_per_second": 5.0}}],
    }
    features = extract_features(snapshot)
    assert features["active_connection_count"] == 12.0
    assert features["remote_endpoint_count"] == 3.0
    assert features["established_count"] == 5.0
    assert features["listen_count"] == 2.0
    assert features["other_state_count"] == 1.0
    assert features["new_remote_endpoint_count"] == 1.0
    assert not any(name.startswith("dshield_") for name in features)
    assert features["bytes_received_per_second"] == 150.0
    assert features["bytes_sent_per_second"] == 15.0


def test_extract_features_reads_process_port_and_anomaly_fields():
    snapshot = {
        "distinct_process_count": 4, "suspicious_port_match_count": 2,
        "port_scan_suspected_count": 1,
        "traffic_anomaly": {"packet_rate_zscore": 3.5, "byte_rate_zscore": None},
    }
    features = extract_features(snapshot)
    assert features["distinct_process_count"] == 4.0
    assert features["suspicious_port_match_count"] == 2.0
    assert features["port_scan_suspected_count"] == 1.0
    assert features["packet_rate_zscore"] == 3.5
    assert features["byte_rate_zscore"] == 0.0  # None (not enough baseline yet) -> 0.0, not NaN/raise


def test_extract_features_handles_baseline_sample_sentinel():
    # new_remote_endpoints_since_previous_sample can be the string "baseline_sample"
    # on the very first sample -- must not raise or coerce it into a number.
    features = extract_features({"new_remote_endpoints_since_previous_sample": "baseline_sample"})
    assert features["new_remote_endpoint_count"] == 0.0


def test_load_checkpoint_missing_path_returns_none(tmp_path):
    assert load_checkpoint(tmp_path / "does_not_exist.pt") is None


def test_assess_without_checkpoint_never_fabricates_a_verdict(tmp_path):
    snapshot = {"active_connection_count": 1, "remote_endpoint_count": 0, "remote_endpoints": []}
    result = assess_network_with_classifier(snapshot, {}, tmp_path / "missing.pt")
    assert result["decision"] == "REVIEW"
    assert result["model_decision"] == "REVIEW"
    assert result["insufficient_evidence"] is True
    assert result["model"] == MODEL_NAME_UNTRAINED
    assert result["advisory_only"] is True
    assert result["enforcement_applied"] is False
    assert "не обучен" in result["summary"]


def test_assess_evidence_ids_capped_and_deduplicated(tmp_path):
    snapshot = {"remote_endpoints": [{"id": "a"}, {"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}]}
    result = assess_network_with_classifier(snapshot, {"ok": True}, tmp_path / "missing.pt")
    assert len(result["evidence_ids"]) <= 3
    assert len(set(result["evidence_ids"])) == len(result["evidence_ids"])


def test_assess_result_is_json_serializable(tmp_path):
    import json
    snapshot = {"active_connection_count": 1, "remote_endpoints": []}
    result = assess_network_with_classifier(snapshot, {}, tmp_path / "missing.pt")
    json.dumps(result, ensure_ascii=False)  # must not raise


def test_load_checkpoint_rejects_wrong_feature_version(tmp_path):
    import torch
    from torch import nn
    path = tmp_path / "stale.pt"
    model = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 16), nn.ReLU(),
                           nn.Linear(16, 8), nn.ReLU(), nn.Linear(8, 3))
    torch.save({"feature_version": -1, "classes": ["ALLOW", "REVIEW", "BLOCK"],
               "state_dict": model.state_dict(), "mean": [0.0] * len(FEATURE_NAMES),
               "std": [1.0] * len(FEATURE_NAMES)}, path)
    assert load_checkpoint(path) is None


def test_assess_rejects_legacy_three_class_checkpoint(tmp_path):
    """Old model decisions are not compatible with the reviewed binary schema."""
    import torch
    from torch import nn
    path = tmp_path / "trained.pt"
    model = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 16), nn.ReLU(),
                           nn.Linear(16, 8), nn.ReLU(), nn.Linear(8, 3))
    # Bias the final layer hard toward the BLOCK class (index 2) regardless of input.
    with torch.no_grad():
        model[-1].bias.fill_(0.0)
        model[-1].bias[2] = 50.0
    torch.save({
        "feature_version": __import__("integrityguard.network_classifier",
                                      fromlist=["FEATURE_VERSION"]).FEATURE_VERSION,
        "classes": ["ALLOW", "REVIEW", "BLOCK"], "state_dict": model.state_dict(),
        "mean": [0.0] * len(FEATURE_NAMES), "std": [1.0] * len(FEATURE_NAMES),
        "n_samples": 50, "class_counts": {"ALLOW": 30, "REVIEW": 19, "BLOCK": 1},
        "caveat": "test checkpoint",
    }, path)
    snapshot = {"active_connection_count": 1, "remote_endpoints": []}
    result = assess_network_with_classifier(snapshot, {}, path)
    assert result["model_decision"] == "REVIEW"
    assert result["decision"] == "REVIEW"
    assert result["insufficient_evidence"] is True
    assert result["enforcement_applied"] is False
    assert result["advisory_only"] is True

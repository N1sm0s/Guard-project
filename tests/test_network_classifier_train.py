from integrityguard.network_classifier import (
    FEATURE_NAMES,
    assess_network_with_classifier,
    load_checkpoint,
)
from integrityguard.network_classifier_train import train
from integrityguard.network_evidence import NetworkEventLog


def _snapshot(active_connection_count: float) -> dict:
    return {
        "observed_at_utc": "2026-01-01T00:00:00+00:00",
        "interfaces": [], "remote_endpoints": [], "new_remote_endpoints": [],
        "active_connection_count": active_connection_count, "remote_endpoint_count": 0,
        "connection_state_counts": {},
    }


def test_train_skips_when_too_few_labeled_examples(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    event_log.capture(_snapshot(1), assessment={"model_decision": "ALLOW"}, source="test")
    summary = train(event_log, tmp_path / "model.pt", min_samples=8)
    assert summary["skipped"] is True
    assert summary["n_samples"] == 0
    assert summary["reason"] == "insufficient_evidence_attached_labels"
    assert not (tmp_path / "model.pt").exists()


def test_train_skips_when_only_one_class_present(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    for i in range(10):
        event_log.capture(_snapshot(i), assessment={"model_decision": "ALLOW"}, source="test")
    summary = train(event_log, tmp_path / "model.pt", min_samples=8)
    assert summary["skipped"] is True
    assert summary["reason"] == "insufficient_evidence_attached_labels"


def test_train_does_not_learn_from_historical_model_decisions(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    decisions = (["ALLOW"] * 6) + (["REVIEW"] * 4) + ["BLOCK"]
    for i, decision in enumerate(decisions):
        event_log.capture(_snapshot(i), assessment={"model_decision": decision}, source="test")
    checkpoint_path = tmp_path / "model.pt"
    summary = train(event_log, checkpoint_path, min_samples=8)
    assert summary["skipped"] is True
    assert summary["reason"] == "insufficient_evidence_attached_labels"
    assert summary["n_samples"] == 0
    assert not checkpoint_path.exists()


def test_train_ignores_events_with_unlabeled_or_unknown_decision(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    event_log.capture(_snapshot(1), assessment=None, source="test")  # no assessment at all
    event_log.capture(_snapshot(2), assessment={"model_decision": "NOT_A_REAL_DECISION"}, source="test")
    summary = train(event_log, tmp_path / "model.pt", min_samples=1)
    assert summary["n_samples"] == 0
    assert summary["skipped"] is True



def test_train_reports_no_heldout_metrics_when_too_few_examples_to_split(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    for i, decision in enumerate((["ALLOW"] * 6) + (["REVIEW"] * 4) + ["BLOCK"]):
        event_log.capture(_snapshot(i), assessment={"model_decision": decision}, source="test")
    summary = train(event_log, tmp_path / "model.pt", min_samples=8)
    assert summary["skipped"] is True
    assert summary["reason"] == "insufficient_evidence_attached_labels"
    assert summary["n_samples"] == 0


def test_train_refuses_unreviewed_labels_even_when_they_are_separable(tmp_path):
    event_log = NetworkEventLog(tmp_path / "events.sqlite")
    # Separable by construction: ALLOW low, REVIEW mid, BLOCK high connection counts.
    plan = [("ALLOW", 0, 30), ("REVIEW", 100, 15), ("BLOCK", 300, 5)]
    for decision, base, count in plan:
        for i in range(count):
            event_log.capture(_snapshot(base + i), assessment={"model_decision": decision},
                              source="test")
    checkpoint_path = tmp_path / "model.pt"
    summary = train(event_log, checkpoint_path, min_samples=8)

    assert summary["skipped"] is True
    assert summary["reason"] == "insufficient_evidence_attached_labels"
    assert summary["n_samples"] == 0
    assert not checkpoint_path.exists()

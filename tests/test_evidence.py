import hashlib
import io
import json
import sqlite3
from unittest.mock import patch

import numpy as np
import torch

from integrityguard.evidence import EvidenceStore
from integrityguard.audit_reviews import AuditReviews
from integrityguard.online_learn import confirm, list_pending, maybe_queue


class AlwaysAudit:
    @staticmethod
    def random():
        return 0.0

    @staticmethod
    def integers(_low, _high):
        return 123


def test_evidence_links_model_event_features_and_human_label(tmp_path):
    db_path = tmp_path / "registry" / "evidence.sqlite"
    store = EvidenceStore(db_path)
    store.register_model("model-hash", tmp_path / "detector.pt", {"threshold": 0.7})
    event = {"event_id": "event-1", "time": "2026-11-11T10:00:00+00:00", "package": "pkg",
             "version": "2", "fingerprint": "pkg-hash", "verdict": "REVIEW",
             "analysis_mode": "reference_missing", "model_sha256": "model-hash"}
    store.record_event(event)
    store.record_event(event)
    features = {"x": torch.arange(6, dtype=torch.float32).reshape(2, 3),
                "adj": torch.eye(2), "layers": torch.ones((1, 4)), "behav": torch.zeros(3)}
    feature_sha = store.record_features("event-1", features)
    store.confirm_label("event-1", True, reviewer="operator-a")
    store.confirm_label("event-1", False, reviewer="operator-a")

    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM model_versions").fetchone()[0] == 1
        metadata = json.loads(db.execute("SELECT metadata_json FROM model_versions").fetchone()[0])
        assert metadata == {"threshold": 0.7}
        assert "state" not in metadata
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        row = db.execute("SELECT feature_sha256,feature_schema,feature_blob FROM feature_observations").fetchone()
        assert row[0] == feature_sha == hashlib.sha256(row[2]).hexdigest()
        assert json.loads(row[1])["x"]["shape"] == [2, 3]
        with np.load(io.BytesIO(row[2]), allow_pickle=False) as arrays:
            np.testing.assert_array_equal(arrays["x"], features["x"].numpy())
        labels = db.execute("SELECT label FROM confirmed_labels ORDER BY confirmed_at").fetchall()
        assert {item[0] for item in labels} == {"attack", "benign"}


def test_audit_feedback_persists_feature_and_label_provenance(tmp_path):
    data_root = tmp_path / "data"
    store = EvidenceStore(tmp_path / "registry" / "evidence.sqlite")
    fingerprint = "a" * 64
    event = {"event_id": "audit-event", "time": "2026-11-11T10:00:00+00:00", "package": "pkg",
             "version": "1", "fingerprint": fingerprint, "verdict": "REVIEW", "model_sha256": "model"}
    store.record_event(event)
    features = {"x": torch.ones((2, 3)), "adj": torch.eye(2),
                "layers": torch.ones((1, 4)), "behav": torch.zeros(5)}
    item_id = maybe_queue(data_root, event, features, AlwaysAudit(), store.path)
    item = next(item for item in list_pending(data_root) if item["id"] == item_id)
    assert item["event_id"] == "audit-event"
    assert item["model_sha256"] == "model"
    assert item["feature_sha256"]

    evidence_path = tmp_path / "primary-source.txt"
    evidence_path.write_text("Independently reviewed evidence for the labelled artifact.", encoding="utf-8")
    rationale = "The primary source identifies this artifact and documents the observed issue."
    reviews = AuditReviews(data_root / "online" / "label_reviews.sqlite")
    with patch("integrityguard.audit_reviews.reviewer_identity", return_value="reviewer-a"):
        first_review = reviews.propose("audit-event", fingerprint, True, evidence_path, rationale)
    assert first_review["accepted"] is False
    with patch("integrityguard.audit_reviews.reviewer_identity", return_value="reviewer-b"):
        confirmed = confirm(data_root, item_id, True, evidence_path=evidence_path, rationale=rationale)
    assert confirmed["bin_y"] == 1.0
    buf = torch.load(data_root / "online" / "confirmed.pt", map_location="cpu", weights_only=True)
    assert buf[0]["_event_id"] == "audit-event"
    assert buf[0]["_fingerprint"] == fingerprint
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT label FROM confirmed_labels WHERE event_id='audit-event'").fetchone()[0] == "attack"


def test_legacy_jsonl_backfill_is_idempotent_and_marks_unknown_provenance(tmp_path):
    event_file = tmp_path / "events.jsonl"
    event_file.write_text(json.dumps({"time": "2026-11-11T10:00:00+00:00", "package": "legacy",
                                     "version": "1", "fingerprint": "old", "verdict": "REVIEW"}) + "\n",
                          encoding="utf-8")
    store = EvidenceStore(tmp_path / "evidence.sqlite")
    assert store.backfill_jsonl(event_file) == 1
    assert store.backfill_jsonl(event_file) == 0
    with sqlite3.connect(store.path) as db:
        event_id, event_json, model_hash = db.execute(
            "SELECT event_id,event_json,model_sha256 FROM events").fetchone()
    event = json.loads(event_json)
    assert event_id.startswith("legacy-")
    assert event["evidence_origin"] == "legacy_jsonl"
    assert model_hash is None


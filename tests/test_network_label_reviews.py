"""Evidence-attached adjudication mechanics for live network telemetry.

These tests cover event/flow binding, evidence-file integrity, a single
accountable operator, conflict handling, and status reporting. The text fixture
is test-only and does not establish real label quality.
"""
import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import psutil

from integrityguard import network_label_reviews as nlr
from integrityguard.network_telemetry import NetworkTelemetry
from integrityguard.network_evidence import NetworkEventLog
from integrityguard.network_label_reviews import NetworkLabelReviews

RATIONALE = "Smoke-test review: single real telemetry observation, no corroborating signal beyond this note."


class NetworkLabelReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        tmp = Path(self.temp.name)
        self.events = NetworkEventLog(tmp / "network_events.sqlite")
        snapshot = NetworkTelemetry().sample(psutil)
        self.event_id = self.events.capture(snapshot)
        stored = self.events.get(self.event_id)
        self.snapshot_sha256 = stored["snapshot_sha256"]
        flows = stored["snapshot"].get("remote_endpoints", [])
        if not flows:
            self.skipTest("no live remote flows observed on this machine right now")
        self.flow_id = flows[0]["id"]
        self.evidence = tmp / "evidence.txt"
        self.evidence.write_text("Observed one real flow during an automated test run; no further corroboration.",
                                 encoding="utf-8")
        self.store = NetworkLabelReviews(tmp / "network_label_reviews.sqlite")

    def propose(self, is_malicious=False):
        return self.store.propose(self.event_id, self.flow_id, self.snapshot_sha256, is_malicious,
                                  self.evidence, RATIONALE)

    def test_one_accountable_operator_with_attached_artifact_is_recorded(self):
        decision = self.propose()
        self.assertTrue(decision["accepted"])
        self.assertEqual(decision["status"], "evidence_attached_adjudication")
        self.assertEqual(decision["label"], 0)

    def test_repeated_submission_by_one_account_is_still_one_adjudication(self):
        self.propose()
        decision = self.propose()
        self.assertTrue(decision["accepted"])
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0], 2)

    def test_repeat_submission_from_one_account_updates_same_adjudication(self):
        self.propose(is_malicious=False)
        decision = self.propose(is_malicious=False)
        self.assertTrue(decision["accepted"])
        self.assertEqual(decision["status"], "evidence_attached_adjudication")
        self.assertEqual(decision["label"], 0)

    def test_conflicting_evidence_backed_adjudications_are_disputed(self):
        self.propose(is_malicious=False)
        with mock.patch.object(nlr, "reviewer_identity", return_value="second-reviewer-account"):
            decision = self.propose(is_malicious=True)
        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["status"], "disputed")
        self.assertIsNone(decision["label"])

    def test_missing_fingerprint_rejected(self):
        with self.assertRaises(ValueError):
            self.store.propose(self.event_id, self.flow_id, "not-a-sha256", False, self.evidence, RATIONALE)

    def test_missing_rationale_rejected(self):
        with self.assertRaises(ValueError):
            self.store.propose(self.event_id, self.flow_id, self.snapshot_sha256, False, self.evidence, "too short")

    def test_application_verdict_is_not_ground_truth(self):
        self.evidence.write_text("GUI label: ALLOW\\nNo threat signals detected.", encoding="utf-8")
        decision = self.propose(is_malicious=False)
        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["status"], "invalid_evidence")
        self.assertEqual(self.store.adjudicated_snapshot_labels(self.events), [])

    def test_status_counts_reflects_mixed_outcomes(self):
        counts = self.store.status_counts()
        self.assertEqual(counts, {"items": 0, "awaiting_evidence": 0, "disputed": 0,
                                  "evidence_attached_adjudication": 0, "invalid_evidence": 0})
        self.propose(is_malicious=False)
        counts = self.store.status_counts()
        self.assertEqual(counts["items"], 1)
        self.assertEqual(counts["evidence_attached_adjudication"], 1)
        self.assertEqual(counts["awaiting_evidence"], 0)

    def test_evidence_blob_preserved_and_hash_verified(self):
        self.propose()
        with closing(sqlite3.connect(self.store.path)) as db:
            sha, content = db.execute("SELECT evidence_sha256,evidence FROM reviews").fetchone()
        self.assertEqual(content, self.evidence.read_bytes())
        self.assertEqual(hashlib.sha256(content).hexdigest(), sha)


if __name__ == "__main__":
    unittest.main()

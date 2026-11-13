"""Two-reviewer agreement mechanics for real network-flow labeling.

Mirrors tests/test_audit_reviews_real.py's approach, applied to
NetworkLabelReviews and keyed to a real NetworkTelemetry.sample() snapshot
captured via NetworkEventLog (not a hand-built flow). No real incident
catalog of confirmed-malicious traffic exists for this project yet, so these
tests verify the review mechanics themselves -- evidence integrity, the
one-account-cannot-confirm-twice rule, two-distinct-accounts agreement, and
disagreement reporting -- rather than any specific real verdict. Simulating
a second reviewer account is unavoidable in an automated test (only one OS
account is available here), done by monkeypatching reviewer_identity() for
that one call; this does not relax the real one-vote-per-account rule the
module itself enforces by OS username.
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
from integrityguard.network_ai import NetworkTelemetry
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

    def test_single_reviewer_is_not_accepted(self):
        decision = self.propose()
        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["status"], "awaiting_independent_review")
        self.assertEqual(decision["reviewer_count"], 1)

    def test_one_account_voting_twice_never_reaches_agreement(self):
        self.propose()
        decision = self.propose()
        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["reviewer_count"], 1)
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0], 2)

    def test_two_distinct_accounts_agreeing_is_verified(self):
        self.propose(is_malicious=False)
        with mock.patch.object(nlr, "reviewer_identity", return_value="second-reviewer-account"):
            decision = self.propose(is_malicious=False)
        self.assertTrue(decision["accepted"])
        self.assertEqual(decision["status"], "verified_local_review")
        self.assertEqual(decision["label"], 0)
        self.assertEqual(decision["reviewer_count"], 2)

    def test_two_distinct_accounts_disagreeing_is_disputed(self):
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

    def test_evidence_blob_preserved_and_hash_verified(self):
        self.propose()
        with closing(sqlite3.connect(self.store.path)) as db:
            sha, content = db.execute("SELECT evidence_sha256,evidence FROM reviews").fetchone()
        self.assertEqual(content, self.evidence.read_bytes())
        self.assertEqual(hashlib.sha256(content).hexdigest(), sha)


if __name__ == "__main__":
    unittest.main()

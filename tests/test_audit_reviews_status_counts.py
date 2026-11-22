"""Unit coverage for AuditReviews.status_counts(), independent of real incident evidence.

tests/test_audit_reviews_real.py exercises propose()/decision() against a real incident
catalog and is skipped now that catalog is gone (see docs: outputs/labeling-readiness
was lost to an unrelated disk cleanup). status_counts() is pure aggregation over
whatever rows exist, so it is tested here with synthetic rows -- this checks the
aggregation mechanics (the dashboard chart's data source), not any real verdict.
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from integrityguard import audit_reviews as ar
from integrityguard.audit_reviews import AuditReviews

FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64
RATIONALE = "Synthetic unit-test rationale, long enough to pass the length check."


class AuditReviewsStatusCountsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        tmp = Path(self.temp.name)
        self.evidence = tmp / "evidence.txt"
        self.evidence.write_text("synthetic evidence content for a unit test", encoding="utf-8")
        self.store = AuditReviews(tmp / "label_reviews.sqlite")

    def test_empty_store_has_zero_counts(self):
        self.assertEqual(self.store.status_counts(),
                         {"items": 0, "awaiting_independent_review": 0,
                          "disputed": 0, "verified_local_review": 0})

    def test_mix_of_awaiting_disputed_and_verified(self):
        # event-a: single reviewer -> awaiting_independent_review
        self.store.propose("event-a", FINGERPRINT_A, True, self.evidence, RATIONALE)

        # event-b: two reviewers agree -> verified_local_review
        self.store.propose("event-b", FINGERPRINT_B, False, self.evidence, RATIONALE)
        with mock.patch.object(ar, "reviewer_identity", return_value="second-reviewer-account"):
            self.store.propose("event-b", FINGERPRINT_B, False, self.evidence, RATIONALE)

        # event-c: two reviewers disagree -> disputed
        self.store.propose("event-c", FINGERPRINT_A, True, self.evidence, RATIONALE)
        with mock.patch.object(ar, "reviewer_identity", return_value="second-reviewer-account"):
            self.store.propose("event-c", FINGERPRINT_A, False, self.evidence, RATIONALE)

        counts = self.store.status_counts()
        self.assertEqual(counts, {"items": 3, "awaiting_independent_review": 1,
                                  "disputed": 1, "verified_local_review": 1})

    def test_repeat_vote_by_same_reviewer_does_not_inflate_items_or_counts(self):
        self.store.propose("event-a", FINGERPRINT_A, True, self.evidence, RATIONALE)
        self.store.propose("event-a", FINGERPRINT_A, True, self.evidence, RATIONALE)
        counts = self.store.status_counts()
        self.assertEqual(counts["items"], 1)
        self.assertEqual(counts["awaiting_independent_review"], 1)


if __name__ == "__main__":
    unittest.main()

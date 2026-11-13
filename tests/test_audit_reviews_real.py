"""Proposed review checks on an existing incident report; no training samples."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from integrityguard.audit_reviews import AuditReviews

ROOT = Path(__file__).resolve().parents[1] / 'outputs/labeling-readiness/primary-evidence'


@unittest.skipUnless((ROOT / 'catalog.json').exists(), 'Real incident evidence required')
class AuditReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        cases = json.loads((ROOT / 'catalog.json').read_text(encoding='utf-8'))['cases']
        self.case = next(c for c in cases if 'archive_evidence' in c)
        self.fingerprint = self.case['archive_evidence']['sha256']
        archive = Path(self.case['archive_evidence']['path'])
        if not archive.exists():
            self.skipTest('Existing real archive unavailable')
        with archive.open('rb') as stream:
            self.assertEqual(hashlib.file_digest(stream, 'sha256').hexdigest(), self.fingerprint)
        self.doc = ROOT / self.case['source_snapshot']
        self.store = AuditReviews(Path(self.temp.name) / 'reviews.sqlite')

    def propose(self):
        return self.store.propose(self.case['case_id'], self.fingerprint, True, self.doc,
                                  'Primary incident report names the affected release; archive association still requires independent review.')

    def test_one_account_cannot_confirm_twice(self):
        self.assertFalse(self.propose()['accepted'])
        decision = self.propose()
        self.assertFalse(decision['accepted'])
        self.assertEqual(decision['reviewer_count'], 1)
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM reviews').fetchone()[0], 2)

    def test_missing_artifact_binding_rejected(self):
        with self.assertRaises(ValueError):
            self.store.propose(self.case['case_id'], '', True, self.doc, 'Evidence requires exact artifact binding.')

    def test_missing_rationale_rejected(self):
        with self.assertRaises(ValueError):
            self.store.propose(self.case['case_id'], self.fingerprint, True, self.doc, '')

    def test_evidence_snapshot_preserved(self):
        self.propose()
        with closing(sqlite3.connect(self.store.path)) as db:
            sha, content = db.execute('SELECT evidence_sha256,evidence FROM reviews').fetchone()
        self.assertEqual(content, self.doc.read_bytes())
        self.assertEqual(hashlib.sha256(content).hexdigest(), sha)

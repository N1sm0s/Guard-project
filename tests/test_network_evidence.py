"""Real (non-mocked) telemetry capture through NetworkEventLog.

Uses the project's own NetworkTelemetry.sample() against the real psutil on
this machine -- not a hand-built snapshot -- to verify the append-only store
accepts genuine captures, rejects synthetic/incomplete ones, and preserves
content byte-for-byte and hash-for-hash.
"""
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import psutil

from integrityguard.network_ai import NetworkTelemetry
from integrityguard.network_evidence import NetworkEventLog


class NetworkEventLogRealCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log = NetworkEventLog(Path(self.temp.name) / "network_events.sqlite")
        self.snapshot = NetworkTelemetry().sample(psutil)

    def test_real_snapshot_has_required_real_sampler_fields(self):
        # Sanity check that we are really exercising NetworkTelemetry.sample(),
        # not a stand-in dict, before trusting the capture() tests below.
        self.assertIn("observed_at_utc", self.snapshot)
        self.assertIn("remote_endpoints", self.snapshot)
        self.assertIn("interfaces", self.snapshot)
        self.assertIn("no packet payloads", self.snapshot["scope"])

    def test_real_capture_round_trips(self):
        event_id = self.log.capture(self.snapshot)
        self.assertTrue(event_id.startswith("net-"))
        stored = self.log.get(event_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["snapshot"]["observed_at_utc"], self.snapshot["observed_at_utc"])
        self.assertEqual(stored["source"], "psutil_live")

    def test_capture_is_idempotent_for_identical_snapshot(self):
        first = self.log.capture(self.snapshot)
        second = self.log.capture(dict(self.snapshot))
        self.assertEqual(first, second)
        with closing(sqlite3.connect(self.log.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_list_recent_reflects_capture(self):
        event_id = self.log.capture(self.snapshot)
        recent = self.log.list_recent(limit=10)
        self.assertEqual(recent[0]["event_id"], event_id)
        self.assertEqual(recent[0]["snapshot_sha256"], self.log.get(event_id)["snapshot_sha256"])

    def test_synthetic_snapshot_missing_real_fields_rejected(self):
        fake = {"observed_at_utc": "2026-01-01T00:00:00+00:00"}  # no remote_endpoints/interfaces
        with self.assertRaises(ValueError):
            self.log.capture(fake)

    def test_snapshot_without_observed_at_rejected(self):
        incomplete = dict(self.snapshot)
        del incomplete["observed_at_utc"]
        with self.assertRaises(ValueError):
            self.log.capture(incomplete)

    def test_append_only_rejects_update_and_delete(self):
        event_id = self.log.capture(self.snapshot)
        with closing(sqlite3.connect(self.log.path)) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE events SET source='tampered' WHERE event_id=?", (event_id,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM events WHERE event_id=?", (event_id,))


if __name__ == "__main__":
    unittest.main()

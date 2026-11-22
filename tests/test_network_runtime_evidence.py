"""Deterministic journal-integrity tests; fixtures are not model evidence."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from integrityguard.network_runtime_evidence import (
    record_captured_flows,
    record_flow_inference,
    record_packet_capture_segment,
    runtime_summary,
)


class RuntimeEvidenceLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "runtime.sqlite"
        self.candidate = "a" * 64
        self.manifest = "b" * 64

    def _record_segment(self, *, complete_count=1, status="parsed_best_effort"):
        capture = {
            "status": status,
            "counts": {"packets": 12, "parsed": 12, "non_ip_frames": 0,
                       "unsupported_or_truncated": 0},
            "capture_interval_seconds": 30,
            "capture_sha256": "c" * 64,
            "complete_flow_count": complete_count,
        }
        return record_packet_capture_segment(
            self.path, observed_at_utc="2026-11-18T10:00:00Z", capture=capture)

    @staticmethod
    def _flows(*, complete=True):
        return [{
            "protocol": "tcp", "originator_ip": "192.0.2.10", "originator_port": 51000,
            "responder_ip": "192.0.2.20", "responder_port": 443,
            "first_seen": 1.0, "last_seen": 2.0, "duration_seconds": 1.0,
            "total_packets": 4, "total_bytes": 512, "direction_a_bytes": 256,
            "direction_b_bytes": 256, "complete": complete, "features": [0.0] * 8,
        }]

    def _record_inference(self, segment_hash, *, scored=1):
        record_flow_inference(
            self.path, observed_at_utc="2026-11-18T10:00:01Z", inference_ms=2.0,
            flows_scored=scored, capture_status="parsed_best_effort", packets_seen=12,
            candidate_sha256=self.candidate, feature_version=3,
            dataset_manifest_sha256=self.manifest, threshold=0.5,
            capture_segment_hash=segment_hash,
        )

    def test_candidate_inference_requires_a_segment_link(self):
        with self.assertRaisesRegex(ValueError, "bound to their capture segment"):
            record_flow_inference(
                self.path, observed_at_utc="2026-11-18T10:00:01Z", inference_ms=2.0,
                flows_scored=1, capture_status="parsed_best_effort",
                candidate_sha256=self.candidate, feature_version=3,
                dataset_manifest_sha256=self.manifest, threshold=0.5,
            )

    def test_candidate_inference_must_reference_a_real_successful_segment(self):
        self._record_segment()
        with self.assertRaisesRegex(ValueError, "not present in the evidence chain"):
            self._record_inference("d" * 64)

    def test_gate_evidence_requires_same_segment_complete_flow_and_candidate(self):
        segment_hash = self._record_segment(complete_count=1)
        record_captured_flows(
            self.path, segment_hash=segment_hash, observed_at_utc="2026-11-18T10:00:00Z",
            flows=self._flows(complete=True),
        )
        self._record_inference(segment_hash)

        result = runtime_summary(self.path)
        self.assertTrue(result["integrity_valid"])
        self.assertTrue(result["capture_integrity_valid"])
        self.assertTrue(result["captured_flow_integrity_valid"])
        self.assertTrue(result["candidate_capture_link_integrity_valid"])
        self.assertEqual(result["candidate_provenance_by_sha256"][self.candidate], 1)
        self.assertEqual(result["candidate_linked_complete_flow_count"], 1)
        self.assertEqual(result["candidate_linked_complete_flows_by_sha256"][self.candidate], 1)
        self.assertEqual(result["candidate_linked_segment_count"], 1)

    def test_incomplete_flow_does_not_satisfy_integration_gate(self):
        segment_hash = self._record_segment(complete_count=0)
        record_captured_flows(
            self.path, segment_hash=segment_hash, observed_at_utc="2026-11-18T10:00:00Z",
            flows=self._flows(complete=False),
        )
        self._record_inference(segment_hash, scored=0)

        result = runtime_summary(self.path)
        self.assertEqual(result["captured_flow_count"], 1)
        self.assertEqual(result["complete_flow_count"], 0)
        self.assertEqual(result["candidate_linked_complete_flow_count"], 0)

    def test_flows_from_incomplete_capture_keep_chain_valid_but_never_qualify(self):
        segment_hash = self._record_segment(complete_count=1, status="incomplete")
        record_captured_flows(
            self.path, segment_hash=segment_hash, observed_at_utc="2026-11-18T10:00:00Z",
            flows=self._flows(complete=True),
        )
        with self.assertRaisesRegex(ValueError, "successfully parsed capture segment"):
            self._record_inference(segment_hash)
        result = runtime_summary(self.path)
        self.assertTrue(result["capture_integrity_valid"])
        self.assertTrue(result["captured_flow_integrity_valid"])
        self.assertEqual(result["captured_flow_count"], 1)
        self.assertEqual(result["complete_flow_count"], 0)
        self.assertEqual(result["incomplete_capture_flow_count"], 1)
        self.assertEqual(result["candidate_linked_complete_flow_count"], 0)

    def test_complete_flows_are_retained_before_incomplete_rows_at_cap(self):
        segment_hash = self._record_segment(complete_count=1)
        flows = self._flows(complete=False) + self._flows(complete=True)
        stored = record_captured_flows(
            self.path, segment_hash=segment_hash, observed_at_utc="2026-11-18T10:00:00Z",
            flows=flows, max_flows=1,
        )
        self.assertEqual(stored["stored_flow_count"], 1)
        self.assertEqual(stored["omitted_flow_count"], 1)
        self._record_inference(segment_hash)
        self.assertEqual(runtime_summary(self.path)["candidate_linked_complete_flow_count"], 1)

    def test_legacy_unlinked_inference_is_valid_but_not_gate_evidence(self):
        record_flow_inference(
            self.path, observed_at_utc="2026-11-18T10:00:01Z", inference_ms=2.0,
            flows_scored=1, capture_status="parsed_best_effort",
        )
        result = runtime_summary(self.path)
        self.assertTrue(result["integrity_valid"])
        self.assertEqual(result["sample_count"], 1)
        self.assertEqual(result["candidate_provenance_samples"], 0)
        self.assertEqual(result["candidate_linked_complete_flow_count"], 0)


if __name__ == "__main__":
    unittest.main()

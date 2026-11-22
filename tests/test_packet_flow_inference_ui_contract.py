"""Contract tests for passing per-flow inference scores into the live UI."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import torch

from integrityguard import network_flow_model


class PacketFlowInferenceUiContractTests(unittest.TestCase):
    def test_assessment_returns_each_complete_flow_score_and_protocol_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            checkpoint_path = root / "network_flow_v3_candidate.pt"
            manifest_path = root / "network_flow_v3_candidate_manifest.json"
            metrics_path = root / "network_flow_v3_candidate_metrics.json"
            manifest = {"dataset_family": "unit-contract"}
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            model = network_flow_model._FlowV3AutoencoderClassifier()
            with torch.no_grad():
                for parameter in model.parameters():
                    parameter.zero_()
                model.classifier.bias[:] = torch.tensor([0.0, 4.0])
            checkpoint = {
                "feature_version": 3,
                "features": list(network_flow_model.FLOW_V3_FEATURE_NAMES),
                "classes": ["benign", "attack"],
                "model_role": "advisory_research_candidate",
                "promotion_eligible": False,
                "target_network_evaluation": "not_performed",
                "dataset_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "threshold": 0.5,
                "mean": [0.0] * len(network_flow_model.FLOW_V3_FEATURE_NAMES),
                "std": [1.0] * len(network_flow_model.FLOW_V3_FEATURE_NAMES),
                "state_dict": model.state_dict(),
                "train_captures": [],
            }
            torch.save(checkpoint, checkpoint_path)
            metrics_path.write_text(json.dumps({
                "dataset_family": "unit-contract", "checkpoint_sha256":
                hashlib.sha256(checkpoint_path.read_bytes()).hexdigest(),
            }), encoding="utf-8")

            flows = [
                {"complete": True, "duration_seconds": 1.0, "total_packets": 2,
                 "total_bytes": 120, "direction_a_bytes": 60, "direction_b_bytes": 60,
                 "protocol": "UDP"},
                {"complete": False, "protocol": "UDP"},
                {"complete": True, "duration_seconds": 1.0, "total_packets": 2,
                 "total_bytes": 120, "direction_a_bytes": 60, "direction_b_bytes": 60,
                 "protocol": "TCP"},
            ]
            result = network_flow_model.assess_completed_packet_flows(flows, checkpoint_path)

        self.assertEqual(result["status"], "recommendation_candidate")
        self.assertEqual(result["scored_flows"], 2)
        self.assertEqual(len(result["flow_scores"]), 2)
        self.assertTrue(result["flow_scores"][0]["is_udp"])
        self.assertEqual(result["flow_scores"][0]["verdict"], "REVIEW")
        self.assertFalse(result["flow_scores"][1]["is_udp"])


if __name__ == "__main__":
    unittest.main()

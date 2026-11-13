"""Permission and network-only behavior of the local operational assistant."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from integrityguard.copilot import answer_with_ollama, is_supported_operational_question
from integrityguard.copilot_tools import COPILOT_READ_CAPABILITIES, TOOL_CAPABILITIES, execute_tool
from integrityguard.network_ai import assess_network_with_ollama


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.payload


class CopilotToolPermissionTests(unittest.TestCase):
    def context(self, capabilities=()):
        return {"principal": "local-test-user", "capabilities": list(capabilities)}

    def test_missing_or_wrong_capability_is_denied(self):
        for name, capability in TOOL_CAPABILITIES.items():
            wrong = next(value for tool, value in TOOL_CAPABILITIES.items() if tool != name)
            for context in (self.context(), self.context({wrong})):
                with self.subTest(tool=name, capability=capability), self.assertRaises(PermissionError):
                    execute_tool(name, {}, context)

    def test_unknown_tool_is_denied_even_with_all_capabilities(self):
        with self.assertRaises(PermissionError):
            execute_tool("arbitrary_file_read", {"path": "C:/secret"},
                         self.context(COPILOT_READ_CAPABILITIES))

    def test_tool_argument_validation_is_strict(self):
        context = self.context({TOOL_CAPABILITIES["network_status"]})
        with self.assertRaises(ValueError):
            execute_tool("network_status", {"path": "C:/secret"}, context)

    def test_malformed_capability_context_is_denied(self):
        for capabilities in (None, "copilot.network.read", [1]):
            context = self.context()
            context["capabilities"] = capabilities
            with self.subTest(capabilities=capabilities), self.assertRaises(PermissionError):
                execute_tool("network_status", {}, context)

    def test_malformed_identity_is_denied(self):
        for principal in ("", "   ", None):
            context = self.context(COPILOT_READ_CAPABILITIES)
            context["principal"] = principal
            with self.subTest(principal=principal), self.assertRaises(PermissionError):
                execute_tool("network_status", {}, context)

    def test_network_status_reads_bounded_real_os_telemetry(self):
        result = execute_tool("network_status", {}, self.context({TOOL_CAPABILITIES["network_status"]}))
        self.assertTrue(result["read_only"])
        self.assertIn("no packet payloads", result["scope"])
        self.assertIsInstance(result["active_connection_count"], int)
        self.assertIn("connection_table_query_succeeded", result)
        self.assertNotIn("connection_visibility_complete", result)
        self.assertLessEqual(len(result["remote_endpoints"]), 40)
        self.assertTrue(all("remote_ip" in flow and "id" in flow for flow in result["remote_endpoints"]))
        self.assertFalse(any("path" in key.lower() for key in result))

    def test_network_status_adds_public_intel_in_gui_enabled_context(self):
        snapshot = {"remote_endpoints": [{"id": "flow-1", "remote_ip": "198.235.24.19"}],
                    "active_connection_count": 1}
        with tempfile.TemporaryDirectory() as temp_dir:
            data_root = Path(temp_dir)
            context = self.context({TOOL_CAPABILITIES["network_status"]})
            context.update(data_root=data_root, network_intel_enabled=True, network_snapshot=snapshot)
            intel = {"source": "DShield", "status": "current", "matches": []}
            with patch("integrityguard.network_threat_intel.lookup_dshield", return_value=intel) as lookup:
                result = execute_tool("network_status", {}, context)
            lookup.assert_called_once_with(snapshot["remote_endpoints"],
                                          data_root / "network_intel" / "dshield_cache.json")
        self.assertIs(result["threat_intelligence"], intel)

    def test_network_questions_route_to_operational_sensor(self):
        self.assertTrue(is_supported_operational_question(
            "Оцени текущий сетевой трафик и состояние функций программы"))
        self.assertFalse(is_supported_operational_question("Какая цель указана в ТЗ?"))

    def test_document_questions_are_declined_without_file_or_model_access(self):
        with patch("urllib.request.urlopen") as urlopen:
            result = answer_with_ollama("Какая цель указана в ТЗ?", "qwen3.5:4b",
                                        tool_context=self.context(COPILOT_READ_CAPABILITIES))
        urlopen.assert_not_called()
        self.assertTrue(result["insufficient_evidence"])
        self.assertIn("сетевой телеметрией", result["answer"])
        self.assertEqual(result["tool_calls"], [])
        self.assertEqual(result["tool_results"], [])

    def test_network_assessment_routes_read_only_sensor_functions(self):
        snapshot = {"remote_endpoints": [{"id": "flow-1", "remote_ip": "192.0.2.10"}],
                    "active_connection_count": 1, "scope": "no packet payloads",
                    "threat_intelligence": {"source": "DShield", "status": "current", "matches": []}}
        app_state = {"automatic_monitoring": True}
        assessment = {"decision": "REVIEW", "summary": "Требуется проверка.",
                      "insufficient_evidence": True, "model": "qwen3.5:4b"}
        context = self.context(COPILOT_READ_CAPABILITIES)
        context["network_snapshot"] = snapshot
        with patch("integrityguard.copilot_tools.execute_tool", side_effect=[snapshot, app_state]) as execute, \
             patch("integrityguard.network_ai.assess_network_with_ollama", return_value=assessment):
            result = answer_with_ollama("Оцени трафик и соединения", "qwen3.5:4b", tool_context=context)
        self.assertEqual(execute.call_count, 2)
        self.assertIn("Рекомендация локальной модели: REVIEW", result["answer"])
        self.assertEqual([item["name"] for item in result["tool_calls"]],
                         ["network_status", "monitoring_status", "network_assessment"])
        self.assertEqual(result["tool_results"][0]["data"]["network_telemetry"]["threat_intelligence"]["source"],
                         "DShield")
        self.assertFalse(result["tool_results"][0]["data"]["ai_assessment"]["decision"] == "BLOCK")

    def test_network_block_is_downgraded_until_real_independent_evaluation(self):
        snapshot = execute_tool("network_status", {}, self.context({TOOL_CAPABILITIES["network_status"]}))
        flow_id = snapshot["remote_endpoints"][0]["id"] if snapshot["remote_endpoints"] else "network_visibility"
        model_response = {"model": "qwen3.5:4b", "message": {"content": json.dumps({
            "decision": "BLOCK", "summary": "Подозрительная активность.",
            "evidence_ids": [flow_id], "insufficient_evidence": False,
        })}}
        with patch("integrityguard.copilot.ensure_ollama_server", return_value=True), \
             patch("urllib.request.urlopen", return_value=_Response(json.dumps(model_response).encode("utf-8"))):
            result = assess_network_with_ollama(snapshot, {"read_only": True}, "qwen3.5:4b")
        self.assertEqual(result["model_decision"], "BLOCK")
        self.assertEqual(result["decision"], "REVIEW")
        self.assertFalse(result["enforcement_applied"])

    def test_network_block_recommendation_is_fail_safe_without_flow_evidence(self):
        snapshot = {"remote_endpoints": [], "connection_table_query_succeeded": True,
                    "interface_counters_available": True, "active_connection_count": 0}
        model_response = {"model": "qwen3.5:4b", "message": {"content": json.dumps({
            "decision": "BLOCK", "summary": "Нужно блокировать.",
            "evidence_ids": ["application_state"], "insufficient_evidence": False,
        })}}
        with patch("integrityguard.copilot.ensure_ollama_server", return_value=True), \
             patch("urllib.request.urlopen", return_value=_Response(json.dumps(model_response).encode("utf-8"))):
            result = assess_network_with_ollama(snapshot, {"read_only": True}, "qwen3.5:4b")
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["model_decision"], "BLOCK")
        self.assertIn("не проверен", result["summary"])
        self.assertFalse(result["enforcement_applied"])

    def test_allow_with_insufficient_evidence_is_downgraded_to_review(self):
        snapshot = {"remote_endpoints": [], "connection_table_query_succeeded": True,
                    "interface_counters_available": True, "active_connection_count": 0}
        model_response = {"model": "qwen3.5:4b", "message": {"content": json.dumps({
            "decision": "ALLOW", "summary": "Доказательств недостаточно.",
            "evidence_ids": ["network_visibility"], "insufficient_evidence": True,
        })}}
        with patch("integrityguard.copilot.ensure_ollama_server", return_value=True), \
             patch("urllib.request.urlopen", return_value=_Response(json.dumps(model_response).encode("utf-8"))):
            result = assess_network_with_ollama(snapshot, {"read_only": True}, "qwen3.5:4b")
        self.assertEqual(result["model_decision"], "ALLOW")
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("недостаток доказательств", result["summary"])
        self.assertFalse(result["enforcement_applied"])

    def test_model_timeout_is_reported_without_automatic_action(self):
        snapshot = {"remote_endpoints": [], "connection_table_query_succeeded": True,
                    "interface_counters_available": True, "active_connection_count": 0}
        with patch("integrityguard.copilot.ensure_ollama_server", return_value=True), \
             patch("urllib.request.urlopen", side_effect=TimeoutError("simulated local timeout")):
            with self.assertRaisesRegex(RuntimeError, "Сетевой анализ Ollama не выполнен"):
                assess_network_with_ollama(snapshot, {"read_only": True}, "qwen3.5:4b")


if __name__ == "__main__":
    unittest.main()

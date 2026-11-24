"""Exit cleanup: owned-session stop, cooperative capture cancel, elevated helper teardown.

Nothing here needs administrator rights: pktmon and taskkill are patched out.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from integrityguard import pktmon_capture as pc
from integrityguard import pktmon_segment as seg


def _completed(text="", returncode=0):
    return subprocess.CompletedProcess([], returncode, text, "")


def _write_session(folder, owner_pid, create_time=100.0):
    etl = Path(folder) / "segment.etl"
    etl.touch()
    (Path(folder) / "owner.json").write_text(
        json.dumps({"pid": owner_pid, "process_create_time": create_time}), encoding="utf-8")
    return etl


class OwnedSessionStopTests(unittest.TestCase):
    def test_refuses_session_whose_owner_names_another_pid(self):
        with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as folder:
            etl = _write_session(folder, owner_pid=os.getpid() + 1)
            with patch.object(pc, "_run", return_value=_completed(f"File name: {etl}\n")) as run:
                ok, _reason = pc.stop_own_capture_session()
            self.assertFalse(ok)
            self.assertEqual([c.args[0][0] for c in run.call_args_list], ["status"])

    def test_refuses_active_session_without_owner_marker(self):
        with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as folder:
            etl = Path(folder) / "segment.etl"
            etl.touch()
            with patch.object(pc, "_run", return_value=_completed(f"File name: {etl}\n")) as run:
                ok, _reason = pc.stop_own_capture_session()
            self.assertFalse(ok)
            self.assertEqual([c.args[0][0] for c in run.call_args_list], ["status"])

    def test_no_active_session_needs_no_stop(self):
        with patch.object(pc, "_run", return_value=_completed(
                "The Pktmon component is not running.\n")) as run:
            ok, _reason = pc.stop_own_capture_session()
        self.assertTrue(ok)
        self.assertEqual([c.args[0][0] for c in run.call_args_list], ["status"])


class StopFlagTests(unittest.TestCase):
    def tearDown(self):
        pc.clear_capture_stop()

    def test_capture_returns_before_pktmon_when_stop_requested(self):
        pc.request_capture_stop()
        with patch.object(pc, "_is_admin", return_value=True), patch.object(pc, "_run") as run:
            result = pc.capture_header_segment(30)
        self.assertEqual(result["status"], "cancelled")
        run.assert_not_called()

    def test_helper_capture_returns_without_uac_or_stop_when_stop_requested(self):
        pc.request_capture_stop()
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(seg, "request_elevated_capture") as request:
            result = seg.capture_via_helper(30, Path(folder), Path("helper.exe"), None)
        request.assert_not_called()
        self.assertEqual(result["status"], "cancelled")


class ElevatedHelperTeardownTests(unittest.TestCase):
    def test_no_taskkill_when_no_helper_was_started(self):
        with patch.object(seg, "_ACTIVE_HELPERS", []), patch.object(seg.subprocess, "run") as run:
            seg.stop_elevated_helper()
        run.assert_not_called()

    def test_kills_tracked_helper_tree_with_taskkill(self):
        class FakeProcess:
            pid = 4242

            def poll(self):
                return None

        with patch.object(seg, "_ACTIVE_HELPERS", [(FakeProcess(), None)]), \
                patch.object(seg.subprocess, "run", return_value=_completed()) as run:
            seg.stop_elevated_helper()
        self.assertEqual(run.call_args.args[0][:5], ["taskkill", "/T", "/F", "/PID", "4242"])


if __name__ == "__main__":
    unittest.main()

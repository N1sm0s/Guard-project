"""Ownership guards for recovering interrupted Pktmon sessions."""
import json
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

from integrityguard import pktmon_capture


class PktmonOwnershipTests(unittest.TestCase):
    def test_parses_russian_status_etl_path(self):
        text = "Файл журнала: C:\\Users\\pavel\\AppData\\Local\\Temp\\integrityguard-pktmon-a1\\segment.etl\n"
        self.assertEqual(
            str(pktmon_capture._active_etl_path(text)),
            r"C:\Users\pavel\AppData\Local\Temp\integrityguard-pktmon-a1\segment.etl",
        )

    def test_only_accepts_direct_child_of_integrityguard_temp_dir(self):
        with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as folder:
            self.assertTrue(pktmon_capture._is_owned_capture_path(Path(folder) / "segment.etl"))
            self.assertFalse(pktmon_capture._is_owned_capture_path(Path(folder) / "other.etl"))
            self.assertFalse(pktmon_capture._is_owned_capture_path(Path(folder) / "nested" / "segment.etl"))
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(pktmon_capture._is_owned_capture_path(Path(folder) / "segment.etl"))

    def test_missing_or_invalid_owner_metadata_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            owner = Path(folder) / "owner.json"
            self.assertIsNone(pktmon_capture._owner_process_state(owner))
            owner.write_text("{}", encoding="utf-8")
            self.assertIsNone(pktmon_capture._owner_process_state(owner))
            owner.write_text("not json", encoding="utf-8")
            self.assertIsNone(pktmon_capture._owner_process_state(owner))

    def test_live_and_reused_pid_states(self):
        fake_psutil = type("Psutil", (), {})

        class NoSuchProcess(Exception):
            pass

        class AccessDenied(Exception):
            pass

        fake_psutil.NoSuchProcess = NoSuchProcess
        fake_psutil.AccessDenied = AccessDenied
        fake_psutil.Process = lambda pid: type("Process", (), {"create_time": lambda self: 100.0})()
        with tempfile.TemporaryDirectory() as folder:
            owner = Path(folder) / "owner.json"
            owner.write_text(json.dumps({"pid": 42, "process_create_time": 100.0}), encoding="utf-8")
            with patch.dict("sys.modules", {"psutil": fake_psutil}):
                self.assertTrue(pktmon_capture._owner_process_state(owner))
                owner.write_text(json.dumps({"pid": 42, "process_create_time": 90.0}), encoding="utf-8")
                self.assertFalse(pktmon_capture._owner_process_state(owner))
                fake_psutil.Process = lambda pid: (_ for _ in ()).throw(NoSuchProcess())
                self.assertFalse(pktmon_capture._owner_process_state(owner))

    def test_recovery_never_stops_unowned_or_unknown_session(self):
        with patch.object(pktmon_capture, "_run") as run:
            self.assertFalse(pktmon_capture._recover_stale_owned_capture(
                r"File name: C:\\Windows\\Temp\\foreign.etl"))
            run.assert_not_called()

    def test_recovery_stops_stale_owned_session_and_verifies_stop(self):
        fake_psutil = type("Psutil", (), {})

        class NoSuchProcess(Exception):
            pass

        class AccessDenied(Exception):
            pass

        fake_psutil.NoSuchProcess = NoSuchProcess
        fake_psutil.AccessDenied = AccessDenied
        fake_psutil.Process = lambda pid: (_ for _ in ()).throw(NoSuchProcess())
        with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as folder:
            etl = Path(folder) / "segment.etl"
            etl.touch()
            (Path(folder) / "owner.json").write_text(
                json.dumps({"pid": 999999, "process_create_time": 100.0}), encoding="utf-8")
            active = subprocess.CompletedProcess([], 0, f"File name: {etl}\n", "")
            stopped = subprocess.CompletedProcess([], 0, "The Pktmon component is not running.\n", "")
            with patch.dict("sys.modules", {"psutil": fake_psutil}), \
                    patch.object(pktmon_capture, "_run", side_effect=[active,
                        subprocess.CompletedProcess([], 0, "", ""), stopped]) as run:
                self.assertTrue(pktmon_capture._recover_stale_owned_capture(f"File name: {etl}"))
                self.assertEqual([call.args[0][0] for call in run.call_args_list],
                                 ["status", "stop", "status"])

    def test_recovery_does_not_stop_live_owned_session(self):
        fake_psutil = type("Psutil", (), {})

        class NoSuchProcess(Exception):
            pass

        class AccessDenied(Exception):
            pass

        fake_psutil.NoSuchProcess = NoSuchProcess
        fake_psutil.AccessDenied = AccessDenied
        fake_psutil.Process = lambda pid: type("Process", (), {"create_time": lambda self: 100.0})()
        with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as folder:
            etl = Path(folder) / "segment.etl"
            (Path(folder) / "owner.json").write_text(
                json.dumps({"pid": 42, "process_create_time": 100.0}), encoding="utf-8")
            with patch.dict("sys.modules", {"psutil": fake_psutil}), \
                    patch.object(pktmon_capture, "_run") as run:
                self.assertFalse(pktmon_capture._recover_stale_owned_capture(f"File name: {etl}"))
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

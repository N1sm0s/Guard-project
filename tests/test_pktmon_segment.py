"""P2.5: segment files, manifest verification and helper arguments. No real Pktmon is used."""
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from integrityguard import pktmon_capture as pc
from integrityguard import pktmon_segment as seg


def _fake_run_factory(etl_bytes=b"ETL", counters='[{"name":"nic","value":1}]'):
    """Stand-in for pktmon.exe: writes the ETL file on start, a pcapng on etl2pcap."""
    def fake_run(args, timeout=15):
        cmd = args[0]
        if cmd == "status":
            return subprocess.CompletedProcess(args, 0, stdout="Pktmon is not running", stderr="")
        if cmd == "start":
            etl = Path(args[args.index("--file-name") + 1])
            etl.write_bytes(etl_bytes)
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")
        if cmd == "counters":
            return subprocess.CompletedProcess(args, 0, stdout=counters, stderr="")
        if cmd == "stop":
            return subprocess.CompletedProcess(args, 0, stdout="stopped", stderr="")
        if cmd == "etl2pcap":
            out = Path(args[args.index("--out") + 1])
            out.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 16)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(cmd)
    return fake_run


@pytest.fixture
def root(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    return data


def test_capture_writes_manifest_and_verifies(root, tmp_path, monkeypatch):
    segment = root / "seg"
    segment.mkdir()
    with patch.object(pc, "_is_admin", return_value=True), \
         patch.object(pc, "_run", side_effect=_fake_run_factory()), \
         patch("time.sleep", return_value=None):
        manifest = seg.capture_segment_files(1, segment, root)
    assert manifest["format"] == seg.FORMAT
    checked = seg.verify_segment(segment, root)
    assert checked["segment_id"] == manifest["segment_id"]
    assert checked["counters_available"] is True
    assert not any(p.name.startswith("integrityguard-pktmon-") for p in segment.iterdir())


def test_tampered_pcapng_is_rejected(root):
    segment = root / "seg"
    segment.mkdir()
    with patch.object(pc, "_is_admin", return_value=True), \
         patch.object(pc, "_run", side_effect=_fake_run_factory()), \
         patch("time.sleep", return_value=None):
        seg.capture_segment_files(1, segment, root)
    (segment / seg.PCAPNG).write_bytes(b"changed")
    with pytest.raises(seg.SegmentError):
        seg.verify_segment(segment, root)


def test_missing_manifest_or_extra_file_is_rejected(root):
    segment = root / "seg"
    segment.mkdir()
    with pytest.raises(seg.SegmentError):
        seg.verify_segment(segment, root)
    (segment / seg.MANIFEST).write_text(json.dumps({"format": seg.FORMAT, "files": {}}), encoding="utf-8")
    with pytest.raises(seg.SegmentError):
        seg.verify_segment(segment, root)


def test_output_outside_data_root_is_refused(root, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with patch.object(pc, "_is_admin", return_value=True):
        with pytest.raises(seg.SegmentError):
            seg.capture_segment_files(1, outside, root)
    assert not list(outside.iterdir())


def test_helper_refuses_without_administrator(root):
    segment = root / "seg"
    segment.mkdir()
    with patch.object(pc, "_is_admin", return_value=False):
        with pytest.raises(seg.SegmentError):
            seg.capture_segment_files(1, segment, root)


def test_active_foreign_session_is_not_stopped(root):
    segment = root / "seg"
    segment.mkdir()
    calls = []

    def busy(args, timeout=15):
        calls.append(args[0])
        return subprocess.CompletedProcess(args, 0, stdout="Pktmon is running", stderr="")

    with patch.object(pc, "_is_admin", return_value=True), \
         patch.object(pc, "_run", side_effect=busy), \
         patch.object(pc, "_recover_stale_owned_capture", return_value=False):
        with pytest.raises(seg.SegmentError):
            seg.capture_segment_files(1, segment, root)
    assert calls == ["status"]  # no start, no stop


def test_capture_via_helper_refusal_produces_no_flows(root):
    with patch.object(seg, "request_elevated_capture", return_value=1):
        result = seg.capture_via_helper(1, root, Path(sys.executable), Path("tools/pktmon_helper.py"))
    assert result["status"] == "helper_refused"
    assert "flows" not in result


def test_capture_via_helper_rejects_tampered_segment(root):
    def helper(program, script, duration, out_dir, root_dir):
        with patch.object(pc, "_is_admin", return_value=True), \
             patch.object(pc, "_run", side_effect=_fake_run_factory()), \
             patch("time.sleep", return_value=None):
            seg.capture_segment_files(duration, out_dir, root_dir)
        (out_dir / seg.PCAPNG).write_bytes(b"tampered")
        return 0

    with patch.object(seg, "request_elevated_capture", side_effect=helper):
        result = seg.capture_via_helper(1, root, Path(sys.executable), Path("tools/pktmon_helper.py"))
    assert result["status"] == "segment_verification_failed"


def test_helper_cli_rejects_out_of_range_seconds(tmp_path):
    script = Path(__file__).resolve().parents[1] / "tools" / "pktmon_helper.py"
    out = subprocess.run([sys.executable, str(script), "--seconds", "99", "--out-dir", str(tmp_path),
                          "--root", str(tmp_path)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 2

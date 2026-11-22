import json
import subprocess
import sys
from pathlib import Path
import pytest
from integrityguard.system import IntegrityGuard


def test_retry_after_event_write_repairs_history_without_duplicate(tmp_path, monkeypatch):
    guard = IntegrityGuard.__new__(IntegrityGuard)
    guard.registry = tmp_path
    event = dict(event_id="fixed-retry-id", package="test", stage="deploy",
                 version="2", verdict="BLOCK", threat="weights", score=1,
                 fingerprint="abc")
    with monkeypatch.context() as patch:
        def interrupted(*args):
            raise OSError("interrupted before history")
        patch.setattr(guard, "_history", interrupted)
        with pytest.raises(OSError):
            guard.respond(event)
    guard.respond(event)
    guard.respond(event)
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    history = (tmp_path / "baselines/test/history.jsonl").read_text().splitlines()
    assert len(events) == len(history) == 1
    assert events[0]["event_id"] == "fixed-retry-id"


def test_crash_after_atomic_event_write_recovers(tmp_path):
    script = """
import os
import sys
from pathlib import Path
from integrityguard.system import IntegrityGuard
guard = IntegrityGuard.__new__(IntegrityGuard)
guard.registry = Path(sys.argv[1])
event = dict(event_id='crash-id', package='test', stage='deploy',
             version='2', verdict='BLOCK', threat='weights', score=1, fingerprint='abc')
original = os.fsync
if sys.argv[2] == 'crash':
    # The append writes the line, then fsyncs, then commits the index.
    # Exiting right after the first fsync is the crash window between write and commit.
    def interrupted(fd):
        original(fd)
        os._exit(73)
    os.fsync = interrupted
guard.respond(event)
"""
    cwd = Path(__file__).resolve().parents[1]
    first = subprocess.run([sys.executable, "-c", script, str(tmp_path), "crash"],
                           cwd=cwd, timeout=30, capture_output=True, text=True)
    assert first.returncode == 73, first.stderr
    second = subprocess.run([sys.executable, "-c", script, str(tmp_path), "recover"],
                            cwd=cwd, timeout=30, capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    events = (tmp_path / "events.jsonl").read_text().splitlines()
    history = (tmp_path / "baselines/test/history.jsonl").read_text().splitlines()
    assert len(events) == len(history) == 1
    assert json.loads(events[0])["event_id"] == json.loads(history[0])["event_id"]


def test_legacy_partial_line_does_not_block_new_event(tmp_path):
    from integrityguard.journal import append_record
    path = tmp_path / "events.jsonl"
    path.write_text('{"partial":', encoding="utf-8")
    append_record(path, {"event_id": "new"}, lambda path: None)
    append_record(path, {"event_id": "new"}, lambda path: None)
    lines = path.read_text().splitlines()
    assert lines[0] == '{"partial":'
    assert len(lines) == 2
    assert json.loads(lines[1])["event_id"] == "new"

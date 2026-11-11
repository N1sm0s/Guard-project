from pathlib import Path
from unittest.mock import Mock
import subprocess
import sys
import json
import pytest

from integrityguard.intake import process_incoming
from integrityguard.intake import recover_archived
import integrityguard.intake as intake


def test_move_retry_reuses_persisted_result(tmp_path, monkeypatch):
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}", encoding="utf-8")
    index = Path(str(source) + ".index.json")
    index.write_text('{"trusted": true}', encoding="utf-8")
    processed = tmp_path / "processed"
    analyze = Mock(return_value=({"verdict": "BLOCK"}, "block"))
    original = Path.rename
    now = [100.0]
    monkeypatch.setattr(intake.time, "time", lambda: now[0])

    def unavailable(path, target):
        if path == source:
            raise PermissionError("locked")
        return original(path, target)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", unavailable)
        first = process_incoming(source, processed, analyze)
    assert first["moved_to"] == ""
    assert first["retry_after"] == 2
    assert index.exists()
    record = next((tmp_path / "intake_pending").glob("*.json"))
    saved = json.loads(record.read_text(encoding="utf-8"))
    assert saved["retry_count"] == 1 and saved["next_attempt_at"] == 102.0
    after_restart = Mock(side_effect=AssertionError("analysis repeated"))
    second = process_incoming(source, processed, after_restart)
    assert second["moved_to"] == "" and second["retry_after"] == 2
    assert after_restart.call_count == 0
    now[0] += 3
    second = process_incoming(source, processed, after_restart)
    assert Path(second["moved_to"]).is_dir()
    assert second["verdict"] == "BLOCK"
    assert Path(second["moved_to"] + ".index.json").read_text(encoding="utf-8") == '{"trusted": true}'
    assert not index.exists()
    assert not source.exists()
    assert not list((tmp_path / "intake_pending").glob("*.json"))
    analyze.assert_called_once()


def test_invalid_pending_path_is_quarantined_and_never_used(tmp_path):
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}", encoding="utf-8")
    processed = tmp_path / "processed"
    ledger = tmp_path / "intake_pending"
    ledger.mkdir()
    key = intake.hashlib.sha256(str(source.resolve()).encode()).hexdigest()
    record = ledger / (key + ".json")
    record.write_text(json.dumps({"source": str(source.resolve()), "fingerprint": "bad",
                                  "content_hash": "bad", "destination": "allow", "folder": "../escape",
                                  "result": {"event_id": "previous"}}), encoding="utf-8")
    analyze = Mock(return_value=({"event_id": "fresh", "verdict": "REVIEW"}, "review"))

    result = process_incoming(source, processed, analyze)

    assert Path(result["moved_to"]).is_relative_to(processed.resolve())
    assert analyze.call_count == 1
    assert not record.exists()
    assert len(list(ledger.glob("*.corrupt-*"))) == 1


def test_changed_signature_or_index_invalidates_fingerprint(tmp_path):
    from integrityguard.intake import intake_fingerprint
    source = tmp_path / "package"
    source.mkdir()
    (source / "manifest.json").write_text("{}")
    before = intake_fingerprint(source)
    (source / "manifest.sig").write_text("signature")
    signed = intake_fingerprint(source)
    assert before != signed
    Path(str(source) + ".index.json").write_text("{}")
    assert signed != intake_fingerprint(source)


@pytest.mark.parametrize("destination", ["allow", "baseline"])
def test_changed_package_during_analysis_stays_in_queue(tmp_path, destination):
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    manifest = source / "manifest.json"
    manifest.write_text("{}")

    def analyze(path):
        manifest.write_text('{"changed": true}')
        return {"verdict": "ALLOW"}, destination

    with pytest.raises(OSError, match="изменился"):
        process_incoming(source, tmp_path / "processed", analyze)
    assert source.is_dir()
    assert not list((tmp_path / "intake_pending").glob("*.json"))


def test_process_crash_recovers_saved_verdict(tmp_path):
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}")
    side = Path(str(source) + ".index.json")
    side.write_text('{"source": "test"}')
    script = """
import os
import sys
import json
from pathlib import Path
from integrityguard.intake import process_incoming
root = Path(sys.argv[1])
source = root / 'incoming' / 'package'
def analyze(path):
    marker = root / 'analysis-count.txt'
    if marker.exists():
        raise AssertionError('analysis repeated after restart')
    marker.write_text('one')
    return {'verdict': 'BLOCK'}, 'block'
if sys.argv[2] == 'crash':
    def interrupted_move(self, target):
        os._exit(73)
    Path.rename = interrupted_move
result = process_incoming(source, root / 'processed', analyze)
(root / 'result.json').write_text(json.dumps(result))
"""
    cwd = Path(__file__).resolve().parents[1]
    crashed = subprocess.run([sys.executable, "-c", script, str(tmp_path), "crash"],
                             cwd=cwd, timeout=30, capture_output=True, text=True)
    assert crashed.returncode == 73, crashed.stderr
    assert source.exists() and side.exists()
    assert len(list((tmp_path / "intake_pending").glob("*.json"))) == 1
    recovered = subprocess.run([sys.executable, "-c", script, str(tmp_path), "recover"],
                               cwd=cwd, timeout=30, capture_output=True, text=True)
    assert recovered.returncode == 0, recovered.stderr
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["verdict"] == "BLOCK"
    assert Path(result["moved_to"]).is_dir()
    assert Path(result["moved_to"] + ".index.json").read_text() == '{"source": "test"}'
    assert not source.exists()
    assert not list((tmp_path / "intake_pending").glob("*.json"))


def test_recovery_after_archive_move_before_cleanup(tmp_path, monkeypatch):
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}")
    side = Path(str(source) + ".index.json")
    side.write_text("{}")
    rename = Path.rename

    def stop_after_move(path, target):
        rename(path, target)
        raise SystemExit("crash after move")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", stop_after_move)
        with pytest.raises(SystemExit):
            process_incoming(source, tmp_path / "processed",
                             lambda _: ({"verdict": "ALLOW"}, "allow"))
    assert side.exists() and not source.exists()
    assert recover_archived(tmp_path / "incoming", tmp_path / "processed") == 1
    assert not side.exists()
    assert recover_archived(tmp_path / "incoming", tmp_path / "processed") == 0

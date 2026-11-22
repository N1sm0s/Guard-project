"""P2.1: crash-recovery on real child processes for the intake queue and journal.

Each child is killed with os._exit at a chosen point. Recovery runs in a new
process. Checks: the package moves once, analysis is not repeated, and the
journal holds one record per event_id.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHILD = r"""
import json, os, sys
from pathlib import Path
from integrityguard.intake import process_incoming
from integrityguard.journal import append_record

root = Path(sys.argv[1])
mode = sys.argv[2]
source = root / 'incoming' / 'package'
journal = root / 'journal' / 'events.jsonl'

def analyze(path):
    marker = root / 'analysis-count.txt'
    count = int(marker.read_text()) if marker.exists() else 0
    marker.write_text(str(count + 1))
    return {'verdict': 'BLOCK', 'event_id': 'evt-fixed-1'}, 'block'

def publish(result):
    append_record(journal, {'event_id': result['event_id'], 'verdict': result['verdict']},
                  rotate=lambda p: None)
    if mode == 'crash_after_journal':
        os._exit(74)

if mode == 'crash_during_move':
    def interrupted_move(self, target):
        os._exit(75)
    Path.rename = interrupted_move

result = process_incoming(source, root / 'processed', analyze, publish=publish)
(root / 'result.json').write_text(json.dumps(result))
"""


def _run(root: Path, mode: str):
    return subprocess.run([sys.executable, "-c", CHILD, str(root), mode],
                          cwd=ROOT, timeout=60, capture_output=True, text=True)


def _setup(tmp_path: Path) -> Path:
    source = tmp_path / "incoming" / "package"
    source.mkdir(parents=True)
    (source / "manifest.json").write_text("{}")
    return tmp_path


def _journal_ids(root: Path) -> list[str]:
    path = root / "journal" / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["event_id"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_crash_after_journal_write_does_not_duplicate_event(tmp_path):
    root = _setup(tmp_path)
    crashed = _run(root, "crash_after_journal")
    assert crashed.returncode == 74, crashed.stderr
    assert _journal_ids(root) == ["evt-fixed-1"]
    assert (root / "incoming" / "package").exists()  # not moved yet

    recovered = _run(root, "recover")
    assert recovered.returncode == 0, recovered.stderr
    assert _journal_ids(root) == ["evt-fixed-1"]  # idempotent: no second record
    assert not (root / "incoming" / "package").exists()
    assert (root / "analysis-count.txt").read_text() == "1"  # analysis ran once


def test_repeated_crashes_during_move_then_single_success(tmp_path):
    root = _setup(tmp_path)
    for _ in range(2):
        crashed = _run(root, "crash_during_move")
        assert crashed.returncode == 75, crashed.stderr
        assert (root / "incoming" / "package").exists()
    recovered = _run(root, "recover")
    assert recovered.returncode == 0, recovered.stderr
    result = json.loads((root / "result.json").read_text())
    assert Path(result["moved_to"]).is_dir()
    assert _journal_ids(root) == ["evt-fixed-1"]
    assert (root / "analysis-count.txt").read_text() == "1"
    assert not list((root / "incoming" / "package").parent.glob("*"))
    assert not list((root / "intake_pending").glob("*.json"))

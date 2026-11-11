"""Failure recovery in the GUI incoming-directory scheduler."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from PySide6.QtCore import QObject, Signal

from integrityguard.gui import MainWindow


class WorkerSignals(QObject):
    fail = Signal(str)
    finished = Signal()


def scheduler(tmp_path):
    incoming = tmp_path / "incoming"
    package = incoming / "package"
    package.mkdir(parents=True)
    (package / "manifest.json").write_text("{}", encoding="utf-8")
    worker = WorkerSignals()
    state = SimpleNamespace(
        incoming=incoming, _auto_busy=False, _workers=[], _seen={}, _done={},
        run_bg=Mock(return_value=worker), _auto_process=Mock(), _auto_done=Mock(),
    )
    return state, worker, package


def test_failed_worker_allows_retry(tmp_path):
    state, worker, package = scheduler(tmp_path)
    MainWindow._auto_tick(state)
    state.run_bg.assert_not_called()
    MainWindow._auto_tick(state)
    assert state.run_bg.call_count == 1
    assert state._auto_busy
    worker.fail.emit("interrupted read")
    worker.finished.emit()
    assert str(package) not in state._done
    assert not state._auto_busy
    MainWindow._auto_tick(state)
    assert state.run_bg.call_count == 2


def test_interrupted_scan_recovers_after_files_stabilize(tmp_path, monkeypatch):
    state, worker, package = scheduler(tmp_path)
    original = Path.rglob

    def interrupted(path, pattern, *args, **kwargs):
        if path == package:
            raise FileNotFoundError("package disappeared during copy")
        return original(path, pattern, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rglob", interrupted)
        MainWindow._auto_tick(state)
    assert not state._seen
    state.run_bg.assert_not_called()
    MainWindow._auto_tick(state)
    state.run_bg.assert_not_called()
    MainWindow._auto_tick(state)
    state.run_bg.assert_called_once()


def test_incoming_directory_temporarily_unavailable(tmp_path, monkeypatch):
    state, worker, package = scheduler(tmp_path)
    original = Path.iterdir

    def unavailable(path):
        if path == state.incoming:
            raise PermissionError("directory temporarily unavailable")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "iterdir", unavailable)
        MainWindow._auto_tick(state)
    state.run_bg.assert_not_called()
    assert not state._auto_busy
    MainWindow._auto_tick(state)
    MainWindow._auto_tick(state)
    state.run_bg.assert_called_once()

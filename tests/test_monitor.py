import json

import pytest

from integrityguard.collect import save_package
from integrityguard.system import IntegrityGuard
from test_unbaselined import MODEL, package_spec


def _guard(tmp_path):
    return IntegrityGuard(tmp_path / "registry", MODEL, key=b"monitor-test-key",
                          public_intel_enabled=False)


def test_monitor_checkpoint_and_event_are_idempotent_after_restart(tmp_path):
    package = tmp_path / "package"
    save_package(package_spec(9201), package)
    guard = _guard(tmp_path)

    guard.monitor(package, interval=0, once=True)
    guard.monitor(package, interval=1e9, once=True)

    rows = [json.loads(line) for line in (tmp_path / "registry" / "events.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["stage"] == "runtime"
    state = list((tmp_path / "registry" / "monitor_state").glob("*.json"))
    assert len(state) == 1
    checkpoint = json.loads(state[0].read_text())
    assert checkpoint["fingerprint"] == rows[0]["fingerprint"]
    assert checkpoint["event_id"] == rows[0]["event_id"]


def test_monitor_retry_is_bounded_and_invalid_package_is_journaled(tmp_path):
    class StopAfterWait:
        stopped = False
        delays = []

        def is_set(self):
            return self.stopped

        def wait(self, delay):
            self.delays.append(delay)
            self.stopped = True

    package = tmp_path / "broken"
    package.mkdir()
    (package / "manifest.json").write_text("{", encoding="utf-8")
    guard = _guard(tmp_path)
    stop = StopAfterWait()
    errors = []

    guard.monitor(package, interval=0.01, on_error=errors.append, stop_event=stop)

    assert stop.delays == [2.0]
    assert len(errors) == 1
    row = json.loads((tmp_path / "registry" / "events.jsonl").read_text().splitlines()[0])
    assert row["analysis_mode"] == "intake_validation_error"
    assert row["score"] is None and row["risk_score"] is None


def test_monitor_once_records_error_then_preserves_cli_failure(tmp_path):
    package = tmp_path / "missing"
    guard = _guard(tmp_path)

    with pytest.raises(ValueError):
        guard.monitor(package, once=True)

    row = json.loads((tmp_path / "registry" / "events.jsonl").read_text().splitlines()[0])
    assert row["analysis_mode"] == "intake_validation_error"
    assert row["event_id"].startswith("runtime-error-")

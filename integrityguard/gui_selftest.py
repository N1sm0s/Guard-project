"""Real-only GUI smoke check; it must not create or load synthetic packages."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path


def _check_real_wheels(window, wheel_paths, output):
    """Exercise GUI consumers of real scanner events in a temporary registry."""
    from .wheel_scan import register_wheel_baseline, assess_wheel, persist_wheel_event
    from .report import generate, generate_period
    from .evidence import EvidenceStore

    baseline, candidate = (Path(p).resolve(strict=True) for p in wheel_paths)
    registry = Path(window.cfg("registry"))
    register_wheel_baseline(baseline, registry, source_url=baseline.as_uri(),
                            provenance_ref="Local regression check only; temporary trust registry")
    events = [assess_wheel(path, registry) for path in (baseline, candidate)]
    assert events[0]["verdict"] == "ALLOW", events[0]
    assert events[1]["verdict"] == "REVIEW", events[1]
    assert all(e["analysis_mode"] == "wheel_static" and e["score"] is None for e in events)
    for event in events:
        persist_wheel_event(event, registry)
    window._load_events()
    window._load_monitor()
    assert window.e_table.rowCount() == 2, "Real wheel events are missing from the journal"
    assert window.mon_table.rowCount() == 2
    assert window.tiles["total"].text() == "2"
    assert window.tiles["ALLOW"].text() == window.tiles["REVIEW"].text() == "1"
    assert not window.ch_score.events, "A numeric model score must not be invented"
    window.e_filter.setText("no-such-package-for-gui-check")
    assert window.e_table.rowCount() == 0
    window.e_filter.clear()
    assert window.e_table.rowCount() == 2
    assert 'wheel_static' in window.e_detail.toPlainText()
    stored = EvidenceStore(registry / "evidence.sqlite").read_events()
    assert len(stored) == 2
    for i, event in enumerate(stored):
        path = generate(event, output / f"wheel-{i}.pdf")
        assert path.read_bytes().startswith(b"%PDF")
    day = events[0]["time"][:10]
    path = generate_period(stored, output / "period.pdf", day, events[-1]["time"][:10])
    assert path.read_bytes().startswith(b"%PDF")
    print("Real wheels: journal, monitor counters, filtering, SQLite and PDFs passed; no model scores created.")


def run(wheel_paths=None, label_catalog=None) -> int:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        from . import gui
    except Exception as error:  # noqa: BLE001
        print(f"GUI startup import failed: {error}")
        return 1

    app = QApplication.instance() or QApplication([])
    old_data = gui.DATA
    with tempfile.TemporaryDirectory(prefix="integrityguard-real-only-gui-") as temp:
        gui.DATA = Path(temp)
        window = None
        try:
            window = gui.MainWindow()
            window.show()
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.02)
            assert not hasattr(window, "demo_labels")
            assert not hasattr(window, "demo_try_btn")
            assert not hasattr(window, "demo_btn")
            assert not hasattr(window, "all_btn")
            assert not window.r_btn.isEnabled()
            assert window.incoming.is_dir()
            assert not any(item.is_dir() for item in window.incoming.iterdir())
            from .training_process import run_training_process
            runtime_check = run_training_process(Path(temp), Path(window.cfg("model")), probe=True, timeout=60)
            assert runtime_check["status"] == "probe"
            assert runtime_check["runtime"]["readiness"]["confirmed_count"] == 0
            assert runtime_check["candidate"] is None
            # Validate rejection paths without generating training data.
            for options in ({"cpu_threads": 0}, {"ref_val": []}):
                try:
                    gui.online_learn.build_candidate(Path(temp), Path(window.cfg("model")), **options)
                except ValueError:
                    pass
                else:
                    raise AssertionError("Invalid training configuration was accepted")
            if wheel_paths:
                _check_real_wheels(window, wheel_paths, Path(temp))
            if label_catalog:
                from .label_registry import LabelRegistry
                registry = LabelRegistry(Path(temp) / "label_registry.sqlite")
                registry.import_catalog(label_catalog)
                window._load_label_coverage()
                assert window.label_coverage_table.rowCount() == 9
                assert registry.coverage()["cases"] == 3
                assert registry.coverage()["incidents"] == 2
                assert all(window.label_coverage_table.item(i, 2).text() == "0" for i in range(9))
                assert sum(int(window.label_coverage_table.item(i, 1).text()) for i in range(9)) == 3
                print("Real evidence catalog visible in GUI; no imported label treated as verified.")
            _shutdown_test_window(window, app)
            print("GUI starts; real-package intake is ready; synthetic demo actions are disabled; incoming queue is empty.")
            return 0
        except Exception as error:  # noqa: BLE001
            print(f"GUI smoke check failed: {error}")
            _shutdown_test_window(window, app)
            return 1
        finally:
            gui.DATA = old_data


def _shutdown_test_window(window, app) -> None:
    if window is None:
        return
    window._quitting = True
    for name in ("auto_timer", "net_timer", "cleanup_timer", "candidate_timer", "_watch_timer"):
        timer = getattr(window, name, None)
        if timer is not None:
            timer.stop()
    window.close()
    for worker in list(getattr(window, "_workers", [])):
        if worker.isRunning():
            worker.wait(185_000)
    app.processEvents()

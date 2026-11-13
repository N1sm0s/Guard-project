"""Real-only GUI smoke check; it must not create or load synthetic packages."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from contextlib import closing
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


def run(wheel_paths=None, label_catalog=None, copilot_check=False) -> int:
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
            # The real traffic assessment below is explicit; keep the periodic
            # background run from racing the test's locally hosted model calls.
            window._network_ai_paused = True
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
            if copilot_check:
                from . import network_threat_intel
                original_dshield_lookup = network_threat_intel.lookup_dshield
                # Keep GUI regression runs offline and honor DShield's hourly
                # feed limit. The feed parser and cache are covered by unit tests.
                network_threat_intel.lookup_dshield = lambda _endpoints, _cache: {
                    "source": network_threat_intel.ATTRIBUTION,
                    "source_url": network_threat_intel.FEED_URL,
                    "status": "selftest_fixture", "checked_at_utc": None,
                    "age_seconds": None, "feed_sha256": "0" * 64,
                    "network_entries_count": 0, "matches": [], "refresh_error": None,
                    "policy": "Test fixture only; no network access.",
                }
                window.cp_model.setEditText("qwen3.5:4b")
                window._copilot_refresh_models()
                deadline = time.monotonic() + 30
                while not window.cp_refresh.isEnabled() and time.monotonic() < deadline:
                    app.processEvents()
                    time.sleep(0.02)
                if not window.cp_refresh.isEnabled() or "qwen3.5:4b" not in window.cp_model.currentText():
                    raise AssertionError("Local Ollama model qwen3.5:4b was not detected")

                def ask_copilot(question):
                    window.cp_question.setText(question)
                    window._copilot_search()
                    deadline = time.monotonic() + 210
                    while not window.cp_search.isEnabled() and time.monotonic() < deadline:
                        app.processEvents()
                        time.sleep(0.02)
                    if not window.cp_search.isEnabled():
                        raise TimeoutError("Copilot GUI request did not finish within 210 seconds")
                    app.processEvents()
                    return window.cp_results.toPlainText()

                network_query = "Оцени текущий сетевой трафик и состояние функций IntegrityGuard"
                network_view = ask_copilot(network_query)
                if "Рекомендация локальной модели" not in network_view \
                        or "tool_result_network_assessment" not in network_view \
                        or "active_connection_count" not in network_view \
                        or "DShield" not in network_view \
                        or "no packet payloads" not in network_view.lower():
                    raise AssertionError("Live Ollama assessment did not use real network/app telemetry")
                if "Захвата packet payload нет" not in network_view \
                        or "не меняет windows firewall" not in network_view.lower():
                    raise AssertionError("Copilot overstated network visibility or enforcement")

                monitoring_view = ask_copilot("Покажи состояние мониторинга сейчас")
                if "IntegrityGuard tool: monitoring_status" not in monitoring_view \
                        or "Автоматический мониторинг:" not in monitoring_view:
                    raise AssertionError("Copilot did not expose the deterministic monitoring status")
                events_view = ask_copilot("Покажи последние события журнала")
                if "IntegrityGuard tool: recent_events" not in events_view:
                    raise AssertionError("Copilot did not route recent events to the safe read-only tool")
                readiness_view = ask_copilot("Сколько подтверждённых примеров есть для обучения?")
                if "IntegrityGuard tool: training_readiness" not in readiness_view \
                        or "бинарного детектора пакетов" not in readiness_view:
                    raise AssertionError("Copilot did not distinguish package detector readiness")

                unsupported_view = ask_copilot("Какая цель указана в ТЗ?")
                if "запрос вне поддерживаемого сетевого/операционного охвата" not in unsupported_view.lower() \
                        or "не читает пользовательские документы" not in unsupported_view.lower():
                    raise AssertionError("Out-of-scope document request was not explicitly declined")

                original_answer = gui.answer_with_ollama
                def controlled_model_failure(*_args, **_kwargs):
                    raise RuntimeError("controlled local inference timeout")
                gui.answer_with_ollama = controlled_model_failure
                try:
                    outage_view = ask_copilot(network_query)
                finally:
                    gui.answer_with_ollama = original_answer
                if "controlled local inference timeout" not in outage_view:
                    raise AssertionError("Copilot did not show a bounded local-model failure")
                recovery_view = ask_copilot(network_query)
                if "IntegrityGuard network advisor" not in recovery_view:
                    raise AssertionError("Copilot did not recover after the simulated model outage")

                window._network_ai_paused = False
                window._network_ai_next = 0
                window._maybe_network_ai_assessment()
                deadline = time.monotonic() + 210
                while window._network_ai_busy and time.monotonic() < deadline:
                    app.processEvents()
                    time.sleep(0.02)
                app.processEvents()
                if window._network_ai_busy:
                    raise TimeoutError("Automatic network assessment did not finish within 210 seconds")
                if not any(token in window.net_ai_note.text() for token in
                           ("ЯВНАЯ АТАКА НЕ УСТАНОВЛЕНА", "НУЖНА ПРОВЕРКА", "РЕКОМЕНДАЦИЯ: БЛОКИРОВАТЬ")):
                    raise AssertionError("Automatic network assessment did not update the Monitoring page")

                from .copilot_audit import CopilotAudit
                audit = CopilotAudit(Path(temp) / "copilot_audit.sqlite")
                verified = audit.verify()
                if not verified["valid"] or verified["checked_records"] != 8:
                    raise AssertionError("Copilot audit chain did not verify seven GUI calls and one periodic assessment")
                import json
                import sqlite3
                with closing(sqlite3.connect(audit.path)) as db:
                    audit_rows = db.execute(
                        "SELECT status, sources_json, tools_json FROM turns ORDER BY seq").fetchall()
                recorded_tools = {tool["name"] for _status, _sources, tools in audit_rows
                                  for tool in json.loads(tools)}
                if not {"network_status", "monitoring_status", "network_assessment",
                        "recent_events", "training_readiness", "network_ai_assessment"}.issubset(recorded_tools):
                    raise AssertionError("Copilot audit is missing operational tool calls")
                gui_sources = [json.loads(sources) for _status, sources, _tools in audit_rows[:7]]
                telemetry_sources = json.loads(audit_rows[7][1])
                if any(gui_sources) or len(telemetry_sources) != 1 \
                        or len(telemetry_sources[0]) != 64:
                    raise AssertionError("Network audit may contain only the periodic telemetry hash")
                if audit_rows[5][0] != "error" or audit_rows[6][0] != "answered":
                    raise AssertionError("Copilot audit did not record model outage and recovery")
                network_threat_intel.lookup_dshield = original_dshield_lookup
                print("Copilot GUI: live network/app assessment, monitoring/events/readiness tools, out-of-scope refusal, model outage/recovery, periodic Monitoring update, and eight audit records passed.")
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

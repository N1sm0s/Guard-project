import pytest

from integrityguard.evidence import EvidenceStore
from integrityguard.report import generate_period, select_period_events


def test_period_report_filters_inclusive_utc_days_and_summarizes(tmp_path):
    events = [
        {"event_id": "a", "time": "2026-11-10T23:59:59Z", "package": "alpha", "version": "1",
         "verdict": "ALLOW", "score": 0.1, "risk_score": 10, "threat": "clean"},
        {"event_id": "b", "time": "2026-11-11T00:00:00+00:00", "package": "βета", "version": "2",
         "verdict": "REVIEW", "analysis_mode": "reference_missing", "score": None, "risk_score": None,
         "assessment_complete": False},
        {"event_id": "c", "time": "2026-11-12T00:00:00+00:00", "package": "outside", "version": "3",
         "verdict": "BLOCK", "score": 0.9},
    ]
    output = tmp_path / "reports" / "period.pdf"
    assert generate_period(events, output, "2026-11-10", "2026-11-11") == output
    assert output.read_bytes().startswith(b"%PDF-")
    selected = select_period_events(events, "2026-11-10", "2026-11-11")
    assert [event["event_id"] for event in selected] == ["a", "b"]


def test_period_report_can_read_complete_journal_store(tmp_path):
    store = EvidenceStore(tmp_path / "registry" / "evidence.sqlite")
    store.record_event({"event_id": "stored", "time": "2026-11-11T12:00:00+00:00", "package": "stored-pkg",
                        "version": "4", "verdict": "REVIEW", "analysis_mode": "reference_missing"})
    output = tmp_path / "stored.pdf"
    generate_period(store.read_events(), output, "2026-11-11", "2026-11-11")
    assert output.is_file()


@pytest.mark.parametrize("start,end", [("bad", "2026-11-11"), ("2026-11-12", "2026-11-11")])
def test_period_report_rejects_invalid_bounds(tmp_path, start, end):
    with pytest.raises(ValueError):
        select_period_events([], start, end)

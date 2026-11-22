"""Journal append with an identifier index: duplicates, legacy history, crash window."""
import json

from integrityguard.journal import append_record


def _ids(path):
    return [json.loads(line)["event_id"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _noop(_):
    return None


def test_duplicate_event_is_not_written_twice(tmp_path):
    path = tmp_path / "events.jsonl"
    for _ in range(3):
        append_record(path, {"event_id": "a"}, _noop)
    append_record(path, {"event_id": "b"}, _noop)
    assert _ids(path) == ["a", "b"]


def test_index_survives_a_new_process_or_connection(tmp_path):
    path = tmp_path / "events.jsonl"
    append_record(path, {"event_id": "keep"}, _noop)
    # a fresh call is equivalent to a restarted process: nothing is cached in memory
    append_record(path, {"event_id": "keep"}, _noop)
    assert _ids(path) == ["keep"]


def test_legacy_journal_without_index_is_indexed_once(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"event_id": "old"}) + "\n", encoding="utf-8")
    append_record(path, {"event_id": "old"}, _noop)
    append_record(path, {"event_id": "new"}, _noop)
    assert _ids(path) == ["old", "new"]


def test_identifier_in_archive_still_blocks_duplicate(tmp_path):
    path = tmp_path / "events.jsonl"
    archive = tmp_path / "events.archive.jsonl"
    archive.write_text(json.dumps({"event_id": "archived"}) + "\n", encoding="utf-8")
    append_record(path, {"event_id": "archived"}, _noop)
    assert not path.exists() or _ids(path) == []


def test_crash_between_write_and_commit_does_not_duplicate(tmp_path):
    """The line reached the file but the index commit was lost: the tail check catches the retry."""
    path = tmp_path / "events.jsonl"
    append_record(path, {"event_id": "first"}, _noop)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event_id": "window"}) + "\n")
    append_record(path, {"event_id": "window"}, _noop)
    assert _ids(path) == ["first", "window"]


def test_partial_last_line_is_terminated_before_new_record(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"partial":', encoding="utf-8")
    append_record(path, {"event_id": "after"}, _noop)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"partial":'
    assert json.loads(lines[1])["event_id"] == "after"


def test_record_without_event_id_is_always_written(tmp_path):
    path = tmp_path / "events.jsonl"
    append_record(path, {"note": 1}, _noop)
    append_record(path, {"note": 1}, _noop)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2

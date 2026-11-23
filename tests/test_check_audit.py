from integrityguard.check_audit import GENESIS, append_check, last_hash, verify


def test_empty_log_verifies_and_starts_from_genesis(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert verify(path)
    assert last_hash(path) == GENESIS


def test_append_links_entries_and_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = append_check(path, {"event_id": "a", "verdict_shown": "REVIEW"})
    second = append_check(path, {"event_id": "b", "verdict_shown": "ALLOW"})
    assert first["prev"] == GENESIS
    assert second["prev"] == first["hash"]
    assert last_hash(path) == second["hash"]
    assert verify(path)


def test_edited_line_breaks_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_check(path, {"event_id": "a", "verdict_shown": "REVIEW"})
    append_check(path, {"event_id": "b", "verdict_shown": "ALLOW"})
    text = path.read_text(encoding="utf-8").replace('"verdict_shown": "REVIEW"', '"verdict_shown": "ALLOW"')
    path.write_text(text, encoding="utf-8")
    assert not verify(path)


def test_removed_middle_line_breaks_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    for name in ("a", "b", "c"):
        append_check(path, {"event_id": name})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert not verify(path)

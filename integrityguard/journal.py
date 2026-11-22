"""Serialized, atomic JSONL appends with retry identifiers.

Each append runs inside one SQLite transaction on the journal directory's lock
database. The event identifier index and the appended line are committed
together: a retry after a crash finds the identifier in the index, or in the
tail of the file when the crash fell between the file write and the commit.

Journals written before the index existed are indexed once from the journal
and its archive, so the duplicate guarantee also covers old history.
"""
import json
import os
import sqlite3
import uuid

TAIL_BYTES = 16 * 1024
TAIL_LINES = 32  # the crash window holds only the most recent record(s)


def _ensure_tables(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS journal_ids "
                       "(journal TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (journal, event_id))")
    connection.execute("CREATE TABLE IF NOT EXISTS journal_built (journal TEXT PRIMARY KEY)")


def _ids_in(path):
    ids = []
    if not path.exists():
        return ids
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                existing = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(existing, dict) and existing.get("event_id"):
                ids.append(str(existing["event_id"]))
    return ids


def _tail_ids(path):
    """Identifiers in the last part of the file. Covers a crash between write and commit."""
    if not path.exists():
        return set()
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - TAIL_BYTES))
        chunk = stream.read()
    ids = set()
    for line in chunk.decode("utf-8", errors="replace").splitlines()[-TAIL_LINES:]:
        try:
            existing = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(existing, dict) and existing.get("event_id"):
            ids.add(str(existing["event_id"]))
    return ids


def _has_identifier(connection, path, key, event_id):
    _ensure_tables(connection)
    built = connection.execute("SELECT 1 FROM journal_built WHERE journal = ?", (key,)).fetchone()
    if not built:
        archive = path.with_name(path.stem + ".archive.jsonl")
        connection.executemany("INSERT OR IGNORE INTO journal_ids (journal, event_id) VALUES (?, ?)",
                               [(key, item) for item in _ids_in(path) + _ids_in(archive)])
        connection.execute("INSERT OR IGNORE INTO journal_built (journal) VALUES (?)", (key,))
    found = connection.execute("SELECT 1 FROM journal_ids WHERE journal = ? AND event_id = ?",
                               (key, event_id)).fetchone()
    return bool(found) or event_id in _tail_ids(path)


def _ends_without_newline(path):
    if not path.exists() or path.stat().st_size == 0:
        return False
    with path.open("rb") as stream:
        stream.seek(-1, os.SEEK_END)
        return stream.read(1) != b"\n"


def append_record(path, record, rotate):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path.parent / "journal-lock.sqlite"), timeout=30)
    try:
        connection.execute("BEGIN IMMEDIATE")
        key = str(path.resolve())
        event_id = record.get("event_id")
        if event_id and _has_identifier(connection, path, key, str(event_id)):
            return
        rotate(path)
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        needs_newline = _ends_without_newline(path)
        with path.open("ab") as stream:
            if needs_newline:
                stream.write(b"\n")
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        if event_id:
            connection.execute("INSERT OR IGNORE INTO journal_ids (journal, event_id) VALUES (?, ?)",
                               (key, str(event_id)))
        connection.commit()
    finally:
        connection.close()

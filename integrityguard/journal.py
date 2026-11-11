"""Serialized, atomic JSONL writes with retry identifiers."""
import json
import os
import sqlite3
import uuid


def append_record(path, record, rotate):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path.parent / "journal-lock.sqlite"), timeout=30)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        connection.execute("BEGIN IMMEDIATE")
        event_id = record.get("event_id")
        if event_id:
            for candidate in (path, path.with_name(path.stem + ".archive.jsonl")):
                if candidate.exists():
                    with candidate.open(encoding="utf-8") as stream:
                        for line in stream:
                            try:
                                existing = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(existing, dict) and existing.get("event_id") == event_id:
                                return
        rotate(path)
        previous = path.read_bytes() if path.exists() else b""
        with temporary.open("wb") as stream:
            stream.write(previous)
            if previous and not previous.endswith(b"\n"):
                stream.write(b"\n")
            stream.write((json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        connection.commit()
    finally:
        connection.close()
        temporary.unlink(missing_ok=True)

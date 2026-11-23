"""Append-only, hash-chained audit of network snapshot checks (research-only).

Each check run appends one JSON line: the previous entry's hash, the record body and
its own SHA-256 over (previous hash, body). ``verify`` recomputes the chain, so an
edited or removed line is detected. Records hold identifiers, decisions and scores,
never packet payloads or addresses.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps({"prev": prev, "body": body}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _entries(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def last_hash(path: Path) -> str:
    entries = _entries(path)
    return entries[-1]["hash"] if entries else GENESIS


def append_check(path: Path, body: dict) -> dict:
    """Append one check record and return the stored entry."""
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = last_hash(path)
    record = {"utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), **body}
    entry = {"prev": prev, "body": record, "hash": _digest(prev, record)}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    return entry


def verify(path: Path) -> bool:
    """True when every entry links to the previous one and its hash matches its body."""
    prev = GENESIS
    for entry in _entries(path):
        if entry.get("prev") != prev or entry.get("hash") != _digest(prev, entry.get("body", {})):
            return False
        prev = entry["hash"]
    return True

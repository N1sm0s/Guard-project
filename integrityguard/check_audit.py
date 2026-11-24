"""Tamper-evident, serialized audit trail for network snapshot checks.

Entries are hash-chained. An atomically written head checkpoint detects tail
truncation or rollback after checkpointing. A process and thread lock serializes
writers. These local files are not a signature or an external immutable archive.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
import uuid

GENESIS = "0" * 64
AUDIT_VERSION = 2
_LOCK_TIMEOUT_SECONDS = 30.0
_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


class AuditLogError(OSError):
    """Audit file or its checkpoint is invalid; append is refused."""


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps({"prev": prev, "body": body}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _thread_lock_for(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.resolve()))
    with _thread_locks_guard:
        return _thread_locks.setdefault(key, threading.Lock())


@contextmanager
def _exclusive_lock(path: Path):
    """Serialize threads and processes using the same audit path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    local_lock = _thread_lock_for(path)
    if not local_lock.acquire(timeout=_LOCK_TIMEOUT_SECONDS):
        raise AuditLogError("Timed out waiting for the audit writer lock")

    lock_file = None
    lock_acquired = False
    try:
        lock_path = path.with_name(path.name + ".lock")
        lock_file = lock_path.open("a+b")
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)

        if os.name == "nt":
            import msvcrt

            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    lock_acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AuditLogError("Timed out waiting for the cross-process audit lock")
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            lock_acquired = True

        yield
    finally:
        try:
            if lock_file is not None:
                if lock_acquired:
                    if os.name == "nt":
                        import msvcrt

                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                lock_file.close()
        finally:
            local_lock.release()


def _read_entries(path: Path) -> list[dict]:
    try:
        raw = path.read_bytes() if path.exists() else b""
    except OSError as error:
        raise AuditLogError(f"Cannot read audit log: {error}") from error
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise AuditLogError("Audit log ends with an incomplete record")
    entries = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            raise AuditLogError(f"Blank line in audit log at line {line_number}")
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditLogError(f"Invalid audit JSON at line {line_number}") from error
        if not isinstance(entry, dict):
            raise AuditLogError(f"Invalid audit entry at line {line_number}")
        entries.append(entry)
    return entries


def _chain_hashes(entries: list[dict]) -> list[str]:
    hashes = [GENESIS]
    previous = GENESIS
    for line_number, entry in enumerate(entries, start=1):
        body = entry.get("body")
        digest = entry.get("hash")
        if not isinstance(body, dict) or not isinstance(digest, str):
            raise AuditLogError(f"Malformed audit entry at line {line_number}")
        if entry.get("prev") != previous or digest != _digest(previous, body):
            raise AuditLogError(f"Hash-chain verification failed at line {line_number}")
        previous = digest
        hashes.append(previous)
    return hashes


def _head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head.json")


def _write_head(path: Path, sequence: int, digest: str, pending: dict | None = None) -> None:
    head_path = _head_path(path)
    temp_path = head_path.with_name(f".{head_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    payload = {"version": 1, "sequence": sequence, "hash": digest}
    if pending is not None:
        payload["pending"] = pending
    try:
        with temp_path.open("xb") as handle:
            handle.write((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, head_path)
        if os.name != "nt":
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _read_head(path: Path) -> dict | None:
    head_path = _head_path(path)
    if not head_path.exists():
        return None
    try:
        head = json.loads(head_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditLogError(f"Audit checkpoint is unreadable: {error}") from error
    if not isinstance(head, dict) or head.get("version") != 1:
        raise AuditLogError("Unknown audit checkpoint format")
    sequence = head.get("sequence")
    digest = head.get("hash")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise AuditLogError("Invalid audit checkpoint sequence")
    if not isinstance(digest, str) or len(digest) != 64:
        raise AuditLogError("Invalid audit checkpoint hash")
    pending = head.get("pending")
    if pending is not None:
        pending_sequence = pending.get("sequence") if isinstance(pending, dict) else None
        pending_hash = pending.get("hash") if isinstance(pending, dict) else None
        if (isinstance(pending_sequence, bool) or pending_sequence != sequence + 1
                or not isinstance(pending_hash, str) or len(pending_hash) != 64):
            raise AuditLogError("Invalid pending audit checkpoint")
    return head


def _inspect_locked(path: Path) -> tuple[list[dict], list[str], dict | None]:
    entries = _read_entries(path)
    hashes = _chain_hashes(entries)
    head = _read_head(path)
    if head is None:
        if any(entry.get("body", {}).get("audit_version") == AUDIT_VERSION for entry in entries):
            raise AuditLogError("Audit checkpoint is missing; refusing to reset the integrity anchor")
        return entries, hashes, None

    sequence = head["sequence"]
    if sequence >= len(hashes) or hashes[sequence] != head["hash"]:
        raise AuditLogError("Audit log was truncated or diverged from its checkpoint")
    pending = head.get("pending")
    if pending is None:
        if sequence != len(entries):
            raise AuditLogError("Audit log tail does not match its checkpoint")
    elif len(entries) == sequence:
        # Process may have stopped after writing the intent but before the JSONL row.
        pass
    elif len(entries) == sequence + 1 and hashes[-1] == pending["hash"]:
        # Process may have stopped after the JSONL flush but before checkpoint commit.
        pass
    else:
        raise AuditLogError("Audit log does not match its pending checkpoint")
    return entries, hashes, head


def _reconcile_pending(path: Path, entries: list[dict], hashes: list[str], head: dict) -> tuple[list[dict], list[str], dict]:
    pending = head.get("pending")
    if pending is None:
        return entries, hashes, head
    sequence = head["sequence"]
    if len(entries) == sequence + 1 and hashes[-1] == pending["hash"]:
        sequence += 1
        digest = hashes[-1]
    else:
        digest = hashes[sequence]
    _write_head(path, sequence, digest)
    return entries, hashes, {"version": 1, "sequence": sequence, "hash": digest}


def last_hash(path: Path) -> str:
    """Return the verified chain tail; refuses to hide a checkpoint mismatch."""
    path = Path(path)
    with _exclusive_lock(path):
        entries, hashes, head = _inspect_locked(path)
        if head is not None:
            entries, hashes, head = _reconcile_pending(path, entries, hashes, head)
        return hashes[-1]


def append_check(path: Path, body: dict) -> dict:
    """Durably append one check record under a cross-process lock."""
    if not isinstance(body, dict):
        raise TypeError("audit body must be a dict")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_lock(path):
        entries, hashes, head = _inspect_locked(path)
        if head is None:
            # One-time migration: anchor the existing valid legacy chain without rewriting it.
            _write_head(path, len(entries), hashes[-1])
        else:
            entries, hashes, head = _reconcile_pending(path, entries, hashes, head)

        previous = hashes[-1]
        record = {**body,
                  "audit_version": AUDIT_VERSION,
                  "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        entry = {"prev": previous, "body": record, "hash": _digest(previous, record)}
        pending = {"sequence": len(entries) + 1, "hash": entry["hash"]}
        _write_head(path, len(entries), previous, pending=pending)
        with path.open("ab", buffering=0) as handle:
            handle.write((json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
            os.fsync(handle.fileno())
        _write_head(path, len(entries) + 1, entry["hash"])
        return entry


def verify(path: Path) -> bool:
    """Verify the chain and, when present, its persisted head checkpoint."""
    path = Path(path)
    try:
        with _exclusive_lock(path):
            _inspect_locked(path)
        return True
    except (AuditLogError, OSError, TypeError, ValueError):
        return False

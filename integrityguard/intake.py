"""Persist analyzed incoming packages until their archive move succeeds."""
import hashlib
import json
import math
import os
import shutil
import time
import uuid
from pathlib import Path

from .collect import fingerprint, file_sha256

DESTINATIONS = {"baseline", "allow", "review", "block", "error"}
MAX_RETRY_SECONDS = 300


def _save_pending(record, saved):
    temporary = record.with_name(record.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(saved, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, record)


def _quarantine_bad_record(record):
    if record.exists():
        record.replace(record.with_name(record.stem + ".corrupt-" + uuid.uuid4().hex))


def _valid_saved_record(saved, source, processed):
    try:
        if not isinstance(saved, dict) or saved.get("source") != str(source.resolve()):
            return False
        if saved.get("destination") not in DESTINATIONS:
            return False
        folder = saved.get("folder")
        if not isinstance(folder, str) or folder in {"", ".", ".."} or Path(folder).name != folder:
            return False
        object_type = saved.get("object_type", "directory")
        source_path = Path(source)
        if object_type not in {"file", "directory"}:
            return False
        if source_path.exists() and (object_type == "file") != source_path.is_file():
            return False
        if not isinstance(saved.get("fingerprint"), str) or not isinstance(saved.get("content_hash"), str):
            return False
        if not isinstance(saved.get("result"), dict) or not isinstance(saved["result"].get("event_id"), str):
            return False
        if int(saved.get("retry_count", 0)) < 0 or not math.isfinite(float(saved.get("next_attempt_at", 0.0))):
            return False
        target = (processed / saved["destination"] / folder).resolve()
        if not source_path.exists():
            target_is_expected = target.is_file() if object_type == "file" else target.is_dir()
            if not target_is_expected:
                return False
        return processed.resolve() in target.parents
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def intake_fingerprint(source, include_signature=True):
    source = Path(source)
    if source.is_file():
        digest = hashlib.sha256()
        digest.update(file_sha256(source).encode())
        stat_result = source.stat()
        digest.update(f"{stat_result.st_size}:{stat_result.st_mtime_ns}".encode())
        return digest.hexdigest()
    digest = hashlib.sha256(fingerprint(source).encode())
    paths = [Path(str(source) + ".index.json"), Path(str(source) + ".control.npz")]
    if include_signature:
        paths.append(source / "manifest.sig")
    for path in paths:
        digest.update(path.name.encode())
        digest.update(file_sha256(path).encode() if path.exists() else b"absent")
    return digest.hexdigest()


def _content_hash(path):
    path = Path(path)
    return file_sha256(path) if path.is_file() else fingerprint(path)


def process_incoming(source, processed, analyze, publish=None):
    source, processed = Path(source), Path(processed)
    ledger = processed.parent / "intake_pending"
    ledger.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(str(source.resolve()).encode()).hexdigest()
    record = ledger / (key + ".json")
    current = intake_fingerprint(source)
    saved = None
    if record.exists():
        try:
            saved = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _quarantine_bad_record(record)
        if saved is not None and not _valid_saved_record(saved, source, processed):
            _quarantine_bad_record(record)
            saved = None
    if saved is None or saved["fingerprint"] != current:
        unsigned_before = intake_fingerprint(source, include_signature=False)
        result, destination = analyze(source)
        if destination not in DESTINATIONS:
            raise ValueError("Unknown intake destination")
        unchanged = intake_fingerprint(source) == current
        if destination == "baseline":
            unchanged = intake_fingerprint(source, include_signature=False) == unsigned_before
        if not unchanged:
            raise OSError("Пакет изменился во время анализа; требуется повторная проверка")
        result = dict(result)
        result.setdefault("event_id", uuid.uuid4().hex)
        is_file = source.is_file()
        object_name = (source.stem + "_" + uuid.uuid4().hex + source.suffix) if is_file \
            else source.name + "_" + uuid.uuid4().hex
        saved = {"fingerprint": intake_fingerprint(source), "result": result,
                 "source": str(source.resolve()), "content_hash": _content_hash(source),
                 "destination": destination, "folder": object_name, "object_type": "file" if is_file else "directory",
                 "retry_count": 0, "next_attempt_at": 0.0}
        if not _valid_saved_record(saved, source, processed):
            raise ValueError("Не удалось сформировать безопасную запись очереди")
        _save_pending(record, saved)
    if publish is not None:
        publish(saved["result"])
    target = processed / saved["destination"] / saved["folder"]
    result = dict(saved["result"], incoming_path=str(source), moved_to="")
    if saved.get("fingerprint") == current:
        wait = max(0.0, float(saved.get("next_attempt_at", 0.0)) - time.time())
        if wait > 0:
            result["move_error"] = saved.get("last_move_error", "перенос ожидает повторной попытки")
            result["retry_after"] = max(1, int(wait + 0.999))
            return result
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        sidecars = [] if source.is_file() else [Path(str(source) + suffix) for suffix in (".index.json", ".control.npz")]
        for sidecar in sidecars:
            if sidecar.exists():
                suffix = str(sidecar)[len(str(source)):]
                shutil.copyfile(sidecar, Path(str(target) + suffix))
        if intake_fingerprint(source) != saved["fingerprint"]:
            raise OSError("Пакет изменился перед переносом; требуется повторная проверка")
        source.rename(target)
    except OSError as error:
        result["move_error"] = str(error)
        message = str(error)
        if "изменился" in message.lower():
            saved["retry_count"] = 0
            saved["next_attempt_at"] = 0.0
        else:
            count = min(16, int(saved.get("retry_count", 0)) + 1)
            delay = min(MAX_RETRY_SECONDS, 2 ** min(count, 8))
            saved["retry_count"] = count
            saved["next_attempt_at"] = time.time() + delay
            saved["last_move_error"] = message[:500]
            result["retry_after"] = delay
        try:
            _save_pending(record, saved)
        except OSError:
            result["queue_persist_error"] = "Не удалось сохранить время повторной попытки; повтор будет при следующем цикле."
        return result
    result["moved_to"] = str(target)
    for sidecar in sidecars:
        try:
            sidecar.unlink(missing_ok=True)
        except OSError as error:
            result["cleanup_error"] = str(error)
    record.unlink(missing_ok=True)
    return result


def recover_archived(incoming, processed):
    incoming, processed = Path(incoming).resolve(), Path(processed).resolve()
    recovered = 0
    for record in (processed.parent / "intake_pending").glob("*.json"):
        saved = json.loads(record.read_text(encoding="utf-8"))
        if "source" not in saved or "content_hash" not in saved:
            continue
        if saved.get("destination") not in DESTINATIONS or not _valid_saved_record(
                saved, Path(saved["source"]), processed):
            raise ValueError("Invalid recovery record")
        source = Path(saved["source"]).resolve()
        target = (processed / saved["destination"] / saved["folder"]).resolve()
        if source.parent != incoming or processed not in target.parents:
            raise ValueError("Invalid recovery path")
        expected_type = saved.get("object_type", "directory")
        target_exists = target.is_file() if expected_type == "file" else target.is_dir()
        if source.exists() or not target_exists:
            continue
        if _content_hash(target) != saved["content_hash"]:
            raise ValueError("Archived package changed before recovery")
        if expected_type == "file":
            record.unlink()
            recovered += 1
            continue
        for suffix in (".index.json", ".control.npz"):
            original = Path(str(source) + suffix)
            archived = Path(str(target) + suffix)
            if original.exists():
                if not archived.exists() or file_sha256(original) != file_sha256(archived):
                    raise ValueError("Sidecar differs during recovery")
                original.unlink()
        record.unlink()
        recovered += 1
    return recovered

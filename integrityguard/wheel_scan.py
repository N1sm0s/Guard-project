"""Static inspection of real Python wheel archives; never imports or installs package code."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import time
import time as _time
import zipfile
from email import message_from_bytes
from pathlib import Path, PurePosixPath

from .scan import scan_code

MAX_WHEEL_FILES = 100_000
MAX_WHEEL_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_WHEEL_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_STATIC_SOURCE_BYTES = 8 * 1024 * 1024


def _name_key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _digest_stream(stream, max_size=MAX_WHEEL_MEMBER_BYTES):
    digest = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        size += len(block)
        if size > max_size:
            raise ValueError("Распакованный элемент превысил лимит размера")
        digest.update(block)
    return digest.digest(), size


def inspect_wheel(path: str | Path) -> dict:
    """Read a wheel in place and return bounded metadata, hashes, RECORD, and static-code facts."""
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.suffix.lower() != ".whl":
        raise ValueError("Ожидается существующий файл .whl")
    artifact_hash = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            artifact_hash.update(chunk)
    artifact_sha = artifact_hash.hexdigest()

    files: dict[str, str] = {}
    captured: dict[str, bytes] = {}
    sizes: dict[str, int] = {}
    total_size = 0
    actual_total_size = 0
    static_budget = MAX_STATIC_SOURCE_BYTES
    findings: list[str] = []
    capabilities: dict[str, list[str]] = {}
    static_scan_complete = True
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_WHEEL_FILES:
            raise ValueError(f"Превышен лимит числа элементов wheel ({MAX_WHEEL_FILES})")
        seen = set()
        for info in infos:
            raw_name = info.filename
            member = PurePosixPath(raw_name)
            mode = info.external_attr >> 16
            if (member.is_absolute() or ".." in member.parts or "\\" in raw_name
                    or any(":" in part for part in member.parts)):
                raise ValueError(f"Небезопасный путь в wheel: {raw_name!r}")
            if stat.S_ISLNK(mode):
                raise ValueError(f"Символическая ссылка в wheel запрещена: {raw_name!r}")
            if raw_name in seen:
                raise ValueError(f"Повторяющийся путь в wheel: {raw_name!r}")
            seen.add(raw_name)
            if info.flag_bits & 1:
                raise ValueError(f"Зашифрованный элемент wheel не поддерживается: {raw_name!r}")
            if info.file_size > MAX_WHEEL_MEMBER_BYTES:
                raise ValueError(f"Элемент wheel превышает предел размера: {raw_name!r}")
            total_size += info.file_size
            if total_size > MAX_WHEEL_TOTAL_BYTES:
                raise ValueError("Превышен суммарный лимит распакованных данных wheel")
            if info.is_dir():
                continue
            with archive.open(info) as source:
                digest, actual_size = _digest_stream(source, MAX_WHEEL_MEMBER_BYTES)
            actual_total_size += actual_size
            if actual_total_size > MAX_WHEEL_TOTAL_BYTES:
                raise ValueError("Превышен суммарный лимит фактически распакованных данных wheel")
            if actual_size != info.file_size:
                raise ValueError(f"Размер элемента не совпал с ZIP directory: {raw_name!r}")
            files[raw_name] = digest.hex()
            sizes[raw_name] = actual_size
            if raw_name.endswith(".dist-info/METADATA") or raw_name.endswith(".dist-info/RECORD"):
                if actual_size > 4 * 1024 * 1024:
                    raise ValueError(f"Метаданные wheel слишком велики: {raw_name!r}")
                with archive.open(info) as source:
                    captured[raw_name] = source.read()
            elif raw_name.endswith(".py") and static_budget > 0:
                limit = min(info.file_size, static_budget, 2 * 1024 * 1024)
                with archive.open(info) as source:
                    content = source.read(limit + 1)
                if len(content) <= limit:
                    static_budget -= len(content)
                    caps, _ = scan_code(content.decode("utf-8", "replace"))
                    if caps:
                        capabilities[raw_name] = sorted(caps)
                else:
                    static_scan_complete = False
                    findings.append(f"static_scan_truncated:{raw_name}")
            elif raw_name.endswith(".py"):
                static_scan_complete = False
                findings.append(f"static_scan_truncated:{raw_name}")
        bad_member = archive.testzip()
        if bad_member is not None:
            raise ValueError(f"CRC-проверка wheel не прошла: {bad_member}")

    metadata_paths = [name for name in captured if name.endswith(".dist-info/METADATA")]
    record_paths = [name for name in captured if name.endswith(".dist-info/RECORD")]
    wheel_metadata_paths = [name for name in files if name.endswith(".dist-info/WHEEL")]
    if len(metadata_paths) != 1 or len(record_paths) != 1 or len(wheel_metadata_paths) != 1:
        raise ValueError("Wheel должен содержать ровно по одному dist-info/METADATA, WHEEL и RECORD")
    meta_path, record_path = metadata_paths[0], record_paths[0]
    msg = message_from_bytes(captured[meta_path])
    package_name, version = msg.get("Name"), msg.get("Version")
    if not package_name or not version:
        raise ValueError("В METADATA отсутствуют обязательные поля Name и Version")

    record_rows = {}
    for row in csv.reader(io.StringIO(captured[record_path].decode("utf-8-sig", "replace"))):
        if len(row) != 3 or row[0] in record_rows:
            raise ValueError("Некорректные или повторяющиеся строки в RECORD")
        record_rows[row[0]] = (row[1], row[2])
    record_checked = 0
    record_mismatches = []
    for name, (declared_hash, declared_size) in record_rows.items():
        if name == record_path:
            if declared_hash or declared_size:
                record_mismatches.append(name)
            continue
        actual_hash = files.get(name)
        if actual_hash is None:
            record_mismatches.append(name)
            continue
        if declared_hash:
            try:
                algo, encoded = declared_hash.split("=", 1)
                if algo.lower() != "sha256":
                    record_mismatches.append(name)
                else:
                    expected = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).hex()
                    if expected != actual_hash:
                        record_mismatches.append(name)
            except (ValueError, TypeError):
                record_mismatches.append(name)
        else:
            record_mismatches.append(name)
        if declared_size:
            try:
                if int(declared_size) != sizes.get(name):
                    record_mismatches.append(name)
            except ValueError:
                record_mismatches.append(name)
        elif name != record_path:
            record_mismatches.append(name)
        record_checked += 1
    extra_files = sorted(set(files) - set(record_rows))
    if extra_files:
        record_mismatches.extend(extra_files)
    record_mismatches = sorted(set(record_mismatches))
    if record_mismatches:
        findings.append("wheel_record_mismatch")

    requirements = list(msg.get_all("Requires-Dist", []))
    return {
        "path": str(path), "sha256": artifact_sha, "name": package_name, "normalized_name": _name_key(package_name),
        "version": version, "metadata_path": meta_path, "file_count": len(files),
        "uncompressed_bytes": total_size, "files": files,
        "record": {"path": record_path, "entries_checked": record_checked,
                   "entry_count": len(record_rows), "mismatches": record_mismatches,
                   "complete": not record_mismatches and set(record_rows) == set(files)},
        "requirements": requirements, "static_capabilities": capabilities, "findings": findings,
        "static_scan_complete": static_scan_complete,
    }


def register_wheel_baseline(wheel_path: str | Path, registry: str | Path, *, source_url: str,
                            provenance_ref: str) -> dict:
    """Pin one exact real wheel with its artifact hash and source provenance."""
    if not source_url or not provenance_ref:
        raise ValueError("Доверенный эталон требует source_url и provenance_ref")
    facts = inspect_wheel(wheel_path)
    if not facts["record"]["complete"]:
        raise ValueError("Wheel с неполным или несовпадающим RECORD нельзя регистрировать как эталон")
    root = Path(registry) / "wheel_baselines" / facts["normalized_name"]
    root.mkdir(parents=True, exist_ok=True)
    wheel_name = f"{facts['version']}_{facts['sha256'][:16]}.whl"
    target = root / wheel_name
    temp_target = target.with_suffix(target.suffix + ".tmp")
    shutil.copyfile(facts["path"], temp_target)
    os.replace(temp_target, target)
    manifest = {key: facts[key] for key in ("name", "normalized_name", "version", "sha256", "file_count",
                                              "uncompressed_bytes", "files", "record", "requirements")}
    manifest.update({"format": "integrityguard-wheel-baseline-v1", "source_url": source_url,
                     "provenance_ref": provenance_ref, "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "wheel_file": wheel_name})
    meta_path = root / f"{facts['sha256']}.json"
    temp_meta = meta_path.with_suffix(".json.tmp")
    temp_meta.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_meta, meta_path)
    return manifest


def assess_wheel(wheel_path: str | Path, registry: str | Path) -> dict:
    """Compare a real wheel with pinned PyPI artefacts; never invent a neural score."""
    started = _time.perf_counter()
    try:
        facts = inspect_wheel(wheel_path)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        path = Path(wheel_path)
        digest = hashlib.sha256(str(path.resolve()).encode("utf-8", "replace")).hexdigest()
        event = {"event_id": f"wheel-invalid-{digest}", "time": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
                 "stage": "deploy", "package": path.name, "version": "?", "baseline_version": None,
                 "fingerprint": None, "analysis_mode": "wheel_validation_error", "assessment_complete": False,
                 "comparison_performed": False, "score": None, "risk_score": None, "model_score": None,
                 "hash_control": None, "verdict": "REVIEW", "threat": "reference_required",
                 "threat_ru": "проверка wheel не завершена", "rules": [str(error)[:500]],
                 "probabilities": {}, "levels": {}, "suspects": [], "actions": [],
                 "timing_ms": {"collect": 0.0, "analyze": 0.0, "total": 0.0},
                 "objective_facts": {"wheel_structure_checked": False}}
        return event

    root = Path(registry) / "wheel_baselines" / facts["normalized_name"]
    baselines = []
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if row.get("format") == "integrityguard-wheel-baseline-v1" and row.get("normalized_name") == facts["normalized_name"]:
                baselines.append(row)
    baseline = next((row for row in baselines if row.get("version") == facts["version"]), None)
    baseline = baseline or max(baselines, key=lambda row: row.get("registered_at", ""), default=None)
    baseline_invalid = False
    if baseline:
        baseline_file = (root / str(baseline.get("wheel_file", ""))).resolve()
        if root.resolve() not in baseline_file.parents or not baseline_file.is_file():
            baseline_invalid = True
        else:
            try:
                pinned = inspect_wheel(baseline_file)
                baseline_invalid = (pinned["sha256"] != baseline.get("sha256")
                                    or pinned["files"] != baseline.get("files")
                                    or pinned["normalized_name"] != baseline.get("normalized_name"))
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
                baseline_invalid = True
        if baseline_invalid:
            baseline = None
    changed = added = removed = []
    if baseline:
        old_files, new_files = baseline.get("files", {}), facts["files"]
        changed = sorted(name for name in old_files.keys() & new_files.keys() if old_files[name] != new_files[name])
        added, removed = sorted(new_files.keys() - old_files.keys()), sorted(old_files.keys() - new_files.keys())
    exact_match = bool(baseline and facts["sha256"] == baseline.get("sha256"))
    rules = []
    if not facts["record"]["complete"]:
        rules.append("RECORD отсутствует, неполон или не совпадает с содержимым wheel")
    if not baseline:
        rules.append("доверенный PyPI wheel-эталон отсутствует или не прошёл проверку; числовая оценка не выполнялась")
    elif exact_match:
        rules.append("SHA-256 wheel совпадает с зарегистрированным доверенным артефактом")
    elif changed or added or removed:
        rules.append(f"состав wheel отличается от эталона: изменено {len(changed)}, добавлено {len(added)}, удалено {len(removed)} файлов")
    if facts["findings"]:
        rules.extend(facts["findings"])
    verdict = "ALLOW" if exact_match and facts["record"]["complete"] and not facts["findings"] else "REVIEW"
    digest = facts["sha256"]
    return {"event_id": f"wheel-{digest}", "time": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "stage": "deploy", "package": facts["name"], "version": facts["version"],
            "baseline_version": baseline.get("version") if baseline else None, "fingerprint": digest,
            "analysis_mode": "wheel_static",
            "assessment_complete": facts["record"]["complete"] and facts["static_scan_complete"],
            "comparison_performed": bool(baseline), "score": None, "risk_score": None, "model_score": None,
            # Shared event contract: hash_control=True means a mismatch/violation.
            "hash_control": (not exact_match) if baseline else None, "verdict": verdict,
            "threat": "clean" if verdict == "ALLOW" else "reference_required",
            "threat_ru": "артефакт совпадает с эталоном" if verdict == "ALLOW" else "требуется проверка",
            "rules": rules, "objective_facts": {key: facts[key] for key in
                ("sha256", "file_count", "uncompressed_bytes", "record", "static_capabilities", "requirements",
                 "static_scan_complete", "findings")},
            "wheel_delta": {"changed": changed[:500], "added": added[:500], "removed": removed[:500]},
            "source_url": baseline.get("source_url") if baseline else None,
            "provenance_ref": baseline.get("provenance_ref") if baseline else None,
            "timing_ms": {"total": round(1000 * (_time.perf_counter() - started), 1)}}


def persist_wheel_event(event: dict, registry: str | Path) -> None:
    """Persist scanner event to the common JSONL and SQLite evidence stores."""
    from .evidence import EvidenceStore
    from .journal import append_record

    root = Path(registry)
    append_record(root / "events.jsonl", event, lambda _path: None)
    EvidenceStore(root / "evidence.sqlite").record_event(event)

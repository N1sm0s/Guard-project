"""Managed acceptance of trusted wheel baselines (P1).

Flow: propose (verify against PyPI, show facts, change nothing) -> the user
decides -> accept (re-check the same file, re-verify, register, audit) or
reject (audit only). A baseline is never created without a successful
verification for the exact file, and an existing baseline of a different
version is replaced only by an explicit decision.

The audit log is an append-only hash chain in <registry>/baseline_acceptance_audit.jsonl.
It records decisions, refusals and hashes; it never stores wheel contents.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .provenance import file_sha256, verify_pypi_wheel
from .wheel_scan import inspect_wheel, register_wheel_baseline

AUDIT_FILE = "baseline_acceptance_audit.jsonl"
PYPI_OK = "pypi_hash_verified"


class AcceptanceError(ValueError):
    """Refusal. The message is shown to the user; no baseline is written."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _audit_path(registry: str | Path) -> Path:
    return Path(registry) / AUDIT_FILE


def _last_hash(path: Path) -> str:
    if not path.is_file():
        return "0" * 64
    last = None
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                last = json.loads(line)
    return last["entry_hash"] if last else "0" * 64


def append_audit(registry: str | Path, entry: dict) -> dict:
    path = _audit_path(registry)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {**entry, "time": _now(), "prev_hash": _last_hash(path)}
    body["entry_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(body, ensure_ascii=False) + "\n")
    return body


def verify_audit(registry: str | Path) -> tuple[bool, int]:
    """Return (chain_intact, entries). Any edit or reorder breaks the chain."""
    path = _audit_path(registry)
    if not path.is_file():
        return True, 0
    previous, count = "0" * 64, 0
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            entry = json.loads(line)
            claimed = entry.pop("entry_hash", None)
            if entry.get("prev_hash") != previous:
                return False, count
            if hashlib.sha256(_canonical(entry)).hexdigest() != claimed:
                return False, count
            previous, count = claimed, count + 1
    return True, count


def _existing_baselines(registry: str | Path, normalized_name: str) -> list[dict]:
    root = Path(registry) / "wheel_baselines" / normalized_name
    rows = []
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if row.get("format") == "integrityguard-wheel-baseline-v1":
                rows.append(row)
    return rows


def propose(wheel_path: str | Path, registry: str | Path, *, source_url: str, provenance_ref: str,
            fetch=verify_pypi_wheel) -> dict:
    """Check a wheel and describe what accepting it would do. Writes nothing to the trust registry."""
    if not source_url or not provenance_ref:
        raise AcceptanceError("Нужны source_url и provenance_ref")
    facts = inspect_wheel(wheel_path)
    if not facts["record"]["complete"]:
        raise AcceptanceError("RECORD неполный или не совпадает с файлами; эталон не принимается")
    verification, problem = None, None
    try:
        verification = fetch(wheel_path, facts)
        if verification.get("status") != PYPI_OK or verification.get("artifact_sha256") != facts["sha256"]:
            problem = "PyPI не подтвердил этот файл"
            verification = None
    except Exception as error:  # network, parsing, mismatch: none of them grants trust
        problem = f"Проверка PyPI не пройдена: {str(error)[:300]}"
    existing = _existing_baselines(registry, facts["normalized_name"])
    same = [row for row in existing if row.get("sha256") == facts["sha256"]]
    other = [row for row in existing if row.get("version") != facts["version"]]
    reasons = []
    if problem:
        reasons.append(problem)
    if same:
        reasons.append("Этот точный файл уже принят ранее")
    return {
        "kind": "baseline_proposal",
        "name": facts["name"], "normalized_name": facts["normalized_name"],
        "version": facts["version"], "artifact_sha256": facts["sha256"],
        "file_count": facts["file_count"], "source_url": source_url, "provenance_ref": provenance_ref,
        "verification": verification,
        "can_accept": verification is not None and not same,
        "replaces_versions": sorted({row.get("version") for row in other if row.get("version")}),
        "reasons": reasons,
        "meaning": "Совпадение с файлом PyPI; не доказательство безопасности или подписи издателя",
    }


def accept(proposal: dict, wheel_path: str | Path, registry: str | Path, *, operator: str,
           decision: str, replace_existing: bool = False, fetch=verify_pypi_wheel) -> dict | None:
    """Apply the user's decision to a proposal. Returns the baseline manifest on accept, else None."""
    if decision not in ("accept", "reject"):
        raise AcceptanceError("Решение должно быть accept или reject")
    if not operator or not operator.strip():
        raise AcceptanceError("Укажите, кто принимает решение")
    base = {"kind": "baseline_decision", "decision": decision, "operator": operator.strip()[:120],
            "name": proposal.get("normalized_name"), "version": proposal.get("version"),
            "artifact_sha256": proposal.get("artifact_sha256"), "source_url": proposal.get("source_url"),
            "provenance_ref": proposal.get("provenance_ref")}
    if decision == "reject":
        append_audit(registry, {**base, "outcome": "rejected"})
        return None

    def refuse(message: str):
        append_audit(registry, {**base, "outcome": "refused", "reason": message})
        raise AcceptanceError(message)

    if not proposal.get("can_accept"):
        refuse("Предложение не допускает принятия: " + "; ".join(proposal.get("reasons") or ["нет подтверждения"]))
    if file_sha256(wheel_path) != proposal.get("artifact_sha256"):
        refuse("Файл изменился после проверки; нужна новая проверка")
    facts = inspect_wheel(wheel_path)
    if facts["sha256"] != proposal["artifact_sha256"] or facts["version"] != proposal["version"]:
        refuse("Файл не совпадает с предложением")
    existing = _existing_baselines(registry, facts["normalized_name"])
    if existing and not replace_existing and proposal.get("replaces_versions"):
        refuse("Есть эталон другой версии; замена требует явного подтверждения replace_existing")
    # Re-verify at accept time so the recorded result is current, not the proposal's copy.
    fresh = fetch(wheel_path, facts)
    if fresh.get("status") != PYPI_OK or fresh.get("artifact_sha256") != facts["sha256"]:
        refuse("Повторная проверка PyPI не подтвердила файл")
    previous = [row.get("version") for row in existing if row.get("version") != facts["version"]]
    manifest = register_wheel_baseline(wheel_path, registry, source_url=proposal["source_url"],
                                       provenance_ref=proposal["provenance_ref"], verification=fresh)
    meta_sha = hashlib.sha256(_canonical(manifest)).hexdigest()
    append_audit(registry, {**base, "outcome": "accepted", "baseline_manifest_sha256": meta_sha,
                            "replaced_versions": previous if replace_existing else [],
                            "pypi_metadata_sha256": fresh.get("metadata_sha256"),
                            "pypi_uploaded_at": fresh.get("uploaded_at")})
    return manifest

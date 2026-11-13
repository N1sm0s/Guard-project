"""Strict, read-only application and network telemetry tools for local Ollama."""
from __future__ import annotations

import json
from pathlib import Path


TOOL_DESCRIPTIONS = {
    "monitoring_status": "Сводка мониторинга: режим, очередь, последние счётчики журнала и наличие локального детектора.",
    "network_status": "Текущие реальные счётчики сетевых интерфейсов и ограниченные метаданные активных TCP/UDP соединений; без содержимого пакетов.",
    "recent_events": "Последние безопасные поля событий IntegrityGuard; лимит 1–10, без путей и содержимого файлов.",
    "training_readiness": "Объективная готовность дообучения бинарного детектора по подтверждённым примерам.",
}
TOOL_CAPABILITIES = {
    "monitoring_status": "copilot.monitoring.read",
    "network_status": "copilot.network.read",
    "recent_events": "copilot.events.read",
    "training_readiness": "copilot.training.readiness",
}
COPILOT_READ_CAPABILITIES = frozenset(TOOL_CAPABILITIES.values())
_VERDICTS = {"ALLOW", "REVIEW", "BLOCK"}
_MAX_JOURNAL_BYTES = 8 * 1024 * 1024


def _read_events(registry: Path, limit: int = 500) -> tuple[list[dict], bool]:
    """Read only bounded JSONL records; the bool signals whether logs were truncated."""
    events: list[dict] = []
    complete = True
    for path in (registry / "events.archive.jsonl", registry / "events.jsonl"):
        try:
            size = path.stat().st_size
            with path.open("rb") as stream:
                if size > _MAX_JOURNAL_BYTES:
                    stream.seek(-_MAX_JOURNAL_BYTES, 2)
                    complete = False
                    stream.readline()  # discard a possibly partial first line
                raw = stream.read(_MAX_JOURNAL_BYTES + 1)
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        for line in raw.splitlines()[-limit:]:
            try:
                item = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(item, dict) and item.get("verdict") in _VERDICTS:
                events.append(item)
    unique: dict[str, dict] = {}
    for event in events:
        event_id = str(event.get("event_id") or "")
        # Duplicate IDs in the active log and its rotated archive count once.
        unique[event_id or f"{event.get('time')}|{event.get('package')}|{event.get('version')}"] = event
    ordered = sorted(unique.values(), key=lambda ev: str(ev.get("time") or ""))
    return ordered[-limit:], complete


def _queue_count(incoming: Path) -> int | None:
    try:
        return sum(1 for item in incoming.iterdir()
                   if (item.is_dir() and (item / "manifest.json").is_file())
                   or (item.is_file() and item.suffix.lower() == ".whl"))
    except OSError:
        return None


def _recent_summary(event: dict) -> dict:
    """Whitelist fields; never expose paths, raw evidence, or arbitrary event payloads."""
    allowed = {"event_id", "time", "package", "version", "stage", "verdict", "threat",
               "analysis_mode", "score", "hash_control"}
    result = {key: event.get(key) for key in allowed if key in event}
    for key in ("event_id", "time", "package", "version", "stage", "verdict", "threat", "analysis_mode"):
        if key in result and not isinstance(result[key], str):
            result.pop(key)
    if not isinstance(result.get("score"), (int, float)):
        result.pop("score", None)
    if not isinstance(result.get("hash_control"), (bool, type(None))):
        result.pop("hash_control", None)
    return result


def execute_tool(name: str, arguments: object, context: dict) -> dict:
    """Dispatch one allowlisted read-only tool with deterministic argument checks.

    `context` is assembled by the active desktop process and is never model
    controlled. No tool accepts arbitrary paths or performs a state change.
    """
    if not isinstance(context, dict) or not isinstance(context.get("principal"), str) \
            or not context["principal"].strip():
        raise PermissionError("UNAUTHORIZED")
    if not isinstance(name, str) or name not in TOOL_DESCRIPTIONS:
        raise PermissionError("FORBIDDEN")
    capability = TOOL_CAPABILITIES[name]
    granted = context.get("capabilities")
    if not isinstance(granted, (list, tuple, set, frozenset)) \
            or any(not isinstance(item, str) for item in granted) or capability not in granted:
        raise PermissionError("FORBIDDEN")
    if not isinstance(arguments, dict):
        raise ValueError("INVALID_ARGUMENT")

    if name == "monitoring_status":
        if arguments:
            raise ValueError("INVALID_ARGUMENT")
        incoming = Path(context["incoming"])
        processed = Path(context["processed"])
        registry = Path(context["registry"])
        detector = Path(context["detector"])
        events, complete = _read_events(registry)
        counts = {verdict: sum(e.get("verdict") == verdict for e in events) for verdict in sorted(_VERDICTS)}
        processed_counts = {}
        for verdict in sorted(_VERDICTS):
            folder = processed / verdict.lower()
            try:
                processed_counts[verdict] = sum(1 for _ in folder.iterdir()) if folder.is_dir() else 0
            except OSError:
                processed_counts[verdict] = None
        baselines = registry / "baselines"
        try:
            baseline_count = sum(1 for item in baselines.iterdir() if (item / "package").exists()) \
                if baselines.is_dir() else 0
        except OSError:
            baseline_count = None
        return {
            "tool": name, "read_only": True,
            "automatic_monitoring": bool(context.get("auto_enabled")),
            "incoming_queue": _queue_count(incoming), "processed_counts": processed_counts,
            "event_counts_in_latest_500_records": counts, "events_observed": len(events),
            "event_log_complete": complete, "last_event_time": events[-1].get("time") if events else None,
            "trusted_baselines": baseline_count, "detector_file_available": detector.is_file(),
            "detector_quality_status": "not_proven_on_independent_real_incidents",
            "scope_note": "Счётчики событий ограничены последними 500 строками доступного журнала.",
        }

    if name == "network_status":
        if arguments:
            raise ValueError("INVALID_ARGUMENT")
        try:
            import psutil
        except ImportError as exc:
            raise RuntimeError("NETWORK_SENSOR_UNAVAILABLE") from exc
        snapshot = context.get("network_snapshot")
        if snapshot is None:
            from .network_ai import NetworkTelemetry
            snapshot = NetworkTelemetry().sample(psutil)
        if not isinstance(snapshot, dict):
            raise ValueError("INVALID_ARGUMENT")
        if context.get("network_intel_enabled") and "threat_intelligence" not in snapshot:
            from .network_threat_intel import lookup_dshield
            snapshot["threat_intelligence"] = lookup_dshield(
                snapshot.get("remote_endpoints", []),
                Path(context["data_root"]) / "network_intel" / "dshield_cache.json")
        snapshot["tool"] = name
        snapshot["read_only"] = True
        snapshot["privacy_note"] = (
            "Счётчики и метаданные сетевых соединений передаются только локальному Ollama на loopback. "
            "Публичный DShield feed загружается приложением, а IP адреса сравниваются локально и не "
            "отправляются источнику."
        )
        return snapshot

    if name == "recent_events":
        if set(arguments) - {"limit"}:
            raise ValueError("INVALID_ARGUMENT")
        limit = arguments.get("limit", 5)
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("INVALID_ARGUMENT")
        registry = Path(context["registry"])
        events, complete = _read_events(registry, limit=limit)
        return {"tool": name, "read_only": True,
                "events": [_recent_summary(ev) for ev in reversed(events)],
                "event_log_complete": complete}

    if name == "training_readiness":
        if arguments:
            raise ValueError("INVALID_ARGUMENT")
        data_root = Path(context["data_root"])
        from .online_learn import candidate_readiness, list_pending
        readiness = candidate_readiness(data_root)
        try:
            pending = len(list_pending(data_root))
        except (OSError, ValueError, RuntimeError):
            pending = None
        return {"tool": name, "read_only": True,
                "confirmed_samples": readiness["confirmed_count"], "benign_samples": readiness["benign_count"],
                "attack_samples": readiness["attack_count"], "minimum_total": readiness["minimum"],
                "minimum_per_class": readiness["minimum_per_label"],
                "binary_detector_candidate_ready": readiness["ready"], "pending_review_count": pending,
                "scope_note": "Это готовность дообучения бинарного детектора пакетов, не корпуса LLM-помощника."}
    raise PermissionError("FORBIDDEN")

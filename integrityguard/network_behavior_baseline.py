"""Operator-selected local network behavior profile; never a ground-truth label."""
from __future__ import annotations

import hashlib
import json
import math
import os
import statistics
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1
MIN_SAMPLES = 30
MIN_DURATION_SECONDS = 600
MAX_GAP_SECONDS = 120
MIN_VALID_COVERAGE = 0.90


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Время снимка не содержит часовой пояс")
    return parsed.astimezone(timezone.utc)


def _features(snapshot: dict) -> dict[str, float]:
    interfaces = snapshot.get("interfaces")
    if not isinstance(interfaces, list) or snapshot.get("interface_counters_available") is not True:
        raise ValueError("Нет доступных счётчиков сетевых интерфейсов")
    if snapshot.get("connection_table_query_succeeded") is not True:
        raise ValueError("Таблица сетевых соединений получена не полностью")
    if snapshot.get("socket_flow_truncated") is True:
        raise ValueError("Список socket flows усечён")
    if any(not isinstance(item, dict) for item in interfaces):
        raise ValueError("Некорректная запись сетевого интерфейса")
    rates = [item.get("rate") for item in interfaces if isinstance(item.get("rate"), dict)]
    if len(rates) != len(interfaces) or not rates:
        raise ValueError("Нет полных скоростей по интерфейсам")
    def number(value, field):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Нет числового значения {field}")
        return float(value)

    result = {
        "active_connections": number(snapshot.get("active_connection_count"), "active_connection_count"),
        "remote_endpoints": number(snapshot.get("remote_endpoint_count"), "remote_endpoint_count"),
        "distinct_processes": number(snapshot.get("distinct_process_count"), "distinct_process_count"),
        "port_scan_suspected": number(snapshot.get("port_scan_suspected_count"), "port_scan_suspected_count"),
        "suspicious_port_matches": number(snapshot.get("suspicious_port_match_count"), "suspicious_port_match_count"),
        "interfaces_up": float(sum(1 for item in interfaces if item.get("is_up") is True)),
    }
    for target, source in (("bytes_received_per_second", "bytes_received_per_second"),
                           ("bytes_sent_per_second", "bytes_sent_per_second"),
                           ("packets_received_per_second", "packets_received_per_second"),
                           ("packets_sent_per_second", "packets_sent_per_second")):
        result[target] = sum(number(rate.get(source), source) for rate in rates)
    if any(not math.isfinite(value) or value < 0 for value in result.values()):
        raise ValueError("В снимке есть некорректные значения")
    return result


def _verified_window(event_db: Path, start_utc: datetime, end_utc: datetime,
                     progress=None) -> list[dict]:
    import sqlite3

    rows = []
    if not event_db.is_file():
        raise FileNotFoundError(f"Журнал сетевых наблюдений не найден: {event_db}")
    with sqlite3.connect(f"file:{event_db.resolve().as_posix()}?mode=ro", uri=True, timeout=10) as db:
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        cursor = db.execute(
            "SELECT event_id,captured_at_utc,snapshot_sha256,snapshot_json,source "
            "FROM events ORDER BY captured_at_utc,event_id")
        for index, (event_id, captured_at, digest, raw, source) in enumerate(cursor, 1):
            if progress and (index == 1 or index % 250 == 0 or index == total):
                progress({"records_processed": index, "records_total": total,
                          "percent": int(index * 100 / max(total, 1))})
            snapshot = json.loads(raw)
            observed_at = _parse_time(snapshot.get("observed_at_utc"))
            if not start_utc <= observed_at <= end_utc:
                continue
            canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":"))
            actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if actual != digest:
                raise ValueError(f"SHA-256 снимка {event_id} не совпадает")
            if source != "gui_periodic":
                raise ValueError(f"Недопустимый источник снимка {event_id}: {source}")
            expected_id = "net-" + hashlib.sha256(
                f"{digest}\0{snapshot['observed_at_utc']}".encode("utf-8")).hexdigest()[:24]
            if event_id != expected_id:
                raise ValueError(f"ID события {event_id} не соответствует снимку")
            try:
                features = _features(snapshot)
                excluded_reason = None
            except ValueError as error:
                # A real event can be authentic while its telemetry is incomplete (for
                # example the sampler's first rate has no prior counter delta). Keep it
                # in provenance, but never turn missing values into zeros or features.
                features, excluded_reason = None, str(error)
            rows.append({"event_id": event_id, "captured_at_utc": _parse_time(captured_at).isoformat(),
                         "observed_at_utc": observed_at.isoformat(),
                         "snapshot_sha256": digest, "features": features,
                         "excluded_reason": excluded_reason})
    rows.sort(key=lambda item: (item["observed_at_utc"], item["event_id"]))
    return rows


def build_profile(event_db: Path, start: datetime, end: datetime, *, operator_selected: bool,
                  progress=None) -> dict:
    """Build from a real interval explicitly selected by the operator for comparison."""
    if not operator_selected:
        raise ValueError("Нужно выбрать период как локальную точку сравнения")
    if start.tzinfo is None or start.utcoffset() is None or end.tzinfo is None or end.utcoffset() is None:
        raise ValueError("У начала и конца периода должен быть явно задан часовой пояс")
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if end <= start or (end - start).total_seconds() < MIN_DURATION_SECONDS:
        raise ValueError("Интервал должен быть не короче 10 минут")
    events = _verified_window(Path(event_db), start, end, progress=progress)
    usable = [event for event in events if event["features"] is not None]
    if len(usable) < MIN_SAMPLES:
        raise ValueError(f"Недостаточно полных снимков: {len(usable)}; требуется минимум {MIN_SAMPLES}")
    coverage = len(usable) / len(events) if events else 0.0
    if coverage < MIN_VALID_COVERAGE:
        raise ValueError(f"Полнота телеметрии {coverage:.1%}; требуется не менее {MIN_VALID_COVERAGE:.0%}")
    times = [_parse_time(event["observed_at_utc"]) for event in usable]
    gaps = [(right-left).total_seconds() for left, right in zip(times, times[1:])]
    if max(gaps, default=0) > MAX_GAP_SECONDS:
        raise ValueError(f"В интервале есть разрыв {max(gaps):.0f} с; предел {MAX_GAP_SECONDS} с")
    features = sorted(usable[0]["features"])
    if any(sorted(event["features"]) != features for event in usable):
        raise ValueError("Схема признаков менялась внутри выбранного интервала")
    summary = {}
    for name in features:
        values = [float(event["features"][name]) for event in usable]
        summary[name] = {
            "median": statistics.median(values),
            "p05": _quantile(values, 0.05),
            "p95": _quantile(values, 0.95),
            "mad": statistics.median(abs(value-statistics.median(values)) for value in values),
        }
    body = {
        "schema": SCHEMA,
        "kind": "operator_selected_network_behavior_profile",
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": {"start_utc": start.isoformat(), "end_utc": end.isoformat()},
        "event_count": len(usable),
        "window_event_count": len(events),
        "telemetry_coverage": coverage,
        "event_ids": [event["event_id"] for event in usable],
        "event_sha256": [event["snapshot_sha256"] for event in usable],
        "excluded_events": [{"event_id": event["event_id"],
                             "snapshot_sha256": event["snapshot_sha256"],
                             "reason": event["excluded_reason"]}
                            for event in events if event["excluded_reason"]],
        "features": summary,
        "operator_selected_reference_period": True,
        "representativeness_asserted": False,
        "selection_confirmation_source": "operator",
        "ground_truth_labels": False,
        "used_for_training": False,
        "used_for_blocking": False,
        "limitations": "Профиль описывает выбранную телеметрию; не подтверждает нормальность, безопасность "
                       "или отсутствие атак и не является меткой.",
    }
    body["profile_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
    return body


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = fraction * (len(ordered)-1)
    lower = int(position)
    upper = min(lower + 1, len(ordered)-1)
    return ordered[lower] + (ordered[upper]-ordered[lower]) * (position-lower)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def save_profile(profile: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    expected = hashlib.sha256(_canonical({key: value for key, value in profile.items()
                                          if key != "profile_sha256"})).hexdigest()
    if profile.get("profile_sha256") != expected:
        raise ValueError("Хеш профиля не совпадает")
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(profile, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def load_profile(path: Path) -> dict | None:
    try:
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
        digest = profile.pop("profile_sha256")
        expected = hashlib.sha256(_canonical(profile)).hexdigest()
        profile["profile_sha256"] = digest
        event_ids = profile.get("event_ids")
        event_hashes = profile.get("event_sha256")
        features = profile.get("features")
        window = profile.get("window")
        event_count = profile.get("event_count")
        window_count = profile.get("window_event_count")
        coverage = profile.get("telemetry_coverage")
        if (profile.get("schema") != SCHEMA or profile.get("kind") != "operator_selected_network_behavior_profile"
                or digest != expected or profile.get("ground_truth_labels") is not False
                or profile.get("used_for_training") is not False or profile.get("used_for_blocking") is not False
                or profile.get("operator_selected_reference_period") is not True
                or profile.get("representativeness_asserted") is not False
                or profile.get("selection_confirmation_source") != "operator"
                or not isinstance(event_ids, list) or not isinstance(event_hashes, list)
                or not isinstance(event_count, int) or event_count < MIN_SAMPLES
                or not isinstance(window_count, int) or window_count < event_count
                or len(event_ids) != event_count or len(event_hashes) != len(event_ids)
                or len(set(event_ids)) != len(event_ids)
                or not all(isinstance(value, str) and len(value) == 64
                           and all(char in "0123456789abcdef" for char in value) for value in event_hashes)
                or isinstance(coverage, bool) or not isinstance(coverage, (int, float))
                or not MIN_VALID_COVERAGE <= coverage <= 1.0
                or not isinstance(window, dict) or not isinstance(features, dict) or not features
                or len(profile.get("excluded_events", [])) != window_count - event_count):
            return None
        start = _parse_time(window.get("start_utc"))
        end = _parse_time(window.get("end_utc"))
        if end <= start or (end - start).total_seconds() < MIN_DURATION_SECONDS:
            return None
        if abs(coverage - event_count / window_count) > 1e-9:
            return None
        for item in features.values():
            if not isinstance(item, dict):
                return None
            values = [float(item[key]) for key in ("median", "p05", "p95", "mad")]
            median, p05, p95, mad = values
            if (not all(math.isfinite(value) for value in values) or mad < 0
                    or p05 > median or median > p95):
                return None
        return profile
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def compare_snapshot(snapshot: dict, profile: dict) -> dict:
    """Return feature deviations only. Never return an allow/block or class label."""
    current = _features(snapshot)
    deviations = []
    baselines = profile.get("features", {})
    if set(baselines) != set(current):
        raise ValueError("Схема профиля и текущего снимка различается; сравнение пропущено")
    for name, baseline in baselines.items():
        value = current[name]
        low, high = float(baseline["p05"]), float(baseline["p95"])
        span = max(high-low, abs(float(baseline["median"])) * 0.05, 1.0)
        if value < low - 0.25*span or value > high + 0.25*span:
            deviations.append({"feature": name, "value": value, "baseline_p05": low,
                               "baseline_p95": high,
                               "direction": "above" if value > high else "below"})
    return {"status": "advisory_deviation" if deviations else "within_observed_range",
            "deviations": deviations,
            "profile_sha256": profile["profile_sha256"],
            "is_ground_truth": False,
            "decision": None}

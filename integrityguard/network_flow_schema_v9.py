"""Version 9 candidate features: v8 flow vector plus duration-missing flag.

This separate schema preserves compatibility with shipped v8 checkpoints.
The new final feature distinguishes a genuinely zero-duration flow from a
publisher Zeek row where duration is missing (``-``). It never assigns labels.
"""
from __future__ import annotations

from . import network_flow_schema as v8

FEATURE_VERSION = 9
FEATURE_NAMES = tuple(v8.FEATURE_NAMES) + ("duration_missing",)


def from_ctu_row(row: dict) -> list[float]:
    duration = str(row.get("Dur", "")).strip()
    missing = duration in {"", "-"}
    normalized = dict(row)
    if missing:
        normalized["Dur"] = "0"
    return v8.from_ctu_row(normalized) + [float(missing)]


def from_live_flow(flow: dict) -> list[float]:
    """Map one completed sensor flow using the same v8 prefix as its base schema."""
    if not isinstance(flow, dict):
        raise ValueError("Live flow must be a mapping")
    duration = flow.get("duration_seconds")
    missing = duration is None or str(duration).strip() == ""
    normalized_duration = "0" if missing else duration
    base = v8.feature_vector(
        normalized_duration,
        flow.get("total_packets"),
        flow.get("total_bytes"),
        flow.get("direction_a_bytes"),
        flow.get("direction_b_bytes"),
        flow.get("protocol"),
    )
    return base + [float(missing)]


def from_zeek_row(columns: list[str]) -> list[float]:
    """Convert Zeek conn.log fields to the v8 flow mapping plus missing flag."""
    if len(columns) < 20:
        raise ValueError("Zeek flow has fewer than 20 data columns")
    duration = str(columns[8]).strip()
    missing = duration in {"", "-"}
    normalized_duration = "0" if missing else duration
    try:
        packets = float(columns[16]) + float(columns[18])
        orig_bytes = float(columns[17])
        resp_bytes = float(columns[19])
    except (TypeError, ValueError) as exc:
        raise ValueError("Zeek packet/byte counters are incomplete") from exc
    vector = v8.feature_vector(normalized_duration, packets, orig_bytes + resp_bytes,
                               orig_bytes, resp_bytes, columns[6])
    return vector + [float(missing)]

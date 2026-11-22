"""Feature v11: v10 flow features plus unlabeled 10-second host context.

Context aggregates all observed rows in a time bucket before supervised labels
are filtered. It contains no IP values and never uses labels or payload bytes.
"""
from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path

from . import network_flow_schema_v10 as v10

FEATURE_VERSION = 11
CONTEXT_NAMES = (
    "originator_flows_10s_log1p",
    "originator_unique_dest_ips_10s_log1p",
    "originator_unique_dest_ports_10s_log1p",
    "originator_failed_ratio_10s",
    "responder_unique_source_ips_10s_log1p",
)
FEATURE_NAMES = tuple(v10.FEATURE_NAMES) + CONTEXT_NAMES
WINDOW_SECONDS = 10.0


def _failed_state(state: str) -> bool:
    return str(state or "").strip().upper() in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR"}


def _window(timestamp: float) -> int:
    return math.floor(float(timestamp) / WINDOW_SECONDS)


def _context_tuple(source_ip, destination_ip, destination_port, timestamp):
    return (str(source_ip), _window(timestamp)), (str(destination_ip),
            int(destination_port), _window(timestamp))


def build_zeek_context_index(path: str | Path) -> dict:
    """Build label-blind context counts from every parseable flow in a capture."""
    source = defaultdict(lambda: [0, set(), set(), 0])
    destination_sources = defaultdict(set)
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not line or line.startswith("#"):
                continue
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) < 21:
                continue
            try:
                timestamp = float(columns[0])
                destination_port = v10._port(columns[5], "responder_port")
                v10.from_zeek_row(columns)
            except (TypeError, ValueError, OverflowError):
                continue
            if not math.isfinite(timestamp):
                continue
            source_key, destination_key = _context_tuple(columns[2], columns[4],
                                                           destination_port, timestamp)
            stats = source[source_key]
            stats[0] += 1
            stats[1].add(columns[4])
            stats[2].add(destination_port)
            stats[3] += int(_failed_state(columns[11]))
            destination_sources[destination_key].add(columns[2])
    return {"source": source, "destination_sources": destination_sources}


def context_from_zeek_row(columns: list[str], index: dict) -> list[float]:
    timestamp = float(columns[0])
    destination_port = v10._port(columns[5], "responder_port")
    source_key, destination_key = _context_tuple(columns[2], columns[4], destination_port, timestamp)
    count, destinations, ports, failed = index["source"].get(source_key, (0, set(), set(), 0))
    source_count = len(index["destination_sources"].get(destination_key, ()))
    return [math.log1p(count), math.log1p(len(destinations)), math.log1p(len(ports)),
            failed / count if count else 0.0, math.log1p(source_count)]


def from_zeek_row(columns: list[str], context_index: dict) -> list[float]:
    return v10.from_zeek_row(columns) + context_from_zeek_row(columns, context_index)


def from_live_flows(flows: list[dict]) -> list[list[float]]:
    """Extract flow + contextual vectors from one observed live segment."""
    source = defaultdict(lambda: [0, set(), set(), 0])
    destination_sources = defaultdict(set)
    keys = []
    for flow in flows:
        timestamp = flow.get("first_seen")
        originator_ip = str(flow.get("originator_ip") or "")
        responder_ip = str(flow.get("responder_ip") or "")
        responder_port = v10._port(flow.get("responder_port", 0), "responder_port")
        if not originator_ip or not responder_ip or timestamp is None:
            keys.append(None)
            continue
        source_key, destination_key = _context_tuple(originator_ip, responder_ip, responder_port, timestamp)
        keys.append((source_key, destination_key))
        stats = source[source_key]
        stats[0] += 1
        stats[1].add(responder_ip)
        stats[2].add(responder_port)
        failed = bool(flow.get("saw_syn") and not flow.get("saw_syn_ack"))
        stats[3] += int(failed)
        destination_sources[destination_key].add(originator_ip)
    vectors = []
    for flow, keys_for_flow in zip(flows, keys):
        base = v10.from_live_flow(flow)
        if keys_for_flow is None:
            context = [0.0] * len(CONTEXT_NAMES)
        else:
            source_key, destination_key = keys_for_flow
            count, destinations, ports, failed = source[source_key]
            inbound_sources = len(destination_sources[destination_key])
            context = [math.log1p(count), math.log1p(len(destinations)),
                       math.log1p(len(ports)), failed / count if count else 0.0,
                       math.log1p(inbound_sources)]
        vectors.append(base + context)
    return vectors

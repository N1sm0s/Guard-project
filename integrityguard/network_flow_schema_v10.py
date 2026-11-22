"""Feature version 10: v9 flow statistics plus transport endpoint/handshake data.

The features use only data recoverable from Zeek conn logs and the application's
payload-free packet flow parser. No address, payload, DNS name, or label is used.
"""
from __future__ import annotations

import math

from . import network_flow_schema_v9 as v9

FEATURE_VERSION = 10
COMMON_DESTINATION_PORTS = (22, 23, 25, 53, 80, 110, 123, 143, 443, 445,
                            554, 1883, 1900, 5353, 6667, 7547, 8080, 8443)
FEATURE_NAMES = tuple(v9.FEATURE_NAMES) + (
    "originator_port_log1p", "responder_port_log1p",
    "destination_port_ephemeral", "destination_port_zero",
    "destination_port_22", "destination_port_23", "destination_port_25",
    "destination_port_53", "destination_port_80", "destination_port_110",
    "destination_port_123", "destination_port_143", "destination_port_443",
    "destination_port_445", "destination_port_554", "destination_port_1883",
    "destination_port_1900", "destination_port_5353", "destination_port_6667",
    "destination_port_7547", "destination_port_8080", "destination_port_8443",
    "tcp_syn_seen", "tcp_syn_ack_seen", "tcp_ack_seen", "tcp_fin_seen",
    "tcp_rst_seen", "tcp_syn_without_syn_ack",
)


def _port(value, name):
    if value is None or str(value).strip() in {"", "-"}:
        return 0
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {name}") from None
    if not 0 <= port <= 65535:
        raise ValueError(f"Invalid {name}")
    return port


def _transport_features(protocol, originator_port, responder_port,
                        saw_syn=False, saw_syn_ack=False, saw_ack=False,
                        saw_fin=False, saw_rst=False):
    proto = str(protocol or "").strip().lower()
    origin = _port(originator_port, "originator_port")
    destination = _port(responder_port, "responder_port")
    tcp = proto == "tcp"
    syn = bool(saw_syn) if tcp else False
    syn_ack = bool(saw_syn_ack) if tcp else False
    ack = bool(saw_ack) if tcp else False
    fin = bool(saw_fin) if tcp else False
    rst = bool(saw_rst) if tcp else False
    return [
        math.log1p(origin), math.log1p(destination),
        float(destination >= 49152), float(destination == 0),
        *[float(destination == p) for p in COMMON_DESTINATION_PORTS],
        float(syn), float(syn_ack), float(ack), float(fin), float(rst),
        float(syn and not syn_ack),
    ]


def from_zeek_row(columns: list[str]) -> list[float]:
    if len(columns) < 21:
        raise ValueError("Zeek flow has fewer than 21 data columns")
    base = v9.from_zeek_row(columns)
    history = str(columns[15]).upper()
    extra = _transport_features(columns[6], columns[3], columns[5],
        "S" in history, "H" in history and "A" in history,
        "A" in history, "F" in history, "R" in history)
    return base + extra


def from_live_flow(flow: dict) -> list[float]:
    if not isinstance(flow, dict):
        raise ValueError("Live flow must be a mapping")
    base = v9.from_live_flow(flow)
    extra = _transport_features(flow.get("protocol"), flow.get("originator_port", 0),
        flow.get("responder_port", 0), flow.get("saw_syn", False),
        flow.get("saw_syn_ack", False), flow.get("saw_ack", False),
        flow.get("saw_fin", False), flow.get("saw_rst", False))
    return base + extra

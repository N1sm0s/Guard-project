"""Canonical, versioned feature contract for bidirectional network flows."""
from __future__ import annotations
import math

FEATURE_VERSION = 8
FEATURE_NAMES = (
    "duration_log1p",
    "total_packets_log1p",
    "total_bytes_log1p",
    "max_direction_bytes_log1p",
    "protocol_tcp",
    "protocol_udp",          # index 5
    "protocol_icmp",
    "protocol_other",
    "bytes_per_pkt_log1p",
    "pkt_rate_log1p",
    "direction_asym",
    # v5: very_ephemeral UDP (dur<0.001s — DNS/NTP: p50=0.0004s)
    # CTU-53 benign=74.2% vs attack=15.0%; CTU-54 benign=90.2% vs attack=38.6%
    "is_very_ephemeral_udp",  # index 11
    "log_total_pkts_x_dur",  # index 12
    # v6: sustained UDP (Rbot C&C: dur>=1.0s AND udp)
    # CTU-53: 60.9% attack vs 0.3% benign; CTU-54: 0.5% attack (not used for 54)
    "is_sustained_udp",      # index 13
    # v7: UDP duration binning — discriminates CTU-54 Neris (p50=0.02s) from benign (p50=0.0004s)
    # and from CTU-53 Rbot (p50=5.26s). Three bins: very_short(<0.001), medium(0.001-1.0), long(>=1.0)
    "udp_dur_medium",        # index 14: UDP AND 0.001<=dur<1.0 (CTU-54 Neris attacks!)
    "udp_dur_log1p",         # index 15: log1p(dur) for UDP only (0.0 for TCP/ICMP)
    # v8: UDP no-response flag — asym==1.0 means only src→dst bytes, no reply
    # CTU-53 Rbot very_ephemeral attack: 63.2% asym==1.0 vs benign: 6.6% (probe scans no response)
    # CTU-54 Neris very_ephemeral attack: 0.0% asym==1.0 (all bidirectional) — safe!
    "is_udp_no_response",    # index 16: UDP AND direction_asym==1.0
)

FEATURE_VERSION_HISTORY = {
    3: ("duration_log1p","total_packets_log1p","total_bytes_log1p",
        "max_direction_bytes_log1p","protocol_tcp","protocol_udp",
        "protocol_icmp","protocol_other"),
    4: ("duration_log1p","total_packets_log1p","total_bytes_log1p",
        "max_direction_bytes_log1p","protocol_tcp","protocol_udp",
        "protocol_icmp","protocol_other",
        "bytes_per_pkt_log1p","pkt_rate_log1p","direction_asym"),
    5: ("duration_log1p","total_packets_log1p","total_bytes_log1p",
        "max_direction_bytes_log1p","protocol_tcp","protocol_udp",
        "protocol_icmp","protocol_other",
        "bytes_per_pkt_log1p","pkt_rate_log1p","direction_asym",
        "is_ephemeral_udp","log_total_pkts_x_dur"),
    6: ("duration_log1p","total_packets_log1p","total_bytes_log1p",
        "max_direction_bytes_log1p","protocol_tcp","protocol_udp",
        "protocol_icmp","protocol_other",
        "bytes_per_pkt_log1p","pkt_rate_log1p","direction_asym",
        "is_ephemeral_udp","log_total_pkts_x_dur","is_sustained_udp"),
    7: FEATURE_NAMES,
}


def _measurement(value, name: str) -> float:
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing flow measurement: {name}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid flow measurement: {name}") from None
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"Invalid flow measurement: {name}")
    return number


def feature_vector(duration_seconds, total_packets, total_bytes, direction_a_bytes,
                   direction_b_bytes, protocol) -> list[float]:
    """Convert complete flow measurements into the stable v7 model vector (16 features)."""
    duration = _measurement(duration_seconds, "duration_seconds")
    packets = _measurement(total_packets, "total_packets")
    byte_count = _measurement(total_bytes, "total_bytes")
    direction_a_count = _measurement(direction_a_bytes, "direction_a_bytes")
    direction_b_count = _measurement(direction_b_bytes, "direction_b_bytes")
    if direction_a_count > byte_count or direction_b_count > byte_count:
        raise ValueError("direction bytes exceed total_bytes")
    protocol_name = str(protocol or "").strip().lower()

    # v3
    v3 = [
        math.log1p(duration),
        math.log1p(packets),
        math.log1p(byte_count),
        math.log1p(max(direction_a_count, direction_b_count)),
        float(protocol_name == "tcp"),
        float(protocol_name == "udp"),
        float(protocol_name in {"icmp", "icmpv6"}),
        float(protocol_name not in {"tcp", "udp", "icmp", "icmpv6"}),
    ]

    # v4
    safe_pkts = max(packets, 1.0)
    safe_dur = max(duration, 0.001)
    bytes_per_pkt = byte_count / safe_pkts
    pkt_rate = packets / safe_dur
    asym = abs(direction_a_count - direction_b_count) / byte_count if byte_count > 0 else 0.0
    v4 = [math.log1p(bytes_per_pkt), math.log1p(pkt_rate), asym]

    # v5: very_ephemeral UDP (benign DNS/NTP: dur~0.0004s)
    # CTU-53 benign UDP: 74.2% dur<0.001 vs attack: 15.0%
    # CTU-54 benign UDP: 90.2% dur<0.001 vs attack: 38.6% (better than old dur<0.1 which was 69.4%!)
    is_very_ephemeral_udp = float(protocol_name == "udp" and duration < 0.001)
    log_pkts_x_dur = math.log1p(packets * duration)
    v5 = [is_very_ephemeral_udp, log_pkts_x_dur]

    # v6: sustained UDP (Rbot C&C: dur>=1.0s AND udp)
    # CTU-53: 60.9% attack vs 0.3% benign; CTU-54: only 0.5% attack (barely relevant)
    is_sustained_udp = float(protocol_name == "udp" and duration >= 1.0)
    v6 = [is_sustained_udp]

    # v7: UDP-specific duration features to discriminate Neris (CTU-54) medium-duration attacks
    # CTU-54 Neris attacks: p50 dur=0.020s (medium range: 0.001-1.0s)
    # CTU-54 benign: p50 dur=0.0004s (very short — below 0.001s)
    # CTU-53 Rbot attacks: p50 dur=5.26s (sustained >1.0s)
    is_udp = (protocol_name == "udp")
    udp_dur_medium = float(is_udp and 0.001 <= duration < 1.0)
    udp_dur_log1p = math.log1p(duration) if is_udp else 0.0
    v7 = [udp_dur_medium, udp_dur_log1p]

    # v8: UDP no-response flag — detects one-directional UDP flows (no reply received)
    # CTU-53 Rbot very_ephemeral attack: 63.2% have asym==1.0 (probe scans, no response)
    # CTU-54 Neris very_ephemeral attack: 0.0% have asym==1.0 (all bidirectional DNS-like) — safe!
    # CTU-53 benign very_ephemeral: only 6.6% have asym==1.0 — good discrimination
    is_udp_no_response = float(is_udp and asym >= 1.0)
    v8 = [is_udp_no_response]

    return v3 + v4 + v5 + v6 + v7 + v8


def from_ctu_row(row: dict) -> list[float]:
    total_bytes = _measurement(row.get("TotBytes"), "total_bytes")
    source_bytes = _measurement(row.get("SrcBytes"), "source_bytes")
    if source_bytes > total_bytes:
        raise ValueError("source_bytes exceeds total_bytes")
    return feature_vector(row.get("Dur"), row.get("TotPkts"), total_bytes,
                          source_bytes, total_bytes - source_bytes, row.get("Proto"))


def from_live_flow(flow: dict) -> list[float]:
    if not isinstance(flow, dict):
        raise ValueError("Live flow must be a mapping")
    return feature_vector(flow.get("duration_seconds"), flow.get("total_packets"),
                          flow.get("total_bytes"), flow.get("direction_a_bytes"),
                          flow.get("direction_b_bytes"), flow.get("protocol"))

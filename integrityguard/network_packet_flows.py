"""Bounded, payload-free decoding and bidirectional flow aggregation.

Supports classic PCAP and PCAPNG frames. The decoder keeps only IP/transport
headers and counters; it never writes packet bytes or payload to the evidence log.
"""
from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from pathlib import Path

from .network_flow_schema import from_live_flow
from .network_flow_schema_v10 import from_live_flow as from_live_flow_v10
from .network_flow_schema_v11 import from_live_flows as from_live_flows_v11

_MAX_CAPTURE_BYTES = 128 * 1024 * 1024
_MAX_FLOWS = 250_000
_UDP_IDLE_TIMEOUT_SECONDS = 1.0
# ICMP has no close handshake and a SYN-flood flow never sends FIN/RST, so the
# same verified-idle rule as UDP is used to close them inside a segment.
_IDLE_TIMEOUT_SECONDS = _UDP_IDLE_TIMEOUT_SECONDS


class CaptureFormatError(ValueError):
    pass


def _read_capture(path: Path, max_bytes: int = _MAX_CAPTURE_BYTES):
    path = Path(path)
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise CaptureFormatError("Capture file is empty or exceeds the processing limit")
    data = path.read_bytes()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        yield from _classic_pcap(data)
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
    else:
        raise CaptureFormatError("Unknown PCAP/PCAPNG magic")


def _classic_pcap(data: bytes):
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    resolution = 1e-9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
    if len(data) < 24:
        raise CaptureFormatError("Truncated PCAP global header")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise CaptureFormatError("Truncated PCAP packet header")
        sec, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > len(data) - offset or captured > 16 * 1024 * 1024:
            raise CaptureFormatError("Invalid PCAP captured packet length")
        frame = data[offset:offset + captured]
        offset += captured
        yield (sec + fraction * resolution, linktype, frame, original)


def _pcapng(data: bytes):
    offset, endian, interfaces = 0, None, []
    while offset < len(data):
        if offset + 12 > len(data):
            raise CaptureFormatError("Truncated PCAPNG block")
        block_type = data[offset:offset + 4]
        if block_type == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Invalid PCAPNG byte-order magic")
            block_length = struct.unpack_from(endian + "I", data, offset + 4)[0]
            interfaces = []
        elif endian is not None:
            block_length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        else:
            raise CaptureFormatError("PCAPNG section header must be first")
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise CaptureFormatError("Invalid PCAPNG block length")
        block = data[offset:offset + block_length]
        if struct.unpack_from(endian + "I", block, block_length - 4)[0] != block_length:
            raise CaptureFormatError("PCAPNG block length trailer mismatch")
        if block_type == b"\x01\x00\x00\x00":  # Interface Description Block
            if block_length < 20:
                raise CaptureFormatError("Truncated PCAPNG interface block")
            linktype = struct.unpack_from(endian + "H", block, 8)[0]
            resolution = 1e-6
            option_offset, option_end = 16, block_length - 4
            while option_offset + 4 <= option_end:
                code, length = struct.unpack_from(endian + "HH", block, option_offset)
                option_offset += 4
                if code == 0:
                    break
                if option_offset + length > option_end:
                    raise CaptureFormatError("Invalid PCAPNG interface option")
                value = block[option_offset:option_offset + length]
                if code == 9 and length == 1:  # if_tsresol
                    raw = value[0]
                    resolution = (2.0 ** -(raw & 0x7f)) if raw & 0x80 else (10.0 ** -raw)
                option_offset += (length + 3) & ~3
            interfaces.append((linktype, resolution))
        elif block_type == b"\x06\x00\x00\x00":  # Enhanced Packet Block
            if block_length < 32:
                raise CaptureFormatError("Truncated PCAPNG packet block")
            interface_id, high, low, captured, original = struct.unpack_from(endian + "IIIII", block, 8)
            if interface_id >= len(interfaces) or captured > block_length - 32:
                raise CaptureFormatError("Invalid PCAPNG packet metadata")
            linktype, resolution = interfaces[interface_id]
            frame = block[28:28 + captured]
            yield (((high << 32) | low) * resolution, linktype, frame, original)
        offset += block_length


def _decode_packet(frame: bytes, linktype: int, original_length: int):
    """Return normalized (timestamp-independent) IP tuple, or None if unsupported."""
    offset = 0
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88a8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ethertype not in (0x0800, 0x86dd):
            # ARP and other L2 frames do not reduce IPv4/IPv6 flow coverage.
            return ("non_ip",)
        version = 4 if ethertype == 0x0800 else 6
    elif linktype in (101, 228, 229):  # raw IP, IPv4 or IPv6
        if not frame:
            return None
        version = frame[0] >> 4
    elif linktype == 113:  # Linux cooked capture
        if len(frame) < 16:
            return None
        protocol_type = struct.unpack_from("!H", frame, 14)[0]
        offset = 16
        if protocol_type not in (0x0800, 0x86dd):
            return ("non_ip",)
        version = 4 if protocol_type == 0x0800 else 6
    else:
        return None

    if version == 4:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0f) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return None
        total_length = struct.unpack_from("!H", frame, offset + 2)[0]
        frag = struct.unpack_from("!H", frame, offset + 6)[0]
        if frag & 0x1fff:  # non-initial fragment: transport ports are not present
            return None
        proto = frame[offset + 9]
        src = ipaddress.ip_address(frame[offset + 12:offset + 16])
        dst = ipaddress.ip_address(frame[offset + 16:offset + 20])
        l4 = offset + ihl
    elif version == 6:
        if len(frame) < offset + 40:
            return None
        payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
        total_length = 40 + payload_length
        proto = frame[offset + 6]
        src = ipaddress.ip_address(frame[offset + 8:offset + 24])
        dst = ipaddress.ip_address(frame[offset + 24:offset + 40])
        l4 = offset + 40
        for _ in range(8):
            if proto in (0, 43, 60):  # hop-by-hop, routing, destination options
                if len(frame) < l4 + 2:
                    return None
                next_proto = frame[l4]
                ext_length = (frame[l4 + 1] + 1) * 8
                if len(frame) < l4 + ext_length:
                    return None
            elif proto == 44:  # fragment header
                if len(frame) < l4 + 8:
                    return None
                next_proto = frame[l4]
                fragment = struct.unpack_from("!H", frame, l4 + 2)[0]
                if (fragment >> 3) & 0x1fff:
                    return None
                ext_length = 8
            elif proto == 51:  # authentication header
                if len(frame) < l4 + 2:
                    return None
                next_proto = frame[l4]
                ext_length = (frame[l4 + 1] + 2) * 4
                if len(frame) < l4 + ext_length:
                    return None
            else:
                break
            proto, l4 = next_proto, l4 + ext_length
    else:
        return None

    if total_length <= 0 or total_length > original_length:
        return None
    if proto in (6, 17):  # TCP, UDP
        if len(frame) < l4 + 4:
            return None
        src_port, dst_port = struct.unpack_from("!HH", frame, l4)
    else:
        src_port = dst_port = 0
    name = "tcp" if proto == 6 else "udp" if proto == 17 \
        else "icmp" if proto in (1, 58) else "other"
    tcp_flags = frame[l4 + 13] if proto == 6 and len(frame) >= l4 + 14 else 0
    return (name, (str(src), src_port), (str(dst), dst_port), total_length, tcp_flags)


def aggregate_capture(path: Path, *, capture_end_timestamp: float | None = None) -> dict:
    """Aggregate packet headers into bidirectional flow records with completeness.

    TCP completion requires an observed SYN followed by FIN/RST. For live
    Pktmon segments, UDP and ICMP flows are treated as idle-closed observations
    only when their last packet precedes the verified capture stop by the idle
    timeout. A half-open TCP flow (the originator sent only SYN packets,
    including retransmissions, and never an ACK or data, e.g. a SYN flood or an
    unanswered connection attempt) is closed by the same idle rule. Offline callers without a capture end timestamp keep these incomplete.
    """
    return aggregate_packets(lambda: _read_capture(path),
                             capture_end_timestamp=capture_end_timestamp)


def aggregate_packets(packet_source, *, capture_end_timestamp: float | None = None) -> dict:
    """Aggregate an iterable of (timestamp, linktype, frame, original_length).

    ``packet_source`` is a zero-argument callable returning the packet
    iterator, so reader errors are reported the same way as for files. This is
    the single aggregation used by live Pktmon segments and offline ingestion.
    """
    flows = OrderedDict()
    counts = {"packets": 0, "parsed": 0, "non_ip_frames": 0,
              "unsupported_or_truncated": 0,
              "flow_limit_reached": False}
    try:
        packets = packet_source()
        for timestamp, linktype, frame, original_length in packets:
            counts["packets"] += 1
            decoded = _decode_packet(frame, linktype, original_length)
            if decoded == ("non_ip",):
                counts["non_ip_frames"] += 1
                continue
            if decoded is None:
                counts["unsupported_or_truncated"] += 1
                continue
            protocol, source, destination, ip_bytes, tcp_flags = decoded
            endpoint_a, endpoint_b = sorted((source, destination))
            key = (protocol, endpoint_a, endpoint_b)
            flow = flows.get(key)
            if flow is None:
                if len(flows) >= _MAX_FLOWS:
                    counts["flow_limit_reached"] = True
                    continue
                flow = {"protocol": protocol, "endpoint_a": endpoint_a,
                        "endpoint_b": endpoint_b, "first_seen": timestamp,
                        "last_seen": timestamp, "total_packets": 0,
                        "total_bytes": 0, "direction_a_bytes": 0,
                        "direction_b_bytes": 0, "originator_port": source[1],
                        "responder_port": destination[1], "originator_ip": source[0],
                        "responder_ip": destination[0], "saw_syn": False,
                        "saw_syn_ack": False, "saw_ack": False,
                        "saw_fin": False, "saw_rst": False,
                        "saw_fin_or_rst": False, "originator_non_syn_packets": 0}
                flows[key] = flow
            direction = "a" if source == endpoint_a else "b"
            if (source == (flow["originator_ip"], flow["originator_port"])
                    and not (protocol == "tcp" and tcp_flags & 0x02)):
                flow["originator_non_syn_packets"] += 1
            flow["total_packets"] += 1
            flow["total_bytes"] += ip_bytes
            flow[f"direction_{direction}_bytes"] += ip_bytes
            flow["first_seen"] = min(flow["first_seen"], timestamp)
            flow["last_seen"] = max(flow["last_seen"], timestamp)
            if protocol == "tcp":
                flow["saw_syn"] |= bool(tcp_flags & 0x02)
                flow["saw_syn_ack"] |= bool((tcp_flags & 0x12) == 0x12)
                flow["saw_ack"] |= bool(tcp_flags & 0x10)
                flow["saw_fin"] |= bool(tcp_flags & 0x01)
                flow["saw_rst"] |= bool(tcp_flags & 0x04)
                flow["saw_fin_or_rst"] |= bool(tcp_flags & (0x01 | 0x04))
            counts["parsed"] += 1
    except OSError as error:
        return {"status": "capture_read_error", "reason": type(error).__name__,
                "counts": counts, "flows": []}
    except CaptureFormatError as error:
        return {"status": "capture_format_error", "reason": str(error),
                "counts": counts, "flows": []}

    records = []
    for flow in flows.values():
        idle = (capture_end_timestamp is not None
                and capture_end_timestamp - flow["last_seen"] >= _IDLE_TIMEOUT_SECONDS)
        complete = (flow["protocol"] == "tcp" and flow["saw_syn"] and flow["saw_fin_or_rst"])
        completion_reason = "tcp_fin_or_rst_after_syn" if complete else "incomplete"
        if (not complete and flow["protocol"] == "tcp" and flow["saw_syn"]
                and flow["originator_non_syn_packets"] == 0 and idle):
            complete, completion_reason = True, "tcp_half_open_idle_1s"
        if flow["protocol"] == "udp":
            complete = idle
            completion_reason = "udp_idle_timeout_1s" if complete else "incomplete"
        if flow["protocol"] == "icmp":
            complete = idle
            completion_reason = "icmp_idle_timeout_1s" if complete else "incomplete"
        record = {
            "duration_seconds": max(flow["last_seen"] - flow["first_seen"], 0.0),
            "total_packets": flow["total_packets"], "total_bytes": flow["total_bytes"],
            "direction_a_bytes": flow["direction_a_bytes"],
            "direction_b_bytes": flow["direction_b_bytes"],
            "originator_port": flow["originator_port"],
            "responder_port": flow["responder_port"],
            "originator_ip": flow["originator_ip"],
            "responder_ip": flow["responder_ip"],
            "first_seen": flow["first_seen"], "last_seen": flow["last_seen"],
            "saw_syn": flow["saw_syn"], "saw_syn_ack": flow["saw_syn_ack"],
            "saw_ack": flow["saw_ack"], "saw_fin": flow["saw_fin"],
            "saw_rst": flow["saw_rst"],
            "protocol": flow["protocol"], "complete": complete,
            "completion_reason": completion_reason,
        }
        try:
            record["features"] = from_live_flow(record)
        except ValueError:
            continue
        try:
            record["features_v10"] = from_live_flow_v10(record)
        except ValueError:
            record["features_v10"] = None
        records.append(record)
    try:
        context_vectors = from_live_flows_v11(records)
        for record, vector in zip(records, context_vectors):
            record["features_v11"] = vector
    except (TypeError, ValueError, OverflowError):
        for record in records:
            record["features_v11"] = None
    ip_candidates = counts["parsed"] + counts["unsupported_or_truncated"]
    coverage = counts["parsed"] / max(ip_candidates, 1)
    status = "ok" if counts["unsupported_or_truncated"] == 0 \
        and not counts["flow_limit_reached"] else "incomplete"
    return {"status": status, "counts": counts, "coverage": coverage,
            "complete_flow_count": sum(bool(row["complete"]) for row in records),
            "flows": records}

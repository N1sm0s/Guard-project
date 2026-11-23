"""Streaming ingestion of public packet captures into labelled v10 feature shards.

Offline, development-only tooling. A capture is read once, sequentially, from a
local path or an HTTP(S) URL; nothing but the derived feature vectors, labels and
a provenance manifest is written to disk. Raw packets, payload and IP addresses
are never persisted.

Flow semantics deliberately match the live Pktmon sensor: the timeline is cut
into fixed windows (10 s by default, like ``capture_header_segment``), each
window is aggregated by :func:`network_packet_flows.aggregate_packets` with the
window end as capture stop, and only flows the runtime would score
(``complete is True``) are kept.

Labels come only from an explicit, publisher-derived rule file. IP addresses and
times are used to *apply* that rule and are not features. This module does not
train, score, select thresholds, or touch independent-test sources.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import json
import struct
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from . import network_packet_flows as npf
from . import network_flow_schema_v10 as v10

SHARD_FORMAT = "integrityguard.flow-shard.v1"
DEFAULT_WINDOW_SECONDS = 10.0
ALLOWED_ROLES = ("train", "dev")
_MAX_FRAME = 16 * 1024 * 1024
_HTTP_CHUNK = 1 << 20
_USER_AGENT = "integrityguard-stream-ingest/1"


class IngestError(ValueError):
    pass


# --------------------------------------------------------------------------- sources

class HashingReader(io.RawIOBase):
    """Sequential reader that hashes every byte it returns."""

    def __init__(self, raw, max_bytes: int | None = None):
        self._raw = raw
        self.sha256 = hashlib.sha256()
        self.md5 = hashlib.md5()
        self.bytes_read = 0
        self._max = max_bytes

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self._raw.read(len(buffer))
        if not data:
            return 0
        self.bytes_read += len(data)
        if self._max is not None and self.bytes_read > self._max:
            raise IngestError("Source exceeds the configured --max-bytes limit")
        self.sha256.update(data); self.md5.update(data)
        buffer[:len(data)] = data
        return len(data)

    def drain(self):
        """Read to EOF so the digest covers the whole source."""
        while self.read(_HTTP_CHUNK):
            pass


class HTTPRangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file via HTTP Range requests.

    Used for ZIP archives so a single member can be read without transferring
    the other members.
    """

    def __init__(self, url: str, timeout: float = 60.0):
        self.url, self.timeout, self.pos = url, timeout, 0
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if response.headers.get("Accept-Ranges", "").lower() != "bytes" or not length:
                raise IngestError("Server does not support byte ranges; ZIP member streaming unavailable")
            self.size = int(length)
        self.bytes_transferred = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=io.SEEK_SET):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.pos, io.SEEK_END: self.size}[whence]
        self.pos = max(0, base + offset)
        return self.pos

    def readinto(self, buffer):
        if self.pos >= self.size or not len(buffer):
            return 0
        end = min(self.pos + len(buffer), self.size) - 1
        request = urllib.request.Request(self.url, headers={
            "User-Agent": _USER_AGENT, "Range": f"bytes={self.pos}-{end}"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status != 206:
                raise IngestError("Range request was not honoured")
            data = response.read()
        buffer[:len(data)] = data
        self.pos += len(data); self.bytes_transferred += len(data)
        return len(data)


def _open_raw(source: str, timeout: float):
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": _USER_AGENT})
        return urllib.request.urlopen(request, timeout=timeout)
    if "://" in source:
        raise IngestError("Only local paths and http(s) URLs are supported")
    return open(Path(source), "rb")


@dataclass
class OpenedSource:
    stream: object
    hasher: HashingReader
    description: dict
    closers: list = field(default_factory=list)

    def close(self):
        for item in reversed(self.closers):
            try:
                item.close()
            except Exception:
                pass


def open_capture_source(source: str, *, zip_member: str | None = None,
                        max_bytes: int | None = None, timeout: float = 60.0) -> OpenedSource:
    """Open a pcap/pcapng (optionally .gz, or a member of a ZIP) as a byte stream.

    The returned hasher covers the bytes of the capture itself (the ZIP member
    after decompression, or the .gz content), which is what the manifest pins.
    """
    closers, desc = [], {"source": source}
    if zip_member:
        if source.startswith(("http://", "https://")):
            container = io.BufferedReader(HTTPRangeFile(source, timeout), buffer_size=_HTTP_CHUNK)
            desc["container_size_bytes"] = container.raw.size
        else:
            container = open(Path(source), "rb")
        closers.append(container)
        archive = zipfile.ZipFile(container)
        closers.append(archive)
        try:
            info = archive.getinfo(zip_member)
        except KeyError:
            raise IngestError(f"ZIP member not found: {zip_member}") from None
        desc.update({"zip_member": zip_member, "zip_member_crc32": f"{info.CRC:08x}",
                     "zip_member_size_bytes": info.file_size})
        raw = archive.open(info)  # zipfile verifies CRC-32 when read to EOF
    else:
        raw = _open_raw(source, timeout)
    closers.append(raw)
    if (zip_member or source).lower().endswith(".gz"):
        raw = gzip.GzipFile(fileobj=raw)
        closers.append(raw)
        desc["decompression"] = "gzip"
    hasher = HashingReader(raw, max_bytes)
    stream = io.BufferedReader(hasher, buffer_size=_HTTP_CHUNK)
    return OpenedSource(stream, hasher, desc, closers)


# --------------------------------------------------------------------------- packets

def _read_exact(stream, n: int, what: str, allow_eof: bool = False) -> bytes | None:
    data = stream.read(n)
    if not data and allow_eof:
        return None
    while len(data) < n:
        more = stream.read(n - len(data))
        if not more:
            raise npf.CaptureFormatError(f"Truncated {what}")
        data += more
    return data


def iter_stream_packets(stream):
    """Yield (timestamp, linktype, frame, original_length) from a pcap/pcapng stream.

    Validation mirrors network_packet_flows._classic_pcap/_pcapng.
    """
    magic = _read_exact(stream, 4, "capture magic")
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        resolution = 1e-9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
        header = _read_exact(stream, 20, "PCAP global header")
        linktype = struct.unpack_from(endian + "I", header, 16)[0]
        while True:
            record = _read_exact(stream, 16, "PCAP packet header", allow_eof=True)
            if record is None:
                return
            sec, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > _MAX_FRAME:
                raise npf.CaptureFormatError("Invalid PCAP captured packet length")
            frame = _read_exact(stream, captured, "PCAP packet data") if captured else b""
            yield (sec + fraction * resolution, linktype, frame, original)
    elif magic == b"\x0a\x0d\x0d\x0a":
        endian, interfaces, block_type = None, [], magic
        while True:
            if block_type is None:
                block_type = _read_exact(stream, 4, "PCAPNG block", allow_eof=True)
                if block_type is None:
                    return
            rest = _read_exact(stream, 8, "PCAPNG block")
            if block_type == b"\x0a\x0d\x0d\x0a":
                bom = rest[4:8]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise npf.CaptureFormatError("Invalid PCAPNG byte-order magic")
                interfaces = []
            elif endian is None:
                raise npf.CaptureFormatError("PCAPNG section header must be first")
            block_length = struct.unpack_from(endian + "I", rest, 0)[0]
            if block_length < 12 or block_length % 4 or block_length > _MAX_FRAME + 64:
                raise npf.CaptureFormatError("Invalid PCAPNG block length")
            block = block_type + rest + _read_exact(stream, block_length - 12, "PCAPNG block body")
            if struct.unpack_from(endian + "I", block, block_length - 4)[0] != block_length:
                raise npf.CaptureFormatError("PCAPNG block length trailer mismatch")
            if block_type == b"\x01\x00\x00\x00":
                if block_length < 20:
                    raise npf.CaptureFormatError("Truncated PCAPNG interface block")
                linktype = struct.unpack_from(endian + "H", block, 8)[0]
                resolution = 1e-6
                option_offset, option_end = 16, block_length - 4
                while option_offset + 4 <= option_end:
                    code, length = struct.unpack_from(endian + "HH", block, option_offset)
                    option_offset += 4
                    if code == 0:
                        break
                    if option_offset + length > option_end:
                        raise npf.CaptureFormatError("Invalid PCAPNG interface option")
                    value = block[option_offset:option_offset + length]
                    if code == 9 and length == 1:
                        raw = value[0]
                        resolution = (2.0 ** -(raw & 0x7f)) if raw & 0x80 else (10.0 ** -raw)
                    option_offset += (length + 3) & ~3
                interfaces.append((linktype, resolution))
            elif block_type == b"\x06\x00\x00\x00":
                if block_length < 32:
                    raise npf.CaptureFormatError("Truncated PCAPNG packet block")
                interface_id, high, low, captured, original = struct.unpack_from(endian + "IIIII", block, 8)
                if interface_id >= len(interfaces) or captured > block_length - 32:
                    raise npf.CaptureFormatError("Invalid PCAPNG packet metadata")
                linktype, resolution = interfaces[interface_id]
                yield (((high << 32) | low) * resolution, linktype, block[28:28 + captured], original)
            block_type = None
    else:
        raise npf.CaptureFormatError("Unknown PCAP/PCAPNG magic")


def source_mac_and_ip(frame: bytes, linktype: int):
    """Return (source MAC, source IP) for Ethernet IP frames, else None.

    Used only to apply publisher label rules that identify attacker devices by
    MAC address; neither value becomes a feature or is persisted.
    """
    if linktype != 1 or len(frame) < 14:
        return None
    offset, ethertype = 14, struct.unpack_from("!H", frame, 12)[0]
    while ethertype in (0x8100, 0x88a8, 0x9100):
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype == 0x0800 and len(frame) >= offset + 20:
        src = ipaddress.ip_address(frame[offset + 12:offset + 16])
    elif ethertype == 0x86dd and len(frame) >= offset + 40:
        src = ipaddress.ip_address(frame[offset + 8:offset + 24])
    else:
        return None
    return frame[6:12].hex(":"), str(src)


def iter_windows(packets, window_seconds: float = DEFAULT_WINDOW_SECONDS, on_packet=None):
    """Split a packet iterator into consecutive live-sensor-like windows.

    Yields (window_index, window_end_timestamp, aggregate_result). Windows are
    aligned to the first packet; packets with a timestamp earlier than the
    current window start (slight reordering) stay in the current window.
    ``on_packet(packet)`` is called for every packet of the window being
    aggregated, before that window's result is yielded.
    """
    if window_seconds <= 0:
        raise IngestError("window_seconds must be positive")
    iterator = iter(packets)
    pending = next(iterator, None)
    if pending is None:
        return
    origin = pending[0]
    errors = []

    while pending is not None:
        index = max(0, int((pending[0] - origin) // window_seconds))
        end = origin + (index + 1) * window_seconds

        def window_packets(first=pending):
            nonlocal pending
            if on_packet:
                on_packet(first)
            yield first
            pending = None
            for packet in iterator:
                if packet[0] >= end:
                    pending = packet
                    return
                if on_packet:
                    on_packet(packet)
                yield packet

        def source():
            try:
                yield from window_packets()
            except npf.CaptureFormatError as error:
                errors.append(str(error))
                raise

        result = npf.aggregate_packets(source, capture_end_timestamp=end)
        yield index, end, result
        if errors:
            return


# --------------------------------------------------------------------------- labels

_LABELS = {"attack": 1, "benign": 0, "exclude": None}


class LabelRule:
    """First-match label rule derived from publisher documentation.

    JSON form::

        {"rule_id": "...", "publisher_reference": "URL or document section",
         "default": "exclude",
         "rules": [{"label": "attack", "ip_any": ["192.168.137.0/24"],
                    "protocol": "udp", "time_from": 1546300800, "time_to": ...}]}

    Supported match keys: ip_any, ip_src (flow originator), ip_dst (responder),
    mac_src (full MACs or 3-byte OUI prefixes seen as Ethernet source of the
    flow originator IP within the same window), protocol (name or list),
    time_from/time_to (epoch seconds, applied to flow first_seen).
    """

    def __init__(self, spec: dict):
        if not isinstance(spec, dict) or not spec.get("rule_id") or not spec.get("publisher_reference"):
            raise IngestError("Label rule needs rule_id and publisher_reference")
        default = spec.get("default", "exclude")
        if default not in _LABELS:
            raise IngestError("Label rule default must be attack, benign or exclude")
        self.spec, self.default, self.rules = spec, default, []
        for item in spec.get("rules", []):
            label = item.get("label")
            if label not in _LABELS:
                raise IngestError(f"Invalid rule label: {label}")
            unknown = set(item) - {"label", "ip_any", "ip_src", "ip_dst", "mac_src", "protocol",
                                   "time_from", "time_to", "note"}
            if unknown:
                raise IngestError(f"Unknown label-rule keys: {sorted(unknown)}")
            nets = {k: [ipaddress.ip_network(v, strict=False) for v in item.get(k, [])]
                    for k in ("ip_any", "ip_src", "ip_dst")}
            macs = tuple(str(m).strip().lower().replace("-", ":") for m in item.get("mac_src", []))
            if any(len(m) not in (8, 17) for m in macs):
                raise IngestError("mac_src entries must be full MACs or 3-byte OUI prefixes")
            protocol = item.get("protocol")
            protocols = None if protocol is None else (
                {protocol} if isinstance(protocol, str) else set(protocol))
            self.rules.append((label, nets, macs, protocols,
                               item.get("time_from"), item.get("time_to")))
        self.uses_mac = any(rule[2] for rule in self.rules)

    @classmethod
    def from_file(cls, path: Path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @staticmethod
    def _in(ip, nets):
        return any(ip in net for net in nets)

    def label(self, flow: dict):
        src = ipaddress.ip_address(flow["originator_ip"])
        dst = ipaddress.ip_address(flow["responder_ip"])
        for label, nets, macs, protocols, t_from, t_to in self.rules:
            if nets["ip_src"] and not self._in(src, nets["ip_src"]):
                continue
            if nets["ip_dst"] and not self._in(dst, nets["ip_dst"]):
                continue
            if nets["ip_any"] and not (self._in(src, nets["ip_any"]) or self._in(dst, nets["ip_any"])):
                continue
            if macs and not any(seen.startswith(prefix)
                                for seen in flow.get("originator_macs", ())
                                for prefix in macs):
                continue
            if protocols and flow["protocol"] not in protocols:
                continue
            if t_from is not None and flow["first_seen"] < t_from:
                continue
            if t_to is not None and flow["first_seen"] >= t_to:
                continue
            return label
        return self.default


# --------------------------------------------------------------------------- ingest

def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HTTP_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_capture(*, source: str, source_id: str, role: str, label_rule_path: Path,
                   out_dir: Path, zip_member: str | None = None,
                   expected_sha256: str | None = None, expected_md5: str | None = None,
                   window_seconds: float = DEFAULT_WINDOW_SECONDS,
                   max_bytes: int | None = None, metadata: dict | None = None,
                   feature_version: int = 10) -> dict:
    """Stream one capture into ``<out_dir>/<source_id>.npz`` plus a manifest.

    Returns the manifest. The shard is written only after the whole source was
    read and any expected checksum matched; otherwise nothing is kept.
    ``feature_version`` 10 (default) or 11 (adds unlabeled 10-second host context).
    """
    if feature_version == 10:
        feature_key, feature_names = "features_v10", list(v10.FEATURE_NAMES)
    elif feature_version == 11:
        from . import network_flow_schema_v11 as v11
        feature_key, feature_names = "features_v11", list(v11.FEATURE_NAMES)
    else:
        raise IngestError("feature_version must be 10 or 11")
    if role not in ALLOWED_ROLES:
        raise IngestError("Only train/dev shards are produced; independent tests use their "
                          "registered one-pass evaluators")
    if not source_id or any(c in source_id for c in "/\\:*?\"<>|"):
        raise IngestError("source_id must be a plain file-name token")
    rule_path = Path(label_rule_path)
    rule = LabelRule.from_file(rule_path)
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    shard_path, manifest_path = out_dir / f"{source_id}.npz", out_dir / f"{source_id}.manifest.json"
    if shard_path.exists() or manifest_path.exists():
        raise IngestError(f"Shard {source_id} already exists; refusing to overwrite evidence")

    started = datetime.now(timezone.utc)
    opened = open_capture_source(source, zip_member=zip_member, max_bytes=max_bytes)
    features, labels, windows, first_seen = [], [], [], []
    counts = {"packets": 0, "parsed": 0, "non_ip_frames": 0, "unsupported_or_truncated": 0,
              "windows": 0, "windows_flow_limit_reached": 0, "windows_with_errors": 0,
              "flows_total": 0, "flows_incomplete_excluded": 0, "flows_feature_error": 0,
              "flows_label_excluded": 0, "attack": 0, "benign": 0,
              "incomplete_by_protocol": {}, "labelled_by_protocol": {}}
    ip_macs: dict[str, set] = {}

    def observe(packet):
        found = source_mac_and_ip(packet[2], packet[1])
        if found:
            ip_macs.setdefault(found[1], set()).add(found[0])

    status, reason = "ok", None
    try:
        for index, _end, result in iter_windows(iter_stream_packets(opened.stream), window_seconds,
                                                on_packet=observe if rule.uses_mac else None):
            counts["windows"] += 1
            for key in ("packets", "parsed", "non_ip_frames", "unsupported_or_truncated"):
                counts[key] += result["counts"][key]
            counts["windows_flow_limit_reached"] += bool(result["counts"]["flow_limit_reached"])
            if result["status"] not in ("ok", "incomplete"):
                counts["windows_with_errors"] += 1
                status, reason = "capture_format_error", result.get("reason")
            for flow in result["flows"]:
                counts["flows_total"] += 1
                if flow.get("complete") is not True:
                    counts["flows_incomplete_excluded"] += 1
                    by = counts["incomplete_by_protocol"]
                    by[flow["protocol"]] = by.get(flow["protocol"], 0) + 1
                    continue
                if flow.get(feature_key) is None:
                    counts["flows_feature_error"] += 1
                    continue
                flow["originator_macs"] = ip_macs.get(flow["originator_ip"], ())
                target = _LABELS[rule.label(flow)]
                if target is None:
                    counts["flows_label_excluded"] += 1
                    continue
                features.append(flow[feature_key]); labels.append(target)
                windows.append(index); first_seen.append(flow["first_seen"])
                counts["attack" if target else "benign"] += 1
                key = f"{flow['protocol']}:{'attack' if target else 'benign'}"
                by = counts["labelled_by_protocol"]
                by[key] = by.get(key, 0) + 1
            ip_macs.clear()
        if status == "ok":
            opened.hasher.drain()
    except npf.CaptureFormatError as error:
        status, reason = "capture_format_error", str(error)
    finally:
        opened.close()

    sha256 = opened.hasher.sha256.hexdigest()
    md5 = opened.hasher.md5.hexdigest()
    checks = {}
    if expected_sha256:
        checks["sha256_matches_expected"] = sha256 == expected_sha256.lower()
    if expected_md5:
        checks["md5_matches_publisher"] = md5 == expected_md5.lower()
    if status != "ok":
        raise IngestError(f"Capture parsing failed ({reason}); no shard written")
    if not all(checks.values()):
        raise IngestError(f"Checksum mismatch {checks}; no shard written")
    if not labels:
        raise IngestError("No complete, labelled flows were produced; no shard written")

    np.savez_compressed(
        shard_path,
        x=np.asarray(features, dtype=np.float32),
        y=np.asarray(labels, dtype=np.int8),
        window=np.asarray(windows, dtype=np.int32),
        first_seen=np.asarray(first_seen, dtype=np.float64),
    )
    manifest = {
        "format": SHARD_FORMAT,
        "research_only": True,
        "source_id": source_id,
        "role": role,
        "created_utc": started.isoformat(timespec="seconds"),
        "source": {**opened.description,
                   "capture_bytes": opened.hasher.bytes_read,
                   "capture_sha256": sha256, "capture_md5": md5, "checks": checks},
        "adapter": {
            "name": "pcap_stream_live_windows",
            "window_seconds": window_seconds,
            "idle_timeout_seconds": npf._IDLE_TIMEOUT_SECONDS,
            "completion_rules": ("tcp SYN then FIN/RST; tcp half-open (originator sent only SYN) "
                                 "idle; udp idle; icmp idle - as network_packet_flows"),
            "max_flows_per_window": npf._MAX_FLOWS,
            "kept": "flows with complete=True only (what the runtime scores)",
            "parser_sha256": _sha256_path(Path(npf.__file__)),
            "ingest_sha256": _sha256_path(Path(__file__)),
        },
        "feature_version": feature_version,
        "feature_names": feature_names,
        "label_rule": {"path": str(rule_path), "sha256": _sha256_path(rule_path),
                       "spec": rule.spec},
        "metadata": metadata or {},
        "counts": counts,
        "shard": {"path": shard_path.name, "sha256": _sha256_path(shard_path),
                  "arrays": ["x", "y", "window", "first_seen"]},
        "privacy": "No packet bytes, payload or IP addresses are stored in the shard.",
        "limitations": ("Publisher labels applied by an explicit rule; testbed captures are not "
                        "target-network evidence; flows split at window boundaries as in the live sensor."),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def load_shard(manifest_path: Path, *, expected_role: str = "train"):
    """Load a shard after verifying its manifest, hash and feature contract."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != SHARD_FORMAT:
        raise IngestError("Unknown shard format")
    if manifest.get("role") != expected_role:
        raise IngestError(f"Shard role {manifest.get('role')!r} is not {expected_role!r}")
    if manifest.get("feature_version") == 10:
        expected_names = list(v10.FEATURE_NAMES)
    elif manifest.get("feature_version") == 11:
        from . import network_flow_schema_v11 as v11
        expected_names = list(v11.FEATURE_NAMES)
    else:
        raise IngestError("Unknown shard feature version")
    if manifest.get("feature_names") != expected_names:
        raise IngestError("Shard feature contract differs from its declared version")
    shard_path = manifest_path.parent / manifest["shard"]["path"]
    if _sha256_path(shard_path) != manifest["shard"]["sha256"]:
        raise IngestError("Shard SHA-256 differs from its manifest")
    with np.load(shard_path) as data:
        x, y = data["x"], data["y"].astype(np.int64)
    if x.shape != (len(y), len(expected_names)):
        raise IngestError("Shard array shape is inconsistent")
    return x, y, manifest

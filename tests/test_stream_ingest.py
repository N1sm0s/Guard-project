"""Deterministic code tests for streaming capture ingestion.

The packets below are hand-built byte fixtures that exercise parsing and
bookkeeping only; they are not traffic samples and carry no model-quality
meaning.
"""
from __future__ import annotations

import gzip
import io
import json
import struct

import numpy as np
import pytest

from integrityguard import network_packet_flows as npf
from integrityguard import stream_ingest as si

A, B, C = "10.0.0.1", "10.0.0.2", "10.0.0.9"


def _ip(addr):
    return bytes(int(x) for x in addr.split("."))


def _frame(src, dst, proto, sport, dport, flags=0, payload=b"", mac=b"\x00" * 6):
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    l4 += payload
    total = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, _ip(src), _ip(dst))
    eth = b"\x00" * 6 + mac + b"\x08\x00"
    return eth + ip + l4


def _pcap(packets):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in packets:
        sec, usec = int(ts), int(round((ts - int(ts)) * 1e6))
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def _pcapng(packets):
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    out = shb + idb
    for ts, frame in packets:
        units = int(round(ts * 1e6))
        padded = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
        body = struct.pack("<IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(frame), len(frame)) + padded
        length = 12 + len(body)
        out += struct.pack("<II", 6, length) + body + struct.pack("<I", length)
    return out


def _session(t0=1000.0):
    return [
        (t0 + 0.0, _frame(A, B, 6, 40000, 80, 0x02)),
        (t0 + 0.1, _frame(B, A, 6, 80, 40000, 0x12)),
        (t0 + 0.2, _frame(A, B, 6, 40000, 80, 0x10, b"x" * 100)),
        (t0 + 0.3, _frame(A, B, 6, 40000, 80, 0x11)),
        (t0 + 0.5, _frame(C, B, 17, 50000, 53, payload=b"q" * 30)),
        (t0 + 0.6, _frame(B, C, 17, 53, 50000, payload=b"r" * 60)),
    ]


def _rule(tmp_path, default="exclude", rules=None):
    path = tmp_path / "rule.json"
    path.write_text(json.dumps({"rule_id": "test", "publisher_reference": "fixture",
                                "default": default, "rules": rules or []}), encoding="utf-8")
    return path


@pytest.mark.parametrize("builder", [_pcap, _pcapng])
def test_stream_reader_matches_file_reader(builder):
    data = builder(_session())
    reference = list(npf._classic_pcap(data) if builder is _pcap else npf._pcapng(data))
    streamed = list(si.iter_stream_packets(io.BytesIO(data)))
    assert len(streamed) == len(reference) == 6
    for got, want in zip(streamed, reference):
        assert got[1:] == want[1:]
        assert got[0] == pytest.approx(want[0])


def test_single_window_equals_file_aggregation(tmp_path):
    data = _pcap(_session())
    path = tmp_path / "c.pcap"; path.write_bytes(data)
    windows = list(si.iter_windows(si.iter_stream_packets(io.BytesIO(data)), 10.0))
    assert len(windows) == 1
    _, end, streamed = windows[0]
    reference = npf.aggregate_capture(path, capture_end_timestamp=end)
    assert [f["features_v10"] for f in streamed["flows"]] == [f["features_v10"] for f in reference["flows"]]
    assert [f["complete"] for f in streamed["flows"]] == [True, True]


def test_flow_crossing_window_boundary_is_split_like_live_sensor():
    packets = _session(t0=1000.0)
    packets[3] = (1010.5, packets[3][1])  # FIN lands in the next 10 s window
    windows = list(si.iter_windows(si.iter_stream_packets(io.BytesIO(_pcap(packets))), 10.0))
    assert [w[0] for w in windows] == [0, 1]
    tcp_first = [f for f in windows[0][2]["flows"] if f["protocol"] == "tcp"][0]
    assert tcp_first["complete"] is False


def test_label_rule_first_match_and_cidr():
    rule = si.LabelRule({"rule_id": "r", "publisher_reference": "doc", "default": "benign",
                         "rules": [{"label": "exclude", "ip_src": ["10.0.0.9/32"], "protocol": "tcp"},
                                   {"label": "attack", "ip_any": ["10.0.0.8/29"]}]})
    flow = {"originator_ip": C, "responder_ip": B, "protocol": "udp", "first_seen": 0}
    assert rule.label(flow) == "attack"
    assert rule.label({**flow, "protocol": "tcp"}) == "exclude"
    assert rule.label({**flow, "originator_ip": A}) == "benign"
    with pytest.raises(si.IngestError):
        si.LabelRule({"rule_id": "r", "publisher_reference": "d", "rules": [{"label": "x"}]})


def test_ingest_writes_shard_without_addresses_and_loads(tmp_path):
    src = tmp_path / "c.pcap.gz"; src.write_bytes(gzip.compress(_pcap(_session())))
    rule = _rule(tmp_path, rules=[{"label": "attack", "ip_any": [C]},
                                  {"label": "benign", "ip_src": [A]}])
    manifest = si.ingest_capture(source=str(src), source_id="fixture", role="train",
                                 label_rule_path=rule, out_dir=tmp_path / "out",
                                 metadata={"os": "fixture"})
    assert manifest["counts"]["attack"] == 1 and manifest["counts"]["benign"] == 1
    assert manifest["source"]["capture_sha256"] == __import__("hashlib").sha256(_pcap(_session())).hexdigest()
    raw = (tmp_path / "out" / "fixture.npz").read_bytes()
    assert b"10.0.0" not in raw
    x, y, loaded = si.load_shard(tmp_path / "out" / "fixture.manifest.json")
    assert x.shape == (2, 46) and sorted(y.tolist()) == [0, 1]
    with pytest.raises(si.IngestError):
        si.load_shard(tmp_path / "out" / "fixture.manifest.json", expected_role="dev")


def test_tampered_shard_and_overwrite_are_rejected(tmp_path):
    src = tmp_path / "c.pcap"; src.write_bytes(_pcap(_session()))
    rule = _rule(tmp_path, default="benign")
    out = tmp_path / "out"
    si.ingest_capture(source=str(src), source_id="s", role="dev", label_rule_path=rule, out_dir=out)
    with pytest.raises(si.IngestError):
        si.ingest_capture(source=str(src), source_id="s", role="dev", label_rule_path=rule, out_dir=out)
    shard = out / "s.npz"
    np.savez_compressed(shard, x=np.zeros((2, 46), np.float32), y=np.zeros(2, np.int8),
                        window=np.zeros(2, np.int32), first_seen=np.zeros(2))
    with pytest.raises(si.IngestError):
        si.load_shard(out / "s.manifest.json", expected_role="dev")


def test_refusals_leave_no_shard(tmp_path):
    src = tmp_path / "c.pcap"; src.write_bytes(_pcap(_session()))
    rule = _rule(tmp_path, default="benign")
    with pytest.raises(si.IngestError):
        si.ingest_capture(source=str(src), source_id="t", role="reserved_independent_test",
                          label_rule_path=rule, out_dir=tmp_path / "o1")
    with pytest.raises(si.IngestError):
        si.ingest_capture(source=str(src), source_id="t", role="train", label_rule_path=rule,
                          out_dir=tmp_path / "o2", expected_sha256="0" * 64)
    assert not (tmp_path / "o2" / "t.npz").exists()
    src.write_bytes(_pcap(_session())[:-5])
    with pytest.raises(si.IngestError):
        si.ingest_capture(source=str(src), source_id="t", role="train", label_rule_path=rule,
                          out_dir=tmp_path / "o3")
    assert not (tmp_path / "o3" / "t.npz").exists()


def test_mac_rule_labels_attacker_device_and_protocol(tmp_path):
    pi = bytes.fromhex("dca632c9e6f4")
    packets = [
        (1000.0, _frame(C, B, 17, 50000, 9999, payload=b"f" * 40, mac=pi)),
        (1000.1, _frame(C, B, 6, 40001, 22, 0x02, mac=pi)),
        (1000.2, _frame(B, C, 6, 22, 40001, 0x14)),
        (1000.3, _frame(A, B, 17, 41000, 53, payload=b"q" * 30, mac=bytes.fromhex("1cfe2b9816dd"))),
    ]
    src = tmp_path / "m.pcap"; src.write_bytes(_pcap(packets))
    rule = _rule(tmp_path, rules=[{"label": "attack", "mac_src": ["DC:A6:32"], "protocol": "udp"}])
    manifest = si.ingest_capture(source=str(src), source_id="mac", role="train",
                                 label_rule_path=rule, out_dir=tmp_path / "out")
    counts = manifest["counts"]
    assert counts["assigned_by_protocol"] == {"udp:attack": 1}
    assert counts["flows_label_excluded"] == 2  # Pi TCP flow and other device's UDP
    assert b"dc:a6:32" not in (tmp_path / "out" / "mac.npz").read_bytes()


def test_idle_completion_for_icmp_and_half_open_tcp():
    packets = [
        (1000.0, _frame(C, B, 1, 0, 0)),                     # ICMP, idle > 1 s before window end
        (1000.1, _frame(C, B, 6, 1234, 80, 0x02)),           # SYN only: half-open
        (1001.1, _frame(C, B, 6, 1234, 80, 0x02)),           # SYN retransmission, still half-open
        (1001.2, _frame(B, C, 6, 80, 1234, 0x12)),           # SYN-ACK never acknowledged
        (1000.2, _frame(A, B, 6, 40000, 443, 0x02)),         # established, no FIN/RST
        (1000.3, _frame(B, A, 6, 443, 40000, 0x12)),
        (1000.4, _frame(A, B, 6, 40000, 443, 0x10, b"d" * 50)),
        (1009.5, _frame(A, C, 1, 0, 0)),                     # ICMP too close to window end
    ]
    (_, _, result), = list(si.iter_windows(si.iter_stream_packets(io.BytesIO(_pcap(packets))), 10.0))
    by_reason = {}
    for flow in result["flows"]:
        by_reason.setdefault(flow["completion_reason"], []).append(flow["protocol"])
    assert by_reason["icmp_idle_timeout_1s"] == ["icmp"]
    assert by_reason["tcp_half_open_idle_1s"] == ["tcp"]
    assert sorted(by_reason["incomplete"]) == ["icmp", "tcp"]


def test_file_aggregation_without_end_time_keeps_idle_flows_incomplete(tmp_path):
    path = tmp_path / "h.pcap"
    path.write_bytes(_pcap([(1000.0, _frame(C, B, 1, 0, 0)), (1000.1, _frame(C, B, 6, 1234, 80, 0x02))]))
    result = npf.aggregate_capture(path)
    assert [f["complete"] for f in result["flows"]] == [False, False]


def test_icmp_flows_are_counted_by_protocol(tmp_path):
    icmp = _frame(C, B, 1, 0, 0)
    src = tmp_path / "i.pcap"; src.write_bytes(_pcap([(1000.0, icmp), (1009.8, icmp)] + _session(1001.0)))
    manifest = si.ingest_capture(source=str(src), source_id="i", role="train",
                                 label_rule_path=_rule(tmp_path, default="benign"),
                                 out_dir=tmp_path / "out")
    assert manifest["counts"]["incomplete_by_protocol"].get("icmp") == 1

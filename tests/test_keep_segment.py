"""Packet segments are kept under the data root, named by hash, and verified."""
import hashlib
from pathlib import Path
from unittest.mock import patch

from integrityguard import pktmon_capture as pc


def test_segment_is_copied_once_and_named_by_hash(tmp_path):
    source = tmp_path / "segment.pcapng"
    source.write_bytes(b"\x0a\x0d\x0d\x0a" + b"packet-headers")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with patch.object(pc, "DATA_ROOT", tmp_path / "data"):
        first = pc._keep_segment(source, digest)
        second = pc._keep_segment(source, digest)
    assert first == second
    assert first.name == digest + ".pcapng"
    assert hashlib.sha256(first.read_bytes()).hexdigest() == digest
    assert not list(first.parent.glob("*.tmp"))


def test_mismatched_hash_is_not_kept(tmp_path):
    source = tmp_path / "segment.pcapng"
    source.write_bytes(b"data")
    with patch.object(pc, "DATA_ROOT", tmp_path / "data"):
        try:
            pc._keep_segment(source, "0" * 64)
        except OSError:
            pass
    assert not (tmp_path / "data" / "pktmon-segments" / ("0" * 64 + ".pcapng")).exists()

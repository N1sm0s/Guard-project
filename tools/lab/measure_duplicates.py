"""Measure exact duplicate frames inside same-timestamp groups of a capture (diagnostic).

A duplicate is a frame whose bytes equal an earlier frame with the identical timestamp.
Usage: python tools/lab/measure_duplicates.py <pcapng> [<pcapng> ...]
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from integrityguard import stream_ingest as si


def measure(path: Path) -> dict:
    op = si.open_capture_source(str(path))
    total = dup = 0
    group_ts = None
    group = set()
    multiplicity = {}
    try:
        for ts, _lt, raw, _ln in si.iter_stream_packets(op.stream):
            total += 1
            if ts != group_ts:
                group_ts, group = ts, set()
            digest = hashlib.sha1(raw).digest()
            if digest in group:
                dup += 1
            else:
                group.add(digest)
    finally:
        op.close()
    return {"file": path.name, "packets": total, "duplicates": dup,
            "dup_share": round(dup / max(total, 1), 4)}


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        print(json.dumps(measure(Path(arg))), flush=True)

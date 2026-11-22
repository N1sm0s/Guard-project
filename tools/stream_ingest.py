"""CLI: stream a public pcap/pcapng into a labelled v10 feature shard.

Example (local file):
  python tools/stream_ingest.py --source capture.pcap --source-id cic-iot23-udpflood-01 \
      --role train --label-rule rules/ciciot2023-udpflood.json \
      --out-dir outputs/network-eval/shards --meta os=linux-iot family=Mirai attack=udp_flood

Example (remote ZIP member, read via HTTP Range without fetching other members):
  python tools/stream_ingest.py --source https://host/archive.zip --zip-member day1/udp.pcap ...

Only derived features, labels and a manifest are written. See
integrityguard/stream_ingest.py for semantics and limitations.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrityguard.stream_ingest import (  # noqa: E402
    ALLOWED_ROLES, DEFAULT_WINDOW_SECONDS, IngestError, ingest_capture)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True, help="local path or http(s) URL")
    parser.add_argument("--zip-member", default=None)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--role", required=True, choices=ALLOWED_ROLES)
    parser.add_argument("--label-rule", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--expected-md5", default=None, help="publisher MD5 of the capture bytes")
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--max-bytes", type=int, default=None)
    parser.add_argument("--meta", nargs="*", default=[], help="key=value facts (os, family, attack type)")
    args = parser.parse_args(argv)
    meta = {}
    for item in args.meta:
        key, sep, value = item.partition("=")
        if not sep or not key:
            parser.error(f"--meta expects key=value, got {item!r}")
        meta[key] = value
    try:
        manifest = ingest_capture(
            source=args.source, source_id=args.source_id, role=args.role,
            label_rule_path=args.label_rule, out_dir=args.out_dir, zip_member=args.zip_member,
            expected_sha256=args.expected_sha256, expected_md5=args.expected_md5,
            window_seconds=args.window_seconds, max_bytes=args.max_bytes, metadata=meta)
    except IngestError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"source_id": manifest["source_id"], "counts": manifest["counts"],
                      "capture_sha256": manifest["source"]["capture_sha256"],
                      "shard_sha256": manifest["shard"]["sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

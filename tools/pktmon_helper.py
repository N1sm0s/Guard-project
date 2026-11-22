"""Elevated Pktmon helper (P2.5). Captures one segment into files and exits.

It accepts only --seconds, --out-dir and --root. Run it through the UAC prompt
requested by the application (integrityguard/pktmon_segment.request_elevated_capture).
Exit codes: 0 segment written; 2 refused or failed (message on stderr).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrityguard.pktmon_segment import SegmentError, capture_segment_files  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.seconds <= 30:
        print("ERROR: --seconds must be between 1 and 30", file=sys.stderr)
        return 2
    try:
        capture_segment_files(args.seconds, args.out_dir, args.root)
    except SegmentError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

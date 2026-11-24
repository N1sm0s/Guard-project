"""Build host-background shards (feature v13) from the app's own capture segments.

Protocol (fixed before the first ingest):
  * roles by segment start time: before SPLIT_UTC -> calibration (threshold only),
    at or after SPLIT_UTC -> check (alarm rate only). The split is never chosen from results.
  * label rule: flows inside the lab subnet 172.20.0.0/24 are excluded; every other complete
    flow is written with y=-1 (unlabeled). Host traffic is never asserted benign by this tool.
  * shards are isolated from supervised train/dev/test directories.
  * segments that yield no complete included flow are skipped and listed in the summary.

Usage: python tools/lab/build_host_background.py
"""
from __future__ import annotations

import datetime as dt
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard import stream_ingest as si  # noqa: E402
from integrityguard.stream_ingest import IngestError, ingest_capture  # noqa: E402

SEG = ROOT / "data" / "pktmon-segments"
OUT = ROOT / "outputs" / "lab" / "unlabeled_host_v13"
RULE = ROOT / "outputs" / "lab" / "session" / "host-background-rules-unlabeled-v2.json"
SPLIT_UTC = dt.datetime(2026, 11, 24, 2, 0, 0, tzinfo=dt.timezone.utc)
SPLIT_TS = SPLIT_UTC.timestamp()


def first_timestamp(path: Path):
    op = si.open_capture_source(str(path))
    try:
        for ts, _lt, _raw, _ln in si.iter_stream_packets(op.stream):
            return ts
    finally:
        op.close()
    return None


def main() -> int:
    rule_spec = {
        "rule_id": "host-background-unlabeled-v2",
        "publisher_reference": "own machine pktmon segments; no ground-truth labels; lab subnet excluded by address",
        "default": "exclude",
        "rules": [{"label": "exclude", "ip_any": ["172.20.0.0/24"], "note": "lab traffic"},
                  {"label": "unlabeled", "ip_any": ["0.0.0.0/0"], "note": "host traffic has no ground-truth label"}],
    }
    if RULE.exists():
        if json.loads(RULE.read_text(encoding="utf-8")) != rule_spec:
            raise SystemExit(f"Refusing to overwrite changed rule file: {RULE}")
    else:
        RULE.parent.mkdir(parents=True, exist_ok=True)
        RULE.write_text(json.dumps(rule_spec, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {"calibration": [], "check": [], "skipped": []}
    for path in sorted(glob.glob(str(SEG / "*.pcapng"))):
        p = Path(path)
        start = first_timestamp(p)
        if start is None:
            summary["skipped"].append({"segment": p.name, "reason": "no packets"})
            continue
        role_group = "calibration" if start < SPLIT_TS else "check"
        sid = f"host-{'cal' if role_group == 'calibration' else 'chk'}-{p.stem[:12]}"
        try:
            manifest = ingest_capture(source=str(p), source_id=sid, role="dev", label_rule_path=RULE,
                                      out_dir=OUT, metadata={"group": role_group}, feature_version=13)
            summary[role_group].append({"source_id": sid, "unlabeled": manifest["counts"]["unlabeled"],
                                        "excluded": manifest["counts"]["flows_label_excluded"]})
        except IngestError as error:
            summary["skipped"].append({"segment": p.name, "reason": str(error)[:160]})
    out = ROOT / "outputs" / "lab" / "diagnostics" / "host_background_summary.json"
    out.write_text(json.dumps({k: (v if k == "skipped" else len(v)) for k, v in summary.items()}, indent=2), encoding="utf-8")
    full = ROOT / "outputs" / "lab" / "diagnostics" / "host_background_shards.json"
    full.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: (v if k == "skipped" else len(v)) for k, v in summary.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

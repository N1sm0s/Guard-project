"""Rebuild lab shards as feature version 13 from the same captures and label rules as v12.

Each v12 manifest names its capture and label rule. The broken first benign-14 shard
(v12-benign-14) is skipped; benign-14b is rebuilt from the rerun capture with its own rule.
Output: outputs/lab/shards_v13/v13-<scenario>.npz plus manifest (role dev).

Usage: python tools/lab/build_v13_shards.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.stream_ingest import ingest_capture  # noqa: E402

V12 = ROOT / "outputs" / "lab" / "shards_v12"
import argparse
OUT = ROOT / "outputs" / "lab" / "shards_v13"
SKIP = {"v12-benign-14"}
SPECIAL = {"v12-benign-14b": ("outputs/lab/session/benign-14.pcapng",
                              "outputs/lab/session/benign14-rules-v2.json")}


def main(argv=None) -> int:
    global OUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--dedupe-same-timestamp', action='store_true')
    args = parser.parse_args(argv)
    OUT = args.out
    dedupe = args.dedupe_same_timestamp
    jobs = []
    for manifest_path in sorted(V12.glob("*.manifest.json")):
        sid = manifest_path.name.replace(".manifest.json", "")
        if sid in SKIP:
            continue
        if sid in SPECIAL:
            source, rule = SPECIAL[sid]
        else:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
            source, rule = m["source"]["source"], m["label_rule"]["path"]
        jobs.append((sid, source, rule))
    for sid, source, rule in jobs:
        new_id = sid.replace("v12-", "v13-", 1)
        manifest = ingest_capture(
            source=str(ROOT / source) if not Path(source).is_absolute() else source,
            source_id=new_id, role="dev", label_rule_path=ROOT / rule.replace("\\", "/"),
            out_dir=OUT, metadata={"scenario": new_id.replace("v13-", "")},
            feature_version=13, dedupe_same_timestamp=dedupe)
        print(json.dumps({"source_id": new_id, "counts": {k: manifest["counts"][k] for k in ("attack", "benign")}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Merge lab background shards into one file per role, keeping roles separate.

Roles (never mixed):
  train      : background used for training (all benign shards except calibration and check)
  calibration: background used only to choose the threshold (real-benign-10, real-benign-11 when present)
  check      : sess-benign-08 stays a single file (never merged with anything)

Each merged .npz keeps: x, y, window, first_seen, and source_index (position in the manifest's source list),
so every flow traces back to its original shard. Original shards are NOT deleted: registrations refer to them.

Usage: python tools/lab/merge_background.py --out outputs/lab/shards/merged
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
SHARDS = ROOT / "outputs" / "lab" / "shards"
CALIBRATION = ["real-benign-10", "real-benign-11"]
CHECK = ["sess-benign-08"]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def background_ids() -> list[str]:
    ids = []
    for path in sorted(SHARDS.glob("*.manifest.json")):
        sid = path.name[: -len(".manifest.json")]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["counts"]["attack"] == 0 and manifest["counts"]["benign"] > 0:
            ids.append(sid)
    return ids


def merge(role: str, source_ids: list[str], out_dir: Path) -> dict | None:
    if not source_ids:
        return None
    arrays = {"x": [], "y": [], "window": [], "first_seen": [], "source_index": []}
    sources = []
    for index, sid in enumerate(source_ids):
        with np.load(SHARDS / f"{sid}.npz") as data:
            arrays["x"].append(data["x"]); arrays["y"].append(data["y"])
            arrays["window"].append(data["window"]); arrays["first_seen"].append(data["first_seen"])
            arrays["source_index"].append(np.full(len(data["y"]), index, dtype=np.int32))
        sources.append({"index": index, "source_id": sid, "shard_sha256": sha256_file(SHARDS / f"{sid}.npz"),
                        "manifest_sha256": sha256_file(SHARDS / f"{sid}.manifest.json"),
                        "flows": int(len(arrays["y"][-1]))})
    out_dir.mkdir(parents=True, exist_ok=True)
    npz = out_dir / f"bg-{role}-merged.npz"
    np.savez_compressed(npz, **{k: np.concatenate(v) for k, v in arrays.items()})
    manifest = {"kind": "merged_background", "role": role, "research_only": True,
                "shard": npz.name, "shard_sha256": sha256_file(npz), "flows": int(sum(s["flows"] for s in sources)),
                "label": "benign only (attack count must be 0)", "sources": sources,
                "note": "source_index maps each flow to sources[]; originals kept unchanged."}
    assert all(int(v) == 0 for v in np.load(npz)["y"]), "merged background must contain no attack labels"
    (out_dir / f"bg-{role}-merged.manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    bg = background_ids()
    calib = [s for s in CALIBRATION if s in bg]
    check = [s for s in CHECK if s in bg]
    train = [s for s in bg if s not in calib and s not in check]
    done = {}
    for role, ids in (("train", train), ("calibration", calib), ("check", check)):
        m = merge(role, ids, args.out)
        if m:
            done[role] = {"flows": m["flows"], "sources": len(m["sources"])}
    print(json.dumps(done, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

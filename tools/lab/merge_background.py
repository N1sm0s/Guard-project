"""Merge explicitly assigned lab background shards into role-specific files.

Every source id must appear in exactly one of TRAIN, CALIBRATION, or CHECK.
Unknown benign shards, missing assigned shards, malformed manifests, and
overlapping roles stop the merge before any output is written. New data must
be assigned deliberately instead of defaulting to train.

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
ROLES = {
    "train": [
        "real-benign-09",
        "seg-198a18204f88", "seg-40a44af44b2e", "seg-8ad2c9f42a58",
        "seg-a3dce53a790d", "seg-a79696bafe07", "seg-bbd742974136",
        "seg-c148e0bdb98f", "seg-d354cafc19b9", "seg-d83f49591e1a",
        "seg-f2f205f2ac00",
        "sess-benign-06", "sess-benign-07", "sess-benign-07b",
    ],
    "calibration": ["real-benign-10", "real-benign-11"],
    "check": ["real-benign-12", "sess-benign-08"],
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def background_ids() -> set[str]:
    ids = set()
    manifest_paths = {p.name[: -len(".manifest.json")]: p
                      for p in SHARDS.glob("*.manifest.json")}
    shard_ids = {p.stem for p in SHARDS.glob("*.npz")}
    if set(manifest_paths) != shard_ids:
        missing_npz = sorted(set(manifest_paths) - shard_ids)
        missing_manifest = sorted(shard_ids - set(manifest_paths))
        raise ValueError(f"Shard/manifest mismatch: missing npz={missing_npz}, missing manifest={missing_manifest}")
    for sid, path in sorted(manifest_paths.items()):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            counts = manifest["counts"]
            attack, benign = counts["attack"], counts["benign"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError(f"Invalid shard manifest {path.name}: {error}") from error
        if (isinstance(attack, bool) or not isinstance(attack, int) or attack < 0
                or isinstance(benign, bool) or not isinstance(benign, int) or benign < 0):
            raise ValueError(f"Invalid label counts in {path.name}")
        if attack == 0 and benign > 0:
            ids.add(sid)
    return ids


def validate_roles(roles: dict[str, list[str]], discovered: set[str]) -> None:
    """Require a complete, disjoint, explicit assignment of all benign shards."""
    expected_roles = {"train", "calibration", "check"}
    if set(roles) != expected_roles:
        raise ValueError(f"Roles must be exactly {sorted(expected_roles)}")
    owners: dict[str, str] = {}
    for role, source_ids in roles.items():
        if not source_ids:
            raise ValueError(f"Role {role!r} has no assigned shards")
        if len(source_ids) != len(set(source_ids)):
            raise ValueError(f"Role {role!r} contains duplicate shard ids")
        for sid in source_ids:
            if sid in owners:
                raise ValueError(f"Shard {sid!r} is assigned to both {owners[sid]!r} and {role!r}")
            owners[sid] = role
    assigned, unknown = set(owners), discovered - set(owners)
    missing = assigned - discovered
    if missing:
        raise ValueError(f"Assigned background shards are missing: {sorted(missing)}")
    if unknown:
        raise ValueError(f"Unassigned benign shards found; assign a role explicitly: {sorted(unknown)}")


def merge(role: str, source_ids: list[str], out_dir: Path) -> dict:
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
    with np.load(npz) as merged:
        if not np.all(merged["y"] == 0):
            npz.unlink(missing_ok=True)
            raise ValueError(f"Merged {role} shard contains non-benign labels")
    (out_dir / f"bg-{role}-merged.manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    bg = background_ids()
    validate_roles(ROLES, bg)
    done = {}
    for role, ids in ROLES.items():
        m = merge(role, ids, args.out)
        done[role] = {"flows": m["flows"], "sources": len(m["sources"])}
    print(json.dumps(done, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

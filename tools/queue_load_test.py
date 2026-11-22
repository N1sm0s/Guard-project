"""P2.2: load and crash-recovery measurement for the intake queue and journal.

IMPORTANT: the packages are synthetic directories. This measures queue and
journal mechanics only. It is not evidence of model quality or detection.

Measured:
  1. throughput of process_incoming + journal append for N packages;
  2. peak Python heap during the run (tracemalloc);
  3. crash during the run (child killed mid-move), then recovery time and
     correctness: every package moved exactly once, journal has one record
     per event_id.

Usage:
  python tools/queue_load_test.py --out docs/queue-load-20261123.json --n 1000
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import tracemalloc
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrityguard.intake import process_incoming  # noqa: E402
from integrityguard.journal import append_record  # noqa: E402


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_packages(root: Path, n: int) -> list[Path]:
    incoming = root / "incoming"
    incoming.mkdir(parents=True)
    out = []
    for i in range(n):
        package = incoming / f"pkg-{i:05d}"
        package.mkdir()
        (package / "manifest.json").write_text(json.dumps({"synthetic": True, "index": i}), encoding="utf-8")
        out.append(package)
    return out


def analyze(path: Path):
    return {"verdict": "ALLOW", "event_id": uuid.uuid5(uuid.NAMESPACE_URL, str(path)).hex}, "allow"


def run_queue(root: Path, packages: list[Path]) -> dict:
    journal = root / "journal" / "events.jsonl"
    processed = root / "processed"
    moved, errors = 0, 0

    def publish(result):
        append_record(journal, {"event_id": result["event_id"], "verdict": result["verdict"]},
                      rotate=lambda p: None)

    started = time.perf_counter()
    for package in packages:
        result = process_incoming(package, processed, analyze, publish=publish)
        if result.get("moved_to"):
            moved += 1
        else:
            errors += 1
    elapsed = time.perf_counter() - started
    return {"moved": moved, "errors": errors, "seconds": round(elapsed, 3),
            "packages_per_second": round(len(packages) / elapsed, 1) if elapsed else None}


CHILD = r"""
import os, sys, uuid
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from integrityguard.intake import process_incoming
from integrityguard.journal import append_record
root, crash_at = Path(sys.argv[2]), int(sys.argv[3])
journal = root / "journal" / "events.jsonl"
packages = sorted((root / "incoming").glob("pkg-*"))
count = {"n": 0}
def analyze(path):
    return {"verdict": "ALLOW", "event_id": uuid.uuid5(uuid.NAMESPACE_URL, str(path)).hex}, "allow"
def publish(result):
    append_record(journal, {"event_id": result["event_id"], "verdict": result["verdict"]}, rotate=lambda p: None)
def interrupted(self, target):
    os._exit(91)
for index, package in enumerate(packages):
    if index == crash_at:
        Path.rename = interrupted
    process_incoming(package, root / "processed", analyze, publish=publish)
"""


def crash_and_recover(root: Path, packages: list[Path], crash_at: int, src: Path) -> dict:
    crashed = subprocess.run([sys.executable, "-c", CHILD, str(src), str(root), str(crash_at)],
                             capture_output=True, text=True, timeout=1800)
    crashed_ok = crashed.returncode == 91
    remaining = sorted((root / "incoming").glob("pkg-*"))
    started = time.perf_counter()
    recovered = run_queue(root, remaining)
    recovery_seconds = round(time.perf_counter() - started, 3)
    ids = [json.loads(line)["event_id"] for line in
           (root / "journal" / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    processed_count = sum(1 for _ in (root / "processed" / "allow").iterdir()) \
        if (root / "processed" / "allow").is_dir() else 0
    return {"crash_injected_at_index": crash_at, "crash_exit_code_ok": crashed_ok,
            "packages_left_after_crash": len(remaining),
            "recovery_run": recovered, "recovery_seconds": recovery_seconds,
            "journal_records": len(ids), "journal_unique_event_ids": len(set(ids)),
            "packages_archived": processed_count,
            "exactly_once": len(ids) == len(set(ids)) == len(packages)
                            and processed_count == len(packages) and not list((root / "incoming").glob("pkg-*"))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--n", type=int, default=1000)
    parser.add_argument("--workdir", type=Path, default=Path(os.environ.get("TEMP", ".")) / "queue-load")
    args = parser.parse_args(argv)
    if args.n < 10:
        raise SystemExit("n must be at least 10")

    work = args.workdir / uuid.uuid4().hex
    report = {"kind": "queue_load_test", "synthetic_packages": True,
              "not_model_evidence": True,
              "environment": {"python": platform.python_version(), "platform": platform.platform(),
                              "cpu_count": os.cpu_count()},
              "code_sha256": {"intake.py": sha256_file(ROOT / "integrityguard" / "intake.py"),
                              "journal.py": sha256_file(ROOT / "integrityguard" / "journal.py")},
              "n": args.n}
    try:
        # 1. throughput with peak heap
        run_root = work / "throughput"
        packages = make_packages(run_root, args.n)
        tracemalloc.start()
        report["throughput"] = run_queue(run_root, packages)
        report["throughput"]["peak_heap_mb"] = round(tracemalloc.get_traced_memory()[1] / 1e6, 2)
        tracemalloc.stop()
        ids = [json.loads(line)["event_id"] for line in
               (run_root / "journal" / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        report["throughput"]["journal_records"] = len(ids)
        report["throughput"]["journal_unique_event_ids"] = len(set(ids))

        # 2. crash in the middle, recovery, exactly-once check
        crash_root = work / "crash"
        packages = make_packages(crash_root, args.n)
        report["crash_recovery"] = crash_and_recover(crash_root, packages, args.n // 2, ROOT)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("throughput", "crash_recovery")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

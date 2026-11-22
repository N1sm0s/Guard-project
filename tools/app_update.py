"""Command-line wrapper for P2.3 install/rollback (see integrityguard/app_update.py).

Examples:
  python tools/app_update.py install --installed dist/IntegrityGuard --staged build/staging/IntegrityGuard --backups dist/backups
  python tools/app_update.py rollback --installed dist/IntegrityGuard --backup dist/backups/<time> --backups dist/backups

The installed application must be closed before install. The self-test runs the
staged EXE with --selftest-gui and must exit 0.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from integrityguard import app_update as up  # noqa: E402


def selftest(exe: Path) -> int:
    return subprocess.run([str(exe), "--selftest-gui"], timeout=900).returncode


def running_exes() -> list[str]:
    paths = []
    for proc in psutil.process_iter(["name", "exe"]):
        if (proc.info.get("name") or "").lower() == up.EXE_NAME.lower() and proc.info.get("exe"):
            paths.append(proc.info["exe"])
    return paths


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    inst = sub.add_parser("install")
    inst.add_argument("--installed", type=Path, required=True)
    inst.add_argument("--staged", type=Path, required=True)
    inst.add_argument("--backups", type=Path, required=True)
    roll = sub.add_parser("rollback")
    roll.add_argument("--installed", type=Path, required=True)
    roll.add_argument("--backup", type=Path, required=True)
    roll.add_argument("--backups", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            saved = up.install(args.installed.resolve(), args.staged.resolve(), args.backups.resolve(),
                               selftest=selftest, running_exe_paths=running_exes())
            print(f"installed; backup: {saved}")
        else:
            up.rollback(args.installed.resolve(), args.backup.resolve(), args.backups.resolve())
            print("rolled back")
    except up.UpdateError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Privileged half of the Pktmon split (P2.5): capture one segment to files.

Runs only inside the elevated helper (tools/pktmon_helper.py). It performs the
same Pktmon sequence as pktmon_capture.capture_header_segment (status, owner
marker, start, counters, stop, etl2pcap) but stops at files: segment.pcapng,
counters.json and manifest.json with SHA-256 of both data files.

The unprivileged application reads the files with verify_segment(), which
checks every hash before any parsing.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from . import pktmon_capture as pc

ROOT = Path(__file__).resolve().parents[1]
HELPER_EXE = "pktmon_helper.exe"
MANIFEST = "manifest.json"
PCAPNG = "segment.pcapng"
COUNTERS = "counters.json"
FORMAT = "integrityguard-pktmon-segment-v1"


class SegmentError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_out_dir(out_dir: Path, root: Path) -> Path:
    """The helper writes only inside an existing application data root, no links."""
    out_dir = Path(out_dir)
    root = Path(root).resolve(strict=True)
    if out_dir.is_symlink():
        raise SegmentError("Каталог вывода не может быть символической ссылкой")
    resolved = out_dir.resolve()
    if root not in resolved.parents or not resolved.is_dir():
        raise SegmentError("Каталог вывода должен быть существующей папкой внутри каталога данных")
    return resolved


def capture_segment_files(duration: int, out_dir: Path, root: Path) -> dict:
    """Capture one bounded segment and write the files. Returns the manifest or raises SegmentError."""
    if os.name != "nt":
        raise SegmentError("Pktmon доступен только в Windows")
    if not pc._is_admin():
        raise SegmentError("Помощник запущен без прав администратора")
    out_dir = _check_out_dir(out_dir, root)
    duration = max(1, min(int(duration), pc._CAPTURE_SECONDS_MAX))
    status = pc._run(["status"])
    status_text = f"{status.stdout}\n{status.stderr}"
    if status.returncode != 0:
        raise SegmentError("Не удалось проверить состояние Pktmon")
    if not pc._is_not_running(status_text) and pc._recover_stale_owned_capture(status_text):
        status = pc._run(["status"])
        status_text = f"{status.stdout}\n{status.stderr}"
    if not pc._is_not_running(status_text):
        raise SegmentError("Есть активная Pktmon-сессия; её владелец не подтверждён, поэтому она не остановлена")

    started_at = time.time()
    with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-", dir=out_dir) as temp:
        etl_path = Path(temp) / "segment.etl"
        raw_pcapng = Path(temp) / PCAPNG
        import psutil
        owner = {"pid": os.getpid(), "process_create_time": float(psutil.Process(os.getpid()).create_time())}
        (Path(temp) / pc._OWNER_FILE).write_text(json.dumps(owner, sort_keys=True), encoding="utf-8")
        start = pc._run(["start", "--capture", "--comp", "nics", "--pkt-size", "64",
                         "--flags", "0x012", "--file-name", str(etl_path),
                         "--file-size", str(pc._ETL_LIMIT_MB), "--log-mode", "circular"])
        if start.returncode != 0:
            raise SegmentError("Pktmon не запустился: " + (start.stderr or start.stdout or "").strip()[:300])
        counter_text = ""
        try:
            time.sleep(duration)
            counters = pc._run(["counters", "--json"], timeout=15)
            counter_text = (counters.stdout or "").strip() if counters.returncode == 0 else ""
        finally:
            stop = pc._run(["stop"], timeout=30)
        if stop.returncode != 0:
            raise SegmentError("Не подтверждена штатная остановка захвата; сегмент отброшен")
        end_at = time.time()
        if not etl_path.is_file() or etl_path.stat().st_size == 0:
            raise SegmentError("Pktmon не сохранил пакеты в этом интервале")
        if etl_path.stat().st_size >= pc._ETL_LIMIT_MB * 1024 * 1024 * 0.95:
            raise SegmentError("Файл приблизился к лимиту; сегмент отброшен")
        converted = pc._run(["etl2pcap", str(etl_path), "--out", str(raw_pcapng)], timeout=60)
        if converted.returncode != 0 or not raw_pcapng.is_file():
            raise SegmentError("Не удалось преобразовать ETL в pcapng")
        shutil.move(str(raw_pcapng), str(out_dir / PCAPNG))

    counters_path = out_dir / COUNTERS
    counters_path.write_text(counter_text or "null", encoding="utf-8")
    manifest = {"format": FORMAT, "duration_seconds": duration,
                "segment_id": uuid.uuid4().hex,
                "started_at": started_at, "ended_at": end_at,
                "files": {PCAPNG: {"sha256": _sha256(out_dir / PCAPNG),
                                   "bytes": (out_dir / PCAPNG).stat().st_size},
                          COUNTERS: {"sha256": _sha256(counters_path),
                                     "bytes": counters_path.stat().st_size}},
                "counters_available": bool(counter_text)}
    (out_dir / MANIFEST).write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
    return manifest


def verify_segment(segment_dir: Path, root: Path) -> dict:
    """Check the manifest and every file hash before any parsing. Returns the manifest."""
    segment_dir = _check_out_dir(segment_dir, root)
    manifest_path = segment_dir / MANIFEST
    if not manifest_path.is_file():
        raise SegmentError("В сегменте нет манифеста")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise SegmentError("Неизвестный формат сегмента")
    files = manifest.get("files") or {}
    if set(files) != {PCAPNG, COUNTERS}:
        raise SegmentError("Состав файлов сегмента не совпадает с манифестом")
    for name, expected in files.items():
        path = segment_dir / name
        if path.is_symlink() or not path.is_file():
            raise SegmentError(f"Файл сегмента отсутствует или является ссылкой: {name}")
        if path.stat().st_size != expected["bytes"] or _sha256(path) != expected["sha256"]:
            raise SegmentError(f"SHA-256 файла не совпадает с манифестом: {name}")
    return manifest


def helper_command() -> tuple[Path, Path | None]:
    """Return (program, script). Packaged app: the helper EXE next to the app, no script.
    Source checkout: this Python interpreter and tools/pktmon_helper.py."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / HELPER_EXE, None
    return Path(sys.executable), ROOT / "tools" / "pktmon_helper.py"


def request_elevated_capture(program: Path, script: Path | None, duration: int, out_dir: Path,
                             root: Path) -> int:
    """Start the helper with the Windows UAC prompt and wait for its exit code.

    The command line is built here with each path quoted and passed to PowerShell
    through an environment variable, so a path cannot change the command itself.
    """
    if os.name != "nt":
        raise SegmentError("Запрос повышения прав доступен только в Windows")
    parts = ([str(script)] if script else []) + ["--seconds", str(int(duration)),
                                                 "--out-dir", str(out_dir), "--root", str(root)]
    argline = " ".join('"' + part.replace('"', "") + '"' if (" " in part or not part.startswith("--")) else part
                       for part in parts)
    script_text = (
        "$p = Start-Process -FilePath $env:IG_FILE -Verb RunAs -Wait -PassThru -WindowStyle Hidden "
        "-ArgumentList $env:IG_ARGS; exit $p.ExitCode"
    )
    env = dict(os.environ, IG_FILE=str(program), IG_ARGS=argline)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script_text],
        capture_output=True, text=True, timeout=int(duration) + 300, env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return completed.returncode


def capture_via_helper(duration: int, root: Path, program: Path, script: Path | None,
                       *, out_base: Path | None = None) -> dict:
    """Unprivileged side: request a segment, verify it, and return a parsed result.

    The result has the same shape as capture_header_segment's, so callers can
    keep using it. Refusals and failed verification never produce flow data.
    """
    from .network_packet_flows import aggregate_capture

    root = Path(root).resolve(strict=True)
    base = Path(out_base) if out_base else root / "pktmon-segments"
    base.mkdir(parents=True, exist_ok=True)
    out_dir = base / uuid.uuid4().hex
    out_dir.mkdir()
    code = request_elevated_capture(program, script, duration, out_dir, root)
    if code != 0:
        return {"status": "helper_refused", "reason": f"Помощник не выполнил захват (код {code})"}
    try:
        manifest = verify_segment(out_dir, root)
    except (SegmentError, OSError, ValueError) as error:
        return {"status": "segment_verification_failed", "reason": str(error)[:300]}
    pcapng = out_dir / PCAPNG
    result = aggregate_capture(pcapng, capture_end_timestamp=manifest["ended_at"])
    result["capture_sha256"] = manifest["files"][PCAPNG]["sha256"]
    result["capture_interval_seconds"] = manifest["duration_seconds"]
    result["capture_scope"] = "NIC packet headers, first 64 bytes only; payload is not retained"
    result["capture_completeness"] = "best_effort; Pktmon drop counters not yet joined"
    result["drop_counters_available"] = bool(manifest.get("counters_available"))
    result["segment_id"] = manifest["segment_id"]
    if result.get("status") == "ok":
        result["status"] = "parsed_best_effort"
    return result

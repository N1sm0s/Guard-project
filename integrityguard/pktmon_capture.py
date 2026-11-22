"""Bounded Pktmon packet-header capture for Windows.

Only the first 64 bytes of each NIC packet are logged. ETL/PCAPNG files live in
a temporary directory and are removed after flow counters are extracted.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .network_packet_flows import aggregate_capture

_CAPTURE_SECONDS_MAX = 30
_ETL_LIMIT_MB = 64
_LEGACY_CAPTURE_IDLE_SECONDS = 30 * 60
_OWNER_FILE = "owner.json"


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    executable = shutil.which("pktmon.exe") or str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                                                        / "System32" / "pktmon.exe")
    return subprocess.run([executable, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                          check=False)


def _is_not_running(status_text: str) -> bool:
    value = status_text.casefold()
    return any(marker in value for marker in (
        "not running", "is stopped", "не запущен", "не выполняется", "остановлен"))


def _active_etl_path(status_text: str) -> Path | None:
    """Extract the active ETL path from English or Russian `pktmon status`."""
    patterns = (
        r"(?im)^\s*(?:log\s+file|file\s+name|файл\s+журнала|имя\s+файла)\s*:\s*(.+?\.etl)\s*$",
        r"(?i)([a-z]:\\[^\r\n]*?\.etl)",
    )
    for pattern in patterns:
        match = re.search(pattern, status_text)
        if match:
            return Path(match.group(1).strip().strip('"'))
    return None


def _is_owned_capture_path(etl_path: Path | str) -> bool:
    """Accept only this app's segment.etl directly under its temp directory."""
    try:
        path = Path(etl_path)
        temp_root = Path(tempfile.gettempdir())
        return (path.name.casefold() == "segment.etl"
                and path.parent.name.casefold().startswith("integrityguard-pktmon-")
                and os.path.normcase(os.path.abspath(path.parent.parent))
                == os.path.normcase(os.path.abspath(temp_root)))
    except (OSError, TypeError, ValueError):
        return False


def _owner_process_state(owner_path: Path) -> bool | None:
    """True means same process alive; False stale; None means fail closed."""
    try:
        owner = json.loads(owner_path.read_text(encoding="utf-8"))
        pid = int(owner["pid"])
        created = float(owner["process_create_time"])
        if pid <= 0 or created <= 0:
            return None
        import psutil
        try:
            process = psutil.Process(pid)
            return abs(float(process.create_time()) - created) < 0.01
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError, ValueError):
            return None
    except (OSError, ValueError, TypeError, KeyError, ImportError):
        return None


def _legacy_capture_is_stale(etl_path: Path) -> bool | None:
    """Identify old app-owned sessions created before owner.json was added.

    This fallback is deliberately strict: the ETL must be under this app's
    unique temp prefix, its directory must have been idle for 30 minutes, no
    owner marker may exist, and no older IntegrityGuard process may still be
    alive. Any inaccessible process metadata or file state fails closed.
    """
    try:
        stat = etl_path.parent.stat()
        owner_path = etl_path.parent / _OWNER_FILE
        try:
            owner_path.read_bytes()
        except FileNotFoundError:
            pass
        except OSError:
            return None
        else:
            # If a marker exists but could not be interpreted, don't bypass it.
            return None
        if time.time() - stat.st_mtime < _LEGACY_CAPTURE_IDLE_SECONDS:
            return False

        import psutil
        project_root = os.path.normcase(os.path.abspath(Path(__file__).resolve().parents[1]))
        for proc in psutil.process_iter(("name", "exe", "cmdline", "create_time")):
            if proc.pid == os.getpid():
                continue
            try:
                info = proc.info
                name = (info.get("name") or "").casefold()
                if name not in {"integrityguard.exe", "pythonw.exe"}:
                    continue
                exe = os.path.normcase(os.path.abspath(info.get("exe") or ""))
                command = " ".join(info.get("cmdline") or [])
                command_norm = os.path.normcase(os.path.abspath(command)) if command else ""
                is_app = exe.startswith(project_root + os.sep) or project_root in command_norm
                if not is_app:
                    # A pythonw process whose command line can't be inspected
                    # could still be this app, so don't assume it is unrelated.
                    if name == "pythonw.exe" and not command:
                        return None
                    continue
                created = float(info.get("create_time") or 0)
                if created <= 0:
                    return None
                if created <= stat.st_mtime:
                    return False
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, TypeError, ValueError):
                return None
        return True
    except (OSError, ImportError, TypeError, ValueError):
        return None


def _recover_stale_owned_capture(status_text: str) -> bool:
    """Stop only a confirmed stale capture with our own persisted PID marker."""
    etl_path = _active_etl_path(status_text)
    if etl_path is None or not _is_owned_capture_path(etl_path):
        return False
    owner_state = _owner_process_state(etl_path.parent / _OWNER_FILE)
    stale_legacy = owner_state is None and _legacy_capture_is_stale(etl_path) is True
    if owner_state is not False and not stale_legacy:
        return False
    # Recheck immediately before the global stop command in case the active
    # session changed since the first status query.
    try:
        current = _run(["status"])
    except (OSError, subprocess.SubprocessError):
        return False
    current_text = f"{current.stdout}\n{current.stderr}"
    current_path = _active_etl_path(current_text)
    if (current.returncode != 0 or _is_not_running(current_text)
            or current_path is None
            or os.path.normcase(os.path.abspath(current_path))
            != os.path.normcase(os.path.abspath(etl_path))):
        return False
    try:
        stopped = _run(["stop"], timeout=30)
        verify = _run(["status"])
    except (OSError, subprocess.SubprocessError):
        return False
    verify_text = f"{verify.stdout}\n{verify.stderr}"
    if stopped.returncode != 0 or verify.returncode != 0 or not _is_not_running(verify_text):
        return False
    try:
        shutil.rmtree(etl_path.parent)
    except OSError:
        pass
    return True


def capture_header_segment(duration_seconds: int = 10) -> dict:
    """Capture one bounded segment. Never stops a Pktmon session it did not start."""
    if os.name != "nt":
        return {"status": "unsupported_platform", "reason": "Pktmon доступен только в Windows."}
    if not _is_admin():
        return {"status": "administrator_required",
                "reason": "Для Pktmon нужен запуск IntegrityGuard с правами администратора."}
    duration = max(1, min(int(duration_seconds), _CAPTURE_SECONDS_MAX))
    try:
        status = _run(["status"])
    except (OSError, subprocess.SubprocessError) as error:
        return {"status": "pktmon_status_error", "reason": type(error).__name__}
    status_text = f"{status.stdout}\n{status.stderr}"
    if status.returncode != 0:
        return {"status": "pktmon_status_error", "reason": "Не удалось проверить состояние Pktmon."}
    if not _is_not_running(status_text) and _recover_stale_owned_capture(status_text):
        try:
            status = _run(["status"])
            status_text = f"{status.stdout}\n{status.stderr}"
        except (OSError, subprocess.SubprocessError):
            return {"status": "pktmon_status_error", "reason": "Не удалось повторно проверить Pktmon."}
        if status.returncode != 0:
            return {"status": "pktmon_status_error", "reason": "Не удалось повторно проверить Pktmon."}
    if not _is_not_running(status_text):
        return {"status": "pktmon_in_use",
                "reason": "Есть активная Pktmon-сессия; её владелец не подтверждён, поэтому она не остановлена."}

    with tempfile.TemporaryDirectory(prefix="integrityguard-pktmon-") as temp:
        etl_path = Path(temp) / "segment.etl"
        pcapng_path = Path(temp) / "segment.pcapng"
        started = False
        stop_result = None
        capture_end_timestamp = None
        counter_snapshot = None
        try:
            try:
                import psutil
                owner = {"pid": os.getpid(),
                         "process_create_time": float(psutil.Process(os.getpid()).create_time())}
                (Path(temp) / _OWNER_FILE).write_text(
                    json.dumps(owner, sort_keys=True), encoding="utf-8")
            except (OSError, ValueError, ImportError):
                return {"status": "capture_owner_metadata_error",
                        "reason": "Не удалось сохранить владельца Pktmon-сессии; захват не запущен."}
            start = _run(["start", "--capture", "--comp", "nics", "--pkt-size", "64",
                          "--flags", "0x012", "--file-name", str(etl_path),
                          "--file-size", str(_ETL_LIMIT_MB), "--log-mode", "circular"])
            if start.returncode != 0:
                return {"status": "pktmon_start_error",
                        "reason": (start.stderr or start.stdout or "Pktmon не запустился.").strip()[:400]}
            started = True
            time.sleep(duration)
            try:
                counters = _run(["counters", "--json"], timeout=15)
                counter_text = (counters.stdout or "").strip()
                parsed_counters = json.loads(counter_text) if counter_text else None
                if counters.returncode == 0 and isinstance(parsed_counters, (dict, list)):
                    counter_snapshot = {
                        "sha256": hashlib.sha256(counter_text.encode("utf-8")).hexdigest(),
                        "items": len(parsed_counters) if isinstance(parsed_counters, list)
                        else len(parsed_counters),
                    }
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                counter_snapshot = None
        except (OSError, subprocess.SubprocessError) as error:
            return {"status": "pktmon_start_error", "reason": type(error).__name__}
        finally:
            if started:
                try:
                    stop_result = _run(["stop"], timeout=30)
                except (OSError, subprocess.SubprocessError):
                    stop_result = None
        if stop_result is None or stop_result.returncode != 0:
            return {"status": "pktmon_stop_error",
                    "reason": "Не подтверждена штатная остановка захвата; сегмент не оценивается."}
        capture_end_timestamp = time.time()
        if not etl_path.is_file() or etl_path.stat().st_size == 0:
            return {"status": "empty_capture", "reason": "Pktmon не сохранил пакеты в этом интервале."}
        if etl_path.stat().st_size >= _ETL_LIMIT_MB * 1024 * 1024 * 0.95:
            return {"status": "capture_limit_reached",
                    "reason": "Файл приблизился к лимиту; возможна потеря старых пакетов, оценка пропущена."}
        try:
            converted = _run(["etl2pcap", str(etl_path), "--out", str(pcapng_path)], timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            return {"status": "pcapng_conversion_error", "reason": type(error).__name__}
        if converted.returncode != 0 or not pcapng_path.is_file():
            return {"status": "pcapng_conversion_error",
                    "reason": (converted.stderr or converted.stdout or "Не удалось преобразовать ETL.").strip()[:400]}
        capture_sha256 = hashlib.sha256(pcapng_path.read_bytes()).hexdigest()
        result = aggregate_capture(pcapng_path, capture_end_timestamp=capture_end_timestamp)
        result["capture_sha256"] = capture_sha256
        result["capture_interval_seconds"] = duration
        result["capture_scope"] = "NIC packet headers, first 64 bytes only; payload is not retained"
        result["capture_completeness"] = "best_effort; Pktmon drop counters not yet joined"
        result["drop_counters_available"] = counter_snapshot is not None
        if counter_snapshot is not None:
            result["pktmon_counter_snapshot_sha256"] = counter_snapshot["sha256"]
            result["pktmon_counter_snapshot_items"] = counter_snapshot["items"]
        if result.get("status") == "ok":
            result["status"] = "parsed_best_effort"
        return result

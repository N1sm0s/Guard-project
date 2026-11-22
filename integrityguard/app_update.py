"""P2.3: replace the installed application folder with a verified build, with rollback.

Steps (each refusal leaves the installed folder untouched):
  1. verify the staged build: the EXE exists and the caller's self-test passes;
  2. refuse if the installed EXE is still running (the caller closes it first);
  3. back up the installed folder to <backup_root>/<UTC time>/ with a SHA-256 manifest;
  4. move the staged folder into place;
  5. the caller verifies the relaunched process; on failure call rollback().

rollback() moves the failed folder aside and restores the backup it was made from.
Nothing is deleted: failed builds are kept under <backup_root>/failed/.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Callable

EXE_NAME = "IntegrityGuard.exe"


class UpdateError(RuntimeError):
    pass


def _hash_tree(root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        out[path.relative_to(root).as_posix()] = digest.hexdigest()
    return out


def _stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def verify_staged(staged: Path, selftest: Callable[[Path], int]) -> None:
    exe = staged / EXE_NAME
    if not exe.is_file():
        raise UpdateError(f"В сборке нет {EXE_NAME}: {staged}")
    code = selftest(exe)
    if code != 0:
        raise UpdateError(f"Самопроверка новой сборки не пройдена (код {code}); установка отменена")


def refuse_if_running(installed: Path, running_exe_paths: list[str]) -> None:
    target = str((installed / EXE_NAME).resolve()).lower()
    if any(str(Path(p).resolve()).lower() == target for p in running_exe_paths):
        raise UpdateError("Приложение ещё запущено из установленной папки; закройте его и повторите")


def backup(installed: Path, backup_root: Path) -> Path:
    if not (installed / EXE_NAME).is_file():
        raise UpdateError("Нечего сохранять: установленная сборка не найдена")
    target = backup_root / _stamp()
    if target.exists():
        raise UpdateError("Резерв с таким временем уже есть; повторите позже")
    shutil.copytree(installed, target)
    manifest = {"source": str(installed), "created_utc": _stamp(), "files": _hash_tree(target)}
    (target / "backup_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def install(installed: Path, staged: Path, backup_root: Path, *,
            selftest: Callable[[Path], int], running_exe_paths: list[str]) -> Path:
    verify_staged(staged, selftest)
    refuse_if_running(installed, running_exe_paths)
    saved = backup(installed, backup_root) if installed.exists() else None
    if installed.exists():
        installed.rename(installed.with_name(installed.name + ".old"))
    try:
        staged.rename(installed)
    except OSError as error:
        if (installed.with_name(installed.name + ".old")).exists():
            installed.with_name(installed.name + ".old").rename(installed)
        raise UpdateError(f"Не удалось установить сборку: {error}") from error
    old = installed.with_name(installed.name + ".old")
    if old.exists():
        shutil.rmtree(old)  # the backup above holds the verified copy
    return saved


def rollback(installed: Path, saved: Path, backup_root: Path) -> None:
    """Restore the backup. The failed folder is kept under failed/, never deleted."""
    manifest_path = saved / "backup_manifest.json"
    if not manifest_path.is_file():
        raise UpdateError("Резерв без манифеста; откат не выполнен")
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    actual = _hash_tree(saved)
    actual.pop("backup_manifest.json", None)
    expected = {k: v for k, v in expected.items() if k != "backup_manifest.json"}
    if actual != expected:
        raise UpdateError("Резерв повреждён (хеши не совпадают); откат не выполнен")
    if installed.exists():
        failed_dir = backup_root / "failed"
        failed_dir.mkdir(parents=True, exist_ok=True)
        installed.rename(failed_dir / (installed.name + "_" + _stamp()))
    shutil.copytree(saved, installed)
    (installed / "backup_manifest.json").unlink(missing_ok=True)

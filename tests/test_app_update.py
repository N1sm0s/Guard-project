"""P2.3: install and rollback on copies of the application folder (no system changes)."""
from pathlib import Path

import pytest

from integrityguard import app_update as up


def _build(folder: Path, marker: str) -> Path:
    folder.mkdir(parents=True)
    (folder / up.EXE_NAME).write_bytes(b"MZ" + marker.encode())
    (folder / "_internal").mkdir()
    (folder / "_internal" / "lib.dat").write_text(marker)
    return folder


def _ok(_exe):
    return 0


def _fails(_exe):
    return 3


def test_install_replaces_folder_and_keeps_verified_backup(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    backups = tmp_path / "dist" / "backups"
    saved = up.install(installed, staged, backups, selftest=_ok, running_exe_paths=[])
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"new")
    assert not staged.exists()
    assert saved is not None and saved.parent == backups
    assert (saved / up.EXE_NAME).read_bytes().endswith(b"old")
    assert (saved / "backup_manifest.json").is_file()
    assert not (installed.with_name(installed.name + ".old")).exists()


def test_failed_selftest_leaves_installed_folder_untouched(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    with pytest.raises(up.UpdateError):
        up.install(installed, staged, tmp_path / "backups", selftest=_fails, running_exe_paths=[])
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"old")
    assert staged.exists()
    assert not (tmp_path / "backups").exists()


def test_running_instance_blocks_install(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    with pytest.raises(up.UpdateError):
        up.install(installed, staged, tmp_path / "backups", selftest=_ok,
                   running_exe_paths=[str(installed / up.EXE_NAME)])
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"old")


def test_other_running_program_does_not_block(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    up.install(installed, staged, tmp_path / "backups", selftest=_ok,
               running_exe_paths=[str(tmp_path / "elsewhere" / up.EXE_NAME)])
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"new")


def test_rollback_restores_previous_build_and_keeps_failed_copy(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    backups = tmp_path / "dist" / "backups"
    saved = up.install(installed, staged, backups, selftest=_ok, running_exe_paths=[])
    up.rollback(installed, saved, backups)
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"old")
    assert not (installed / "backup_manifest.json").exists()
    failed = list((backups / "failed").iterdir())
    assert len(failed) == 1 and (failed[0] / up.EXE_NAME).read_bytes().endswith(b"new")


def test_tampered_backup_is_not_restored(tmp_path):
    installed = _build(tmp_path / "dist" / "IntegrityGuard", "old")
    staged = _build(tmp_path / "staging" / "IntegrityGuard", "new")
    backups = tmp_path / "dist" / "backups"
    saved = up.install(installed, staged, backups, selftest=_ok, running_exe_paths=[])
    (saved / "_internal" / "lib.dat").write_text("changed")
    with pytest.raises(up.UpdateError):
        up.rollback(installed, saved, backups)
    assert (installed / up.EXE_NAME).read_bytes().endswith(b"new")

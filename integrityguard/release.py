"""Atomic, evidence-gated activation and rollback for detector candidates."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .candidate_eval import evaluate_candidate, sha256_file


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _atomic_copy(source: Path, target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with source.open("rb") as src, temporary.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        shutil.copystat(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _manifest_path(data_root: Path, candidate_id: str) -> Path:
    path = (data_root / "models" / "candidates" / candidate_id / "candidate.json").resolve()
    if not path.is_relative_to((data_root / "models" / "candidates").resolve()):
        raise ValueError("Некорректный ID кандидата")
    return path


def _append_history(path: Path, record: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    operation_id = record.get("operation_id")
    if operation_id and path.is_file():
        with path.open(encoding="utf-8") as existing:
            for line in existing:
                try:
                    if json.loads(line).get("operation_id") == operation_id:
                        return
                except (ValueError, AttributeError):
                    continue
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _finish_state(state_path: Path, state: dict, candidate_path: Path | None = None):
    _atomic_json(state_path, state)
    if candidate_path and candidate_path.exists():
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        if state.get("action") == "promote":
            candidate["status"] = "promoted" if state.get("status") == "committed" else candidate.get("status")
            candidate["promotion_performed"] = state.get("status") == "committed"
            candidate["activated_at"] = state.get("completed_at")
            candidate["activation_backup"] = state.get("backup_path")
            candidate["activated_model_sha256"] = state.get("candidate_sha256")
        elif state.get("action") == "rollback" and state.get("status") == "committed":
            candidate["status"] = "rolled_back"
            candidate["promotion_performed"] = False
            candidate["rolled_back_at"] = state.get("completed_at")
        _atomic_json(candidate_path, candidate)


def recover_release(data_root: str | Path, model_path: str | Path) -> dict | None:
    """Resolve a crash-interrupted atomic release before the UI uses the model."""
    data_root, model_path = Path(data_root).resolve(), Path(model_path).resolve()
    state_path = data_root / "models" / "release_state.json"
    if not state_path.is_file():
        return None
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "prepared":
        if state.get("status") == "committed":
            current_sha = sha256_file(model_path)
            if current_sha != state.get("candidate_sha256"):
                state.update(status="needs_review", current_sha256=current_sha,
                             message="Активная модель не совпадает с завершённой операцией выпуска/отката.")
                _atomic_json(state_path, state)
                return state
            candidate_path = _manifest_path(data_root, state["candidate_id"])
            _finish_state(state_path, state, candidate_path)
            _append_history(data_root / "models" / "release_history.jsonl", state)
        return state
    current_sha = sha256_file(model_path)
    candidate_path = _manifest_path(data_root, state["candidate_id"])
    if current_sha == state.get("candidate_sha256"):
        state.update(status="committed", completed_at=_utc_now(), recovered_after_crash=True)
        _finish_state(state_path, state, candidate_path)
        _append_history(data_root / "models" / "release_history.jsonl", state)
    elif current_sha == state.get("previous_sha256"):
        state.update(status="aborted", completed_at=_utc_now(), recovered_after_crash=True)
        _finish_state(state_path, state)
    else:
        state.update(status="needs_review", current_sha256=current_sha,
                     message="Активная модель не совпадает ни с одним хешем незавершённой операции.")
        _atomic_json(state_path, state)
    return state


def promote_candidate(data_root: str | Path, candidate_id: str,
                      model_path: str | Path) -> dict:
    """Re-evaluate, back up and atomically activate a release-eligible candidate."""
    data_root, model_path = Path(data_root).resolve(), Path(model_path).resolve()
    candidate_manifest = _manifest_path(data_root, candidate_id)
    candidate = json.loads(candidate_manifest.read_text(encoding="utf-8"))
    evaluation = candidate.get("evaluation") or {}
    if candidate.get("status") != "release_eligible" or candidate.get("promotion_allowed") is not True:
        raise ValueError("Кандидат не прошёл независимые критерии выпуска")
    evaluation_path = Path(evaluation.get("evaluation_manifest", "")).resolve()
    if not evaluation_path.is_file():
        raise ValueError("Манифест независимой оценки недоступен; повторная проверка невозможна")
    if sha256_file(evaluation_path) != evaluation.get("evaluation_manifest_sha256"):
        raise ValueError("Манифест независимой оценки изменился после вычисления допуска")
    if sha256_file(model_path) != candidate.get("parent_model_sha256"):
        raise ValueError("Активная модель отличается от родительской модели кандидата")
    artifact = (candidate_manifest.parent / "detector.pt").resolve()
    if sha256_file(artifact) != evaluation.get("candidate_model_sha256"):
        raise ValueError("Checkpoint кандидата изменился после оценки")

    fresh = evaluate_candidate(data_root, candidate_id, evaluation_path)
    if not fresh.get("release_eligible"):
        raise ValueError("Повторная независимая оценка не прошла критерии выпуска")
    if fresh["evaluation_data_sha256"] != evaluation.get("evaluation_data_sha256"):
        raise ValueError("Holdout изменился после первоначальной оценки")
    if sha256_file(model_path) != candidate.get("parent_model_sha256"):
        raise ValueError("Родительская модель изменилась во время повторной оценки")
    candidate = json.loads(candidate_manifest.read_text(encoding="utf-8"))
    evaluation = candidate["evaluation"]
    candidate_sha = sha256_file(artifact)
    if candidate_sha != evaluation.get("candidate_model_sha256"):
        raise ValueError("Checkpoint кандидата изменился во время повторной оценки")

    backup_dir = data_root / "models" / "release_backups"
    backup = backup_dir / f"{candidate_id}-{candidate['parent_model_sha256'][:16]}.pt"
    if backup.exists():
        if sha256_file(backup) != candidate["parent_model_sha256"]:
            raise ValueError("Резервная копия с ожидаемым именем имеет неверный хеш")
    else:
        _atomic_copy(model_path, backup)
    if sha256_file(backup) != candidate["parent_model_sha256"]:
        raise OSError("Не удалось подтвердить резервную копию активной модели")

    state_path = data_root / "models" / "release_state.json"
    previous_state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else None
    if previous_state and previous_state.get("status") == "prepared":
        raise RuntimeError("Обнаружена незавершённая операция выпуска; сначала выполните восстановление")
    if sha256_file(model_path) != candidate["parent_model_sha256"]:
        raise ValueError("Активная модель изменилась перед активацией")
    state = {"action": "promote", "status": "prepared", "candidate_id": candidate_id,
             "operation_id": uuid.uuid4().hex,
             "active_model_path": str(model_path), "backup_path": str(backup),
             "previous_sha256": candidate["parent_model_sha256"], "candidate_sha256": candidate_sha,
             "evaluation_data_sha256": evaluation["evaluation_data_sha256"],
             "evaluation_manifest_sha256": evaluation["evaluation_manifest_sha256"],
             "prepared_at": _utc_now()}
    _atomic_json(state_path, state)
    _atomic_copy(artifact, model_path)
    if sha256_file(model_path) != candidate_sha:
        _atomic_copy(backup, model_path)
        state.update(status="failed_restored", completed_at=_utc_now())
        _finish_state(state_path, state)
        raise OSError("Хеш активной модели после замены не совпал; исходная модель восстановлена")
    state.update(status="committed", completed_at=_utc_now(), re_evaluated_at=fresh["evaluated_at"])
    _finish_state(state_path, state, candidate_manifest)
    _append_history(data_root / "models" / "release_history.jsonl", state)
    return state


def rollback_candidate(data_root: str | Path, model_path: str | Path) -> dict:
    """Restore the exact parent-model backup if the currently active hash is unchanged."""
    data_root, model_path = Path(data_root).resolve(), Path(model_path).resolve()
    state_path = data_root / "models" / "release_state.json"
    if not state_path.is_file():
        raise ValueError("История выпуска отсутствует")
    previous = json.loads(state_path.read_text(encoding="utf-8"))
    if previous.get("status") != "committed" or previous.get("action") != "promote":
        raise ValueError("Нет завершённой активации, которую можно откатить")
    if Path(previous.get("active_model_path", "")).resolve() != model_path:
        raise ValueError("Путь активной модели не совпадает с записью выпуска")
    active_sha = sha256_file(model_path)
    if active_sha != previous.get("candidate_sha256"):
        raise ValueError("Активная модель изменилась после выпуска; автоматический откат остановлен")
    backup = Path(previous["backup_path"]).resolve()
    if sha256_file(backup) != previous.get("previous_sha256"):
        raise ValueError("Резервная копия не совпадает с исходной моделью")
    state = {"action": "rollback", "status": "prepared", "candidate_id": previous["candidate_id"],
             "operation_id": uuid.uuid4().hex,
             "active_model_path": str(model_path), "backup_path": str(backup),
             "previous_sha256": active_sha, "candidate_sha256": previous["previous_sha256"],
             "prepared_at": _utc_now()}
    _atomic_json(state_path, state)
    _atomic_copy(backup, model_path)
    if sha256_file(model_path) != state["candidate_sha256"]:
        candidate_artifact = data_root / "models" / "candidates" / state["candidate_id"] / "detector.pt"
        _atomic_copy(candidate_artifact, model_path)
        state.update(status="failed_restored", completed_at=_utc_now())
        _atomic_json(state_path, state)
        raise OSError("Откат не подтвердился по хешу; предыдущий активный файл восстановлен")
    state.update(status="committed", completed_at=_utc_now())
    candidate_manifest = _manifest_path(data_root, state["candidate_id"])
    _finish_state(state_path, state, candidate_manifest)
    _append_history(data_root / "models" / "release_history.jsonl", state)
    return state

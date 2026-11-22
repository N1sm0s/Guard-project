"""Самообучение на реальном трафике через аудит карантина.

Карантин (вердикты REVIEW/BLOCK) сам по себе даёт только факт «отклонение от
эталона», но не метку конкретного типа угрозы и не гарантию, что это вообще
атака, а не ложное срабатывание. Чтобы не закреплять собственные ошибки
детектора как «подтверждённые атаки» (самоотравление), в обучение попадают
только образцы, которые явно подтвердил человек через аудит-выборку —
случайную долю карантинных пакетов (см. AUDIT_RATE).

Подтверждённые образцы используются только для бинарной дообучающей цели
(«подозрительно» / «норма»): они не привязываются к конкретному из 9 классов
угроз, так как для реального трафика такой метки не существует.
"""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import time
from pathlib import Path

import numpy as np
import torch

AUDIT_RATE = 0.15  # доля карантинных пакетов (REVIEW/BLOCK), ставящихся на аудит
MIN_CANDIDATE_SAMPLES = 20
MIN_SAMPLES_PER_LABEL = 5
MAX_CANDIDATE_SAMPLES = 500
CANDIDATE_INTERVAL_SECONDS = 24 * 60 * 60


def _dirs(data_root: Path) -> Path:
    d = Path(data_root) / "online"
    (d / "pending").mkdir(parents=True, exist_ok=True)
    return d


def _queue_path(d: Path) -> Path:
    return d / "audit_queue.json"


def _load_queue(d: Path) -> list:
    p = _queue_path(d)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_queue(d: Path, queue: list) -> None:
    _queue_path(d).write_text(json.dumps(queue, ensure_ascii=False, indent=1), encoding="utf-8")


def maybe_queue(data_root: Path, event: dict, features: dict, rng=None, evidence_db=None) -> str | None:
    """С вероятностью AUDIT_RATE ставит карантинный пакет на аудит человеком.

    features — словарь с тензорами x/adj/layers/behav (см. features.extract()).
    Возвращает id записи, если пакет поставлен на аудит, иначе None.
    """
    rng = rng or np.random.default_rng()
    if rng.random() >= AUDIT_RATE:
        return None
    d = _dirs(data_root)
    item_id = f"{int(time.time() * 1000)}_{int(rng.integers(0, 1_000_000))}"
    torch.save({"x": features["x"], "adj": features["adj"], "layers": features["layers"],
               "behav": features["behav"]}, d / "pending" / f"{item_id}.pt")
    feature_sha = None
    if evidence_db is not None and event.get("event_id"):
        from .evidence import EvidenceStore
        feature_sha = EvidenceStore(evidence_db).record_features(event["event_id"], features)
    queue = _load_queue(d)
    queue.append({"id": item_id, "time": event.get("time") or time.strftime("%Y-%m-%d %H:%M:%S"),
                 "package": event.get("package", ""), "verdict": event.get("verdict", ""),
                 "project_id": event.get("project_id") or event.get("package", ""),
                 "threat_ru": event.get("threat_ru", ""), "score": event.get("score"),
                 "event_id": event.get("event_id"), "fingerprint": event.get("fingerprint"),
                 "model_sha256": event.get("model_sha256"), "feature_sha256": feature_sha,
                 "evidence_db": str(evidence_db) if evidence_db is not None else None})
    _save_queue(d, queue)
    return item_id

def maybe_queue_network(data_root: Path, event_id: str, snap_json: str,
                        decision: str, features: dict, rng=None) -> str | None:
    """Ставит сетевой снимок на аудит человеком (для обучения классификатора сети).

    Вызывается из _check_nn() после получения вердикта от нейросети.
    features — словарь 26 именованных float-признаков из extract_features().
    decision — 'ALLOW', 'REVIEW' или 'BLOCK'.
    Возвращает id записи, если пакет поставлен на аудит, иначе None.
    """
    # Ставим на аудит только подозрительные (REVIEW/BLOCK), с вероятностью AUDIT_RATE
    if decision not in ("REVIEW", "BLOCK"):
        return None
    rng = rng or np.random.default_rng()
    if rng.random() >= AUDIT_RATE:
        return None
    d = _dirs(data_root)
    item_id = f"net_{int(time.time() * 1000)}_{int(rng.integers(0, 1_000_000))}"
    # Сохраняем признаки как тензор (совместимость с confirm())
    feat_tensor = torch.tensor(list(features.values()), dtype=torch.float32)
    feat_names = list(features.keys())
    torch.save({"network_features": feat_tensor, "feature_names": feat_names,
                "snap_json": snap_json, "decision": decision}, d / "pending" / f"{item_id}.pt")
    queue = _load_queue(d)
    queue.append({"id": item_id, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "package": "Сетевой снимок", "verdict": decision,
                 "project_id": str(event_id)[:20],
                 "threat_ru": f"Автоанализ: {decision}", "score": None,
                 "event_id": str(event_id), "fingerprint": None,
                 "model_sha256": None, "feature_sha256": None,
                 "evidence_db": None, "source": "network_classifier"})
    _save_queue(d, queue)
    return item_id


def list_pending(data_root: Path) -> list:
    """Записи, ожидающие подтверждения человеком (новые — первыми)."""
    return list(reversed(_load_queue(_dirs(data_root))))


def pending_count(data_root: Path) -> int:
    return len(_load_queue(_dirs(data_root)))


def confirm(data_root: Path, item_id: str, is_attack: bool, *, evidence_path=None, rationale="") -> dict | None:
    """Подтверждение/отклонение аудит-записи человеком.

    is_attack=True  — подтверждена настоящая угроза (бинарная метка 1).
    is_attack=False — ложное срабатывание, пакет на деле легитимен (метка 0);
                       это и защищает от закрепления собственных ошибок детектора.
    """
    d = _dirs(data_root)
    queue = _load_queue(d)
    item = next((it for it in queue if it["id"] == item_id), None)
    if item is None:
        return None
    from .audit_reviews import AuditReviews
    if evidence_path is None:
        raise ValueError("Для разметки требуется файл свидетельства и обоснование")
    reviews = AuditReviews(d / "label_reviews.sqlite")
    decision = reviews.propose(item.get("event_id"), item.get("fingerprint"), is_attack, evidence_path, rationale)
    if not decision["accepted"]:
        return {**item, "review_status": decision["status"]}
    src = d / "pending" / f"{item_id}.pt"
    if not src.exists():
        raise ValueError("Файл признаков отсутствует; метка не добавлена в обучение")
    try:
        feats = torch.load(src, map_location="cpu", weights_only=True)
    except (OSError, RuntimeError, EOFError) as error:
        raise ValueError("Не удалось прочитать признаки; исходный файл сохранён для проверки") from error
    buf = _load_confirmed(d)
    event_id = item.get("event_id")
    if event_id and any(sample.get("_event_id") == event_id for sample in buf):
        for sample in buf:
            if sample.get("_event_id") == event_id:
                sample["bin_y"] = float(bool(is_attack))
                sample["_review_ids"] = decision["review_ids"]
        confirmed_path = d / "confirmed.pt"
        temp_path = confirmed_path.with_suffix(".tmp")
        torch.save(buf, temp_path)
        temp_path.replace(confirmed_path)
        if item.get("evidence_db"):
            from .evidence import EvidenceStore
            EvidenceStore(item["evidence_db"]).confirm_label(event_id, is_attack)
        _save_queue(d, [it for it in queue if it["id"] != item_id])
        src.unlink(missing_ok=True)
        item["bin_y"] = float(bool(is_attack))
        return item
    buf.append({**feats, "bin_y": float(bool(is_attack)), "_event_id": event_id or "",
                "_fingerprint": item.get("fingerprint") or "",
                "_project_id": item.get("project_id") or item.get("package") or "",
                "_model_sha256": item.get("model_sha256") or "",
                "_label_source": "human_audit"})
    buf[-1]["_review_ids"] = decision["review_ids"]
    confirmed_path = d / "confirmed.pt"
    temp_path = confirmed_path.with_suffix(".tmp")
    torch.save(buf, temp_path)
    temp_path.replace(confirmed_path)
    if event_id and item.get("evidence_db"):
        from .evidence import EvidenceStore
        EvidenceStore(item["evidence_db"]).confirm_label(event_id, is_attack)
    _save_queue(d, [it for it in queue if it["id"] != item_id])
    src.unlink(missing_ok=True)
    item["bin_y"] = float(bool(is_attack))
    return item


def _load_confirmed(d: Path) -> list:
    p = d / "confirmed.pt"
    if not p.exists():
        return []
    try:
        buf = torch.load(p, map_location="cpu", weights_only=True)
        return buf if isinstance(buf, list) else []
    except (OSError, RuntimeError, EOFError):
        return []


def load_confirmed(data_root: Path) -> list:
    """Подтверждённые человеком реальные образцы, готовые к дообучению."""
    d = _dirs(data_root)
    from .audit_reviews import AuditReviews
    reviews = AuditReviews(d / "label_reviews.sqlite")
    eligible = []
    for sample in _load_confirmed(d):
        if not isinstance(sample, dict) or not sample.get("_review_ids"):
            continue
        decision = reviews.decision(sample.get("_event_id"), sample.get("_fingerprint"))
        if decision["accepted"] and decision["label"] == sample.get("bin_y") and decision["review_ids"] == sample["_review_ids"]:
            eligible.append(sample)
    return eligible


def confirmed_count(data_root: Path) -> int:
    return len(load_confirmed(data_root))


def clear_confirmed(data_root: Path) -> None:
    """Очищает буфер подтверждённых образцов (после успешного дообучения на них)."""
    p = _dirs(data_root) / "confirmed.pt"
    p.unlink(missing_ok=True)


def _confirmed_data_sha(samples: list[dict]) -> str:
    digest = hashlib.sha256()
    for sample in sorted(samples, key=lambda row: str(row.get("_event_id", ""))):
        digest.update(str(int(float(sample.get("bin_y", 0.0)) >= 0.5)).encode())
        digest.update(str(sample.get("_event_id", "")).encode("utf-8", "replace"))
        digest.update(json.dumps([sample.get("_project_id"), sample.get("_fingerprint")],
                                 ensure_ascii=True).encode())
        digest.update(json.dumps(sample.get("_review_ids", []), sort_keys=True).encode())
        for name in ("x", "adj", "layers", "behav"):
            value = sample[name]
            array = value.detach().cpu().contiguous().numpy() if hasattr(value, "detach") else np.asarray(value)
            digest.update(name.encode())
            digest.update(str(array.dtype).encode())
            digest.update(str(tuple(array.shape)).encode())
            digest.update(array.tobytes())
    return digest.hexdigest()


def candidate_readiness(data_root: Path, minimum=MIN_CANDIDATE_SAMPLES,
                        minimum_per_label=MIN_SAMPLES_PER_LABEL) -> dict:
    """Return auditable data sufficiency counts without training or changing state."""
    samples = load_confirmed(data_root)
    counts = {0: 0, 1: 0}
    for sample in samples:
        counts[int(float(sample.get("bin_y", 0.0)) >= 0.5)] += 1
    ready = len(samples) >= minimum and min(counts.values()) >= minimum_per_label
    return {"ready": ready, "confirmed_count": len(samples), "benign_count": counts[0],
            "attack_count": counts[1], "minimum": minimum,
            "minimum_per_label": minimum_per_label,
            "training_data_sha256": _confirmed_data_sha(samples) if samples else None}


def claim_candidate_schedule(data_root: Path, now: float | None = None,
                             interval=CANDIDATE_INTERVAL_SECONDS) -> dict:
    """Persistently claim a due training run after evidence-count and cadence gates."""
    readiness = candidate_readiness(data_root)
    if not readiness["ready"]:
        return {**readiness, "claimed": False, "reason": "insufficient_balanced_confirmed_data"}
    now = float(now if now is not None else time.time())
    state_path = Path(data_root) / "online" / "candidate_schedule.sqlite"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(state_path, timeout=30) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("""CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY CHECK(id=1), last_started REAL NOT NULL,
            last_status TEXT NOT NULL, data_sha256 TEXT, candidate_id TEXT)""")
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT last_started,last_status,data_sha256,candidate_id FROM schedule WHERE id=1").fetchone()
        last_started = float(row[0]) if row else 0.0
        if row and now - last_started < interval:
            return {**readiness, "claimed": False, "reason": "training_interval_not_elapsed",
                    "next_due_at": last_started + interval}
        db.execute("""INSERT INTO schedule(id,last_started,last_status,data_sha256,candidate_id)
            VALUES(1,?,'running',?,NULL) ON CONFLICT(id) DO UPDATE SET
            last_started=excluded.last_started,last_status='running',
            data_sha256=excluded.data_sha256,candidate_id=NULL""",
            (now, readiness["training_data_sha256"]))
        db.commit()
    return {**readiness, "claimed": True, "reason": "scheduled", "started_at": now}


def finish_candidate_schedule(data_root: Path, status: str, candidate_id: str | None = None) -> None:
    state_path = Path(data_root) / "online" / "candidate_schedule.sqlite"
    if not state_path.exists():
        return
    with sqlite3.connect(state_path, timeout=30) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("UPDATE schedule SET last_status=?,candidate_id=? WHERE id=1",
                   (str(status)[:80], candidate_id))


def build_candidate(data_root: Path, model_path: Path, ref_val=None, device="auto", cpu_threads=4) -> dict | None:
    """Train and persist an isolated candidate; never replace the active detector.

    Promotion is deliberately left to a later independent-evaluation gate. The
    confirmed examples remain in the evidence buffer until an explicit lifecycle
    decision consumes them.
    """
    if ref_val is not None:
        raise ValueError("Непроверенная ref_val не допускается: нужна отдельная подтверждённая реальная выборка")
    if isinstance(cpu_threads, bool) or not isinstance(cpu_threads, int) or not 1 <= cpu_threads <= (os.cpu_count() or 1):
        raise ValueError("Число потоков должно быть от 1 до числа логических процессоров")
    confirmed = load_confirmed(data_root)
    readiness = candidate_readiness(data_root)
    if not readiness["ready"]:
        return None
    import torch
    from .model import load_detector, save_detector
    from .train import finetune_binary

    model_path = Path(model_path)
    active_bytes = model_path.read_bytes()
    active_sha = hashlib.sha256(active_bytes).hexdigest()
    data_sha = readiness["training_data_sha256"]
    candidate_id = hashlib.sha256(f"{active_sha}:{data_sha}".encode()).hexdigest()[:20]
    candidate_dir = Path(data_root) / "models" / "candidates" / candidate_id
    artifact = candidate_dir / "detector.pt"
    manifest_path = candidate_dir / "candidate.json"
    if artifact.is_file() and manifest_path.is_file():
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    candidate_dir.mkdir(parents=True, exist_ok=True)
    per_label = {0: [sample for sample in confirmed if float(sample.get("bin_y", 0.0)) < 0.5],
                 1: [sample for sample in confirmed if float(sample.get("bin_y", 0.0)) >= 0.5]}
    cap_per_label = MAX_CANDIDATE_SAMPLES // 2
    selected = []
    for label in (0, 1):
        group = per_label[label]
        if len(group) <= cap_per_label:
            selected.extend(group)
        else:
            indices = np.linspace(0, len(group) - 1, cap_per_label, dtype=int)
            selected.extend(group[index] for index in indices)
    model, meta = load_detector(model_path)
    import torch
    previous_threads = torch.get_num_threads()
    if device not in ("auto", "cpu", "cuda"):
        raise ValueError("Устройство обучения: auto, cpu или cuda")
    training_device = "cuda" if device == "auto" and torch.cuda.is_available() else (
        "cpu" if device == "auto" else device)
    if training_device == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA недоступна в этом окружении обучения")
    torch.set_num_threads(cpu_threads)
    try:
        model, threshold = finetune_binary(model, selected, ref_val, epochs=3, device=training_device)
    finally:
        torch.set_num_threads(previous_threads)
    threshold = threshold if threshold is not None else meta.get("threshold", 0.5)
    save_detector(model, artifact, {"threshold": threshold,
                                    "block_threshold": max(threshold, 0.9),
                                    "candidate_id": candidate_id,
                                    "parent_model_sha256": active_sha,
                                    "training_data_sha256": data_sha})
    manifest = {"candidate_id": candidate_id, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "artifact": str(artifact), "parent_model": str(model_path),
                "parent_model_sha256": active_sha, "training_data_sha256": data_sha,
                "training_event_ids": sorted({str(s.get("_event_id")) for s in confirmed if s.get("_event_id")}),
                "training_project_ids": sorted({str(s.get("_project_id", "")).strip() for s in confirmed
                                                 if str(s.get("_project_id", "")).strip()}),
                "training_project_ids_complete": all(isinstance(s.get("_project_id"), str) and
                                                     s["_project_id"].strip() for s in confirmed),
                "training_fingerprints": sorted({str(s.get("_fingerprint")) for s in confirmed
                                                  if s.get("_fingerprint")}),
                "confirmed_sample_count": len(confirmed), "training_sample_count": len(selected),
                "resource_limits": {"device": training_device, "torch_threads": cpu_threads, "epochs": 3,
                                    "max_samples": MAX_CANDIDATE_SAMPLES},
                "status": "awaiting_independent_evaluation",
                "evaluation": None,
                "calibration": "parent_threshold_retained; no_verified_calibration_dataset",
                "promotion_allowed": False,
                "limitations": ["нет независимого набора реальных пакетов для оценки",
                                "кандидат не активирован; рабочая модель не изменена"]}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest

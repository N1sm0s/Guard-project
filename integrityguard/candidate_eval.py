"""Independent, provenance-checked evaluation and fail-closed release gate."""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from .model import load_detector, collate
from .train import auc

MIN_CLEAN = 200
MIN_ATTACK = 100
MAX_FPR_UPPER_95 = 0.02
MIN_RECALL_LOWER_95 = 0.80
MAX_FPR_REGRESSION = 0.01
MAX_RECALL_REGRESSION = 0.02
MAX_AUC_REGRESSION = 0.02


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 1.0
    p = successes / total
    den = 1 + z * z / total
    center = (p + z * z / (2 * total)) / den
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / den
    return max(0.0, center - margin), min(1.0, center + margin)


def release_decision(parent: dict, candidate: dict, n_clean: int, n_attack: int) -> dict:
    """Apply absolute quality and non-regression gates with conservative intervals."""
    recall_lower, _ = wilson(round(candidate["recall"] * n_attack), n_attack)
    _, fpr_upper = wilson(round(candidate["fpr"] * n_clean), n_clean)
    auc_regression_ok = (isinstance(candidate.get("auc"), (int, float))
                         and isinstance(parent.get("auc"), (int, float))
                         and math.isfinite(candidate["auc"]) and math.isfinite(parent["auc"])
                         and candidate["auc"] >= parent["auc"] - MAX_AUC_REGRESSION)
    gates = {
        "minimum_clean_samples": n_clean >= MIN_CLEAN,
        "minimum_attack_samples": n_attack >= MIN_ATTACK,
        "candidate_recall_lower_95": recall_lower >= MIN_RECALL_LOWER_95,
        "candidate_fpr_upper_95": fpr_upper <= MAX_FPR_UPPER_95,
        "recall_non_regression": candidate["recall"] >= parent["recall"] - MAX_RECALL_REGRESSION,
        "fpr_non_regression": candidate["fpr"] <= parent["fpr"] + MAX_FPR_REGRESSION,
        "auc_non_regression": auc_regression_ok,
    }
    return {"eligible": all(gates.values()), "gates": gates,
            "candidate_recall_lower_95": recall_lower, "candidate_fpr_upper_95": fpr_upper,
            "limits": {"minimum_clean": MIN_CLEAN, "minimum_attack": MIN_ATTACK,
                       "max_fpr_upper_95": MAX_FPR_UPPER_95,
                       "min_recall_lower_95": MIN_RECALL_LOWER_95,
                       "max_fpr_regression": MAX_FPR_REGRESSION,
                       "max_recall_regression": MAX_RECALL_REGRESSION,
                       "max_auc_regression": MAX_AUC_REGRESSION}}


def _validate_holdout(manifest_path: Path, candidate: dict) -> tuple[dict, list[dict], str, str, Path]:
    manifest_sha = sha256_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    required = ("format", "data_kind", "independent", "candidate_id", "reviewer",
                "collected_at", "source_refs", "attestation", "samples_file",
                "samples_sha256", "sample_count", "label_schema")
    missing = [key for key in required if key not in manifest]
    if missing:
        raise ValueError("В манифесте независимой оценки отсутствуют поля: " + ", ".join(missing))
    if manifest["format"] != "integrityguard-independent-evaluation-v1":
        raise ValueError("Неподдерживаемый формат независимой оценки")
    if manifest["data_kind"] != "real" or manifest["independent"] is not True:
        raise ValueError("Оценка допускается только на независимо собранных реальных данных")
    if manifest["candidate_id"] != candidate["candidate_id"]:
        raise ValueError("Набор оценки привязан к другому кандидату")
    if not str(manifest["reviewer"]).strip() or not str(manifest["attestation"]).strip():
        raise ValueError("Укажите проверяющего и подтверждение происхождения/разметки")
    if not isinstance(manifest["source_refs"], list) or not manifest["source_refs"] \
            or not all(str(ref).strip() for ref in manifest["source_refs"]):
        raise ValueError("Нужны ссылки или идентификаторы первичных источников данных")
    if manifest["label_schema"] != "binary_v1":
        raise ValueError("Ожидается бинарная разметка binary_v1")
    sample_path = (manifest_path.parent / str(manifest["samples_file"])).resolve()
    if not sample_path.is_relative_to(manifest_path.parent.resolve()):
        raise ValueError("Файл выборки должен находиться рядом с манифестом оценки")
    actual_sha = sha256_file(sample_path)
    if actual_sha != manifest["samples_sha256"]:
        raise ValueError("SHA-256 файла независимой выборки не совпал с манифестом")
    samples = torch.load(sample_path, map_location="cpu", weights_only=True)
    if not isinstance(samples, list) or len(samples) != int(manifest["sample_count"]):
        raise ValueError("Число образцов не совпадает с манифестом оценки")

    train_ids = set(candidate.get("training_event_ids", []))
    train_fingerprints = set(candidate.get("training_fingerprints", []))
    seen_ids, seen_fingerprints = set(), set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"Образец {index} имеет неверный формат")
        for key in ("_event_id", "_fingerprint", "_project_id", "_label_evidence",
                    "x", "adj", "layers", "behav", "y"):
            if key not in sample:
                raise ValueError(f"В образце {index} отсутствует поле {key}")
        event_id, fingerprint = str(sample["_event_id"]), str(sample["_fingerprint"])
        if not event_id or event_id in seen_ids or not fingerprint or fingerprint in seen_fingerprints:
            raise ValueError("В независимой выборке обнаружены пустые или повторные event_id/SHA-256")
        if event_id in train_ids or fingerprint in train_fingerprints:
            raise ValueError("Независимая выборка пересекается с подтверждёнными обучающими примерами")
        if not str(sample["_project_id"]).strip() or not str(sample["_label_evidence"]).strip():
            raise ValueError("У каждого образца должны быть project_id и доказательство метки")
        if int(sample["y"]) not in (0, 1):
            raise ValueError("В holdout допускаются только бинарные метки 0/1")
        for key in ("x", "adj", "layers", "behav"):
            value = sample[key]
            if not torch.is_tensor(value) or not torch.isfinite(value).all():
                raise ValueError(f"Признак {key} образца {index} не является конечным тензором")
        seen_ids.add(event_id)
        seen_fingerprints.add(fingerprint)
    if sha256_file(manifest_path) != manifest_sha or sha256_file(sample_path) != actual_sha:
        raise OSError("Манифест или holdout изменился во время проверки")
    return manifest, samples, actual_sha, manifest_sha, sample_path


def _binary_metrics(model, samples, threshold: float) -> dict:
    labels = np.asarray([int(s["y"]) for s in samples], dtype=bool)
    scores = []
    model.eval()
    with torch.no_grad():
        for offset in range(0, len(samples), 128):
            output = model(collate(samples[offset:offset + 128]))
            scores.extend((1 - F.softmax(output["logits"], -1)[:, 0]).cpu().tolist())
    scores = np.asarray(scores, dtype=float)
    flags = scores >= float(threshold)
    tp = int((flags & labels).sum())
    fp = int((flags & ~labels).sum())
    positives, negatives = int(labels.sum()), int((~labels).sum())
    auc_value = float(auc(scores, labels))
    return {"n": len(samples), "clean_n": negatives, "attack_n": positives,
            "recall": tp / max(positives, 1), "fpr": fp / max(negatives, 1),
            "precision": tp / max(tp + fp, 1), "auc": auc_value if math.isfinite(auc_value) else None,
            "threshold": float(threshold)}


def evaluate_candidate(data_root: str | Path, candidate_id: str,
                       evaluation_manifest: str | Path) -> dict:
    """Evaluate a candidate on a disjoint real holdout; persist evidence, never promote."""
    data_root = Path(data_root)
    candidate_dir = data_root / "models" / "candidates" / candidate_id
    manifest_path = candidate_dir / "candidate.json"
    candidate_manifest_sha = sha256_file(manifest_path)
    candidate = json.loads(manifest_path.read_text(encoding="utf-8"))
    if candidate.get("candidate_id") != candidate_id:
        raise ValueError("ID каталога не совпадает с манифестом кандидата")
    holdout_path = Path(evaluation_manifest).resolve()
    holdout_manifest, samples, holdout_sha, holdout_manifest_sha, sample_path = \
        _validate_holdout(holdout_path, candidate)
    candidate_path = candidate_dir / "detector.pt"
    parent_path = Path(candidate["parent_model"])
    if sha256_file(parent_path) != candidate.get("parent_model_sha256"):
        raise ValueError("Родительская модель изменилась после обучения кандидата")
    parent_sha = sha256_file(parent_path)
    candidate_sha = sha256_file(candidate_path)
    candidate_model, candidate_meta = load_detector(candidate_path)
    parent_model, parent_meta = load_detector(parent_path)
    if candidate_meta.get("parent_model_sha256") != candidate.get("parent_model_sha256"):
        raise ValueError("Checkpoint кандидата не подтверждает указанную родительскую модель")
    candidate_metrics = _binary_metrics(candidate_model, samples, candidate_meta.get("threshold", 0.5))
    parent_metrics = _binary_metrics(parent_model, samples, parent_meta.get("threshold", 0.5))
    if sha256_file(parent_path) != parent_sha or sha256_file(candidate_path) != candidate_sha:
        raise OSError("Одна из моделей изменилась во время независимой оценки; результат отброшен")
    if sha256_file(holdout_path) != holdout_manifest_sha or sha256_file(sample_path) != holdout_sha:
        raise OSError("Манифест или файл независимой выборки изменился во время оценки")
    if sha256_file(manifest_path) != candidate_manifest_sha:
        raise OSError("Манифест кандидата изменился во время оценки")
    decision = release_decision(parent_metrics, candidate_metrics,
                                candidate_metrics["clean_n"], candidate_metrics["attack_n"])
    result = {"evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "evaluation_manifest": str(Path(evaluation_manifest).resolve()),
              "evaluation_manifest_sha256": holdout_manifest_sha,
              "evaluation_data_sha256": holdout_sha,
              "candidate_model_sha256": candidate_sha,
              "parent_model_sha256": parent_sha,
              "source_refs": holdout_manifest["source_refs"],
              "reviewer": holdout_manifest["reviewer"],
              "n": len(samples), "parent_metrics": parent_metrics,
              "candidate_metrics": candidate_metrics, "decision": decision,
              "release_eligible": decision["eligible"],
              "promotion_performed": False,
              "note": "Оценка не активирует кандидата автоматически."}
    candidate["evaluation"] = result
    candidate["status"] = "release_eligible" if decision["eligible"] else "rejected_by_release_gate"
    candidate["promotion_allowed"] = bool(decision["eligible"])
    temp = manifest_path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(candidate, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, manifest_path)
    return result

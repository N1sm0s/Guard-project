"""Train the experimental host-snapshot classifier from evidence-attached decisions.

Historical model decisions and DShield matches are context, never training targets. The
training unit is a real captured network snapshot. A snapshot is labeled BLOCK
when any observed remote endpoint has an agreed malicious label, and ALLOW only
when every observed endpoint has an agreed benign label. Partial or disputed
snapshots are excluded. Temporal holdouts with an embargo keep nearby samples
out of different partitions; the final test partition is never used to fit or
select thresholds.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .network_classifier import (ARCH_WIDE, FEATURE_NAMES, FEATURE_VERSION,
                                 LABEL_SOURCE, _DECISIONS, build_model,
                                 extract_features)

_MIN_SAMPLES = 60
_MIN_TRAIN_PER_CLASS = 10
_MIN_HOLDOUT_PER_CLASS = 5
_EMBARGO = timedelta(minutes=5)
_MAX_VALIDATION_FPR = 0.01
_MAX_VALIDATION_FALSE_ALLOW = 0.01
_EPOCHS_MAX = 500
_EARLY_STOP_PATIENCE = 40


def _build_table(labeled_events: list[dict]) -> tuple[list[list[float]], list[str], list[str]]:
    rows, labels, times = [], [], []
    for event in labeled_events:
        label = event.get("label")
        timestamp = event.get("captured_at_utc")
        if label not in _DECISIONS or not isinstance(timestamp, str):
            continue
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        features = extract_features(event.get("snapshot") or {})
        rows.append([features[name] for name in FEATURE_NAMES])
        labels.append(label)
        times.append(timestamp)
    return rows, labels, times


def _temporal_split(times: list[str]) -> tuple[list[int], list[int], list[int]]:
    """Chronological 60/20/20 split, purging five minutes around each boundary."""
    order = sorted(range(len(times)), key=lambda i: (times[i], i))
    if len(order) < 3:
        return [], [], []
    first = datetime.fromisoformat(times[order[int(len(order) * 0.60)]].replace("Z", "+00:00"))
    second = datetime.fromisoformat(times[order[int(len(order) * 0.80)]].replace("Z", "+00:00"))
    first_start, first_end = first - _EMBARGO, first + _EMBARGO
    second_start, second_end = second - _EMBARGO, second + _EMBARGO
    train, validation, test = [], [], []
    for i in order:
        timestamp = datetime.fromisoformat(times[i].replace("Z", "+00:00"))
        if timestamp < first_start:
            train.append(i)
        elif first_end <= timestamp < second_start:
            validation.append(i)
        elif timestamp >= second_end:
            test.append(i)
    return train, validation, test


def _counts(labels: list[str]) -> dict[str, int]:
    return {label: labels.count(label) for label in _DECISIONS}


def _has_class_support(labels: list[str], minimum: int) -> bool:
    counts = _counts(labels)
    return all(counts[label] >= minimum for label in _DECISIONS)


def _select_thresholds(scores, labels) -> tuple[float, float]:
    """Choose empirical reject-option thresholds on validation only.

    BLOCK maximizes attack recall subject to <=1% observed benign false blocks.
    ALLOW maximizes benign coverage subject to <=1% observed attacks allowed.
    Thresholds default to REVIEW for every sample if the validation set cannot
    demonstrate the requested constraints.
    """
    import numpy as np

    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels)
    benign, attack = labels == 0, labels == 1
    candidates = np.unique(np.concatenate(([0.0, 1.000001], scores)))

    block_threshold = 1.000001
    best_block_recall = -1.0
    for threshold in candidates:
        fpr = float((scores[benign] >= threshold).mean()) if benign.any() else 1.0
        recall = float((scores[attack] >= threshold).mean()) if attack.any() else 0.0
        if fpr <= _MAX_VALIDATION_FPR and recall > best_block_recall:
            block_threshold, best_block_recall = float(threshold), recall

    allow_threshold = -1.0
    best_allow_coverage = -1.0
    for threshold in candidates:
        false_allow = float((scores[attack] <= threshold).mean()) if attack.any() else 1.0
        coverage = float((scores[benign] <= threshold).mean()) if benign.any() else 0.0
        if false_allow <= _MAX_VALIDATION_FALSE_ALLOW and threshold < block_threshold \
                and coverage > best_allow_coverage:
            allow_threshold, best_allow_coverage = float(threshold), coverage
    return allow_threshold, block_threshold


def _rank_auc(scores, positive) -> float | None:
    import numpy as np

    scores, positive = np.asarray(scores, dtype=float), np.asarray(positive, dtype=bool)
    if positive.all() or not positive.any():
        return None
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    sorted_scores = scores[order]
    start = 0
    while start < len(scores):
        end = start
        while end + 1 < len(scores) and sorted_scores[end + 1] == sorted_scores[start]:
            end += 1
        ranks[order[start:end + 1]] = (start + end) / 2 + 1
        start = end + 1
    positives, negatives = positive.sum(), (~positive).sum()
    return float((ranks[positive].sum() - positives * (positives + 1) / 2) /
                 (positives * negatives))


def _average_precision(scores, positive) -> float | None:
    import numpy as np

    scores, positive = np.asarray(scores, dtype=float), np.asarray(positive, dtype=bool)
    count = int(positive.sum())
    if count == 0 or count == len(positive):
        return None
    order = np.argsort(-scores, kind="mergesort")
    sorted_positive = positive[order]
    cumulative = np.cumsum(sorted_positive)
    ranks = np.arange(1, len(positive) + 1)
    return float((cumulative[sorted_positive] / ranks[sorted_positive]).sum() / count)


def _metrics(scores, labels, allow_threshold, block_threshold) -> dict:
    import numpy as np

    scores, labels = np.asarray(scores, dtype=float), np.asarray(labels, dtype=int)
    benign, attack = labels == 0, labels == 1
    block = scores >= block_threshold
    allow = scores <= allow_threshold
    review = ~(block | allow)
    tp, fp = int((block & attack).sum()), int((block & benign).sum())
    fn = int((~block & attack).sum())
    tn = int((~block & benign).sum())
    return {
        "n": int(len(labels)), "class_counts": {"ALLOW": int(benign.sum()), "BLOCK": int(attack.sum())},
        "accuracy_block_vs_not_block": round(float((tp + tn) / max(len(labels), 1)), 4),
        "block_precision": round(tp / max(tp + fp, 1), 4),
        "block_recall": round(tp / max(tp + fn, 1), 4),
        "block_fpr": round(fp / max(int(benign.sum()), 1), 4),
        "attack_captured_recall": round(float((~allow[attack]).mean()), 4) if attack.any() else None,
        "false_allow_rate": round(float(allow[attack].mean()), 4) if attack.any() else None,
        "benign_allow_rate": round(float(allow[benign].mean()), 4) if benign.any() else None,
        "review_rate": round(float(review.mean()), 4),
        "roc_auc": _rank_auc(scores, attack), "pr_auc_average_precision": _average_precision(scores, attack),
        "brier_score": round(float(np.mean((scores - attack.astype(float)) ** 2)), 4),
    }


def train(event_log, checkpoint_path: Path, min_samples: int = _MIN_SAMPLES,
          reviews=None) -> dict:
    """Train only on complete evidence-attached adjudications from real snapshots.

    This host-level telemetry model is experimental and is not the release-gate
    packet-flow candidate. A single operator adjudication is allowed by policy;
    attached evidence integrity is checked, but its publisher/content is not
    independently authenticated by this code.
    """
    checkpoint_path = Path(checkpoint_path)
    if reviews is None:
        from .network_label_reviews import NetworkLabelReviews
        reviews = NetworkLabelReviews(Path(event_log.path).with_name("network_label_reviews.sqlite"))
    labeled = reviews.adjudicated_snapshot_labels(event_log)
    rows, labels, times = _build_table(labeled)
    class_counts = _counts(labels)
    minimum = max(1, min_samples // 6)
    if len(rows) < min_samples or not _has_class_support(labels, minimum):
        return {"skipped": True, "reason": "insufficient_evidence_attached_labels",
                "n_samples": len(rows), "class_counts": class_counts,
                "adjudicated_snapshot_labels": len(labeled), "label_source": LABEL_SOURCE}

    train_idx, val_idx, test_idx = _temporal_split(times)
    split_labels = [[labels[i] for i in part] for part in (train_idx, val_idx, test_idx)]
    split_note = "temporal_only"
    if not _has_class_support(split_labels[0], _MIN_TRAIN_PER_CLASS) \
            or not _has_class_support(split_labels[1], _MIN_HOLDOUT_PER_CLASS) \
            or not _has_class_support(split_labels[2], _MIN_HOLDOUT_PER_CLASS):
        # Never mix neighboring captures or incidents just to make training run.
        # If the chronological partitions cannot support both classes, wait for
        # more independent data instead of reporting a leaky test.
        return {"skipped": True, "reason": "insufficient_temporal_class_support",
                "n_samples": len(rows), "class_counts": class_counts,
                "split_counts": {name: _counts(part) for name, part in
                                 zip(("train", "validation", "test"), split_labels)},
                "split_note": split_note,
                "embargo_minutes": _EMBARGO.total_seconds() / 60, "label_source": LABEL_SOURCE}

    import numpy as np
    import torch
    from torch import nn

    x_all = np.asarray(rows, dtype="float32")
    label_to_idx = {label: i for i, label in enumerate(_DECISIONS)}
    y_all = np.asarray([label_to_idx[label] for label in labels], dtype="int64")
    x_train, y_train = x_all[train_idx], y_all[train_idx]
    mean, std = x_train.mean(axis=0), x_train.std(axis=0)
    std[std < 1e-6] = 1.0
    x_train_t = torch.from_numpy((x_train - mean) / std)
    y_train_t = torch.from_numpy(y_train)
    x_val = torch.from_numpy((x_all[val_idx] - mean) / std)
    y_val = torch.from_numpy(y_all[val_idx])

    train_counts = np.bincount(y_train, minlength=len(_DECISIONS)).astype("float32")
    weights = len(y_train) / np.maximum(train_counts, 1)
    weights = weights / weights.sum() * len(_DECISIONS)
    loss_fn = nn.CrossEntropyLoss(weight=torch.from_numpy(weights.astype("float32")))
    torch.manual_seed(0)
    model = build_model(ARCH_WIDE)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-4)

    best_val_loss, best_state, stale = float("inf"), None, 0
    stopped_epoch = _EPOCHS_MAX
    for epoch in range(1, _EPOCHS_MAX + 1):
        model.train()
        optimizer.zero_grad()
        loss_fn(model(x_train_t), y_train_t).backward()
        optimizer.step()
        model.eval()
        with torch.no_grad():
            val_loss = float(loss_fn(model(x_val), y_val))
        if val_loss < best_val_loss - 1e-4:
            best_val_loss, stale = val_loss, 0
            best_state = {key: value.clone() for key, value in model.state_dict().items()}
        else:
            stale += 1
            if stale >= _EARLY_STOP_PATIENCE:
                stopped_epoch = epoch
                break
    if best_state is None:
        return {"skipped": True, "reason": "training_did_not_produce_checkpoint",
                "n_samples": len(rows), "class_counts": class_counts}
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        val_scores = torch.softmax(model(x_val), dim=1)[:, label_to_idx["BLOCK"]].numpy()
    val_labels = y_all[val_idx]
    allow_threshold, block_threshold = _select_thresholds(val_scores, val_labels)

    x_test = torch.from_numpy((x_all[test_idx] - mean) / std)
    with torch.no_grad():
        test_scores = torch.softmax(model(x_test), dim=1)[:, label_to_idx["BLOCK"]].numpy()
    test_metrics = _metrics(test_scores, y_all[test_idx], allow_threshold, block_threshold)
    caveat = ("Результат относится только к экспериментальной модели host-снимков; метки внесены "
              "одним ответственным оператором с приложенным файлом, подлинность источника кодом не проверяется. "
              "Разбиение по времени "
              "с пятиминутным зазором; test не участвовал в обучении, ранней остановке или подборе порогов. "
              "Пороговые ограничения проверяются на небольшой выборке и не являются гарантией качества "
              "или разрешением на автоблокировку.")
    metadata = {
        "label_source": LABEL_SOURCE, "feature_version": FEATURE_VERSION,
        "n_samples": len(rows), "n_train": len(train_idx), "n_val": len(val_idx), "n_test": len(test_idx),
        "class_counts": class_counts,
        "split_counts": {name: _counts(part) for name, part in
                         zip(("train", "validation", "test"), split_labels)},
        "split_note": split_note,
        "embargo_minutes": _EMBARGO.total_seconds() / 60,
        "stopped_epoch": stopped_epoch, "allow_threshold": allow_threshold,
        "block_threshold": block_threshold,
        "validation_metrics": _metrics(val_scores, val_labels, allow_threshold, block_threshold),
        "test_metrics": test_metrics,
        "caveat": caveat,
    }
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = checkpoint_path.with_name(f"{checkpoint_path.name}.{os.getpid()}.tmp")
    torch.save({"feature_version": FEATURE_VERSION, "label_source": LABEL_SOURCE,
                "feature_names": list(FEATURE_NAMES), "classes": list(_DECISIONS),
                "arch": ARCH_WIDE, "state_dict": model.state_dict(),
                "mean": mean.tolist(), "std": std.tolist(),
                "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                **metadata}, temporary_path)
    os.replace(temporary_path, checkpoint_path)
    return {"skipped": False, "checkpoint_path": str(checkpoint_path), **metadata}

"""Grouped cross-validation on all real CTU-13 scenarios, then final all-data fit.

Publisher labels retain their original provenance. Background/ambiguous labels
are excluded from supervised loss and labeled metrics. The final checkpoint is
research-only: grouped CV is not a target-network independent evaluation.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION  # noqa: E402
from tools.train_ctu13_multicapture_candidate import (  # noqa: E402
    AutoencoderClassifier, class_for_label, confusion, read_training_capture,
    row_count, sha256,
)
from tools.train_ctu13_scenario_candidate_v2 import SPECS as BASE_SPECS  # noqa: E402

DATA = ROOT / "outputs" / "network-eval"
OUT = DATA / "ctu13-all-scenarios-flow-v3-candidate-v1.pt"
METRICS = DATA / "ctu13-all-scenarios-flow-v3-metrics-v1.json"
MANIFEST = DATA / "ctu13-all-scenarios-flow-v3-manifest-v1.json"

# Every official CTU-13 capture 42–54 is present exactly once across these folds.
# Grouping by whole capture prevents flows from the same scenario crossing splits.
FOLDS = {
    "fold_1": ["50"],
    "fold_2": ["51"],
    "fold_3": ["44", "45", "46", "52"],
    "fold_4": ["42", "54"],
    "fold_5": ["43", "47", "48", "49", "53"],
}
EXTRA_TRAIN = ["SME-ECHO"]
MAX_VALIDATION_FPR = 0.001
EPOCHS = 20
RECONSTRUCTION_EPOCHS = 2

SPECS = {key: value for key, value in BASE_SPECS.items() if key != "SME-ECHO"}
SPECS.update({
    "51": (DATA / "official-ctu13" / "capture20110818_ctu51.binetflow", "train", 1_309_791,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow"),
    "52": (DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow", "train", 107_251,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow"),
    "53": (DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", "train", 325_471,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-53/detailed-bidirectional-flow-labels/capture20110819.binetflow"),
    "SME-ECHO": (DATA / "official-ctu-sme11" / "ctu-sme11-echo-derived-features.csv.gz", "train", 53_568,
                 "https://doi.org/10.5281/zenodo.7958259"),
})


def _feature_stats(x: np.memmap, slices: dict[str, tuple[int, int]], ids: list[str]):
    total = 0
    sums = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    sums_sq = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    for capture in ids:
        start, end = slices[capture]
        for offset in range(start, end, 250_000):
            chunk = np.asarray(x[offset:min(offset + 250_000, end)], dtype=np.float64)
            sums += chunk.sum(axis=0)
            sums_sq += np.square(chunk).sum(axis=0)
            total += len(chunk)
    mean = (sums / max(total, 1)).astype(np.float32)
    variance = np.maximum(sums_sq / max(total, 1) - np.square(mean), 0.0)
    std = np.sqrt(variance).astype(np.float32)
    std[std < 1e-6] = 1.0
    return mean, std


def _indices(slices: dict[str, tuple[int, int]], ids: list[str]) -> np.ndarray:
    return np.concatenate([np.arange(*slices[capture], dtype=np.int64) for capture in ids])


def _normalized_batch(x: np.memmap, indexes: np.ndarray,
                      mean: np.ndarray, std: np.ndarray, device: str) -> torch.Tensor:
    values = np.asarray(x[indexes], dtype=np.float32)
    values -= mean
    values /= std
    return torch.from_numpy(values).to(device)


def _fit(x: np.memmap, y: np.memmap, slices: dict[str, tuple[int, int]],
         train_ids: list[str], seed: int, device: str):
    train_indices = _indices(slices, train_ids)
    y_train_all = np.asarray(y[train_indices], dtype=np.int8)
    labeled_indices = train_indices[y_train_all >= 0]
    labels = np.asarray(y[labeled_indices], dtype=np.int64)
    if len(np.unique(labels)) != 2:
        raise RuntimeError(f"Training fold lacks both source-labeled classes: {train_ids}")
    mean, std = _feature_stats(x, slices, train_ids)

    torch.manual_seed(seed)
    model = AutoencoderClassifier().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    rng = np.random.default_rng(seed)
    for epoch in range(RECONSTRUCTION_EPOCHS):
        order = rng.permutation(train_indices)
        total_loss = 0.0
        seen = 0
        model.train()
        for start in range(0, len(order), 8192):
            indexes = order[start:start + 8192]
            batch = _normalized_batch(x, indexes, mean, std, device)
            reconstructed, _ = model(batch)
            loss = torch.nn.functional.mse_loss(reconstructed, batch)
            optimizer.zero_grad(); loss.backward(); optimizer.step()
            total_loss += float(loss.detach()) * len(indexes)
            seen += len(indexes)
        print(f"seed={seed} reconstruction {epoch + 1}/{RECONSTRUCTION_EPOCHS}: "
              f"{total_loss / max(seen, 1):.6f}", flush=True)

    counts = np.bincount(labels, minlength=2).astype(np.float32)
    weights = len(labels) / np.maximum(counts, 1)
    weights = weights / weights.sum() * 2
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32,
                                                             device=device))
    label_to_idx = {0: 0, 1: 1}
    labels_t = torch.from_numpy(np.asarray([label_to_idx[int(value)] for value in labels],
                                          dtype=np.int64))
    for epoch in range(EPOCHS):
        order = rng.permutation(len(labeled_indices))
        model.train()
        for start in range(0, len(order), 8192):
            take = order[start:start + 8192]
            indexes = labeled_indices[take]
            batch = _normalized_batch(x, indexes, mean, std, device)
            targets = labels_t[take].to(device)
            _, logits = model(batch)
            loss = loss_fn(logits, targets)
            optimizer.zero_grad(); loss.backward(); optimizer.step()
        print(f"seed={seed} classification {epoch + 1}/{EPOCHS}", flush=True)
    model.eval()
    return model, mean, std


def _score_capture(model, x: np.memmap, y: np.memmap,
                   span: tuple[int, int], mean: np.ndarray, std: np.ndarray,
                   device: str):
    start, end = span
    target_all = np.asarray(y[start:end], dtype=np.int8)
    mask = target_all >= 0
    local_x = np.asarray(x[start:end], dtype=np.float32)[mask]
    local_y = target_all[mask].astype(np.int64)
    scores: list[float] = []
    with torch.no_grad():
        for offset in range(0, len(local_x), 32768):
            batch = np.asarray(local_x[offset:offset + 32768], dtype=np.float32)
            batch = (batch - mean) / std
            logits = model(torch.from_numpy(batch).to(device))[1]
            scores.extend(torch.softmax(logits, dim=1)[:, 1].cpu().numpy().tolist())
    return local_y, np.asarray(scores, dtype=np.float64)


def main() -> None:
    ctu_ids = [str(number) for number in range(42, 55)]
    fold_ids = [capture for ids in FOLDS.values() for capture in ids]
    if sorted(fold_ids) != sorted(ctu_ids) or len(fold_ids) != len(set(fold_ids)):
        raise RuntimeError("CV groups must cover each CTU-13 scenario exactly once")

    for capture, (path, _, expected, _) in SPECS.items():
        if not path.is_file():
            raise FileNotFoundError(f"Missing capture {capture}: {path}")
        actual = row_count(path)
        if actual != expected:
            raise RuntimeError(f"Capture {capture} row count mismatch: expected {expected}, got {actual}")

    all_ids = ctu_ids + EXTRA_TRAIN
    total_rows = sum(SPECS[capture][2] for capture in all_ids)
    scratch_x = OUT.with_suffix(".features.f32")
    scratch_y = OUT.with_suffix(".labels.i8")
    x = np.memmap(scratch_x, mode="w+", dtype="float32",
                  shape=(total_rows, len(FEATURE_NAMES)))
    y = np.memmap(scratch_y, mode="w+", dtype="int8", shape=(total_rows,))
    slices: dict[str, tuple[int, int]] = {}
    provenance: dict[str, dict] = {}
    label_counts: dict[str, dict] = {}
    offset = 0
    for capture in all_ids:
        path, _, expected, url = SPECS[capture]
        written, counts = read_training_capture(path, x, y, offset, expected)
        slices[capture] = (offset, offset + written)
        split = "grouped_cross_validation" if capture in ctu_ids else "training_extra"
        provenance[capture] = {"source_url": url, "bytes": path.stat().st_size,
                               "sha256": sha256(path), "rows": written, "split": split}
        label_counts[capture] = dict(counts)
        offset += written
        print(f"ingested scenario {capture}: {written:,} rows; labels={dict(counts)}", flush=True)
    if offset != total_rows:
        raise RuntimeError(f"Internal row count mismatch {offset} != {total_rows}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    predictions_by_capture: dict[str, dict] = {}
    all_oof_y: list[np.ndarray] = []
    all_oof_scores: list[np.ndarray] = []
    for fold_number, (fold_name, held_ids) in enumerate(FOLDS.items(), start=1):
        train_ids = [capture for capture in all_ids if capture not in held_ids]
        model, mean, std = _fit(x, y, slices, train_ids, 100 + fold_number, device)
        fold_predictions = {}
        for capture in held_ids:
            target, scores = _score_capture(model, x, y, slices[capture], mean, std, device)
            fold_predictions[capture] = (target, scores)
            all_oof_y.append(target)
            all_oof_scores.append(scores)
            predictions_by_capture[capture] = {
                "fold": fold_name, "train_captures": train_ids,
                "labeled_counts": label_counts[capture],
                "fixed_threshold_0_5": confusion(target, scores, 0.5),
            }
            print(f"OOF scenario {capture}: "
                  f"{confusion(target, scores, 0.5)}", flush=True)

    oof_y = np.concatenate(all_oof_y)
    oof_scores = np.concatenate(all_oof_scores)
    cv_report = {
        "scenario_count": len(ctu_ids), "folds": FOLDS,
        "labeled_rows": int(len(oof_y)),
        "excluded_unknown_rows": int(sum(label_counts[c].get("unknown", 0) for c in ctu_ids)),
        "fixed_threshold_0_5": confusion(oof_y, oof_scores, 0.5),
        "per_scenario": predictions_by_capture,
        "note": "Pooled out-of-fold group evaluation; not an external target-network test.",
    }

    # Final development fit includes every CTU-13 scenario and the previously
    # used Echo training capture. The resulting checkpoint is not release-eligible.
    final_model, mean, std = _fit(x, y, slices, all_ids, 999, device)
    metrics = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_family": "all 13 official CTU-13 scenarios plus CTU-SME-11 Echo",
        "label_provenance": "source-published CTU-13 manual flow labels and CTU-SME-11 expert labels; no dual-review claim",
        "label_mapping": {
            "ctu_attack": "Label starts with flow=From-Botnet-",
            "ctu_benign": "Label starts with flow=From-Normal-",
            "ctu_unknown_excluded_from_supervised_loss": "all remaining labels, including Background and To-*",
            "ctu_sme_attack": "Zeek conn.log.labeled malicious",
            "ctu_sme_benign": "Zeek conn.log.labeled benign",
        },
        "training_rows_all_real_flows": total_rows,
        "training_label_counts_by_capture": label_counts,
        "grouped_cross_validation": cv_report,
        "feature_version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "fixed_operating_threshold": 0.5,
        "device": device,
        "model_role": "research_candidate_after_all_scenario_grouped_cv",
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
        "provenance": provenance,
    }
    manifest = {"created_at_utc": metrics["created_at_utc"],
                "scenario_splits": FOLDS, "training_extra": EXTRA_TRAIN,
                "label_mapping": metrics["label_mapping"], "provenance": provenance}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    torch.save({
        "state_dict": final_model.cpu().state_dict(), "mean": mean.tolist(),
        "std": std.tolist(), "features": list(FEATURE_NAMES),
        "feature_version": FEATURE_VERSION, "classes": ["benign", "attack"],
        "dataset_family": metrics["dataset_family"],
        "train_captures": all_ids, "grouped_cv_folds": FOLDS,
        "threshold": 0.5, "evaluation": cv_report,
        "model_role": metrics["model_role"], "promotion_eligible": False,
        "target_network_evaluation": "not_performed", "enforcement_applied": False,
    }, OUT)
    metrics["checkpoint_sha256"] = sha256(OUT)
    METRICS.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    x._mmap.close(); y._mmap.close()
    scratch_x.unlink(missing_ok=True); scratch_y.unlink(missing_ok=True)
    print(json.dumps({"checkpoint": str(OUT), "checkpoint_sha256": metrics["checkpoint_sha256"],
                      "grouped_cross_validation": cv_report, "device": device,
                      "promotion_eligible": False}, indent=2))


if __name__ == "__main__":
    main()

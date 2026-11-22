"""Train a real-traffic CTU-13 candidate with capture-level holdouts.

The dataset owner's labels are preserved as source-provided labels. This is an
offline research candidate, not a two-reviewer-verified local model and not an
authorization to block traffic.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, from_ctu_row  # noqa: E402

DATA = ROOT / "outputs" / "network-eval"
OUT = DATA / "ctu13-scenarios-flow-v3-candidate-v2.pt"
METRICS = DATA / "ctu13-scenarios-flow-v3-metrics-v2.json"
MANIFEST = DATA / "ctu13-scenarios-flow-v3-manifest-v2.json"

SPECS = {
    "42": (DATA / "ctu-42.binetflow", "train", 2_824_636,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"),
    "43": (DATA / "ctu-43.binetflow", "train", 1_808_122,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/detailed-bidirectional-flow-labels/capture20110810-2.binetflow"),
    "44": (DATA / "official-ctu13" / "capture20110812_ctu44.binetflow", "train", 4_710_638,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/detailed-bidirectional-flow-labels/capture20110812.binetflow"),
    "46": (DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow", "train", 129_832,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow"),
    "47": (DATA / "official-ctu13" / "capture20110816_ctu47.binetflow", "train", 558_919,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/detailed-bidirectional-flow-labels/capture20110816.binetflow"),
    "SME-ECHO": (DATA / "official-ctu-sme11" / "ctu-sme11-echo-derived-features.csv.gz", "train", 53_568,
                 "https://doi.org/10.5281/zenodo.7958259"),
    "45": (DATA / "official-ctu13" / "capture20110815_ctu45.binetflow", "train", 1_121_076,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"),
    "48": (DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow", "train", 114_077,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow"),
    "49": (DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow", "train", 2_954_230,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"),
    "50": (DATA / "official-ctu13" / "capture20110817_ctu50.binetflow", "validation", 2_087_508,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow"),
    "54": (DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow", "test", 1_925_149,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"),
}
MAX_VALIDATION_FPR = 0.001  # fixed before fitting: 0.1% empirical benign FPR ceiling


class AutoencoderClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 32), nn.ReLU(),
                                     nn.Linear(32, 12), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(12, 32), nn.ReLU(),
                                     nn.Linear(32, len(FEATURE_NAMES)))
        self.classifier = nn.Linear(12, 2)

    def forward(self, values):
        latent = self.encoder(values)
        return self.decoder(latent), self.classifier(latent)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def class_for_label(label: str) -> int:
    label = (label or "").strip()
    if label.startswith("flow=From-Botnet-"):
        return 1
    if label.startswith("flow=From-Normal-"):
        return 0
    return -1  # background, disputed/other and unassigned labels are not benign


def row_count(path: Path) -> int:
    source = gzip.open(path, "rt", encoding="utf-8", newline="") if path.name.endswith(".csv.gz") \
        else path.open(encoding="utf-8", newline="")
    with source as stream:
        return sum(1 for _ in csv.DictReader(stream))


def read_training_capture(path: Path, features: np.memmap, labels: np.memmap,
                          offset: int, expected_rows: int) -> tuple[int, Counter]:
    counts: Counter = Counter()
    written = 0
    if path.name.endswith(".csv.gz"):
        source = gzip.open(path, "rt", encoding="utf-8", newline="")
    else:
        source = path.open(encoding="utf-8", newline="")
    with source as stream:
        for row in csv.DictReader(stream):
            try:
                if path.name.endswith(".csv.gz"):
                    features[offset + written] = [float(row[name]) for name in FEATURE_NAMES]
                    target = 1 if row["label"] == "attack" else 0 if row["label"] == "benign" else -1
                else:
                    features[offset + written] = from_ctu_row(row)
                    target = class_for_label(row.get("Label", ""))
            except ValueError as error:
                raise RuntimeError(f"Invalid real flow at {path.name}:{written}: {error}") from error
            labels[offset + written] = target
            counts[{1: "attack", 0: "benign", -1: "unknown"}[target]] += 1
            written += 1
    if written != expected_rows:
        raise RuntimeError(f"Row count changed for {path.name}: expected {expected_rows}, got {written}")
    return written, counts


def read_labeled_capture(path: Path) -> tuple[np.ndarray, np.ndarray, Counter]:
    vectors: list[list[float]] = []
    targets: list[int] = []
    counts: Counter = Counter()
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            target = class_for_label(row.get("Label", ""))
            if target < 0:
                counts["unknown_excluded"] += 1
                continue
            try:
                vectors.append(from_ctu_row(row))
            except ValueError:
                counts["invalid_excluded"] += 1
                continue
            targets.append(target)
            counts["attack" if target else "benign"] += 1
    x = np.asarray(vectors, dtype=np.float32)
    y = np.asarray(targets, dtype=np.int64)
    if len(x) == 0 or len(np.unique(y)) != 2:
        raise RuntimeError(f"{path.name} must contain source-labeled benign and attack flows")
    return x, y, counts


def probs(model, x: np.ndarray, mean: np.ndarray, std: np.ndarray,
          device: str, batch_size: int = 32768) -> np.ndarray:
    normalized = (x - mean) / std
    result = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(normalized), batch_size):
            values = torch.from_numpy(normalized[start:start + batch_size]).to(device)
            result.extend(torch.softmax(model(values)[1], dim=1)[:, 1].cpu().numpy().tolist())
    return np.asarray(result, dtype=np.float64)


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def confusion(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    actual = y == 1
    predicted = p >= threshold
    tp = int(np.count_nonzero(actual & predicted))
    fp = int(np.count_nonzero(~actual & predicted))
    fn = int(np.count_nonzero(actual & ~predicted))
    tn = int(np.count_nonzero(~actual & ~predicted))
    ratio = lambda n, d: (n / d) if d else None
    return {
        "n": int(len(y)), "n_attack": int(actual.sum()), "n_benign": int((~actual).sum()),
        "threshold": float(threshold), "tp_attack": tp, "fp_benign": fp,
        "fn_attack": fn, "tn_benign": tn,
        "accuracy": ratio(tp + tn, len(y)),
        "attack_precision": ratio(tp, tp + fp), "attack_recall": ratio(tp, tp + fn),
        "benign_false_positive_rate": ratio(fp, fp + tn),
        "attack_recall_ci95_wilson": wilson_interval(tp, tp + fn),
        "benign_false_positive_rate_ci95_wilson": wilson_interval(fp, fp + tn),
    }


def select_threshold(y: np.ndarray, p: np.ndarray) -> tuple[float, dict]:
    best = None
    for threshold in np.unique(p):
        metrics = confusion(y, p, float(threshold))
        if metrics["benign_false_positive_rate"] <= MAX_VALIDATION_FPR:
            key = (metrics["attack_recall"], -metrics["benign_false_positive_rate"], float(threshold))
            if best is None or key > best[0]:
                best = (key, float(threshold), metrics)
    if best is None:
        return math.nextafter(1.0, math.inf), confusion(y, p, math.nextafter(1.0, math.inf))
    return best[1], best[2]


def main() -> None:
    for capture, (path, _, expected, _) in SPECS.items():
        if not path.is_file():
            raise FileNotFoundError(f"Missing capture {capture}: {path}")
        actual = row_count(path)
        if actual != expected:
            raise RuntimeError(f"Capture {capture} row count mismatch: expected {expected}, got {actual}")

    train_ids = [key for key, spec in SPECS.items() if spec[1] == "train"]
    validation_ids = [key for key, spec in SPECS.items() if spec[1] == "validation"]
    test_ids = [key for key, spec in SPECS.items() if spec[1] == "test"]
    train_rows = sum(SPECS[key][2] for key in train_ids)
    scratch_x = OUT.with_suffix(".features.f32")
    scratch_y = OUT.with_suffix(".labels.i8")
    x_train = np.memmap(scratch_x, mode="w+", dtype="float32",
                        shape=(train_rows, len(FEATURE_NAMES)))
    y_train = np.memmap(scratch_y, mode="w+", dtype="int8", shape=(train_rows,))
    provenance: dict[str, dict] = {}
    label_counts: dict[str, dict] = {}
    offset = 0
    for capture in train_ids:
        path, split, expected, url = SPECS[capture]
        written, counts = read_training_capture(path, x_train, y_train, offset, expected)
        offset += written
        label_counts[capture] = dict(counts)
        provenance[capture] = {"source_url": url, "bytes": path.stat().st_size,
                               "sha256": sha256(path), "rows": written, "split": split}
        if capture == "SME-ECHO":
            external_metrics = json.loads((DATA / "ctu-sme11-echo-independent-metrics.json").read_text(encoding="utf-8"))
            provenance[capture].update({
                "source_archive_sha256": external_metrics["capture_sha256"],
                "source_archive": "official CTU-SME-11 Amazon Echo archive; CC-BY-4.0",
                "derived_feature_sha256": sha256(path),
                "source_label_mapping": "CTU-SME conn.log.labeled malicious->attack, benign->benign",
            })
        print(f"ingested CTU-{capture}: {written:,} rows; labels={dict(counts)}", flush=True)

    mean = np.asarray(x_train.mean(axis=0), dtype=np.float32)
    std = np.asarray(x_train.std(axis=0), dtype=np.float32)
    std[std < 1e-6] = 1.0
    x_train[:] = (x_train - mean) / std
    x_train.flush()
    y_train.flush()
    labeled = np.flatnonzero(y_train >= 0)
    y_labeled = np.asarray(y_train[labeled], dtype=np.int64)
    if len(np.unique(y_labeled)) != 2:
        raise RuntimeError("Training split must contain both source-labeled classes")

    torch.manual_seed(17)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = AutoencoderClassifier().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    batch_size = 8192
    # Self-supervised reconstruction sees only real training captures.
    for epoch in range(2):
        model.train()
        order = torch.randperm(train_rows)
        total = 0.0
        for indexes in order.split(batch_size):
            batch = torch.from_numpy(np.array(x_train[indexes.numpy()], copy=True)).to(device)
            reconstructed, _ = model(batch)
            loss = nn.functional.mse_loss(reconstructed, batch)
            optimizer.zero_grad(); loss.backward(); optimizer.step()
            total += float(loss.detach()) * len(indexes)
        print(f"reconstruction epoch {epoch + 1}/2: {total / train_rows:.6f}", flush=True)

    targets = torch.from_numpy(y_labeled)
    class_counts = np.bincount(y_labeled, minlength=2)
    weights = torch.tensor([len(y_labeled) / max(int(n), 1) for n in class_counts],
                           dtype=torch.float32, device=device)
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    for epoch in range(20):
        model.train()
        order = torch.randperm(len(labeled))
        total = 0.0
        for ids in order.split(4096):
            rows = labeled[ids.numpy()]
            batch = torch.from_numpy(np.array(x_train[rows], copy=True)).to(device)
            y = targets[ids].to(device)
            _, logits = model(batch)
            loss = loss_fn(logits, y)
            optimizer.zero_grad(); loss.backward(); optimizer.step()
            total += float(loss.detach()) * len(rows)
        print(f"classification epoch {epoch + 1}/20: {total / len(labeled):.6f}", flush=True)

    val_id = validation_ids[0]
    val_path, _, _, val_url = SPECS[val_id]
    x_val, y_val, val_counts = read_labeled_capture(val_path)
    p_val = probs(model, x_val, mean, std, device)
    threshold, val_at_operating_point = select_threshold(y_val, p_val)
    validation = {"capture": val_id, "source_url": val_url, "counts": dict(val_counts),
                  "fixed_threshold_0_5": confusion(y_val, p_val, 0.5),
                  "selected_threshold": threshold,
                  "selected_threshold_metrics": val_at_operating_point,
                  "threshold_selection": "maximize attack recall subject to validation FPR <= 0.1%"}
    provenance[val_id] = {"source_url": val_url, "bytes": val_path.stat().st_size,
                          "sha256": sha256(val_path), "rows": SPECS[val_id][2], "split": "validation"}
    del x_val, y_val, p_val

    test_reports = {}
    all_test_x, all_test_y, all_test_prob = [], [], []
    for capture in test_ids:
        path, _, expected, url = SPECS[capture]
        x, y, counts = read_labeled_capture(path)
        p = probs(model, x, mean, std, device)
        test_reports[capture] = {"source_url": url, "counts": dict(counts),
                                 "fixed_threshold_0_5": confusion(y, p, 0.5),
                                 "validation_selected_threshold": confusion(y, p, threshold)}
        provenance[capture] = {"source_url": url, "bytes": path.stat().st_size,
                               "sha256": sha256(path), "rows": expected, "split": "independent_test"}
        all_test_x.append(x); all_test_y.append(y); all_test_prob.append(p)
        print(f"evaluated untouched test CTU-{capture}: {dict(counts)}", flush=True)
    test = {"captures": test_ids,
            "combined_counts": {"attack": int(sum((y == 1).sum() for y in all_test_y)),
                                "benign": int(sum((y == 0).sum() for y in all_test_y))},
            "fixed_threshold_0_5": confusion(np.concatenate(all_test_y), np.concatenate(all_test_prob), 0.5),
            "validation_selected_threshold": confusion(np.concatenate(all_test_y),
                                                        np.concatenate(all_test_prob), threshold),
            "per_capture": test_reports}

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_family": "official CTU-13 scenarios 42-54 plus official CTU-SME-11",
        "label_provenance": "source-provided CTU-13 labels (manual packet analysis by dataset authors) plus CTU-SME-11 expert labels; dual-review agreement not asserted",
        "label_mapping": {"ctu13_attack": "Label starts with flow=From-Botnet-",
                          "ctu13_benign": "Label starts with flow=From-Normal-",
                          "ctu13_unknown_excluded": "all other labels, including Background and To-Background",
                          "ctu_sme_attack": "Zeek conn.log.labeled label=malicious",
                          "ctu_sme_benign": "Zeek conn.log.labeled label=benign",
                          "ctu_sme_incomplete_excluded": "flows missing required measurements"},
        "capture_split": {"train": train_ids, "validation": validation_ids, "independent_test": test_ids},
        "training_rows_all_real_flows": train_rows,
        "training_label_counts_by_capture": label_counts,
        "label_coverage_by_capture": {
            capture: {"labeled_rows": int(sum(v for k, v in label_counts[capture].items()
                                                  if k in {"attack", "benign"})),
                      "unknown_rows": int(label_counts[capture].get("unknown", 0)),
                      "all_rows": int(SPECS[capture][2])}
            for capture in train_ids
        },
        "threshold_policy": {"validation_fpr_ceiling": MAX_VALIDATION_FPR,
                             "selection": validation["threshold_selection"]},
        "validation": validation,
        "independent_test": test,
        "feature_version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "device": device,
        "model_role": "advisory_research_candidate",
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
        "provenance": provenance,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps({"created_at_utc": report["created_at_utc"],
                                    "dataset_family": report["dataset_family"],
                                    "provenance": provenance,
                                    "capture_split": report["capture_split"],
                                    "label_mapping": report["label_mapping"]}, indent=2) + "\n",
                        encoding="utf-8")
    torch.save({"state_dict": model.cpu().state_dict(), "mean": mean.tolist(),
                "std": std.tolist(), "features": list(FEATURE_NAMES),
                "feature_version": FEATURE_VERSION, "classes": ["benign", "attack"],
                "dataset_family": "official CTU-13 scenarios 42-54", "train_captures": train_ids,
                "validation_capture": val_id, "independent_test_captures": test_ids,
                "dataset_manifest_sha256": sha256(MANIFEST),
                "threshold": threshold, "validation_fpr_ceiling": MAX_VALIDATION_FPR,
                "evaluation": test["validation_selected_threshold"],
                "model_role": "advisory_research_candidate", "promotion_eligible": False,
                "target_network_evaluation": "not_performed", "enforcement_applied": False}, OUT)
    report["checkpoint_sha256"] = sha256(OUT)
    METRICS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    x_train._mmap.close(); y_train._mmap.close()
    scratch_x.unlink(missing_ok=True); scratch_y.unlink(missing_ok=True)
    print(json.dumps({"checkpoint": str(OUT), "checkpoint_sha256": report["checkpoint_sha256"],
                      "validation": validation, "independent_test": test,
                      "promotion_eligible": False, "device": device}, indent=2))


if __name__ == "__main__":
    main()

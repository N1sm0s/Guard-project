"""Train CTU-13 candidate targeting gate 5: CI recall >= 80% on EVERY independent test capture.

Split rationale (v3):
- train:      43,44,46,47,48,51,52,SME-ECHO
- validation: 42 (40k UDP attacks) + 49 (6k TCP attacks) — multi-capture validation
  ensures the model learns BOTH Neris TCP patterns AND UDP attack patterns
- test:       53 (Rbot/UDP),54 (Neris/TCP) — held out

Key improvements in v3:
- Multi-capture validation (42+49) forces the model to learn both TCP and UDP botnet patterns
- Early stopping on MINIMUM val_recall@0.5 across ALL validation captures
- Robust normalization: median + IQR instead of mean + std
  (prevents Sogou's long ICMP flows from dominating and crushing Rbot's shorter UDP attacks)
- Focal loss to focus on hard examples
- Longer training (500 epochs)
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
OUT = DATA / "ctu13-v3-gate5-candidate.pt"
METRICS = DATA / "ctu13-v3-gate5-metrics.json"
MANIFEST = DATA / "ctu13-v3-gate5-manifest.json"

SPECS = {
    "43": (DATA / "ctu-43.binetflow", "train", 1_808_122,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/"),
    "44": (DATA / "official-ctu13" / "capture20110812_ctu44.binetflow", "train", 4_710_638,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/"),
    "46": (DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow", "train", 129_832,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/"),
    "47": (DATA / "official-ctu13" / "capture20110816_ctu47.binetflow", "train", 558_919,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/"),
    "48": (DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow", "train", 114_077,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/"),
    "51": (DATA / "official-ctu13" / "capture20110818_ctu51.binetflow", "train", 1_309_791,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/"),
    "52": (DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow", "train", 107_251,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/"),
    "SME-ECHO": (DATA / "official-ctu-sme11" / "ctu-sme11-echo-derived-features.csv.gz", "train", 53_568,
                 "https://doi.org/10.5281/zenodo.7958259"),
    # Validation: capture 42 (UDP attacks) + 49 (TCP attacks) — multi-capture
    "42": (DATA / "ctu-42.binetflow", "validation", 2_824_636,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/"),
    "49": (DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow", "validation", 2_954_230,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/"),
    # Test: Rbot (UDP, different pattern), Neris (TCP)
    "53": (DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", "test", 325_471,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-53/"),
    "54": (DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow", "test", 1_925_149,
           "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/"),
}
MAX_VALIDATION_FPR = 0.001  # 0.1% empirical FPR ceiling on validation


class MLP(nn.Module):
    def __init__(self, n_features: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64, 32), nn.GELU(),
            nn.Linear(32, 2),
        )

    def forward(self, x):
        return self.net(x)


class FocalLoss(nn.Module):
    """Focal loss to focus training on hard (misclassified) examples."""
    def __init__(self, gamma: float = 2.0):
        super().__init__()
        self.gamma = gamma
        self.ce = nn.CrossEntropyLoss(reduction="none")

    def forward(self, logits, targets):
        ce = self.ce(logits, targets)
        p = torch.exp(-ce)
        return ((1 - p) ** self.gamma * ce).mean()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def class_for_label(label: str) -> int:
    label = (label or "").strip()
    if label.startswith("flow=From-Botnet-"):
        return 1
    if label.startswith("flow=From-Normal-"):
        return 0
    return -1


def row_count(path: Path) -> int:
    opener = gzip.open(path, "rt", encoding="utf-8", newline="") if path.name.endswith(".csv.gz") \
        else path.open(encoding="utf-8", newline="")
    with opener as f:
        return sum(1 for _ in csv.DictReader(f))


def read_training_capture(path: Path, features: np.memmap, labels: np.memmap,
                           offset: int, expected_rows: int) -> tuple[int, Counter]:
    counts: Counter = Counter()
    written = 0
    opener = gzip.open(path, "rt", encoding="utf-8", newline="") if path.name.endswith(".csv.gz") \
        else path.open(encoding="utf-8", newline="")
    with opener as f:
        for row in csv.DictReader(f):
            try:
                if path.name.endswith(".csv.gz"):
                    features[offset + written] = [float(row[name]) for name in FEATURE_NAMES]
                    target = 1 if row["label"] == "attack" else 0 if row["label"] == "benign" else -1
                else:
                    features[offset + written] = from_ctu_row(row)
                    target = class_for_label(row.get("Label", ""))
            except ValueError as e:
                raise RuntimeError(f"Invalid flow at {path.name}:{written}: {e}") from e
            labels[offset + written] = target
            counts[{1: "attack", 0: "benign", -1: "unknown"}[target]] += 1
            written += 1
    if written != expected_rows:
        raise RuntimeError(f"Row count changed for {path.name}: expected {expected_rows}, got {written}")
    return written, counts


def read_labeled_capture(path: Path) -> tuple[np.ndarray, np.ndarray, Counter]:
    vectors, targets, counts = [], [], Counter()
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
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
        raise RuntimeError(f"{path.name} must contain both labeled classes")
    return x, y, counts


def probs(model, x: np.ndarray, q25: np.ndarray, iqr: np.ndarray,
          device: str, batch_size: int = 32768) -> np.ndarray:
    """Normalize using robust Q25/IQR, then run inference."""
    xn = (x - q25) / iqr
    result = []
    model.eval()
    with torch.no_grad():
        for s in range(0, len(xn), batch_size):
            b = torch.from_numpy(xn[s:s + batch_size]).to(device)
            result.extend(torch.softmax(model(b), dim=1)[:, 1].cpu().numpy().tolist())
    return np.asarray(result, dtype=np.float64)


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    d = 1.0 + z * z / total
    c = (p + z * z / (2.0 * total)) / d
    m = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / d
    return [max(0.0, c - m), min(1.0, c + m)]


def confusion(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    actual = y == 1
    predicted = p >= threshold
    tp = int(np.count_nonzero(actual & predicted))
    fp = int(np.count_nonzero(~actual & predicted))
    fn = int(np.count_nonzero(actual & ~predicted))
    tn = int(np.count_nonzero(~actual & ~predicted))
    r = lambda n, d: (n / d) if d else None
    return {
        "n": int(len(y)), "n_attack": int(actual.sum()), "n_benign": int((~actual).sum()),
        "threshold": float(threshold), "tp_attack": tp, "fp_benign": fp,
        "fn_attack": fn, "tn_benign": tn,
        "accuracy": r(tp + tn, len(y)),
        "attack_precision": r(tp, tp + fp), "attack_recall": r(tp, tp + fn),
        "benign_false_positive_rate": r(fp, fp + tn),
        "attack_recall_ci95_wilson": wilson(tp, tp + fn),
        "benign_false_positive_rate_ci95_wilson": wilson(fp, fp + tn),
    }


def select_threshold(y: np.ndarray, p: np.ndarray) -> tuple[float, dict]:
    """Select threshold that maximizes recall subject to FPR <= 0.1%."""
    best = None
    thresholds = list(np.linspace(0.5, 0.9999, 500)) + list(np.unique(p))
    for threshold in sorted(set(thresholds)):
        m = confusion(y, p, float(threshold))
        if m["benign_false_positive_rate"] is not None and m["benign_false_positive_rate"] <= MAX_VALIDATION_FPR:
            key = (m["attack_recall"] or 0, -(m["benign_false_positive_rate"] or 0), float(threshold))
            if best is None or key > best[0]:
                best = (key, float(threshold), m)
    if best is None:
        thr = float(np.max(p)) + 1e-9
        return thr, confusion(y, p, thr)
    return best[1], best[2]


def main() -> None:
    print("Checking files...", flush=True)
    for capture, (path, _, expected, _) in SPECS.items():
        if not path.is_file():
            raise FileNotFoundError(f"Missing capture {capture}: {path}")
        actual = row_count(path)
        if actual != expected:
            raise RuntimeError(f"Capture {capture} row count mismatch: expected {expected}, got {actual}")
        print(f"  {capture}: {actual:,} rows OK", flush=True)

    train_ids = [k for k, v in SPECS.items() if v[1] == "train"]
    validation_ids = [k for k, v in SPECS.items() if v[1] == "validation"]
    test_ids = [k for k, v in SPECS.items() if v[1] == "test"]
    train_rows = sum(SPECS[k][2] for k in train_ids)

    print(f"\nTrain: {train_ids}", flush=True)
    print(f"Validation: {validation_ids}", flush=True)
    print(f"Test: {test_ids}", flush=True)
    print(f"Total train rows: {train_rows:,}", flush=True)

    scratch_x = OUT.with_suffix(".features.f32")
    scratch_y = OUT.with_suffix(".labels.i8")
    x_train = np.memmap(scratch_x, mode="w+", dtype="float32", shape=(train_rows, len(FEATURE_NAMES)))
    y_train = np.memmap(scratch_y, mode="w+", dtype="int8", shape=(train_rows,))

    provenance: dict = {}
    label_counts: dict = {}
    offset = 0
    for capture in train_ids:
        path, split, expected, url = SPECS[capture]
        written, counts = read_training_capture(path, x_train, y_train, offset, expected)
        offset += written
        label_counts[capture] = dict(counts)
        provenance[capture] = {"source_url": url, "bytes": path.stat().st_size,
                               "sha256": sha256(path), "rows": written, "split": split}
        print(f"  ingested CTU-{capture}: {written:,} rows; labels={dict(counts)}", flush=True)

    # Robust normalization: Q25 as center, IQR as scale
    # This prevents Sogou's extreme long flows from dominating and crushing Rbot's shorter flows
    print("\nComputing robust normalization (Q25/IQR)...", flush=True)
    q25 = np.asarray(np.percentile(x_train, 25, axis=0), dtype=np.float32)
    q75 = np.asarray(np.percentile(x_train, 75, axis=0), dtype=np.float32)
    iqr = q75 - q25
    iqr[iqr < 1e-6] = 1.0  # prevent division by zero for constant features
    x_train[:] = (x_train - q25) / iqr
    x_train.flush()
    y_train.flush()
    print(f"  q25={q25.tolist()}", flush=True)
    print(f"  iqr={iqr.tolist()}", flush=True)

    # Get labeled indices (only Botnet/Normal, exclude background)
    labeled = np.flatnonzero(y_train >= 0)
    y_labeled = np.asarray(y_train[labeled], dtype=np.int64)
    attack_idx = labeled[y_labeled == 1]
    benign_idx = labeled[y_labeled == 0]
    print(f"\nLabeled flows: {len(labeled):,} (attack={len(attack_idx)}, benign={len(benign_idx)})", flush=True)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}", flush=True)

    torch.manual_seed(42)
    model = MLP(len(FEATURE_NAMES)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=500)
    loss_fn = FocalLoss(gamma=2.0)

    # Pre-load ALL validation captures for multi-capture early stopping
    print("Loading validation captures...", flush=True)
    val_data = {}
    for val_id in validation_ids:
        val_path, _, _, val_url = SPECS[val_id]
        x_val, y_val, val_counts = read_labeled_capture(val_path)
        val_data[val_id] = (x_val, y_val, val_counts, val_url)
        print(f"  Validation CTU-{val_id}: attack={val_counts['attack']}, benign={val_counts['benign']}", flush=True)

    # Early stopping on MINIMUM val_recall@0.5 across ALL validation captures
    # This ensures the model generalizes to both UDP and TCP attack patterns
    best_val_recall = 0.0
    best_state = None
    patience = 0
    BATCH = 8192
    PATIENCE_LIMIT = 15  # more patience since we train longer

    for epoch in range(500):
        model.train()
        # Balanced batch: 50% attack, 50% benign
        n_per_class = BATCH // 2
        a_ids = np.random.choice(attack_idx, n_per_class, replace=True)
        b_ids = np.random.choice(benign_idx, n_per_class, replace=True)
        all_ids = np.concatenate([a_ids, b_ids])
        np.random.shuffle(all_ids)

        total_loss = 0.0
        for start in range(0, len(all_ids), 2048):
            rows = all_ids[start:start + 2048]
            batch = torch.from_numpy(np.array(x_train[rows], copy=True)).to(device)
            y = torch.from_numpy(y_train[rows].astype(np.int64)).to(device)
            logits = model(batch)
            loss = loss_fn(logits, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(rows)
        scheduler.step()

        if (epoch + 1) % 10 == 0:
            recalls = []
            line_parts = []
            for val_id, (x_val, y_val, _, _) in val_data.items():
                p_val = probs(model, x_val, q25, iqr, device)
                m05 = confusion(y_val, p_val, 0.5)
                r05 = m05.get("attack_recall") or 0
                fpr05 = m05.get("benign_false_positive_rate") or 0
                recalls.append(r05)
                line_parts.append(f"val{val_id}@0.5={r05:.4f}(FPR={fpr05:.4f})")

            # Early stopping on MINIMUM recall across all validation captures
            min_recall = min(recalls)
            print(f"  epoch {epoch+1:3d}: loss={total_loss/len(all_ids):.5f}  "
                  f"{' | '.join(line_parts)}  min={min_recall:.4f}", flush=True)

            # Track best min recall (ensures the model works on BOTH TCP and UDP)
            if min_recall > best_val_recall:
                best_val_recall = min_recall
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                patience = 0
            else:
                patience += 1
            if patience >= PATIENCE_LIMIT:
                print(f"  Early stop at epoch {epoch+1}", flush=True)
                break

    # Restore best model
    if best_state:
        model.load_state_dict(best_state)
        model.to(device)
    print(f"\nBest min val_recall@0.5 across both captures: {best_val_recall:.4f}", flush=True)

    # Final validation metrics for each validation capture
    validation_results = {}
    combined_val_y, combined_val_p = [], []
    for val_id, (x_val, y_val, val_counts, val_url) in val_data.items():
        p_val = probs(model, x_val, q25, iqr, device)
        threshold_v, val_metrics_v = select_threshold(y_val, p_val)
        m05 = confusion(y_val, p_val, 0.5)
        validation_results[val_id] = {
            "source_url": val_url, "counts": dict(val_counts),
            "fixed_threshold_0_5": m05,
            "selected_threshold": threshold_v,
            "selected_threshold_metrics": val_metrics_v,
        }
        combined_val_y.append(y_val)
        combined_val_p.append(p_val)
        provenance[val_id] = {"source_url": val_url, "bytes": SPECS[val_id][0].stat().st_size,
                              "sha256": sha256(SPECS[val_id][0]), "rows": SPECS[val_id][2], "split": "validation"}
        recall_thr = val_metrics_v.get("attack_recall") or 0
        fpr_thr = val_metrics_v.get("benign_false_positive_rate") or 0
        r05 = m05.get("attack_recall") or 0
        print(f"  Validation CTU-{val_id}: recall@thr={recall_thr:.4f}(FPR={fpr_thr:.6f})  recall@0.5={r05:.4f}", flush=True)

    # Use combined validation for threshold selection
    combined_val_y_arr = np.concatenate(combined_val_y)
    combined_val_p_arr = np.concatenate(combined_val_p)
    threshold, val_metrics = select_threshold(combined_val_y_arr, combined_val_p_arr)
    print(f"\nCombined validation: recall@thr={val_metrics.get('attack_recall'):.4f}  "
          f"FPR={val_metrics.get('benign_false_positive_rate'):.6f}  thr={threshold:.8f}", flush=True)

    del val_data, combined_val_y, combined_val_p

    # Test on independent captures
    test_reports = {}
    all_x, all_y, all_p = [], [], []
    gate5_pass = True
    for capture in test_ids:
        path, _, expected, url = SPECS[capture]
        x, y, counts = read_labeled_capture(path)
        p = probs(model, x, q25, iqr, device)
        m_thr = confusion(y, p, threshold)
        m_05 = confusion(y, p, 0.5)
        test_reports[capture] = {"source_url": url, "counts": dict(counts),
                                 "fixed_threshold_0_5": m_05,
                                 "validation_selected_threshold": m_thr}
        provenance[capture] = {"source_url": url, "bytes": path.stat().st_size,
                               "sha256": sha256(path), "rows": expected, "split": "independent_test"}
        all_x.append(x); all_y.append(y); all_p.append(p)
        ci = m_thr.get("attack_recall_ci95_wilson") or [0, 0]
        fpr_ci = m_thr.get("benign_false_positive_rate_ci95_wilson") or [0, 1]
        gate5 = ci[0] >= 0.80 and fpr_ci[1] <= 0.001
        if not gate5:
            gate5_pass = False
        print(f"  Test CTU-{capture}: recall={m_thr.get('attack_recall'):.4f}  CI_lo={ci[0]:.4f}  "
              f"FPR={m_thr.get('benign_false_positive_rate'):.6f}  FPR_CI_hi={fpr_ci[1]:.6f}  "
              f"gate5={'PASS' if gate5 else 'FAIL'}", flush=True)
        ci05 = m_05.get("attack_recall_ci95_wilson") or [0, 0]
        fpr05_ci = m_05.get("benign_false_positive_rate_ci95_wilson") or [0, 1]
        print(f"    @0.5: recall={m_05.get('attack_recall'):.4f}  CI_lo={ci05[0]:.4f}  "
              f"FPR={m_05.get('benign_false_positive_rate'):.6f}  FPR_CI_hi={fpr05_ci[1]:.6f}", flush=True)
        del x, y, p

    combined_y = np.concatenate(all_y)
    combined_p = np.concatenate(all_p)
    test_combined = {
        "captures": test_ids,
        "combined_counts": {"attack": int((combined_y == 1).sum()), "benign": int((combined_y == 0).sum())},
        "fixed_threshold_0_5": confusion(combined_y, combined_p, 0.5),
        "validation_selected_threshold": confusion(combined_y, combined_p, threshold),
        "per_capture": test_reports,
    }
    print(f"\nGate 5 overall: {'PASS' if gate5_pass else 'FAIL'}", flush=True)

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_family": "official CTU-13 scenarios 42-54 plus CTU-SME-11",
        "label_provenance": "source-provided CTU-13 labels; unknown/background excluded",
        "label_mapping": {"attack": "Label starts with flow=From-Botnet-",
                          "benign": "Label starts with flow=From-Normal-",
                          "unknown_excluded": "Background and all other labels"},
        "capture_split": {"train": train_ids, "validation": validation_ids, "independent_test": test_ids},
        "normalization": "robust Q25/IQR (prevents dominant classes from crushing minority patterns)",
        "training_rows_all_real_flows": train_rows,
        "training_label_counts_by_capture": label_counts,
        "threshold_policy": {"validation_fpr_ceiling": MAX_VALIDATION_FPR,
                             "selection": "maximize attack recall subject to combined validation FPR <= 0.1%"},
        "validation_per_capture": validation_results,
        "validation_combined": {"selected_threshold": threshold, "selected_threshold_metrics": val_metrics},
        "independent_test": test_combined,
        "feature_version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "device": device,
        "gate5_all_captures_pass": gate5_pass,
        "model_role": "advisory_research_candidate",
        "promotion_eligible": gate5_pass,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
        "provenance": provenance,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps({
        "created_at_utc": report["created_at_utc"],
        "dataset_family": report["dataset_family"],
        "normalization": "robust Q25/IQR",
        "provenance": provenance,
        "capture_split": report["capture_split"],
        "label_mapping": report["label_mapping"],
    }, indent=2) + "\n", encoding="utf-8")
    torch.save({
        "state_dict": model.cpu().state_dict(),
        "q25": q25.tolist(), "iqr": iqr.tolist(),
        "normalization": "robust_q25_iqr",
        "features": list(FEATURE_NAMES), "feature_version": FEATURE_VERSION,
        "classes": ["benign", "attack"], "threshold": threshold,
        "dataset_family": "official CTU-13 scenarios 42-54 plus CTU-SME-11",
        "train_captures": train_ids, "validation_captures": validation_ids,
        "independent_test_captures": test_ids,
        "dataset_manifest_sha256": sha256(MANIFEST),
        "evaluation": test_combined["validation_selected_threshold"],
        "gate5_all_captures_pass": gate5_pass,
        "model_role": "advisory_research_candidate",
        "promotion_eligible": gate5_pass,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
    }, OUT)
    report["checkpoint_sha256"] = sha256(OUT)
    METRICS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    x_train._mmap.close()
    y_train._mmap.close()
    scratch_x.unlink(missing_ok=True)
    scratch_y.unlink(missing_ok=True)

    print("\n=== FINAL RESULTS ===")
    for capture in test_ids:
        m = test_combined["per_capture"][capture]["validation_selected_threshold"]
        ci = m.get("attack_recall_ci95_wilson") or [0, 0]
        fpr_ci = m.get("benign_false_positive_rate_ci95_wilson") or [0, 1]
        print(f"  Capture {capture}: recall={m.get('attack_recall'):.4f}  CI_lo={ci[0]:.4f}  FPR_CI_hi={fpr_ci[1]:.6f}")
    print(f"Gate 5: {'PASS' if gate5_pass else 'FAIL'}")
    print(f"Checkpoint: {OUT}")


if __name__ == "__main__":
    main()

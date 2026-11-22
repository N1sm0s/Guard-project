"""Train the live-socket classifier and evaluate it on the held-out CTU-43 capture."""
import argparse
import csv
import gzip
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
from torch import nn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrityguard.network_flow_model import FEATURE_NAMES, FEATURE_VERSION, feature_vector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("outputs/network-eval/ctu-all-captures-labeled.csv.gz"))
    parser.add_argument("--manifest", type=Path, default=Path("outputs/network-eval/ctu-all-captures-labeled-manifest.json"))
    parser.add_argument("--checkpoint", type=Path,
                        default=Path("outputs/network-eval/network-flow-v2-candidate.pt"))
    parser.add_argument("--metrics", type=Path,
                        default=Path("outputs/network-eval/ctu-flow-v2-candidate-metrics.json"))
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    dataset_sha256 = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    if dataset_sha256 != manifest["dataset_sha256"]:
        parser.error("Dataset hash does not match its manifest")

    rows = {"ctu-42.binetflow": [], "ctu-43.binetflow": []}
    labels = {"ctu-42.binetflow": [], "ctu-43.binetflow": []}
    source_ports = {"ctu-42.binetflow": [], "ctu-43.binetflow": []}
    unknown_by_capture = Counter()
    with gzip.open(args.dataset, "rt", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            capture, target = row["capture"], row["target"]
            if capture not in rows:
                continue
            if target not in {"attack", "benign"}:
                unknown_by_capture[capture] += 1
                continue
            try:
                features = feature_vector(row["Dport"], row["Proto"], row["Sport"])
            except (TypeError, ValueError):
                unknown_by_capture[capture] += 1
                continue
            rows[capture].append(features)
            labels[capture].append(1 if target == "attack" else 0)
            source_port_text = str(row["Sport"]).strip()
            source_ports[capture].append(
                int(source_port_text, 16) if source_port_text.lower().startswith("0x")
                else int(source_port_text))

    train_x = np.asarray(rows["ctu-42.binetflow"], dtype=np.float32)
    train_y = np.asarray(labels["ctu-42.binetflow"], dtype=np.int64)
    test_x = np.asarray(rows["ctu-43.binetflow"], dtype=np.float32)
    test_y = np.asarray(labels["ctu-43.binetflow"], dtype=np.int64)
    if len(train_x) == 0 or len(test_x) == 0 or len(set(train_y.tolist())) != 2:
        parser.error("Both captures need explicitly labeled attack and benign flows")
    mean, std = train_x.mean(0), train_x.std(0)
    std[std < 1e-6] = 1
    train_x = (train_x - mean) / std
    test_x = (test_x - mean) / std

    torch.manual_seed(17)
    model = nn.Sequential(nn.Linear(len(FEATURE_NAMES), 16), nn.ReLU(), nn.Linear(16, 8),
                          nn.ReLU(), nn.Linear(8, 2))
    x, y = torch.from_numpy(train_x), torch.from_numpy(train_y)
    counts = np.bincount(train_y, minlength=2)
    weights = torch.tensor([len(y) / max(int(value), 1) for value in counts], dtype=torch.float32)
    loss_function = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003)
    model.train()
    for epoch in range(20):
        order = torch.randperm(len(y))
        total_loss = 0.0
        for indices in order.split(8192):
            batch_x, batch_y = x[indices], y[indices]
            optimizer.zero_grad()
            loss = loss_function(model(batch_x), batch_y)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(indices)
        print(f"epoch {epoch + 1}/20 loss={total_loss / len(y):.5f}", flush=True)

    model.eval()
    with torch.no_grad():
        probabilities = torch.softmax(model(torch.from_numpy(test_x)), dim=1)[:, 1].numpy()
    predicted = probabilities >= 0.5
    actual = test_y == 1
    tp = int((predicted & actual).sum())
    fp = int((predicted & ~actual).sum())
    fn = int((~predicted & actual).sum())
    tn = int((~predicted & ~actual).sum())

    # Audit whether the newly added local/source port alone behaves like a label
    # shortcut. It is a diagnostic, never a training feature or ground truth.
    port_labels = defaultdict(Counter)
    for port, label in zip(source_ports["ctu-42.binetflow"], train_y):
        port_labels[port][int(label)] += 1
    port_tp = port_fp = port_fn = port_tn = port_unseen = 0
    for port, label in zip(source_ports["ctu-43.binetflow"], test_y):
        majority = port_labels.get(port)
        if not majority:
            port_unseen += 1
            continue
        port_prediction = int(majority[1] > majority[0])
        if port_prediction and label:
            port_tp += 1
        elif port_prediction:
            port_fp += 1
        elif label:
            port_fn += 1
        else:
            port_tn += 1
    port_covered = port_tp + port_fp + port_fn + port_tn
    port_coverage = port_covered / len(test_y)
    port_recall = port_tp / max(port_tp + port_fn, 1)
    port_fpr = port_fp / max(port_fp + port_tn, 1)
    shortcut_suspected = port_coverage >= 0.80 and port_recall >= 0.95 and port_fpr <= 0.01

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    metrics = {
        "dataset_sha256": dataset_sha256,
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "training_capture": "ctu-42.binetflow",
        "independent_test_capture": "ctu-43.binetflow",
        "training_labeled_counts": dict(Counter("attack" if value else "benign" for value in train_y)),
        "test_labeled_counts": dict(Counter("attack" if value else "benign" for value in test_y)),
        "unlabeled_rows_excluded_from_supervised_fit": dict(unknown_by_capture),
        "threshold": 0.5,
        "confusion": {"tp_attack": tp, "fp_benign": fp, "fn_attack": fn, "tn_benign": tn},
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "attack_precision": ratio(tp, tp + fp),
        "attack_recall": ratio(tp, tp + fn),
        "benign_false_positive_rate": ratio(fp, fp + tn),
        "source_port_only_shortcut_audit": {
            "coverage": port_coverage,
            "attack_recall_on_covered_rows": port_recall,
            "benign_false_positive_rate_on_covered_rows": port_fpr,
            "covered_rows": port_covered,
            "unseen_source_port_rows": port_unseen,
            "confusion": {"tp_attack": port_tp, "fp_benign": port_fp,
                          "fn_attack": port_fn, "tn_benign": port_tn},
            "shortcut_suspected": shortcut_suspected,
        },
        "promotion_eligible": not shortcut_suspected,
        "scope": "Per-socket local/remote ports and transport protocol only. Advisory candidate. CTU-13 capture evaluation is not live-network validation.",
    }
    args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "mean": mean.tolist(), "std": std.tolist(),
                "feature_version": FEATURE_VERSION,
                "features": list(FEATURE_NAMES), "classes": ["benign", "attack"],
                "dataset_sha256": dataset_sha256, "model_name": "IntegrityGuard CTU flow classifier",
                "promotion_eligible": not shortcut_suspected,
                "training_capture": "ctu-42.binetflow", "held_out_capture": "ctu-43.binetflow",
                "evaluation": {key: metrics[key] for key in (
                    "accuracy", "attack_precision", "attack_recall", "benign_false_positive_rate",
                    "threshold", "independent_test_capture")}}, args.checkpoint)
    args.metrics.parent.mkdir(parents=True, exist_ok=True)
    args.metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()

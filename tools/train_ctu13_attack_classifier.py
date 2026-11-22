"""Train a CTU-13 binary network model with unlabeled-flow representation pretraining.

All flows from CTU-42 participate in self-supervised reconstruction. Only explicit
From-Botnet/From-Normal CTU labels participate in supervised fitting. CTU-43 is
held out completely and is used only for final metrics.
"""
import argparse
import csv
import gzip
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from torch import nn
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrityguard.network_flow_schema import (FEATURE_NAMES, FEATURE_VERSION,
                                                from_ctu_row)


class AutoencoderClassifier(nn.Module):
    def __init__(self, feature_count):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(feature_count, 32), nn.ReLU(),
                                     nn.Linear(32, 12), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(12, 32), nn.ReLU(),
                                     nn.Linear(32, feature_count))
        self.classifier = nn.Linear(12, 2)

    def forward(self, values):
        latent = self.encoder(values)
        return self.decoder(latent), self.classifier(latent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("outputs/network-eval/ctu-all-captures-labeled.csv.gz"))
    parser.add_argument("--manifest", type=Path, default=Path("outputs/network-eval/ctu-all-captures-labeled-manifest.json"))
    parser.add_argument("--output", type=Path,
                        default=Path("outputs/network-eval/ctu13-flow-v3-candidate.pt"))
    parser.add_argument("--pretrain-epochs", type=int, default=2)
    parser.add_argument("--supervised-epochs", type=int, default=20)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    digest = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    if digest != manifest["dataset_sha256"]:
        parser.error("Dataset SHA-256 does not match its manifest")
    train_capture, test_capture = "ctu-42.binetflow", "ctu-43.binetflow"
    train_rows = 2_824_636
    test_rows = 1_808_122
    feature_count = len(FEATURE_NAMES)
    scratch = args.output.with_suffix(".features.dat")
    train_x = np.memmap(scratch, mode="w+", dtype="float32",
                        shape=(train_rows + test_rows, feature_count))
    train_y = np.memmap(args.output.with_suffix(".labels.dat"), mode="w+",
                        dtype="int8", shape=(train_rows + test_rows,))
    offsets = {train_capture: 0, test_capture: train_rows}
    written = Counter()
    label_counts = Counter()
    with gzip.open(args.dataset, "rt", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            capture = row["capture"]
            if capture not in offsets:
                continue
            offset = offsets[capture] + written[capture]
            if written[capture] >= (train_rows if capture == train_capture else test_rows):
                parser.error(f"Unexpected extra rows for {capture}")
            try:
                train_x[offset] = from_ctu_row(row)
            except ValueError as error:
                parser.error(f"Invalid flow feature at {capture} row {written[capture]}: {error}")
            target = row["target"]
            train_y[offset] = 1 if target == "attack" else 0 if target == "benign" else -1
            if train_y[offset] >= 0:
                label_counts[(capture, target)] += 1
            written[capture] += 1
    if written[train_capture] != train_rows or written[test_capture] != test_rows:
        parser.error("Capture row counts differ from expected dataset totals")

    x_train = train_x[:train_rows]
    y_train = train_y[:train_rows]
    x_test = train_x[train_rows:]
    y_test = train_y[train_rows:]
    mean = np.asarray(x_train.mean(axis=0), dtype="float32")
    std = np.asarray(x_train.std(axis=0), dtype="float32")
    std[std < 1e-6] = 1.0
    x_train[:] = (x_train - mean) / std
    x_test[:] = (x_test - mean) / std
    train_x.flush()
    train_y.flush()

    torch.manual_seed(17)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = AutoencoderClassifier(feature_count).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    batch_size = 8192

    # Self-supervised training sees every CTU-42 flow, including unresolved labels.
    for epoch in range(args.pretrain_epochs):
        model.train()
        order = torch.randperm(train_rows)
        total_loss = 0.0
        for indices in order.split(batch_size):
            batch = torch.from_numpy(np.array(x_train[indices.numpy()], copy=True)).to(device)
            reconstructed, _ = model(batch)
            loss = nn.functional.mse_loss(reconstructed, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(indices)
        print(f"reconstruction epoch {epoch + 1}/{args.pretrain_epochs}: "
              f"{total_loss / train_rows:.6f}", flush=True)

    labeled_indices = np.flatnonzero(y_train >= 0)
    targets = torch.from_numpy(np.asarray(y_train[labeled_indices], dtype="int64"))
    class_counts = np.bincount(targets.numpy(), minlength=2)
    class_weights = torch.tensor(
        [len(targets) / max(int(count), 1) for count in class_counts],
        dtype=torch.float32, device=device)
    loss_function = nn.CrossEntropyLoss(weight=class_weights)
    for epoch in range(args.supervised_epochs):
        model.train()
        order = torch.randperm(len(labeled_indices))
        total_loss = 0.0
        for batch_ids in order.split(4096):
            rows = labeled_indices[batch_ids.numpy()]
            batch = torch.from_numpy(np.array(x_train[rows], copy=True)).to(device)
            labels = targets[batch_ids].to(device)
            _, logits = model(batch)
            loss = loss_function(logits, labels)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(rows)
        print(f"classification epoch {epoch + 1}/{args.supervised_epochs}: "
              f"{total_loss / len(labeled_indices):.6f}", flush=True)

    test_indices = np.flatnonzero(y_test >= 0)
    truth = np.asarray(y_test[test_indices], dtype=bool)
    predictions = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(test_indices), batch_size):
            rows = test_indices[start:start + batch_size]
            batch = torch.from_numpy(np.array(x_test[rows], copy=True)).to(device)
            _, logits = model(batch)
            predictions.extend((logits.softmax(dim=1)[:, 1] >= 0.5).cpu().numpy())
    predicted = np.asarray(predictions, dtype=bool)
    tp = int((predicted & truth).sum())
    fp = int((predicted & ~truth).sum())
    fn = int((~predicted & truth).sum())
    tn = int((~predicted & ~truth).sum())

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    metrics = {
        "dataset_sha256": digest,
        "train_capture": train_capture,
        "independent_test_capture": test_capture,
        "all_train_capture_flows_used_for_self_supervised_pretraining": train_rows,
        "labeled_train_counts": {key[1]: count for key, count in label_counts.items() if key[0] == train_capture},
        "labeled_test_counts": {key[1]: count for key, count in label_counts.items() if key[0] == test_capture},
        "unlabeled_train_flows_used_for_supervised_loss": 0,
        "threshold": 0.5,
        "confusion": {"tp_attack": tp, "fp_benign": fp, "fn_attack": fn, "tn_benign": tn},
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "attack_precision": ratio(tp, tp + fp),
        "attack_recall": ratio(tp, tp + fn),
        "benign_false_positive_rate": ratio(fp, fp + tn),
        "feature_version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "device": device,
        "pretrain_epochs": args.pretrain_epochs,
        "supervised_epochs": args.supervised_epochs,
        "model_role": "advisory_research_candidate",
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.cpu().state_dict(), "mean": mean.tolist(),
                "std": std.tolist(), "features": list(FEATURE_NAMES),
                "feature_version": FEATURE_VERSION,
                "classes": ["benign", "attack"], "dataset_sha256": digest,
                "train_capture": train_capture, "held_out_capture": test_capture,
                "evaluation": {key: metrics[key] for key in (
                    "threshold", "confusion", "accuracy", "attack_precision",
                    "attack_recall", "benign_false_positive_rate")},
                "model_role": "advisory_research_candidate",
                "promotion_eligible": False,
                "target_network_evaluation": "not_performed",
                "enforcement_applied": False}, args.output)
    args.output.with_name("ctu13-flow-v3-candidate-metrics.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    train_x._mmap.close()
    train_y._mmap.close()
    scratch.unlink(missing_ok=True)
    args.output.with_suffix(".labels.dat").unlink(missing_ok=True)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()

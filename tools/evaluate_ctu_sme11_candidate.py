"""Evaluate a frozen CTU-13 model on untouched, real CTU-SME-11 Zeek flows.

This script never fits or tunes the model. It uses the threshold selected on
CTU-45 and treats CTU-SME labels as source-provided expert labels.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import math
import sys
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, feature_vector  # noqa: E402

DATA = ROOT / "outputs" / "network-eval"
ARCHIVE = DATA / "official-ctu-sme11" / "ctu-sme11-echo.tar.bz2"
CHECKPOINT = DATA / "ctu13-flow-v3-multicapture-candidate.pt"
CTU_METRICS = DATA / "ctu13-flow-v3-multicapture-metrics.json"
OUTPUT = DATA / "ctu-sme11-echo-independent-metrics.json"
FEATURE_EXPORT = DATA / "official-ctu-sme11" / "ctu-sme11-echo-derived-features.csv.gz"


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
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wilson(k: int, n: int, z: float = 1.959963984540054):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / d
    return [max(0, c - m), min(1, c + m)]


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    truth = y == 1
    pred = p >= threshold
    tp = int(np.count_nonzero(truth & pred))
    fp = int(np.count_nonzero(~truth & pred))
    fn = int(np.count_nonzero(truth & ~pred))
    tn = int(np.count_nonzero(~truth & ~pred))
    return {
        "n": int(len(y)), "n_attack": int(truth.sum()), "n_benign": int((~truth).sum()),
        "threshold_from_ctu45": threshold,
        "tp_attack": tp, "fp_benign": fp, "fn_attack": fn, "tn_benign": tn,
        "attack_precision": tp / (tp + fp) if tp + fp else None,
        "attack_recall": tp / (tp + fn) if tp + fn else None,
        "attack_recall_ci95_wilson": wilson(tp, tp + fn),
        "benign_false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "benign_false_positive_rate_ci95_wilson": wilson(fp, fp + tn),
    }


def main():
    if not ARCHIVE.is_file() or not CHECKPOINT.is_file():
        raise FileNotFoundError("CTU-SME archive or frozen candidate checkpoint is missing")
    ctu_metrics = json.loads(CTU_METRICS.read_text(encoding="utf-8"))
    threshold = float(ctu_metrics["validation"]["selected_threshold"])
    checkpoint = torch.load(CHECKPOINT, map_location="cpu", weights_only=True)
    if checkpoint.get("feature_version") != FEATURE_VERSION \
            or checkpoint.get("features") != list(FEATURE_NAMES) \
            or checkpoint.get("classes") != ["benign", "attack"]:
        raise RuntimeError("candidate checkpoint feature schema mismatch")
    model = AutoencoderClassifier()
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    mean = np.asarray(checkpoint["mean"], dtype=np.float32)
    std = np.asarray(checkpoint["std"], dtype=np.float32)
    std[std < 1e-6] = 1.0

    per_day: dict[str, dict] = defaultdict(lambda: {"features": [], "labels": [], "counts": Counter()})
    fields = None
    with tarfile.open(ARCHIVE, mode="r|bz2") as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith("/zeek/conn.log.labeled"):
                continue
            parts = member.name.split("/")
            day = next((part for part in parts if part.startswith("2023-02-")), "unknown")
            stream = archive.extractfile(member)
            if stream is None:
                continue
            local_fields = None
            for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith("#fields\t"):
                    local_fields = line.split("\t")[1:]
                    fields = local_fields
                    continue
                if not line or line.startswith("#") or local_fields is None:
                    continue
                per_day[day]["counts"]["flow_rows"] += 1
                values = line.split("\t")
                if len(values) != len(local_fields):
                    per_day[day]["counts"]["malformed"] += 1
                    continue
                row = dict(zip(local_fields, values))
                label = row.get("label", "").strip().lower()
                if label not in {"malicious", "benign"}:
                    per_day[day]["counts"]["unknown_excluded"] += 1
                    continue
                try:
                    duration = row.get("duration")
                    packets = float(row.get("orig_pkts", "-")) + float(row.get("resp_pkts", "-"))
                    orig_bytes = float(row.get("orig_ip_bytes", "-"))
                    resp_bytes = float(row.get("resp_ip_bytes", "-"))
                    vector = feature_vector(duration, packets, orig_bytes + resp_bytes,
                                            orig_bytes, resp_bytes, row.get("proto"))
                except (TypeError, ValueError):
                    per_day[day]["counts"]["incomplete_excluded"] += 1
                    continue
                per_day[day]["features"].append(vector)
                per_day[day]["labels"].append(int(label == "malicious"))
                per_day[day]["counts"][label] += 1

    if not fields:
        raise RuntimeError("No Zeek conn.log.labeled members found in CTU-SME archive")
    with gzip.open(FEATURE_EXPORT, "wt", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["capture", "label", *FEATURE_NAMES])
        for day in sorted(per_day):
            item = per_day[day]
            for vector, target in zip(item["features"], item["labels"]):
                writer.writerow([day, "attack" if target else "benign", *vector])
    all_y, all_p = [], []
    day_results = {}
    for day in sorted(per_day):
        x = np.asarray(per_day[day]["features"], dtype=np.float32)
        y = np.asarray(per_day[day]["labels"], dtype=np.int64)
        if not len(y):
            day_results[day] = {"counts": dict(per_day[day]["counts"]), "metrics": None}
            continue
        values = torch.from_numpy((x - mean) / std)
        with torch.no_grad():
            p = torch.softmax(model(values)[1], dim=1)[:, 1].numpy().astype(np.float64)
        all_y.append(y); all_p.append(p)
        counts = dict(per_day[day]["counts"])
        labeled = counts.get("benign", 0) + counts.get("malicious", 0)
        counts["complete_labeled_coverage"] = labeled / max(counts.get("flow_rows", 0), 1)
        day_results[day] = {"counts": counts,
                            "fixed_threshold_0_5": metrics(y, p, 0.5),
                            "ctu45_selected_threshold": metrics(y, p, threshold)}
    if not all_y or len(np.unique(np.concatenate(all_y))) != 2:
        raise RuntimeError("CTU-SME scored data did not contain both source-labeled classes")
    total_flows = sum(day["counts"].get("flow_rows", 0) for day in per_day.values())
    complete_labeled_flows = sum(day["counts"].get("benign", 0) + day["counts"].get("malicious", 0)
                                 for day in per_day.values())
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "CTU-SME-11 Amazon Echo device, 7 real captured days; Zenodo 7958259 / DOI 10.5281/zenodo.7958259",
        "license": "CC-BY-4.0",
        "label_provenance": "dataset-provided expert labels; no two-reviewer claim",
        "capture_sha256": sha256(ARCHIVE),
        "derived_feature_file": str(FEATURE_EXPORT.relative_to(ROOT)),
        "derived_feature_file_sha256": sha256(FEATURE_EXPORT),
        "checkpoint_sha256": sha256(CHECKPOINT),
        "threshold_source": "fixed from CTU-45 validation; not tuned on CTU-SME",
        "threshold": threshold,
        "coverage": {"source_flow_rows": total_flows,
                     "complete_labeled_flows_scored": complete_labeled_flows,
                     "fraction": complete_labeled_flows / max(total_flows, 1)},
        "field_mapping": {"duration": "duration", "total_packets": "orig_pkts + resp_pkts",
                          "total_bytes": "orig_ip_bytes + resp_ip_bytes",
                          "direction_bytes": "orig_ip_bytes, resp_ip_bytes", "protocol": "proto"},
        "label_mapping": {"attack": "malicious", "benign": "benign",
                          "excluded": "background, unknown, incomplete"},
        "per_day": day_results,
        "combined_fixed_threshold_0_5": metrics(np.concatenate(all_y), np.concatenate(all_p), 0.5),
        "combined_ctu45_selected_threshold": metrics(np.concatenate(all_y), np.concatenate(all_p), threshold),
        "model_role": "external_independent_advisory_evaluation",
        "promotion_eligible": False,
        "target_network_evaluation": "not_performed",
        "enforcement_applied": False,
    }
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"combined_fixed_threshold_0_5": report["combined_fixed_threshold_0_5"],
                      "combined_ctu45_selected_threshold": report["combined_ctu45_selected_threshold"],
                      "coverage": report["coverage"], "per_day": day_results,
                      "capture_sha256": report["capture_sha256"]}, indent=2))


if __name__ == "__main__":
    main()

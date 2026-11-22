"""Break down validation-candidate errors by publisher CTU flow label."""
from __future__ import annotations
import csv, json, sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.train_v9 import (OUT, VALIDATION_CAPTURE, MLP, load_capture)


def main():
    experiment = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups"
    ckpt = torch.load(experiment / "expanded_class_balanced.pt", map_location="cpu", weights_only=False)
    model = MLP(len(ckpt["feature_names"]))
    model.load_state_dict(ckpt["state_dict"]); model.eval()
    x_all, y_all, labels = [], [], []
    for cid, path in VALIDATION_CAPTURE.items():
        x, y, _udp, _excluded = load_capture(cid, path)
        x_all.append(x); y_all.append(y)
        with path.open("r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                label = (row.get("Label") or "").strip()
                if label.startswith("flow=From-Botnet-") or label.startswith("flow=From-Normal-"):
                    labels.append(label)
    x = np.concatenate(x_all); y = np.concatenate(y_all)
    mean = np.asarray(ckpt["mean"], np.float32); scale = np.asarray(ckpt["scale"], np.float32)
    x = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
    with torch.no_grad():
        p = torch.softmax(model(torch.from_numpy(x)), dim=1)[:, 1].numpy()
    summary = json.loads((experiment / "validation_summary.json").read_text(encoding="utf-8"))
    threshold = summary["validation_operating_point"]["threshold"]
    by_label = defaultdict(lambda: {"n": 0, "detected": 0, "score_sum": 0.0})
    for label, target, score in zip(labels, y, p):
        item = by_label[label]
        item["n"] += 1; item["score_sum"] += float(score)
        if score >= threshold: item["detected"] += 1
    rows = []
    for label, item in sorted(by_label.items(), key=lambda kv: (kv[0].startswith("flow=From-Normal-"), -kv[1]["n"])):
        rows.append({"label": label, "class": "attack" if label.startswith("flow=From-Botnet-") else "benign",
                     "flows": item["n"], "detected": item["detected"],
                     "recall_or_fpr": item["detected"] / item["n"],
                     "mean_score": item["score_sum"] / item["n"]})
    out = experiment / "ctu45_label_error_breakdown.json"
    out.write_text(json.dumps({"capture": "45", "checkpoint": "class_balanced.pt",
                               "threshold_selected_on_validation": threshold,
                               "by_publisher_label": rows,
                               "warning": "Validation diagnostics only; no independent test data loaded."},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    for row in rows:
        print(f"{row['class']:6} {row['flows']:7d} {row['recall_or_fpr']:.4%} {row['label']}")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()

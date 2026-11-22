"""One-shot external transfer check for the frozen class-balanced CTU candidate.

Uses only existing public IoT-23 v2 files other than the user-requested-to-delete
7-1 file. The threshold is frozen from CTU-45 validation; this script never
selects a threshold and never writes a deployable/promotion-eligible model.
"""
from __future__ import annotations
import hashlib, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, feature_vector
from tools.train_v9 import MLP, OUT

DATA = ROOT / "outputs" / "network-eval" / "official-iot23v2"
CHECKPOINT_PATH = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups" / "expanded_class_balanced.pt"
OUTFILE = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups" / "iot23_transfer_diagnostic.json"
CAPTURES = {
    "malware_34_1": (DATA / "ctu-iot-malware-34-1-zeek-conn.log.labeled", False),
    "clean_honeypot_4_1": (DATA / "ctu-honeypot-4-1-zeek-conn.log.labeled", True),
    "clean_honeypot_5_1": (DATA / "ctu-honeypot-5-1-zeek-conn.log.labeled", True),
    "clean_honeypot_7_2": (DATA / "ctu-honeypot-7-2-zeek-conn.log.labeled", True),
    "clean_honeypot_7_3": (DATA / "ctu-honeypot-7-3-zeek-conn.log.labeled", True),
    "clean_honeypot_7_4": (DATA / "ctu-honeypot-7-4-zeek-conn.log.labeled", True),
}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wilson(successes, total, z=1.959963984540054):
    if total <= 0: return None
    p = successes / total; den = 1 + z*z/total
    center = p + z*z/(2*total)
    margin = z * ((p*(1-p) + z*z/(4*total))/total) ** 0.5
    return [max(0.0, (center-margin)/den), min(1.0, (center+margin)/den)]


def parse_line(line):
    cols = line.rstrip("\r\n").split("\t")
    if len(cols) < 21: raise ValueError("too few Zeek columns")
    tail = cols[-1].strip().split()
    label = tail[-2].lower() if len(tail) >= 3 else ""
    orig_pkts, resp_pkts = float(cols[16]), float(cols[18])
    orig_bytes, resp_bytes = float(cols[17]), float(cols[19])
    x = feature_vector(cols[8], orig_pkts+resp_pkts, orig_bytes+resp_bytes,
                       orig_bytes, resp_bytes, cols[6])
    return label, x


def main():
    ckpt_path = CHECKPOINT_PATH
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    if ckpt.get("feature_version") != FEATURE_VERSION or ckpt.get("feature_names") != list(FEATURE_NAMES):
        raise RuntimeError("frozen checkpoint does not match current flow feature schema")
    model = MLP(len(FEATURE_NAMES)); model.load_state_dict(ckpt["state_dict"]); model.eval()
    threshold = float(ckpt["threshold_selected_on_validation"])  # selected on CTU capture 45 only
    mean = np.asarray(ckpt["mean"], dtype=np.float32)
    scale = np.asarray(ckpt["scale"], dtype=np.float32)
    freeze_time = datetime.now(timezone.utc).isoformat()
    reports, combined_y, combined_scores = {}, [], []
    checkpoint_hash = sha256(ckpt_path)
    for name, (path, capture_is_clean) in CAPTURES.items():
        if not path.is_file(): raise FileNotFoundError(path)
        y, vectors, counts = [], [], {"malicious": 0, "benign": 0, "unknown_excluded": 0,
                                      "incomplete_excluded": 0}
        for line in path.open("r", encoding="utf-8", errors="replace"):
            if not line or line.startswith("#"): continue
            try: label, vector = parse_line(line)
            except (ValueError, IndexError, TypeError):
                counts["incomplete_excluded"] += 1; continue
            if label == "malicious": target = 1
            elif label == "benign": target = 0
            elif capture_is_clean and not label: target = 0
            else:
                counts["unknown_excluded"] += 1; continue
            counts["malicious" if target else "benign"] += 1
            y.append(target); vectors.append(vector)
        if not y: raise RuntimeError(f"No scored labels in {path}")
        x = np.asarray(vectors, np.float32)
        x = np.clip((x - mean) / scale, -10.0, 10.0).astype(np.float32)
        with torch.no_grad():
            scores = torch.softmax(model(torch.from_numpy(x)), dim=1)[:, 1].numpy()
        y = np.asarray(y, np.int64); pred = scores >= threshold
        tp = int(((y == 1) & pred).sum()); fn = int(((y == 1) & ~pred).sum())
        fp = int(((y == 0) & pred).sum()); tn = int(((y == 0) & ~pred).sum())
        report = {"capture_sha256": sha256(path), "counts": counts, "n": len(y),
                  "threshold_from_ctu45_validation": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                  "attack_recall": tp/(tp+fn) if tp+fn else None,
                  "attack_recall_ci95_wilson": wilson(tp, tp+fn),
                  "benign_fpr": fp/(fp+tn) if fp+tn else None,
                  "benign_fpr_ci95_wilson": wilson(fp, fp+tn)}
        reports[name] = report
        combined_y.append(y); combined_scores.append(scores)
        print(name, report, flush=True)
    y = np.concatenate(combined_y); scores = np.concatenate(combined_scores); pred = scores >= threshold
    tp = int(((y == 1) & pred).sum()); fn = int(((y == 1) & ~pred).sum())
    fp = int(((y == 0) & pred).sum()); tn = int(((y == 0) & ~pred).sum())
    result = {"created_at_utc": datetime.now(timezone.utc).isoformat(),
              "frozen_before_scoring_at_utc": freeze_time,
              "dataset": "official MCFP/Stratosphere IoT-23 v2",
              "label_policy": "published Malicious/Benign flow labels; capture-level clean designation only for publisher-designated clean captures; unknown excluded",
              "excluded_capture": "CTU Honeypot Capture 7-1 (user requested deletion)",
              "checkpoint": ckpt_path.name, "checkpoint_sha256": checkpoint_hash,
              "split_note": "external transfer check only; no training or threshold choice on IoT-23",
              "per_capture": reports,
              "combined": {"n": len(y), "n_attack": int((y==1).sum()), "n_benign": int((y==0).sum()),
                           "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                           "attack_recall": tp/(tp+fn) if tp+fn else None,
                           "attack_recall_ci95_wilson": wilson(tp,tp+fn),
                           "benign_fpr": fp/(fp+tn) if fp+tn else None,
                           "benign_fpr_ci95_wilson": wilson(fp,fp+tn)},
              "promotion_eligible": False,
              "warning": "External transfer evidence only; does not replace per-capture gate or target-network evaluation."}
    OUTFILE.parent.mkdir(parents=True, exist_ok=True)
    OUTFILE.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUTFILE}")


if __name__ == "__main__": main()

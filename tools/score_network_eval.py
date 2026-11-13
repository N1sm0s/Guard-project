"""Score recorded decisions against independent labels, joined by case ID."""
import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path


def read_cases(path, column, allowed):
    cases = {}
    input_hashes = set()
    source = path.read_bytes()
    with io.StringIO(source.decode("utf-8-sig"), newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"case_id", column}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError(f"Missing columns in {path}: {', '.join(sorted(required))}")
        for row in reader:
            if "input_sha256" in reader.fieldnames:
                digest = row.get("input_sha256") or ""
                if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                    raise ValueError(f"Invalid input_sha256 in {path}, line {reader.line_num}")
                input_hashes.add(digest.lower())
            case = row.get("case_id")
            value = row.get(column)
            if column == "model_decision" and value == "" and row.get("decision") == "ERROR":
                value = "ERROR"
            if not case or case in cases or value not in allowed:
                raise ValueError(f"Invalid or duplicate row in {path}: {case!r}")
            cases[case] = value
    if len(input_hashes) > 1:
        raise ValueError(f"Multiple input datasets in {path}")
    return cases, hashlib.sha256(source).hexdigest(), next(iter(input_hashes), None)


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("labels", type=Path, help="CSV with case_id,label (attack, benign, unknown)")
    parser.add_argument("predictions", type=Path, help="CSV with case_id,decision (ALLOW, REVIEW, BLOCK, ERROR)")
    parser.add_argument("--decision-column", choices=("decision", "model_decision"), default="decision",
                        help="Score the application decision or the original model recommendation.")
    parser.add_argument("--input", type=Path, help="Verify the prediction hash against this telemetry JSONL.")
    args = parser.parse_args()
    try:
        labels, labels_sha256, labels_input = read_cases(args.labels, "label", {"attack", "benign", "unknown"})
        predictions, predictions_sha256, predictions_input = read_cases(
            args.predictions, args.decision_column, {"ALLOW", "REVIEW", "BLOCK", "ERROR"})
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if labels_input is not None and labels_input != predictions_input:
        parser.error("Label and prediction input hashes must match.")
    if args.input is not None:
        try:
            with args.input.open("rb") as stream:
                actual_input = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError as error:
            parser.error(str(error))
        if actual_input != predictions_input:
            parser.error("Telemetry file SHA-256 does not match the prediction input hash.")
    if not labels or labels.keys() != predictions.keys():
        parser.error("Labels and predictions must contain the same nonempty set of case IDs.")
    counts = {
        label: {decision: 0 for decision in ("ALLOW", "REVIEW", "BLOCK", "ERROR")}
        for label in ("attack", "benign", "unknown")
    }
    for case, label in labels.items():
        counts[label][predictions[case]] += 1
    attack, benign = counts["attack"], counts["benign"]
    attack_alerts = attack["REVIEW"] + attack["BLOCK"]
    false_alerts = benign["REVIEW"] + benign["BLOCK"]
    definitive = sum(group["ALLOW"] + group["BLOCK"] for group in (attack, benign))
    print(json.dumps({
        "decision_column": args.decision_column,
        "labels_sha256": labels_sha256,
        "predictions_sha256": predictions_sha256,
        "input_sha256": predictions_input,
        "definitive_decisions_on_labeled_cases": definitive,
        "definitive_coverage_on_labeled_cases": ratio(definitive, sum(attack.values()) + sum(benign.values())),
        "accuracy_on_definitive_labeled_cases": ratio(attack["BLOCK"] + benign["ALLOW"], definitive),
        "counts": counts,
        "alert_recall": ratio(attack_alerts, sum(attack.values())),
        "alert_precision_excluding_unknown": ratio(attack_alerts, attack_alerts + false_alerts),
        "benign_false_alert_rate": ratio(false_alerts, sum(benign.values())),
        "review_rate": ratio(sum(group["REVIEW"] for group in counts.values()), len(labels)),
        "error_rate": ratio(sum(group["ERROR"] for group in counts.values()), len(labels)),
        "error_rate_by_label": {
            label: ratio(group["ERROR"], sum(group.values()))
            for label, group in counts.items()
        },
        "review_rate_by_label": {
            label: ratio(group["REVIEW"], sum(group.values()))
            for label, group in counts.items()
        },
        "block_recommendation_precision_excluding_unknown": ratio(
            attack["BLOCK"], attack["BLOCK"] + benign["BLOCK"]
        ),
        "attack_allow_rate": ratio(attack["ALLOW"], sum(attack.values())),
        "attack_block_recommendation_rate": ratio(attack["BLOCK"], sum(attack.values())),
        "benign_block_recommendation_rate": ratio(benign["BLOCK"], sum(benign.values())),
        "unknown_label_rate": ratio(sum(counts["unknown"].values()), len(labels)),
    }, indent=2))


if __name__ == "__main__":
    main()

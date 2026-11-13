"""Replay unlabeled offline telemetry through the IntegrityGuard advisor."""
import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

from integrityguard.network_ai import assess_network_with_ollama


def endpoint_projection(snapshot):
    """Keep shared endpoint fields and preserve their observation scope."""
    return {
        "scope": snapshot.get("scope"),
        "remote_endpoint_count": snapshot.get("remote_endpoint_count"),
        "remote_endpoints": [
            {field: endpoint[field] for field in ("id", "protocols", "remote_ports_sample")
             if field in endpoint}
            for endpoint in snapshot.get("remote_endpoints", [])
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="JSONL with case_id, snapshot and app_state")
    parser.add_argument("predictions", type=Path, help="New CSV output")
    parser.add_argument("--model", default="qwen3.5:4b")
    parser.add_argument("--endpoint-only", action="store_true",
                        help="Compare shared endpoint fields without application state.")
    args = parser.parse_args()
    cases = {}
    source_digest = hashlib.sha256()
    try:
        stream = args.cases.open("rb")
    except OSError as error:
        parser.error(f"Cannot open input {args.cases}: {error.strerror}")
    with stream:
        for line_number, line in enumerate(stream, start=1):
            source_digest.update(line)
            try:
                case = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                parser.error(f"{args.cases}:{line_number}: {error}")
            if (not isinstance(case, dict)
                    or set(case) != {"case_id", "snapshot", "app_state"}
                    or not isinstance(case["case_id"], str) or not case["case_id"].strip()
                    or case["case_id"] in cases or not isinstance(case["snapshot"], dict)
                    or not isinstance(case["app_state"], dict)):
                parser.error(f"{args.cases}:{line_number}: expected a unique case ID, snapshot and app state objects.")
            cases[case["case_id"]] = case
    if not cases:
        parser.error("Input contains no cases.")
    source_hash = source_digest.hexdigest()
    with args.predictions.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("case_id", "decision", "model_decision", "model", "error",
                         "summary", "evidence_ids", "insufficient_evidence", "input_sha256", "projection"))
        projection = "endpoint-only-v1" if args.endpoint_only else "original"
        for case_id, case in cases.items():
            snapshot, app_state = case["snapshot"], case["app_state"]
            try:
                if args.endpoint_only:
                    snapshot, app_state = endpoint_projection(snapshot), {}
                result = assess_network_with_ollama(snapshot, app_state, args.model)
                writer.writerow((case_id, result["decision"], result["model_decision"], result["model"], "",
                                 result["summary"], json.dumps(result["evidence_ids"]),
                                 result["insufficient_evidence"], source_hash, projection))
            except (ValueError, RuntimeError, OSError) as error:
                print(f"{case_id!r}: {type(error).__name__}: {str(error)!r}", file=sys.stderr)
                writer.writerow((case_id, "ERROR", "", args.model, type(error).__name__, "", "", "", source_hash, projection))
            stream.flush()


if __name__ == "__main__":
    main()

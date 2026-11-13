"""Summarize operator firewall actions in an IntegrityGuard audit database."""
import argparse
from collections import Counter
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from integrityguard.copilot_audit import CopilotAudit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_db", type=Path, nargs="?",
                        help="Audit database path. Defaults to the configured IntegrityGuard data directory.")
    args = parser.parse_args()
    if args.audit_db is None:
        from integrityguard.paths import DATA_ROOT

        args.audit_db = DATA_ROOT / "copilot_audit.sqlite"
    pending = Counter()
    completed = Counter()
    completed_by_action = {"firewall_block": Counter(), "firewall_unblock": Counter()}
    unmatched_results = 0
    try:
        uri = args.audit_db.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            rows = db.execute(
                "SELECT timestamp_utc,principal,question_sha256,answer_sha256,model,status,"
                "sources_json,tools_json,previous_hash,record_hash FROM turns ORDER BY seq"
            ).fetchall()
            integrity = CopilotAudit.verify_rows(rows)
            if not integrity["valid"]:
                parser.error(f"Audit integrity check failed: {integrity['reason']}")
            for _, _, key, _, _, _, _, raw, _, _ in rows:
                for tool in json.loads(raw):
                    name = tool.get("name")
                    if name not in {"firewall_block", "firewall_unblock"}:
                        continue
                    operation = (key, name)
                    status = tool["status"]
                    if status == "requested":
                        pending[operation] += 1
                    else:
                        completed[status] += 1
                        completed_by_action[name][status] += 1
                        if pending[operation]:
                            pending[operation] -= 1
                        else:
                            unmatched_results += 1
    except (sqlite3.Error, ValueError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps({"audit_integrity": integrity, "results_by_status": dict(completed),
                      "results_by_action": completed_by_action,
                      "requests_without_result": sum(pending.values()),
                      "pending_operations": [
                          {"operation_sha256": key, "action": name, "count": count}
                          for (key, name), count in sorted(pending.items()) if count
                      ],
                      "results_without_request_marker": unmatched_results}, indent=2))


if __name__ == "__main__":
    main()

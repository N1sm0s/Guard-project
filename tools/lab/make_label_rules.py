"""Turn a lab scenario log into a label rule file for tools/stream_ingest.py.

The log is JSON Lines, one scenario per line, written BEFORE the scenario starts
and closed after it stops:

  {"scenario_id": "udp-01", "label": "attack:udp_flood", "attacker_mac": "00:15:5d:00:7e:05",
   "victim_ip": "172.20.0.10", "lab_subnet": "172.20.0.0/24", "tool": "hping3",
   "command": "hping3 --udp --flood -p 53 172.20.0.10", "start_utc": "2026-11-24T10:00:00Z",
   "end_utc": "2026-11-24T10:02:00Z", "operator": "pavel"}

Rules produced (first match wins, so the attack rules come first):
  * attack scenario: flows whose originator MAC is the attacker MAC, inside the
    scenario time window, with the victim as responder (ip_dst = victim);
  * benign scenario: flows inside the lab subnet only (ip_src and ip_dst both in
    lab_subnet) inside the window;
  * everything else: excluded (default "exclude").

Usage:
  python tools/lab/make_label_rules.py --log lab-log.jsonl --out lab-rules.json
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
REQUIRED = ("scenario_id", "label", "start_utc", "end_utc", "operator", "lab_subnet")


class LogError(ValueError):
    pass


def _epoch(text: str) -> float:
    if not isinstance(text, str) or not text.endswith("Z"):
        raise LogError(f"time must be UTC with Z suffix: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def load_log(path: Path) -> list[dict]:
    rows = []
    seen = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise LogError(f"line {number}: invalid JSON ({error})") from None
        for key in REQUIRED:
            if not row.get(key):
                raise LogError(f"line {number}: missing {key}")
        if row["scenario_id"] in seen:
            raise LogError(f"line {number}: duplicate scenario_id {row['scenario_id']}")
        seen.add(row["scenario_id"])
        start, end = _epoch(row["start_utc"]), _epoch(row["end_utc"])
        if not end > start:
            raise LogError(f"line {number}: end must be after start")
        label = row["label"]
        if label == "benign":
            pass
        elif label.startswith("attack:"):
            mac = str(row.get("attacker_mac", "")).lower()
            if not MAC_RE.match(mac):
                raise LogError(f"line {number}: attacker_mac must be a full MAC")
            if not row.get("victim_ip"):
                raise LogError(f"line {number}: attack scenario needs victim_ip")
            ipaddress.ip_address(row["victim_ip"])
            row["attacker_mac"] = mac
        else:
            raise LogError(f"line {number}: label must be 'benign' or 'attack:<type>'")
        ipaddress.ip_network(row["lab_subnet"], strict=False)
        row["_start"], row["_end"] = start, end
        rows.append(row)
    if not rows:
        raise LogError("the log has no scenarios")
    return rows


def build_rules(rows: list[dict], log_sha256: str) -> dict:
    rules = []
    for row in rows:
        window = {"time_from": int(row["_start"]), "time_to": int(row["_end"])}
        if row["label"] == "benign":
            subnet = str(ipaddress.ip_network(row["lab_subnet"], strict=False))
            rules.append({"label": "benign", "ip_src": [subnet], "ip_dst": [subnet],
                          "note": row["scenario_id"], **window})
        else:
            rules.append({"label": "attack", "mac_src": [row["attacker_mac"]],
                          "ip_dst": [row["victim_ip"]], "note": row["scenario_id"], **window})
    return {"rule_id": "lab-" + log_sha256[:12],
            "publisher_reference": "Operator lab scenario log (docs/lab-collection-protocol-2026-11.md); "
                                   "labels are the operator's own schedule, not a publisher dataset",
            "log_sha256": log_sha256, "default": "exclude", "rules": rules}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = load_log(args.log)
    except LogError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.log.read_bytes()).hexdigest()
    rules = build_rules(rows, digest)
    args.out.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"scenarios": len(rows), "rules": len(rules["rules"]), "log_sha256": digest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

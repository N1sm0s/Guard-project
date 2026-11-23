"""Lab scenario log -> label rules. Pure logic; no VM, no traffic."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "lab"))
import make_label_rules as mlr  # noqa: E402
sys.path.insert(0, str(ROOT))
from integrityguard.stream_ingest import LabelRule  # noqa: E402

ATTACK = {"scenario_id": "udp-01", "label": "attack:udp_flood", "attacker_mac": "00:15:5D:00:7E:05",
          "victim_ip": "172.20.0.10", "lab_subnet": "172.20.0.0/24", "tool": "hping3",
          "command": "hping3 --udp --flood -p 53 172.20.0.10", "start_utc": "2026-11-24T10:00:00Z",
          "end_utc": "2026-11-24T10:02:00Z", "operator": "pavel"}
BENIGN = {"scenario_id": "ben-01", "label": "benign", "lab_subnet": "172.20.0.0/24",
          "start_utc": "2026-11-24T09:00:00Z", "end_utc": "2026-11-24T09:20:00Z", "operator": "pavel"}


def _write(tmp_path, *rows):
    path = tmp_path / "lab-log.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_rules_are_valid_for_stream_ingest(tmp_path):
    log = _write(tmp_path, BENIGN, ATTACK)
    rules = mlr.build_rules(mlr.load_log(log), "f" * 64)
    rule = LabelRule(rules)  # must parse with the production label rule loader
    assert rule.default == "exclude"
    assert len(rules["rules"]) == 2


def test_attack_rule_uses_normalized_mac_and_window(tmp_path):
    log = _write(tmp_path, ATTACK)
    rule = mlr.build_rules(mlr.load_log(log), "a" * 64)["rules"][0]
    assert rule["label"] == "attack"
    assert rule["mac_src"] == ["00:15:5d:00:7e:05"]
    assert rule["ip_dst"] == ["172.20.0.10"]
    assert rule["time_to"] - rule["time_from"] == 120


def test_benign_rule_requires_both_endpoints_in_lab_subnet(tmp_path):
    log = _write(tmp_path, BENIGN)
    rules = mlr.build_rules(mlr.load_log(log), "b" * 64)
    lab = LabelRule(rules)
    inside = {"originator_ip": "172.20.0.5", "responder_ip": "172.20.0.10", "protocol": "tcp",
              "first_seen": rules["rules"][0]["time_from"] + 5}
    outside = {**inside, "responder_ip": "93.184.216.34"}
    assert lab.label(inside) == "benign"
    assert lab.label(outside) == "exclude"


def test_flow_outside_window_is_excluded(tmp_path):
    log = _write(tmp_path, ATTACK)
    rules = mlr.build_rules(mlr.load_log(log), "c" * 64)
    lab = LabelRule(rules)
    late = {"originator_ip": "172.20.0.5", "responder_ip": "172.20.0.10", "protocol": "udp",
            "first_seen": rules["rules"][0]["time_to"] + 1, "originator_macs": ("00:15:5d:00:7e:05",)}
    assert lab.label(late) == "exclude"


@pytest.mark.parametrize("change, message", [
    ({"end_utc": "2026-11-24T09:00:00Z"}, "end must be after start"),
    ({"attacker_mac": "not-a-mac"}, "full MAC"),
    ({"label": "maybe"}, "label must be"),
    ({"start_utc": "2026-11-24T10:00:00"}, "UTC with Z"),
])
def test_invalid_rows_are_rejected(tmp_path, change, message):
    bad = {**ATTACK, **change}
    log = _write(tmp_path, bad)
    with pytest.raises(mlr.LogError, match=message):
        mlr.load_log(log)


def test_duplicate_scenario_id_is_rejected(tmp_path):
    log = _write(tmp_path, ATTACK, ATTACK)
    with pytest.raises(mlr.LogError, match="duplicate"):
        mlr.load_log(log)

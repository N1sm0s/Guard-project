"""Schema v12: same-service repetition features (synthetic flow dicts; code test, not evidence)."""
import math
from integrityguard import network_flow_schema_v12 as v12


def _flow(src, dst, port, duration):
    return {"originator_ip": src, "responder_ip": dst, "responder_port": port, "duration_seconds": duration,
            "protocol": "tcp", "total_packets": 6, "total_bytes": 400, "direction_a_bytes": 200,
            "direction_b_bytes": 200, "first_seen": 1000.0, "saw_syn": True, "saw_syn_ack": True,
            "saw_ack": True, "saw_fin": True, "saw_rst": False, "originator_port": 40000,
            "responder_port_value": port}


def test_repeated_short_connections_share_is_high():
    flows = [_flow("172.20.0.5", "172.20.0.10", 22, 0.4) for _ in range(5)]
    vectors = v12.from_live_flows_v12(flows)
    assert len(vectors[0]) == len(v12.FEATURE_NAMES)
    count_feature = vectors[0][-2]
    share_feature = vectors[0][-1]
    assert math.isclose(count_feature, math.log1p(5))
    assert share_feature == 1.0


def test_single_long_session_is_not_repetition():
    flows = [_flow("172.20.0.5", "172.20.0.10", 22, 30.0)]
    vectors = v12.from_live_flows_v12(flows)
    assert vectors[0][-1] == 0.0
    assert math.isclose(vectors[0][-2], math.log1p(1))


def test_different_ports_are_separate_services():
    flows = [_flow("172.20.0.5", "172.20.0.10", 22, 0.4), _flow("172.20.0.5", "172.20.0.10", 80, 0.4)]
    vectors = v12.from_live_flows_v12(flows)
    assert math.isclose(vectors[0][-2], math.log1p(1))
    assert math.isclose(vectors[1][-2], math.log1p(1))

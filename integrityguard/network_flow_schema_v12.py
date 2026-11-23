"""Feature v12: v11 features plus same-service repetition within a 10-second window.

Two context features describe repeated connections from one originator to one responder port:
  * same_service_flows_10s_log1p: log1p of the number of flows with the same originator, responder and port;
  * same_service_short_share_10s: share of those flows that are short (duration under 1 s).

These separate repeated short connection attempts (for example SSH authentication attempts, one
connection per attempt) from a single long session. They use only observed flow fields, never labels.
"""
from __future__ import annotations

import math
from collections import defaultdict

from . import network_flow_schema_v10 as v10
from . import network_flow_schema_v11 as v11

FEATURE_VERSION = 12
SERVICE_NAMES = ("same_service_flows_10s_log1p", "same_service_short_share_10s")
FEATURE_NAMES = tuple(v11.FEATURE_NAMES) + SERVICE_NAMES
SHORT_SECONDS = 1.0


def from_live_flows_v12(flows: list[dict]) -> list[list[float]]:
    """v11 vectors plus the two same-service features, for the flows of one window."""
    base_vectors = v11.from_live_flows(flows)
    groups: dict[tuple, list[float]] = defaultdict(list)
    keys = []
    for flow in flows:
        originator_ip = str(flow.get("originator_ip") or "")
        responder_ip = str(flow.get("responder_ip") or "")
        try:
            responder_port = v10._port(flow.get("responder_port", 0), "responder_port")
        except ValueError:
            keys.append(None)
            continue
        if not originator_ip or not responder_ip:
            keys.append(None)
            continue
        key = (originator_ip, responder_ip, responder_port)
        keys.append(key)
        groups[key].append(float(flow.get("duration_seconds") or 0.0))
    vectors = []
    for base, key in zip(base_vectors, keys):
        if key is None:
            vectors.append(list(base) + [0.0, 0.0])
            continue
        durations = groups[key]
        count = len(durations)
        short = sum(1 for d in durations if d < SHORT_SECONDS)
        vectors.append(list(base) + [math.log1p(count), short / count if count else 0.0])
    return vectors

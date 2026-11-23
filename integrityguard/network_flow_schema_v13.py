"""Feature v13: v12 features plus per-flow packet-size statistics.

Four features describe the IP lengths of the packets of one flow (both directions):
  * pkt_size_mean_log1p: log1p of the mean IP length;
  * pkt_size_max_log1p: log1p of the largest IP length;
  * pkt_size_std_log1p: log1p of the population standard deviation of IP lengths;
  * small_packet_share: share of packets with IP length at most 64 bytes.

These separate one-way UDP noise from request/response UDP exchanges by packet shape
rather than by direction alone. They use only observed packet lengths, never labels
or payload.
"""
from __future__ import annotations

import math

from . import network_flow_schema_v12 as v12

FEATURE_VERSION = 13
SIZE_NAMES = ("pkt_size_mean_log1p", "pkt_size_max_log1p", "pkt_size_std_log1p", "small_packet_share")
FEATURE_NAMES = tuple(v12.FEATURE_NAMES) + SIZE_NAMES


def _size_vector(flow: dict) -> list[float]:
    count = int(flow.get("total_packets") or 0)
    if count <= 0:
        return [0.0, 0.0, 0.0, 0.0]
    total = float(flow.get("pkt_size_sum") or 0)
    total_sq = float(flow.get("pkt_size_sumsq") or 0)
    mean = total / count
    variance = max(total_sq / count - mean * mean, 0.0)
    return [
        math.log1p(mean),
        math.log1p(float(flow.get("pkt_size_max") or 0)),
        math.log1p(math.sqrt(variance)),
        float(flow.get("small_packets") or 0) / count,
    ]


def from_live_flows_v13(flows: list[dict]) -> list[list[float]]:
    """v12 vectors plus the four packet-size features, for the flows of one window."""
    base_vectors = v12.from_live_flows_v12(flows)
    return [list(base) + _size_vector(flow) for base, flow in zip(base_vectors, flows)]

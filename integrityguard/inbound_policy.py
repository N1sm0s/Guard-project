"""Conservative policy for completed inbound packet-counter windows."""
from ipaddress import ip_address


def inbound_rate_candidates(current, previous, *, packets_per_second, protected=()):
    """Return public sources exceeding a configured limit in two windows.

    Each mapping contains measured per-source packets/second for one complete
    capture window. Missing sources carry no evidence into the decision.
    """
    if packets_per_second <= 0:
        raise ValueError("The packet rate limit must be positive")
    protected_addresses = {ip_address(address) for address in protected}
    candidates = set()
    for source in current.keys() & previous.keys():
        address = ip_address(source)
        if not address.is_global or address.is_multicast or address in protected_addresses:
            continue
        if min(current[source], previous[source]) >= packets_per_second:
            candidates.add(str(address))
    return sorted(candidates)


def inbound_packet_rates(rows, *, local_addresses, start, stop):
    """Aggregate (timestamp, source IP, destination IP) header rows in [start, stop)."""
    from collections import Counter
    from math import isfinite

    if not isfinite(start) or not isfinite(stop) or stop <= start:
        raise ValueError("Invalid capture window")
    local = {ip_address(address) for address in local_addresses}
    if not local:
        raise ValueError("Local capture addresses are required")
    counts = Counter()
    for timestamp, source, destination in rows:
        if not isfinite(timestamp):
            raise ValueError("Invalid packet timestamp")
        if start <= timestamp < stop:
            source_ip, destination_ip = ip_address(source), ip_address(destination)
            if destination_ip in local and source_ip not in local:
                counts[str(source_ip)] += 1
    return {source: count / (stop - start) for source, count in counts.items()}

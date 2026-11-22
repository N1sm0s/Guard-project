"""Live network telemetry from OS interface counters and socket metadata.

No packet payload capture, language model calls, or firewall actions occur here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import statistics
import time
from collections import deque
from datetime import datetime, timezone

_MAX_FLOWS = 40
_MAX_MODEL_FLOWS = 16384
_SUSPICIOUS_REMOTE_PORTS = {
    1337: "часто используется бэкдорами/C2 ('leet')",
    4444: "стандартный порт обработчика Metasploit/Meterpreter",
    5554: "порт, который открывал червь Sasser",
    6666: "нестандартный IRC-порт, часто у IRC-ботнетов",
    6667: "IRC; исторически использовался управляющими серверами ботнетов",
    9001: "часто Tor relay/control; само по себе не доказательство",
    12345: "порт классического backdoor NetBus",
    31337: "классический backdoor-порт ('elite')",
}
_PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 15
_RATE_BASELINE_WINDOW = 30

def _endpoint(value) -> tuple[str, int] | None:
    if not value:
        return None
    try:
        return str(value.ip), int(value.port)
    except AttributeError:
        try:
            return str(value[0]), int(value[1])
        except (IndexError, TypeError, ValueError):
            return None


class NetworkTelemetry:
    """Take real, bounded snapshots from psutil with per-interface deltas."""

    def __init__(self):
        self._previous_io: dict[str, tuple[int, int, int, int]] = {}
        self._previous_at: float | None = None
        self._previous_remote_counts: dict[str, int] = {}
        # Rolling local baseline of total packet/byte rate (sum across interfaces), used
        # only to flag "unusually high for this machine right now" -- never a public feed,
        # never alone sufficient for a decision.
        self._rate_history: deque[tuple[float, float]] = deque(maxlen=_RATE_BASELINE_WINDOW)

    def sample(self, psutil_module) -> dict:
        now = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            io = psutil_module.net_io_counters(pernic=True) or {}
            stats = psutil_module.net_if_stats() or {}
        except Exception as exc:  # noqa: BLE001 — preserve explicit visibility state
            io, stats = {}, {}
            interface_error = type(exc).__name__
        else:
            interface_error = None

        had_previous_sample = self._previous_at is not None
        dt = max(now - self._previous_at, 1e-3) if had_previous_sample else None
        interfaces = []
        current_io: dict[str, tuple[int, int, int, int]] = {}
        total_packet_rate = 0.0
        total_byte_rate = 0.0
        any_rate_known = False
        for name, counter in sorted(io.items()):
            received = (int(counter.bytes_recv), int(counter.packets_recv))
            sent = (int(counter.bytes_sent), int(counter.packets_sent))
            current_io[str(name)] = (*received, *sent)
            old = self._previous_io.get(str(name))
            rate = None
            if old is not None and dt is not None:
                bytes_in_rate = round(max(received[0] - old[0], 0) / dt, 1)
                packets_in_rate = round(max(received[1] - old[1], 0) / dt, 1)
                bytes_out_rate = round(max(sent[0] - old[2], 0) / dt, 1)
                packets_out_rate = round(max(sent[1] - old[3], 0) / dt, 1)
                rate = {
                    "bytes_received_per_second": bytes_in_rate,
                    "packets_received_per_second": packets_in_rate,
                    "bytes_sent_per_second": bytes_out_rate,
                    "packets_sent_per_second": packets_out_rate,
                }
                any_rate_known = True
                total_packet_rate += packets_in_rate + packets_out_rate
                total_byte_rate += bytes_in_rate + bytes_out_rate
            status = stats.get(name)
            interfaces.append({
                "name": str(name)[:96], "is_up": bool(status.isup) if status else None,
                "bytes_received_total": received[0], "packets_received_total": received[1],
                "bytes_sent_total": sent[0], "packets_sent_total": sent[1], "rate": rate,
            })
        self._previous_io = current_io
        self._previous_at = now

        # Anomaly score against THIS machine's own recent history only (never a public
        # baseline, never alone sufficient for a decision) -- computed before the current
        # sample is folded into the history, so a single spike cannot inflate its own score.
        traffic_anomaly = {
            "packet_rate_zscore": None, "byte_rate_zscore": None,
            "baseline_samples": len(self._rate_history),
            "note": "Z-оценка относительно последних локальных замеров этой машины; не публичная норма "
                     "и не самостоятельное доказательство атаки.",
        }
        if any_rate_known:
            if len(self._rate_history) >= 5:
                packet_history = [item[0] for item in self._rate_history]
                byte_history = [item[1] for item in self._rate_history]
                packet_mean, byte_mean = statistics.fmean(packet_history), statistics.fmean(byte_history)
                packet_std, byte_std = statistics.pstdev(packet_history), statistics.pstdev(byte_history)
                if packet_std > 1e-6:
                    traffic_anomaly["packet_rate_zscore"] = round((total_packet_rate - packet_mean) / packet_std, 2)
                if byte_std > 1e-6:
                    traffic_anomaly["byte_rate_zscore"] = round((total_byte_rate - byte_mean) / byte_std, 2)
            self._rate_history.append((total_packet_rate, total_byte_rate))

        remote_summary: dict[str, dict] = {}
        state_counts: dict[str, int] = {}
        flow_error = None
        try:
            connections = psutil_module.net_connections(kind="inet")
        except Exception as exc:  # noqa: BLE001 — psutil may require elevated privileges
            connections = []
            flow_error = type(exc).__name__
        process_name_cache: dict[int, str | None] = {}
        distinct_process_names: set[str] = set()
        model_flows: list[dict] = []
        observed_socket_flow_count = 0
        for conn in connections:
            local = _endpoint(getattr(conn, "laddr", None))
            remote = _endpoint(getattr(conn, "raddr", None))
            status = str(getattr(conn, "status", "UNKNOWN") or "UNKNOWN")[:32]
            state_counts[status] = state_counts.get(status, 0) + 1
            family = getattr(conn, "family", None)
            kind = getattr(conn, "type", None)
            protocol = "TCP" if kind == socket.SOCK_STREAM else "UDP" if kind == socket.SOCK_DGRAM else "OTHER"
            pid = getattr(conn, "pid", None)
            process_name = None
            if isinstance(pid, int) and pid > 0:
                if pid not in process_name_cache:
                    try:
                        process_name_cache[pid] = str(psutil_module.Process(pid).name())[:80]
                    except Exception:  # noqa: BLE001 — process may have exited, or access denied
                        process_name_cache[pid] = None
                process_name = process_name_cache[pid]
            if process_name:
                distinct_process_names.add(process_name)
            if not remote:
                continue
            observed_socket_flow_count += 1
            if len(model_flows) < _MAX_MODEL_FLOWS:
                model_flows.append({
                    "local_port": int(local[1]) if local else 0,
                    "remote_port": int(remote[1]),
                    "protocol": protocol,
                    "state": status,
                })
            try:
                parsed_remote = ipaddress.ip_address(remote[0])
                remote_ip = str(parsed_remote)
                if parsed_remote.is_loopback:
                    remote_scope = "loopback"
                elif parsed_remote.is_private:
                    remote_scope = "private"
                elif parsed_remote.is_global:
                    remote_scope = "public"
                else:
                    remote_scope = "reserved_or_special"
            except ValueError:
                remote_ip = remote[0][:64]
                remote_scope = "unknown"
            summary = remote_summary.setdefault(remote_ip, {
                "remote_ip": remote_ip, "connections": 0, "protocols": set(),
                "states": {}, "remote_ports": set(), "local_ports": set(),
                "connection_samples": [],
                "address_family": "IPv6" if family == socket.AF_INET6 else "IPv4",
                "remote_scope": remote_scope, "process_names": set(),
            })
            summary["connections"] += 1
            summary["protocols"].add(protocol)
            summary["states"][status] = summary["states"].get(status, 0) + 1
            summary["remote_ports"].add(remote[1])
            if len(summary["connection_samples"]) < 256:
                summary["connection_samples"].append({
                    "local_port": int(local[1]) if local else 0,
                    "remote_port": int(remote[1]),
                    "protocol": protocol,
                    "state": status,
                })
            if local:
                summary["local_ports"].add(local[1])
            if process_name:
                summary["process_names"].add(process_name)
        flows = []
        port_scan_suspected_count = 0
        suspicious_port_match_count = 0
        for remote_ip, summary in remote_summary.items():
            flow_id = hashlib.sha256(remote_ip.encode("utf-8", "replace")).hexdigest()[:12]
            previous_count = self._previous_remote_counts.get(remote_ip, 0)
            suspicious_hits = [
                {"port": port, "note": _SUSPICIOUS_REMOTE_PORTS[port]}
                for port in sorted(summary["remote_ports"]) if port in _SUSPICIOUS_REMOTE_PORTS
            ]
            port_scan_suspected = (len(summary["remote_ports"]) >= _PORT_SCAN_DISTINCT_PORTS_THRESHOLD
                                    or len(summary["local_ports"]) >= _PORT_SCAN_DISTINCT_PORTS_THRESHOLD)
            if port_scan_suspected:
                port_scan_suspected_count += 1
            if suspicious_hits:
                suspicious_port_match_count += 1
            flows.append({
                "id": flow_id, "remote_ip": remote_ip,
                "connection_count": summary["connections"],
                "new_connections_since_previous_sample": max(summary["connections"] - previous_count, 0)
                    if had_previous_sample else 0,
                "protocols": sorted(summary["protocols"]), "states": summary["states"],
                "distinct_remote_ports": len(summary["remote_ports"]),
                "remote_ports_sample": sorted(summary["remote_ports"])[:12],
                "connection_samples": summary["connection_samples"],
                "distinct_local_ports": len(summary["local_ports"]),
                "address_family": summary["address_family"],
                "remote_scope": summary["remote_scope"],
                "process_names": sorted(summary["process_names"])[:8],
                "suspicious_remote_ports": suspicious_hits,
                "port_scan_suspected": port_scan_suspected,
            })
        flows.sort(key=lambda item: (-item["connection_count"], item["remote_ip"]))
        previous_ips = set(self._previous_remote_counts)
        new_flows = ([item for item in flows
                      if item["remote_ip"] not in previous_ips
                      or item["new_connections_since_previous_sample"] > 0]
                     if had_previous_sample else [])
        current_counts = {ip: summary["connections"] for ip, summary in remote_summary.items()}
        previous_exists = had_previous_sample
        self._previous_remote_counts = current_counts
        return {
            "observed_at_utc": timestamp,
            "scope": "OS per-interface byte/packet counters and active TCP/UDP socket metadata; no packet payloads",
            "interface_counters_available": interface_error is None,
            "interface_error": interface_error,
            "interfaces": interfaces[:32],
            "connection_table_query_succeeded": flow_error is None,
            "connection_error": flow_error,
            "connection_coverage": "OS socket-table query result; not packet-level capture or a completeness guarantee.",
            "active_connection_count": len(connections),
            "connection_state_counts": state_counts,
            "remote_endpoint_count": len(flows),
            "new_remote_endpoints_since_previous_sample": sum(item["remote_ip"] not in previous_ips
                                                               for item in new_flows)
                if previous_exists else "baseline_sample",
            "new_connections_since_previous_sample": sum(item["new_connections_since_previous_sample"]
                                                          for item in new_flows) if previous_exists else "baseline_sample",
            "remote_endpoints": flows[:_MAX_FLOWS],
            # The classifier consumes this bounded, unaggregated socket list instead
            # of the UI's capped per-endpoint samples. If capped, scoring must abstain.
            "socket_flows": model_flows,
            "observed_socket_flow_count": observed_socket_flow_count,
            "socket_flow_limit": _MAX_MODEL_FLOWS,
            "socket_flow_truncated": observed_socket_flow_count > _MAX_MODEL_FLOWS,
            "new_remote_endpoints": new_flows[:_MAX_FLOWS],
            "new_flow_tracking_note": "A new record means newly visible to this sampler, not necessarily a newly opened socket.",
            "distinct_process_count": len(distinct_process_names),
            "process_attribution_note": "Имя процесса берётся из таблицы соединений ОС (psutil); может быть "
                                         "недоступно без прав администратора.",
            "suspicious_port_match_count": suspicious_port_match_count,
            "suspicious_port_note": "Локальный статический список портов, исторически связанных с "
                                     "бэкдорами/C2; совпадение — это контекст, не доказательство.",
            "port_scan_suspected_count": port_scan_suspected_count,
            "port_scan_threshold": _PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
            "traffic_anomaly": traffic_anomaly,
        }



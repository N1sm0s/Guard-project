"""Bounded, hourly DShield context for observed public IPv4 endpoints.

The feed is an external research signal, not a verdict. Matches are displayed
with provenance and are never a stand-alone reason to block traffic.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


FEED_URL = "https://feeds.dshield.org/feeds/block.txt"
ATTRIBUTION = "SANS Technology Institute, Internet Storm Center (DShield)"
REFRESH_SECONDS = 60 * 60
TIMEOUT_SECONDS = 8
MAX_FEED_BYTES = 1024 * 1024
EXPECTED_ENTRIES = 20
MAX_ENTRIES = 20
_CACHE_SCHEMA = 1


def _utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _parse_feed(raw: bytes) -> tuple[list[dict], int, bool]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FEED_BYTES:
        raise ValueError("invalid_feed_size")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid_feed_encoding") from exc
    if "DShield.org Recommended Block List" not in text:
        raise ValueError("unexpected_feed_identity")

    entries = []
    rejected = 0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            rejected += 1
            continue
        try:
            first = ipaddress.IPv4Address(fields[0].strip())
            last = ipaddress.IPv4Address(fields[1].strip())
            prefix = int(fields[2].strip())
            targets = int(fields[3].strip())
            if prefix != 24 or targets < 0 or targets > 2**32:
                raise ValueError
            network = ipaddress.IPv4Network(f"{first}/{prefix}", strict=True)
            if network.broadcast_address != last or not network.is_global:
                raise ValueError
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            rejected += 1
            continue
        entries.append({
            "cidr": network.with_prefixlen,
            "targets_reported": targets,
            "network_name": fields[4].strip()[:120] if len(fields) > 4 else "",
            "country": fields[5].strip()[:16] if len(fields) > 5 else "",
        })
        if len(entries) > MAX_ENTRIES:
            raise ValueError("too_many_feed_entries")
    if not entries:
        raise ValueError("no_valid_feed_entries")
    return entries, rejected, len(entries) != EXPECTED_ENTRIES or rejected > 0


def _fetch_feed() -> bytes:
    request = urllib.request.Request(
        FEED_URL,
        headers={"Accept": "text/plain", "User-Agent": "IntegrityGuard/1.0 (DShield context lookup)"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        final = urlparse(response.geturl())
        if final.scheme != "https" or final.hostname != "feeds.dshield.org":
            raise ValueError("feed_redirected_outside_dshield")
        body = response.read(MAX_FEED_BYTES + 1)
    if len(body) > MAX_FEED_BYTES:
        raise ValueError("feed_too_large")
    return body


def _read_cache(path: Path) -> dict:
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict) or value.get("schema") != _CACHE_SCHEMA:
        return {}
    entries = value.get("entries")
    checked_at = value.get("checked_at_epoch")
    attempted_at = value.get("last_attempt_epoch")
    if not isinstance(entries, list) or not isinstance(attempted_at, (int, float)) \
            or not math.isfinite(float(attempted_at)):
        return {}
    if checked_at is not None and (not isinstance(checked_at, (int, float))
                                   or not math.isfinite(float(checked_at))):
        return {}
    valid = []
    for item in entries[:MAX_ENTRIES]:
        if not isinstance(item, dict):
            continue
        try:
            network = ipaddress.IPv4Network(item.get("cidr"), strict=True)
            targets = int(item.get("targets_reported"))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError, ValueError):
            continue
        if network.prefixlen != 24 or not network.is_global or targets < 0:
            continue
        valid.append({"cidr": network.with_prefixlen, "targets_reported": targets,
                      "network_name": str(item.get("network_name", ""))[:120],
                      "country": str(item.get("country", ""))[:16]})
    try:
        rejected_rows = max(0, int(value.get("rejected_rows", 0)))
    except (TypeError, ValueError):
        rejected_rows = 1
    digest = value.get("sha256")
    if valid and (checked_at is None or not isinstance(digest, str) or len(digest) != 64):
        return {}
    if not valid and checked_at is not None:
        return {}
    return {"schema": _CACHE_SCHEMA,
            "checked_at_epoch": float(checked_at) if checked_at is not None else None,
            "last_attempt_epoch": float(attempted_at),
            "sha256": digest, "entries": valid,
            "rejected_rows": rejected_rows,
            "partial": bool(value.get("partial", len(valid) != EXPECTED_ENTRIES or rejected_rows > 0)),
            "last_error": str(value.get("last_error", ""))[:80]}


def _write_cache(path: Path, value: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.flush()
        temp_path.replace(path)
    except OSError:
        pass  # Telemetry must remain usable when local caching is unavailable.


def lookup_dshield(remote_endpoints: list[dict], cache_path: Path,
                   *, now: float | None = None, fetcher=None) -> dict:
    """Enrich observed IPs from DShield's public top-20 /24 feed, at most hourly.

    Local endpoint IPs are only matched against the cached feed and are never
    transmitted to DShield. The public response is cached with its hash/time.
    """
    now = time.time() if now is None else float(now)
    observed: dict[str, str] = {}
    for item in remote_endpoints[:40] if isinstance(remote_endpoints, list) else []:
        if not isinstance(item, dict):
            continue
        value = item.get("remote_ip")
        endpoint_id = item.get("id")
        try:
            address = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            continue
        if address.version == 4 and address.is_global:
            observed[str(address)] = str(endpoint_id)[:32] if isinstance(endpoint_id, str) else ""

    result_base = {"source": ATTRIBUTION, "source_url": FEED_URL,
                   "attribution_required": True,
                   "description": "Top 20 reported attacking /24 networks over the last three days; contextual signal only.",
                   "policy": "No automatic blocking; a match is not proof that this observed connection is malicious.",
                   "signature_verified": False}
    if not observed:
        return {**result_base, "status": "not_checked_no_public_ipv4", "checked_at_utc": None,
                "age_seconds": None, "feed_sha256": None, "network_entries_count": 0,
                "matches": [], "refresh_error": None}

    path = Path(cache_path)
    cache = _read_cache(path)
    last_attempt = cache.get("last_attempt_epoch", 0.0)
    should_fetch = not cache or now - last_attempt >= REFRESH_SECONDS
    refresh_error = cache.get("last_error") or None
    if should_fetch:
        attempt = fetcher or _fetch_feed
        try:
            raw = attempt()
            entries, rejected, partial = _parse_feed(raw)
            cache = {"schema": _CACHE_SCHEMA, "checked_at_epoch": now,
                     "last_attempt_epoch": now, "sha256": hashlib.sha256(raw).hexdigest(),
                     "entries": entries, "rejected_rows": rejected, "partial": partial, "last_error": ""}
            _write_cache(path, cache)
            refresh_error = None
        except Exception as exc:  # external feed failure must not disable the local sensor
            refresh_error = type(exc).__name__
            if cache:
                cache["last_attempt_epoch"] = now
                cache["last_error"] = refresh_error
            else:
                cache = {"schema": _CACHE_SCHEMA, "checked_at_epoch": None,
                         "last_attempt_epoch": now, "sha256": None, "entries": [],
                         "rejected_rows": 0, "partial": True, "last_error": refresh_error}
            _write_cache(path, cache)
    elif cache:
        refresh_error = cache.get("last_error") or None

    if not cache or not cache.get("entries") or cache.get("checked_at_epoch") is None:
        return {**result_base, "status": "unavailable", "checked_at_utc": None,
                "age_seconds": None, "feed_sha256": None, "network_entries_count": 0,
                "matches": [], "refresh_error": refresh_error or "NoCachedFeed"}

    age = max(0, int(now - cache["checked_at_epoch"]))
    status = "current" if age <= REFRESH_SECONDS else "stale"
    if cache["partial"] and status == "current":
        status = "partial"
    matches = []
    parsed_networks = [(ipaddress.IPv4Network(item["cidr"]), item) for item in cache["entries"]]
    for address, endpoint_id in sorted(observed.items()):
        parsed_address = ipaddress.IPv4Address(address)
        for network, item in parsed_networks:
            if parsed_address in network:
                matches.append({"endpoint_id": endpoint_id, "remote_ip": address,
                                "cidr": item["cidr"], "targets_reported": item["targets_reported"],
                                "network_name": item["network_name"], "country": item["country"]})
    return {**result_base, "status": status, "checked_at_utc": _utc(cache["checked_at_epoch"]),
            "age_seconds": age, "feed_sha256": cache["sha256"],
            "network_entries_count": len(cache["entries"]), "rejected_rows": cache["rejected_rows"],
            "feed_partial": cache["partial"], "coverage_complete": status == "current",
            "matches": matches, "refresh_error": refresh_error}

"""Read-only lookups of public vulnerability facts for declared public dependencies.

Only dependencies explicitly marked as PyPI are sent to OSV. Package source,
model weights, and module contents are never transmitted. A no-hit response is
not evidence that a package is safe.
"""
from __future__ import annotations

import concurrent.futures
import json
import re
import time
from urllib.parse import quote
import urllib.error
import urllib.request
from pathlib import Path

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
QUERY_CACHE_SECONDS = 24 * 60 * 60
DETAIL_CACHE_SECONDS = 7 * 24 * 60 * 60
MAX_QUERIES = 500
CHUNK_SIZE = 100
MAX_DETAILS = 100
TIMEOUT_SECONDS = 6
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}$")


def _key(name: str, version: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return f"PyPI:{normalized}@{version}"


def _public_query(dep) -> dict | None:
    name, version, source = (str(getattr(dep, key, "")).strip()
                             for key in ("name", "version", "source"))
    if source.lower() != "pypi" or not _PYPI_NAME.fullmatch(name) or not _VERSION.fullmatch(version):
        return None
    return {"package": {"ecosystem": "PyPI", "name": re.sub(r"[-_.]+", "-", name).lower()},
            "version": version}


def _request(url: str, *, payload: dict | None = None) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url, data=data,
        headers={"Accept": "application/json", "User-Agent": "IntegrityGuard/1.0 (public-vulnerability-lookup)",
                 **({"Content-Type": "application/json"} if data is not None else {})},
        method="POST" if data is not None else "GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("OSV response exceeded the 8 MiB limit")
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("OSV returned a non-object JSON response")
    return value


def _read_cache(path: Path) -> dict:
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_cache(path: Path, value: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
        temporary.replace(path)
    except OSError:
        # Cache failure must not prevent the package from being evaluated.
        pass


def _prune_cache(mapping: dict, now: float, ttl: int, limit: int) -> dict:
    kept = []
    for key, item in mapping.items():
        try:
            checked = float(item.get("checked_at", 0))
        except (AttributeError, TypeError, ValueError):
            continue
        if 0 <= now - checked <= ttl:
            kept.append((checked, key, item))
    kept.sort(key=lambda row: row[0])
    return {key: item for _checked, key, item in kept[-limit:]}


def _compact_vulnerability(value: dict) -> dict:
    affected = []
    for item in value.get("affected", [])[:20]:
        package = item.get("package") or {}
        severity = []
        for source in (item.get("ecosystem_specific") or {}, item.get("database_specific") or {}):
            for key in ("severity", "cvss", "cvss_score"):
                if source.get(key) is not None:
                    severity.append({key: str(source[key])[:200]})
        ranges = []
        for version_range in item.get("ranges", [])[:10]:
            events = []
            for event in version_range.get("events", [])[:10]:
                events.append({str(key)[:32]: str(boundary)[:128]
                               for key, boundary in event.items() if isinstance(boundary, (str, int, float))})
            ranges.append({"type": str(version_range.get("type", ""))[:40], "events": events})
        affected.append({"package": package.get("name"), "ecosystem": package.get("ecosystem"),
                         "ranges": ranges, "severity": severity})
    return {"id": str(value.get("id", ""))[:120], "summary": str(value.get("summary", ""))[:500],
            "aliases": [str(item)[:120] for item in value.get("aliases", [])[:20]],
            "published": value.get("published"), "modified": value.get("modified"),
            "withdrawn": value.get("withdrawn"), "affected": affected,
            "references": [{"type": ref.get("type"), "url": ref.get("url")}
                           for ref in value.get("references", [])[:20] if isinstance(ref, dict)],
            "url": "https://osv.dev/vulnerability/" + str(value.get("id", ""))}


def lookup_pypi_dependencies(dependencies, cache_path) -> dict:
    """Return OSV matches and lookup coverage without producing a risk score.

    Results are per declared dependency. Cached query matches live for one day;
    vulnerability details live for seven days and are refreshed when OSV's
    `modified` timestamp changes. Network errors are returned as coverage state.
    """
    entries, seen = [], set()
    skipped = 0
    for dep in dependencies:
        query = _public_query(dep)
        if query is None:
            skipped += 1
            continue
        name, version = query["package"]["name"], query["version"]
        key = _key(name, version)
        if key not in seen:
            entries.append((key, name, version, query))
            seen.add(key)

    now = time.time()
    cache = _read_cache(Path(cache_path))
    queries_cache = cache.setdefault("queries", {})
    details_cache = cache.setdefault("details", {})
    results: dict[str, list[dict]] = {}
    pending = []
    for key, name, version, query in entries:
        saved = queries_cache.get(key, {})
        if now - float(saved.get("checked_at", 0)) <= QUERY_CACHE_SECONDS:
            results[key] = list(saved.get("vulns", []))
        else:
            pending.append((key, name, version, query))

    issues = []
    partial = len(entries) > MAX_QUERIES
    pending = pending[:MAX_QUERIES]
    for start in range(0, len(pending), CHUNK_SIZE):
        chunk = pending[start:start + CHUNK_SIZE]
        try:
            response = _request(OSV_QUERYBATCH, payload={"queries": [item[3] for item in chunk]})
            batch_results = response.get("results")
            if not isinstance(batch_results, list) or len(batch_results) != len(chunk):
                raise ValueError("OSV querybatch result count did not match request")
            for item, result in zip(chunk, batch_results):
                key = item[0]
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                compact_ids = [{"id": str(v.get("id", ""))[:120], "modified": v.get("modified")}
                               for v in vulns if isinstance(v, dict) and v.get("id")]
                results[key] = compact_ids
                queries_cache[key] = {"checked_at": now, "vulns": compact_ids}
                if isinstance(result, dict) and result.get("next_page_token"):
                    partial = True
        except (OSError, ValueError, urllib.error.URLError, TimeoutError) as error:
            issues.append(str(error)[:300])
            break

    ids = {}
    for vulns in results.values():
        for vuln in vulns:
            if vuln.get("id"):
                ids[vuln["id"]] = vuln.get("modified")
    fetch_ids = []
    findings: dict[str, dict] = {}
    for vuln_id, modified in ids.items():
        cached = details_cache.get(vuln_id, {})
        if (cached.get("modified") == modified
                and now - float(cached.get("checked_at", 0)) <= DETAIL_CACHE_SECONDS):
            findings[vuln_id] = cached.get("value", {"id": vuln_id, "url": OSV_VULN.format(vuln_id)})
        elif len(fetch_ids) < MAX_DETAILS:
            fetch_ids.append(vuln_id)
        else:
            partial = True

    if fetch_ids:
        def fetch(vuln_id):
            return vuln_id, _compact_vulnerability(_request(OSV_VULN.format(quote(vuln_id, safe=""))))

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for future in concurrent.futures.as_completed([pool.submit(fetch, item) for item in fetch_ids]):
                try:
                    vuln_id, value = future.result()
                    findings[vuln_id] = value
                    details_cache[vuln_id] = {"checked_at": now, "modified": value.get("modified"), "value": value}
                except Exception as error:  # isolate unavailable detail records from other matches
                    issues.append(str(error)[:300])

    by_dependency = []
    matched = 0
    for key, name, version, _query in entries:
        matches = []
        for item in results.get(key, []):
            value = findings.get(item.get("id"), {"id": item.get("id"), "modified": item.get("modified"),
                                                    "url": "https://osv.dev/vulnerability/" + item.get("id", "")})
            if value.get("withdrawn"):
                continue
            matches.append(value)
        if matches:
            matched += 1
            by_dependency.append({"name": name, "version": version, "vulnerabilities": matches})

    cache["queries"] = _prune_cache(queries_cache, now, 30 * 24 * 60 * 60, 5000)
    cache["details"] = _prune_cache(details_cache, now, 90 * 24 * 60 * 60, 5000)
    _write_cache(Path(cache_path), cache)
    status = "unavailable" if issues and not results else "partial" if issues or partial else "complete"
    return {"source": "OSV", "source_url": "https://osv.dev/", "status": status,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "queried": min(len(entries), MAX_QUERIES) if status != "unavailable" else 0,
            "eligible": len(entries), "skipped_non_pypi_or_invalid": skipped,
            "known_vulnerable_dependencies": matched, "findings": by_dependency,
            "coverage_complete": status == "complete", "limitations": list(dict.fromkeys(issues))[:5]}

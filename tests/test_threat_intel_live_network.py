"""Real-network smoke test for threat_intel.lookup_pypi_dependencies().

test_threat_intel.py exercises the module's logic (request shaping, caching,
error handling, integration with IntegrityGuard.check()) entirely through a
monkeypatched `_request`, so it never actually calls the real OSV service.
threat_intel is the only module in this project that reaches the network, so
this file adds one real call against the live OSV API (https://api.osv.dev/)
to confirm the request/response contract still matches production.

This is deliberately separate from test_threat_intel.py's fast, offline unit
tests: it depends on outbound network access and a third-party service being
reachable, so it skips (rather than fails) when that's not the case -- a
network-dependent smoke test should never turn an unrelated CI run red.
"""
from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from integrityguard import threat_intel
from integrityguard.spec import Dep

# Jinja2 2.4.1 has a long-published, stable OSV advisory (PYSEC-2014-8 /
# CVE-2014-0012): an old enough, well-known record that is very unlikely to
# ever be withdrawn, making it a stable "known vulnerable" live fixture.
_KNOWN_VULNERABLE = Dep("Jinja2", "2.4.1", "", "pypi")


def _skip_if_network_unavailable():
    try:
        urllib.request.urlopen("https://api.osv.dev/v1/vulns/PYSEC-2014-8", timeout=6)
    except urllib.error.URLError as error:
        pytest.skip(f"OSV (api.osv.dev) is not reachable from this environment: {error}")
    except OSError as error:
        pytest.skip(f"network error reaching OSV (api.osv.dev): {error}")


def test_live_osv_lookup_finds_known_advisory_for_a_real_package(tmp_path):
    _skip_if_network_unavailable()
    cache_path = tmp_path / "osv-cache.json"

    result = threat_intel.lookup_pypi_dependencies([_KNOWN_VULNERABLE], cache_path)

    assert result["source"] == "OSV"
    assert result["status"] in ("complete", "partial")
    assert result["eligible"] == 1 and result["skipped_non_pypi_or_invalid"] == 0
    assert result["known_vulnerable_dependencies"] == 1
    assert result["findings"], "expected at least one real OSV finding for Jinja2 2.4.1"
    finding = result["findings"][0]
    assert finding["name"] == "jinja2"
    ids = {vuln["id"] for vuln in finding["vulnerabilities"]}
    assert any(vuln_id.startswith("PYSEC-") or vuln_id.startswith("GHSA-") for vuln_id in ids), ids
    # Real detail records fetched from OSV must carry a real advisory URL and summary.
    detail = finding["vulnerabilities"][0]
    assert detail["url"].startswith("https://osv.dev/vulnerability/")

    # A second call for the same dependency must be served entirely from the
    # on-disk cache -- no further network traffic.
    import urllib.request as _urllib_request
    original_urlopen = _urllib_request.urlopen

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("cached lookup must not hit the network again")

    _urllib_request.urlopen = fail_if_called
    try:
        cached = threat_intel.lookup_pypi_dependencies([_KNOWN_VULNERABLE], cache_path)
    finally:
        _urllib_request.urlopen = original_urlopen
    assert cached["findings"] == result["findings"]


def test_live_osv_lookup_reports_no_known_advisories_for_an_unremarkable_version(tmp_path):
    _skip_if_network_unavailable()
    cache_path = tmp_path / "osv-cache.json"
    # A real, currently-maintained package/version pair with no expected advisories.
    # (Absence of a hit is not proof of safety -- threat_intel documents this itself --
    # this only confirms the real round trip to OSV completes cleanly for a clean case.)
    clean_dep = Dep("packaging", "24.0", "", "pypi")

    result = threat_intel.lookup_pypi_dependencies([clean_dep], cache_path)

    assert result["status"] in ("complete", "partial")
    assert result["eligible"] == 1
    assert isinstance(result["known_vulnerable_dependencies"], int)
    assert result["coverage_complete"] == (result["status"] == "complete")

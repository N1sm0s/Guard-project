from integrityguard import threat_intel
from integrityguard.collect import save_package
from integrityguard.spec import Dep
from integrityguard.system import IntegrityGuard
from test_unbaselined import MODEL, package_spec


def test_osv_queries_only_explicit_public_pypi_dependencies_and_caches_details(tmp_path, monkeypatch):
    calls = []

    def fake_request(url, payload=None):
        calls.append((url, payload))
        if url == threat_intel.OSV_QUERYBATCH:
            assert payload == {"queries": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                                             "version": "2.4.1"}]}
            return {"results": [{"vulns": [{"id": "PYSEC-2014-8", "modified": "2024-01-01T00:00:00Z"}]}]}
        return {"id": "PYSEC-2014-8", "summary": "Known advisory", "modified": "2024-01-01T00:00:00Z",
                "affected": [], "references": []}

    monkeypatch.setattr(threat_intel, "_request", fake_request)
    deps = [Dep("Jinja2", "2.4.1", "", "pypi"), Dep("private-wheel", "1.0", "", "internal")]
    cache = tmp_path / "osv.json"

    first = threat_intel.lookup_pypi_dependencies(deps, cache)
    assert first["status"] == "complete"
    assert first["queried"] == 1 and first["skipped_non_pypi_or_invalid"] == 1
    assert first["findings"][0]["vulnerabilities"][0]["id"] == "PYSEC-2014-8"
    assert len(calls) == 2

    calls.clear()
    second = threat_intel.lookup_pypi_dependencies(deps, cache)
    assert second["findings"] == first["findings"]
    assert calls == []


def test_osv_network_failure_is_reported_as_unavailable_not_clean(tmp_path, monkeypatch):
    import urllib.error

    def fail(*_args, **_kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(threat_intel, "_request", fail)
    result = threat_intel.lookup_pypi_dependencies([Dep("jinja2", "2.4.1", "", "pypi")], tmp_path / "cache.json")

    assert result["status"] == "unavailable"
    assert result["coverage_complete"] is False
    assert result["known_vulnerable_dependencies"] == 0
    assert result["findings"] == []
    assert result["limitations"]


def test_osv_match_is_a_separate_review_finding_without_baseline_score(tmp_path):
    spec = package_spec(9101)
    spec.deps = [Dep("jinja2", "2.4.1", "", "pypi")]
    package = tmp_path / "unbaselined"
    save_package(spec, package)
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key")
    guard._public_intel = lambda _deps: {
        "source": "OSV", "status": "complete", "queried": 1, "eligible": 1,
        "known_vulnerable_dependencies": 1,
        "findings": [{"name": "jinja2", "version": "2.4.1", "vulnerabilities": [
            {"id": "PYSEC-2014-8", "summary": "Known advisory", "url": "https://osv.dev/vulnerability/PYSEC-2014-8"}]}],
        "coverage_complete": True, "limitations": []}

    event = guard.check(package)

    assert event["verdict"] == "REVIEW"
    assert event["analysis_mode"] == "reference_missing"
    assert event["score"] is None and event["risk_score"] is None
    assert event["policy_findings"] == ["known_vulnerable_dependency"]
    assert "PYSEC-2014-8" in " ".join(event["rules"])
    assert event["objective_facts"]["public_intel_status"] == "complete"


def test_known_advisory_overrides_exact_baseline_allow_but_not_detector_score(tmp_path):
    package = tmp_path / "pkg"
    save_package(package_spec(9102), package, key=b"test-signing-key")
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key")
    guard.register_baseline(package)
    guard._public_intel = lambda _deps: {
        "source": "OSV", "status": "complete", "queried": 1, "eligible": 1,
        "known_vulnerable_dependencies": 1,
        "findings": [{"name": "jinja2", "version": "2.4.1", "vulnerabilities": [
            {"id": "PYSEC-2014-8", "summary": "Known advisory", "url": "https://osv.dev/vulnerability/PYSEC-2014-8"}]}],
        "coverage_complete": True, "limitations": []}

    event = guard.check(package)

    assert event["baseline_match"] is True
    assert event["verdict"] == "REVIEW"
    assert event["score"] == 0.0 and event["risk_score"] == 0
    assert event["policy_findings"] == ["known_vulnerable_dependency"]

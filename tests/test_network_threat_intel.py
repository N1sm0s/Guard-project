from integrityguard.network_threat_intel import REFRESH_SECONDS, lookup_dshield


_FEED = ("# DShield.org Recommended Block List\n# Columns (tab delimited)\n" + "\n".join(
    f"198.235.{24 + index}.0\t198.235.{24 + index}.255\t24\t{123 - index}\tNET-{index}\tUS\tNone"
    for index in range(20)
)).encode("utf-8")


def test_dshield_feed_is_attributed_matched_locally_and_cached_hourly(tmp_path):
    calls = []

    def fetch():
        calls.append("fetch")
        return _FEED

    endpoints = [{"id": "flow-1", "remote_ip": "198.235.24.19"},
                 {"id": "flow-2", "remote_ip": "192.168.1.4"}]
    cache = tmp_path / "dshield.json"
    first = lookup_dshield(endpoints, cache, now=10_000, fetcher=fetch)
    assert first["status"] == "current"
    assert first["coverage_complete"] is True
    assert first["attribution_required"] is True
    assert first["signature_verified"] is False
    assert first["policy"].startswith("No automatic blocking")
    assert first["matches"] == [{
        "endpoint_id": "flow-1", "remote_ip": "198.235.24.19", "cidr": "198.235.24.0/24",
        "targets_reported": 123, "network_name": "NET-0", "country": "US",
    }]
    cached = lookup_dshield(endpoints, cache, now=10_000 + 600,
                            fetcher=lambda: (_ for _ in ()).throw(AssertionError("feed fetched too soon")))
    assert cached["feed_sha256"] == first["feed_sha256"]
    assert len(calls) == 1


def test_stale_feed_is_retained_when_hourly_refresh_fails(tmp_path):
    cache = tmp_path / "dshield.json"
    lookup_dshield([{"id": "flow-1", "remote_ip": "198.235.24.19"}], cache,
                   now=20_000, fetcher=lambda: _FEED)
    stale = lookup_dshield(
        [{"id": "flow-1", "remote_ip": "198.235.24.19"}], cache,
        now=20_000 + REFRESH_SECONDS + 1,
        fetcher=lambda: (_ for _ in ()).throw(TimeoutError("offline")),
    )
    assert stale["status"] == "stale"
    assert stale["refresh_error"] == "TimeoutError"
    assert stale["matches"][0]["cidr"] == "198.235.24.0/24"


def test_private_or_invalid_endpoints_do_not_trigger_public_feed_request(tmp_path):
    result = lookup_dshield(
        [{"id": "private", "remote_ip": "10.0.0.5"}, {"id": "invalid", "remote_ip": "not-an-ip"}],
        tmp_path / "dshield.json", now=30_000,
        fetcher=lambda: (_ for _ in ()).throw(AssertionError("feed fetched without public IPv4")),
    )
    assert result["status"] == "not_checked_no_public_ipv4"
    assert result["matches"] == []


def test_invalid_feed_is_not_cached_or_used(tmp_path):
    result = lookup_dshield(
        [{"id": "flow-1", "remote_ip": "198.235.24.19"}], tmp_path / "dshield.json",
        now=40_000, fetcher=lambda: b"not the DShield feed",
    )
    assert result["status"] == "unavailable"
    assert result["refresh_error"] == "ValueError"
    assert result["matches"] == []


def test_short_valid_feed_is_marked_partial_not_complete(tmp_path):
    short_feed = b"""# DShield.org Recommended Block List
198.235.24.0\t198.235.24.255\t24\t123\tNET\tUS\tNone
"""
    result = lookup_dshield(
        [{"id": "flow-1", "remote_ip": "198.235.24.19"}], tmp_path / "dshield.json",
        now=45_000, fetcher=lambda: short_feed,
    )
    assert result["status"] == "partial"
    assert result["feed_partial"] is True
    assert result["coverage_complete"] is False
    assert len(result["matches"]) == 1


def test_failed_initial_fetch_is_rate_limited_for_one_hour(tmp_path):
    cache = tmp_path / "dshield.json"
    first = lookup_dshield(
        [{"id": "flow-1", "remote_ip": "198.235.24.19"}], cache,
        now=50_000, fetcher=lambda: (_ for _ in ()).throw(TimeoutError("offline")),
    )
    assert first["status"] == "unavailable"

    second = lookup_dshield(
        [{"id": "flow-1", "remote_ip": "198.235.24.19"}], cache,
        now=50_000 + 30,
        fetcher=lambda: (_ for _ in ()).throw(AssertionError("feed retried before hourly interval")),
    )
    assert second["status"] == "unavailable"
    assert second["refresh_error"] == "TimeoutError"

from integrityguard.check_hints import hints


def test_no_features_gives_no_hints():
    assert hints(None) == []
    assert hints({}) == []


def test_quiet_snapshot_gives_no_hints():
    assert hints({"port_scan_suspected_count": 0, "packet_rate_zscore": 0.5,
                  "non_https_endpoint_share": 0.1}) == []


def test_firing_rules_explain_the_feature_value():
    found = hints({"port_scan_suspected_count": 2, "packet_rate_zscore": -4.0,
                   "new_remote_endpoint_count": 3})
    names = [item["feature"] for item in found]
    assert names == ["port_scan_suspected_count", "packet_rate_zscore"]
    assert found[0]["value"] == 2.0
    assert "перебор портов" in found[0]["reason"]


def test_non_numeric_values_are_ignored():
    assert hints({"port_scan_suspected_count": "много"}) == []

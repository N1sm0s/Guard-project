"""Stream ingest can write schema v11 shards (v10 flow features plus 5 context features)."""
import io
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrityguard import network_flow_schema_v10 as v10
from integrityguard import network_flow_schema_v11 as v11
from integrityguard import stream_ingest as si
from tests.test_stream_ingest import _frame, _pcap, _session, _rule


def test_v11_shard_has_context_features_and_loads(tmp_path):
    src = tmp_path / "c.pcap"
    src.write_bytes(_pcap(_session()))
    rule = _rule(tmp_path, default="benign")
    manifest = si.ingest_capture(source=str(src), source_id="v11", role="dev", label_rule_path=rule,
                                 out_dir=tmp_path / "out", feature_version=11)
    assert manifest["feature_version"] == 11
    assert len(manifest["feature_names"]) == len(v10.FEATURE_NAMES) + len(v11.CONTEXT_NAMES)
    x, y, loaded = si.load_shard(tmp_path / "out" / "v11.manifest.json", expected_role="dev")
    assert x.shape[1] == len(v11.FEATURE_NAMES)
    assert np.isfinite(x).all()


def test_v10_default_is_unchanged(tmp_path):
    src = tmp_path / "c.pcap"
    src.write_bytes(_pcap(_session()))
    rule = _rule(tmp_path, default="benign")
    manifest = si.ingest_capture(source=str(src), source_id="v10", role="dev", label_rule_path=rule,
                                 out_dir=tmp_path / "out")
    assert manifest["feature_version"] == 10
    x, _, _ = si.load_shard(tmp_path / "out" / "v10.manifest.json", expected_role="dev")
    assert x.shape[1] == len(v10.FEATURE_NAMES)

"""Append-only operational measurements for real network sensor/model runs.

These records measure runtime behavior only. They are never training labels or
evidence of detector accuracy, target-load coverage, or packet completeness.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

_ZERO_HASH = "0" * 64


def record_packet_capture_segment(path: str | Path, *, observed_at_utc: str,
                                  capture: dict, assessment: dict | None = None) -> str:
    """Persist a payload-free result for every real Pktmon attempt."""
    counts = capture.get("counts") if isinstance(capture.get("counts"), dict) else {}
    assessment = assessment if isinstance(assessment, dict) else {}
    payload = {
        "observed_at_utc": str(observed_at_utc),
        "capture_status": str(capture.get("status", "unknown"))[:64],
        "capture_reason": str(capture.get("reason", ""))[:400],
        "capture_interval_seconds": capture.get("capture_interval_seconds"),
        "capture_sha256": capture.get("capture_sha256"),
        "packets_seen": counts.get("packets"),
        "parsed_packets": counts.get("parsed"),
        "non_ip_frames": counts.get("non_ip_frames"),
        "unsupported_or_truncated": counts.get("unsupported_or_truncated"),
        "complete_flow_count": capture.get("complete_flow_count"),
        "drop_counters_available": bool(capture.get("drop_counters_available")),
        "counter_snapshot_sha256": capture.get("pktmon_counter_snapshot_sha256"),
        "model_status": assessment.get("status"),
        "flows_scored": assessment.get("scored_flows"),
        "inference_ms": assessment.get("inference_latency_ms"),
        "candidate_sha256": assessment.get("checkpoint_sha256"),
        "feature_version": assessment.get("feature_version"),
        "dataset_manifest_sha256": assessment.get("dataset_manifest_sha256"),
        "threshold": assessment.get("threshold"),
    }
    for key in ("packets_seen", "parsed_packets", "non_ip_frames",
                "unsupported_or_truncated", "complete_flow_count", "flows_scored"):
        value = payload[key]
        if value is not None and (not isinstance(value, int) or value < 0):
            payload[key] = None
    for key in ("inference_ms", "threshold"):
        value = payload[key]
        if value is not None:
            try:
                payload[key] = float(value)
            except (TypeError, ValueError):
                payload[key] = None

    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path, timeout=30, isolation_level=None)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS packet_capture_segments (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE
            );
            CREATE TRIGGER IF NOT EXISTS packet_segments_no_update
            BEFORE UPDATE ON packet_capture_segments
            BEGIN SELECT RAISE(ABORT, 'capture evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS packet_segments_no_delete
            BEFORE DELETE ON packet_capture_segments
            BEGIN SELECT RAISE(ABORT, 'capture evidence is append-only'); END;
        """)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT record_hash FROM packet_capture_segments ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else _ZERO_HASH
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256((previous + payload_json).encode("utf-8")).hexdigest()
        db.execute("INSERT INTO packet_capture_segments(payload_json,previous_hash,record_hash) VALUES(?,?,?)",
                   (payload_json, previous, digest))
        db.commit()
    return digest


def record_captured_flows(path: str | Path, *, segment_hash: str,
                          observed_at_utc: str, flows: list[dict],
                          max_flows: int = 50_000) -> dict:
    """Persist payload-free flow facts before inference; labels remain unknown.

    This is an operational evidence journal, not a training-label source. Each
    flow is linked to the hash-chained capture segment and gets its own chain
    entry. Model scores are deliberately excluded.
    """
    if (not isinstance(segment_hash, str) or len(segment_hash) != 64
            or any(c not in "0123456789abcdef" for c in segment_hash.lower())):
        raise ValueError("Invalid capture segment hash")
    if not isinstance(flows, list) or not isinstance(max_flows, int) or max_flows < 1:
        raise ValueError("Invalid flow collection")
    # The runtime gate must be able to prove that at least one completed flow
    # was persisted when a segment contains more flows than the journal cap.
    # Keep original order within each group, but reserve capacity for complete
    # flows first; incomplete rows remain explicitly marked and unlabeled.
    ordered = sorted(enumerate(flows),
                     key=lambda item: (not (isinstance(item[1], dict)
                                           and item[1].get("complete") is True), item[0]))
    selected = [flow for _index, flow in ordered[:max_flows]]
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with closing(sqlite3.connect(db_path, timeout=30, isolation_level=None)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS captured_flows (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                segment_hash TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL,
                flow_json TEXT NOT NULL,
                label_status TEXT NOT NULL CHECK(label_status='unknown'),
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS captured_flows_segment_idx
                ON captured_flows(segment_hash);
            CREATE TRIGGER IF NOT EXISTS captured_flows_no_update
            BEFORE UPDATE ON captured_flows
            BEGIN SELECT RAISE(ABORT, 'captured flow evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS captured_flows_no_delete
            BEFORE DELETE ON captured_flows
            BEGIN SELECT RAISE(ABORT, 'captured flow evidence is append-only'); END;
        """)
        db.execute("BEGIN IMMEDIATE")
        segment_row = db.execute(
            "SELECT payload_json FROM packet_capture_segments WHERE record_hash=?", (segment_hash,)
        ).fetchone()
        if not segment_row:
            db.rollback()
            raise ValueError("Capture segment hash is not present in the local evidence chain")
        try:
            segment_payload = json.loads(segment_row[0])
        except (TypeError, json.JSONDecodeError) as error:
            db.rollback()
            raise ValueError("Capture segment payload is invalid") from error
        if segment_payload.get("capture_status") not in ("ok", "parsed_best_effort", "incomplete"):
            db.rollback()
            raise ValueError("Captured flows may only link to parsed or explicitly incomplete segments")
        prior = db.execute("SELECT record_hash FROM captured_flows ORDER BY seq DESC LIMIT 1").fetchone()
        previous = prior[0] if prior else _ZERO_HASH
        for flow in selected:
            if not isinstance(flow, dict):
                continue
            # Keep correlation fields and model inputs only. No packet payload,
            # prediction, or inferred label is written to this journal.
            fact = {}
            for key in ("protocol", "originator_ip", "originator_port", "responder_ip",
                        "responder_port", "first_seen", "last_seen", "duration_seconds",
                        "total_packets", "total_bytes", "direction_a_bytes",
                        "direction_b_bytes", "saw_syn", "saw_syn_ack", "saw_ack",
                        "saw_fin", "saw_rst", "complete", "completion_reason", "features",
                        "features_v10", "features_v11"):
                value = flow.get(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    fact[key] = value
                elif isinstance(value, (list, tuple)) and len(value) <= 256:
                    fact[key] = list(value)
            flow_json = json.dumps(fact, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                   allow_nan=False)
            payload = {"segment_hash": segment_hash, "observed_at_utc": str(observed_at_utc),
                       "flow": fact, "label_status": "unknown", "previous_hash": previous}
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
            db.execute("""INSERT INTO captured_flows
                (segment_hash,observed_at_utc,flow_json,label_status,previous_hash,record_hash)
                VALUES(?,?,?,'unknown',?,?)""",
                       (segment_hash, str(observed_at_utc), flow_json, previous, digest))
            previous = digest
            written += 1
        db.commit()
    return {"stored_flow_count": written, "omitted_flow_count": max(0, len(flows) - written),
            "labels": "unknown", "predictions_persisted": False}


def recent_captured_flows(path: str | Path, *, limit: int = 200) -> dict:
    """Read recent complete, unknown-label flows for live-chart reconstruction.

    This verifies the append-only runtime journals, links each row to a parsed
    capture, and never turns a score into a label. Scores are recomputed by the
    active candidate in the UI; this is only a display cache after app restart.
    """
    if not isinstance(limit, int) or limit < 1 or limit > 2000:
        raise ValueError("Invalid recent-flow limit")
    summary = runtime_summary(path)
    if (summary.get("integrity_valid") is not True
            or summary.get("capture_integrity_valid") is not True
            or summary.get("captured_flow_integrity_valid") is not True):
        return {"status": "integrity_unverified", "flows": []}
    db_path = Path(path)
    if not db_path.is_file():
        return {"status": "empty", "flows": []}
    flows = []
    try:
        with closing(sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True,
                                     timeout=10)) as db:
            rows = db.execute("""
                SELECT f.flow_json, f.label_status, s.payload_json
                FROM captured_flows AS f
                JOIN packet_capture_segments AS s ON s.record_hash=f.segment_hash
                ORDER BY f.seq DESC LIMIT ?
            """, (max(limit * 20, 1000),)).fetchall()
        for flow_json, label_status, segment_json in rows:
            if label_status != "unknown":
                continue
            flow = json.loads(flow_json)
            segment = json.loads(segment_json)
            if (segment.get("capture_status") not in ("ok", "parsed_best_effort")
                    or flow.get("complete") is not True):
                continue
            flows.append(flow)
            if len(flows) >= limit:
                break
    except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
        return {"status": "unreadable", "flows": []}
    flows.reverse()
    return {"status": "ok" if flows else "empty", "flows": flows,
            "label_status": "unknown", "recomputed_scores_are_labels": False}


def record_flow_inference(path: str | Path, *, observed_at_utc: str,
                          inference_ms: float, flows_scored: int,
                          capture_status: str, packets_seen: int | None = None,
                          drop_counters_available: bool = False,
                          candidate_sha256: str | None = None,
                          feature_version: int | None = None,
                          dataset_manifest_sha256: str | None = None,
                          threshold: float | None = None,
                          capture_segment_hash: str | None = None) -> None:
    """Persist inference and, when available, bind it to its capture segment."""
    if not isinstance(inference_ms, (int, float)) or inference_ms < 0 or inference_ms > 3_600_000:
        raise ValueError("Invalid inference duration")
    if not isinstance(flows_scored, int) or flows_scored < 0:
        raise ValueError("Invalid flow count")
    if packets_seen is not None and (not isinstance(packets_seen, int) or packets_seen < 0):
        raise ValueError("Invalid packet count")
    if len(str(capture_status)) > 64:
        raise ValueError("Invalid capture status")
    if capture_segment_hash is not None and (
            not isinstance(capture_segment_hash, str) or len(capture_segment_hash) != 64
            or any(c not in "0123456789abcdef" for c in capture_segment_hash.lower())):
        raise ValueError("Invalid capture segment hash")
    if flows_scored > 0 and candidate_sha256 is not None and capture_segment_hash is None:
        raise ValueError("Candidate-scored flows must be bound to their capture segment")
    metadata = {
        "candidate_sha256": candidate_sha256,
        "feature_version": feature_version,
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "threshold": threshold,
    }
    if any(value is not None for value in metadata.values()):
        if any(value is None for value in metadata.values()):
            raise ValueError("Candidate provenance must be supplied as a complete set")
        for name in ("candidate_sha256", "dataset_manifest_sha256"):
            value = metadata[name]
            if (not isinstance(value, str) or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value.lower())):
                raise ValueError(f"Invalid {name}")
        if not isinstance(feature_version, int) or feature_version < 1:
            raise ValueError("Invalid feature version")
        if (not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1):
            raise ValueError("Invalid candidate threshold")
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path, timeout=30, isolation_level=None)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS flow_inference_samples (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at_utc TEXT NOT NULL,
                inference_ms REAL NOT NULL,
                flows_scored INTEGER NOT NULL,
                packets_seen INTEGER,
                capture_status TEXT NOT NULL,
                drop_counters_available INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                candidate_sha256 TEXT,
                feature_version INTEGER,
                dataset_manifest_sha256 TEXT,
                threshold REAL,
                capture_segment_hash TEXT
            );
            CREATE TRIGGER IF NOT EXISTS flow_samples_no_update
            BEFORE UPDATE ON flow_inference_samples
            BEGIN SELECT RAISE(ABORT, 'runtime evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS flow_samples_no_delete
            BEFORE DELETE ON flow_inference_samples
            BEGIN SELECT RAISE(ABORT, 'runtime evidence is append-only'); END;
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(flow_inference_samples)")}
        for name, sql_type in (("candidate_sha256", "TEXT"), ("feature_version", "INTEGER"),
                               ("dataset_manifest_sha256", "TEXT"), ("threshold", "REAL"),
                               ("capture_segment_hash", "TEXT")):
            if name not in columns:
                db.execute(f"ALTER TABLE flow_inference_samples ADD COLUMN {name} {sql_type}")
        db.execute("BEGIN IMMEDIATE")
        if capture_segment_hash is not None:
            segment_row = db.execute(
                "SELECT payload_json FROM packet_capture_segments WHERE record_hash=?",
                (capture_segment_hash,),
            ).fetchone()
            if not segment_row:
                db.rollback()
                raise ValueError("Inference capture segment is not present in the evidence chain")
            try:
                segment_payload = json.loads(segment_row[0])
            except (TypeError, json.JSONDecodeError) as error:
                db.rollback()
                raise ValueError("Inference capture segment payload is invalid") from error
            if (segment_payload.get("capture_status") not in ("ok", "parsed_best_effort")
                    or str(capture_status) != str(segment_payload.get("capture_status"))):
                db.rollback()
                raise ValueError("Inference must match a successfully parsed capture segment")
        row = db.execute("SELECT record_hash FROM flow_inference_samples ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else _ZERO_HASH
        payload = {
            "observed_at_utc": observed_at_utc,
            "inference_ms": round(float(inference_ms), 6),
            "flows_scored": flows_scored,
            "packets_seen": packets_seen,
            "capture_status": str(capture_status),
            "drop_counters_available": bool(drop_counters_available),
            "previous_hash": previous,
        }
        if candidate_sha256 is not None:
            payload.update(metadata)
        if capture_segment_hash is not None:
            payload["capture_segment_hash"] = capture_segment_hash
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                                .encode("utf-8")).hexdigest()
        db.execute("""INSERT INTO flow_inference_samples
            (observed_at_utc,inference_ms,flows_scored,packets_seen,capture_status,
             drop_counters_available,previous_hash,record_hash,candidate_sha256,
             feature_version,dataset_manifest_sha256,threshold,capture_segment_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (payload["observed_at_utc"], payload["inference_ms"], flows_scored,
                    packets_seen, payload["capture_status"], int(drop_counters_available),
                    previous, digest, candidate_sha256, feature_version,
                    dataset_manifest_sha256, threshold, capture_segment_hash))
        db.commit()


def runtime_summary(path: str | Path) -> dict:
    """Summarize measured calls; never mark the target-load gate as passed."""
    db_path = Path(path)
    if not db_path.is_file():
        return {"sample_count": 0, "p95_inference_ms": None,
                "target_load_tested": False, "drop_counters_observed": False,
                "integrity_valid": True}
    try:
        with closing(sqlite3.connect(db_path, timeout=10)) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(flow_inference_samples)")}
            base_query = (
                "SELECT observed_at_utc,inference_ms,flows_scored,packets_seen,capture_status,"
                "drop_counters_available,previous_hash,record_hash"
            )
            provenance_columns = {"candidate_sha256", "feature_version",
                                  "dataset_manifest_sha256", "threshold"}
            has_capture_link = "capture_segment_hash" in columns
            if provenance_columns.issubset(columns):
                link_select = ",capture_segment_hash" if has_capture_link else ",NULL"
                rows = db.execute(base_query + ",candidate_sha256,feature_version,"
                                  "dataset_manifest_sha256,threshold" + link_select
                                  + " FROM flow_inference_samples "
                                  "ORDER BY seq").fetchall()
            else:
                rows = [tuple(row) + (None, None, None, None) for row in db.execute(
                    base_query + " FROM flow_inference_samples ORDER BY seq").fetchall()]
                rows = [tuple(row) + (None,) for row in rows]
    except sqlite3.Error:
        return {"sample_count": 0, "p95_inference_ms": None,
                "target_load_tested": False, "drop_counters_observed": False,
                "integrity_valid": False, "status": "unreadable"}
    previous = _ZERO_HASH
    values = []
    drop_observed = False
    provenance_samples = 0
    candidate_provenance_by_sha256: dict[str, int] = {}
    inference_records = []
    for (observed_at, inference_ms, flows_scored, packets_seen, capture_status, drops,
         prev_hash, digest, candidate_hash, feature_version, manifest_hash, threshold,
         capture_segment_hash) in rows:
        if prev_hash != previous:
            return {"sample_count": 0, "p95_inference_ms": None,
                    "target_load_tested": False, "drop_counters_observed": False,
                    "integrity_valid": False, "status": "integrity_failed"}
        payload = {
            "observed_at_utc": observed_at,
            "inference_ms": round(float(inference_ms), 6),
            "flows_scored": int(flows_scored),
            "packets_seen": int(packets_seen) if packets_seen is not None else None,
            "capture_status": str(capture_status),
            "drop_counters_available": bool(drops),
            "previous_hash": previous,
        }
        provenance = (candidate_hash, feature_version, manifest_hash, threshold)
        if any(value is not None for value in provenance):
            if any(value is None for value in provenance):
                return {"sample_count": 0, "p95_inference_ms": None,
                        "target_load_tested": False, "drop_counters_observed": False,
                        "integrity_valid": False, "status": "incomplete_candidate_provenance"}
            payload.update({"candidate_sha256": candidate_hash,
                            "feature_version": int(feature_version),
                            "dataset_manifest_sha256": manifest_hash,
                            "threshold": float(threshold)})
            provenance_samples += 1
            candidate_provenance_by_sha256[candidate_hash] = (
                candidate_provenance_by_sha256.get(candidate_hash, 0) + 1)
        if capture_segment_hash is not None:
            if (not isinstance(capture_segment_hash, str) or len(capture_segment_hash) != 64
                    or any(c not in "0123456789abcdef" for c in capture_segment_hash.lower())):
                return {"sample_count": 0, "p95_inference_ms": None,
                        "target_load_tested": False, "drop_counters_observed": False,
                        "integrity_valid": False, "status": "invalid_capture_segment_link"}
            payload["capture_segment_hash"] = capture_segment_hash
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"))
                                  .encode("utf-8")).hexdigest()
        if not isinstance(digest, str) or digest != expected:
            return {"sample_count": 0, "p95_inference_ms": None,
                    "target_load_tested": False, "drop_counters_observed": False,
                    "integrity_valid": False, "status": "integrity_failed"}
        values.append(float(inference_ms))
        drop_observed = drop_observed or bool(drops)
        inference_records.append({
            "flows_scored": int(flows_scored),
            "capture_status": str(capture_status),
            "candidate_sha256": candidate_hash,
            "capture_segment_hash": capture_segment_hash,
        })
        previous = digest
    values.sort()
    p95 = values[max(0, int(len(values) * 0.95 + 0.999999) - 1)] if values else None
    capture_count = 0
    capture_integrity_valid = True
    capture_status_counts: dict[str, int] = {}
    captured_flow_count = 0
    complete_flow_count = 0
    incomplete_capture_flow_count = 0
    captured_flow_integrity_valid = True
    capture_payload_by_hash: dict[str, dict] = {}
    complete_flows_by_segment: dict[str, int] = {}
    try:
        with closing(sqlite3.connect(db_path, timeout=10)) as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='packet_capture_segments'").fetchone()
            if exists:
                previous_capture = _ZERO_HASH
                for payload_json, prev_capture, capture_hash in db.execute(
                        "SELECT payload_json,previous_hash,record_hash FROM packet_capture_segments ORDER BY seq"):
                    if prev_capture != previous_capture or hashlib.sha256(
                            (previous_capture + payload_json).encode("utf-8")).hexdigest() != capture_hash:
                        capture_integrity_valid = False
                        break
                    payload = json.loads(payload_json)
                    status = str(payload.get("capture_status", "unknown"))
                    capture_status_counts[status] = capture_status_counts.get(status, 0) + 1
                    capture_payload_by_hash[capture_hash] = payload
                    previous_capture = capture_hash
                    capture_count += 1
            flow_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='captured_flows'").fetchone()
            if flow_table:
                previous_flow = _ZERO_HASH
                for (segment_hash, observed_at, flow_json, label_status,
                     prev_flow, flow_hash) in db.execute(
                        "SELECT segment_hash,observed_at_utc,flow_json,label_status,"
                        "previous_hash,record_hash FROM captured_flows ORDER BY seq"):
                    if prev_flow != previous_flow or label_status != "unknown":
                        captured_flow_integrity_valid = False
                        break
                    flow = json.loads(flow_json)
                    segment_payload = capture_payload_by_hash.get(segment_hash)
                    if (segment_payload is None
                            or segment_payload.get("capture_status") not in (
                                "ok", "parsed_best_effort", "incomplete")):
                        captured_flow_integrity_valid = False
                        break
                    payload = {"segment_hash": segment_hash, "observed_at_utc": observed_at,
                               "flow": flow, "label_status": "unknown",
                               "previous_hash": previous_flow}
                    expected = hashlib.sha256(json.dumps(
                        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                        allow_nan=False).encode("utf-8")).hexdigest()
                    if expected != flow_hash:
                        captured_flow_integrity_valid = False
                        break
                    if flow.get("complete") is True:
                        if segment_payload.get("capture_status") in ("ok", "parsed_best_effort"):
                            complete_flow_count += 1
                            complete_flows_by_segment[segment_hash] = (
                                complete_flows_by_segment.get(segment_hash, 0) + 1)
                        else:
                            incomplete_capture_flow_count += 1
                    elif segment_payload.get("capture_status") == "incomplete":
                        incomplete_capture_flow_count += 1
                    previous_flow = flow_hash
                    captured_flow_count += 1
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError):
        capture_integrity_valid = False
    candidate_capture_link_integrity_valid = True
    candidate_linked_samples = 0
    candidate_linked_complete_flow_count = 0
    candidate_linked_segments: set[str] = set()
    candidate_linked_samples_by_sha256: dict[str, int] = {}
    candidate_linked_flows_by_sha256: dict[str, int] = {}
    candidate_linked_segments_by_sha256: dict[str, set[str]] = {}
    for inference in inference_records:
        segment_hash = inference["capture_segment_hash"]
        if segment_hash is None or inference["candidate_sha256"] is None:
            continue  # legacy/unlinked records are measurements, not proof of integration
        segment_payload = capture_payload_by_hash.get(segment_hash)
        if (segment_payload is None
                or segment_payload.get("capture_status") not in ("ok", "parsed_best_effort")
                or str(segment_payload.get("capture_status")) != inference["capture_status"]):
            candidate_capture_link_integrity_valid = False
            continue
        reported_complete = segment_payload.get("complete_flow_count")
        if (not isinstance(reported_complete, int) or reported_complete < 0
                or inference["flows_scored"] > reported_complete):
            candidate_capture_link_integrity_valid = False
            continue
        stored_complete = complete_flows_by_segment.get(segment_hash, 0)
        if inference["flows_scored"] > 0 and stored_complete > 0:
            candidate_hash = inference["candidate_sha256"]
            candidate_linked_samples += 1
            candidate_linked_segments.add(segment_hash)
            linked_count = min(inference["flows_scored"], stored_complete)
            candidate_linked_complete_flow_count += linked_count
            candidate_linked_samples_by_sha256[candidate_hash] = (
                candidate_linked_samples_by_sha256.get(candidate_hash, 0) + 1)
            candidate_linked_flows_by_sha256[candidate_hash] = (
                candidate_linked_flows_by_sha256.get(candidate_hash, 0) + linked_count)
            candidate_linked_segments_by_sha256.setdefault(candidate_hash, set()).add(segment_hash)
    return {
        "sample_count": len(values),
        "candidate_provenance_samples": provenance_samples,
        "candidate_provenance_by_sha256": candidate_provenance_by_sha256,
        "capture_segment_count": capture_count,
        "capture_integrity_valid": capture_integrity_valid,
        "capture_status_counts": capture_status_counts,
        "captured_flow_count": captured_flow_count,
        "complete_flow_count": complete_flow_count,
        "incomplete_capture_flow_count": incomplete_capture_flow_count,
        "captured_flow_integrity_valid": captured_flow_integrity_valid,
        "candidate_capture_link_integrity_valid": candidate_capture_link_integrity_valid,
        "candidate_linked_samples": candidate_linked_samples,
        "candidate_linked_complete_flow_count": candidate_linked_complete_flow_count,
        "candidate_linked_segment_count": len(candidate_linked_segments),
        "candidate_linked_samples_by_sha256": candidate_linked_samples_by_sha256,
        "candidate_linked_complete_flows_by_sha256": candidate_linked_flows_by_sha256,
        "candidate_linked_segment_counts_by_sha256": {
            key: len(value) for key, value in candidate_linked_segments_by_sha256.items()
        },
        "p95_inference_ms": round(p95, 3) if p95 is not None else None,
        "target_load_tested": False,
        "drop_counters_observed": drop_observed,
        "integrity_valid": True,
        "evidence_scope": "real Pktmon-backed runtime observations; not a controlled target-load test",
    }

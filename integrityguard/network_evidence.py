"""Append-only store of real, locally captured network telemetry snapshots.

This persists exactly what integrityguard.network_telemetry.NetworkTelemetry.sample()
returns (OS interface counters + active socket metadata; no packet payloads),
plus optional historical model context for backward compatibility. New captures
store no model assessment. Nothing here is a ground-truth label: a model decision
or a DShield match is never written as a verdict. Confirmed human labels belong in
integrityguard.network_label_reviews.NetworkLabelReviews, keyed to the event
and flow id captured here.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class NetworkEventLog:
    """Append-only ledger of real network telemetry snapshots."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, captured_at_utc TEXT NOT NULL,
                snapshot_sha256 TEXT NOT NULL, snapshot_json TEXT NOT NULL,
                assessment_json TEXT, source TEXT NOT NULL)""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'network event records are append-only'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'network event records are append-only'); END""")

    def capture(self, snapshot: dict, assessment: dict | None = None, source: str = "psutil_live") -> str:
        """Persist one real telemetry snapshot verbatim; returns its event id.

        `snapshot` must be the actual return value of NetworkTelemetry.sample()
        (or an equivalent real capture) -- not a hand-built or synthetic dict --
        identified by requiring the real sampler's own `observed_at_utc` field.
        """
        if not isinstance(snapshot, dict) or not snapshot.get("observed_at_utc") \
                or "remote_endpoints" not in snapshot or "interfaces" not in snapshot:
            raise ValueError("Снимок телеметрии должен быть реальным результатом NetworkTelemetry.sample()")
        snapshot_json = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        snapshot_hash = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
        event_id = "net-" + hashlib.sha256(
            f"{snapshot_hash}\0{snapshot['observed_at_utc']}".encode("utf-8")).hexdigest()[:24]
        assessment_json = (json.dumps(assessment, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                           if assessment else None)
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""INSERT OR IGNORE INTO events(event_id,captured_at_utc,snapshot_sha256,
                         snapshot_json,assessment_json,source) VALUES(?,?,?,?,?,?)""",
                       (event_id, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        snapshot_hash, snapshot_json, assessment_json, str(source)[:64]))
        return event_id

    def get(self, event_id: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("""SELECT captured_at_utc,snapshot_sha256,snapshot_json,assessment_json,source
                                FROM events WHERE event_id=?""", (event_id,)).fetchone()
        if row is None:
            return None
        captured_at, snapshot_sha, snapshot_json, assessment_json, source = row
        return {"event_id": event_id, "captured_at_utc": captured_at, "snapshot_sha256": snapshot_sha,
                "snapshot": json.loads(snapshot_json),
                "assessment": json.loads(assessment_json) if assessment_json else None, "source": source}

    def all_labeled(self) -> list[dict]:
        """Legacy accessor for snapshots with historical model assessments.

        These assessments are not ground truth and must not be used to train or
        objectively evaluate the local classifier.
        """
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("""SELECT event_id,captured_at_utc,snapshot_json,assessment_json FROM events
                                 WHERE assessment_json IS NOT NULL ORDER BY captured_at_utc ASC""").fetchall()
        out = []
        for event_id, captured_at, snapshot_json, assessment_json in rows:
            try:
                snapshot = json.loads(snapshot_json)
                assessment = json.loads(assessment_json)
            except (TypeError, ValueError):
                continue
            out.append({"event_id": event_id, "captured_at_utc": captured_at,
                        "snapshot": snapshot, "assessment": assessment})
        return out

    def all_events(self) -> list[dict]:
        """Return real captured snapshots with their stable capture metadata.

        Unlike all_labeled(), this deliberately excludes historical assessments.
        """
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("""SELECT event_id,captured_at_utc,snapshot_sha256,snapshot_json,source
                                 FROM events ORDER BY captured_at_utc,event_id""").fetchall()
        out = []
        for event_id, captured_at, snapshot_sha, snapshot_json, source in rows:
            try:
                snapshot = json.loads(snapshot_json)
            except (TypeError, ValueError):
                continue
            canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != snapshot_sha:
                continue
            out.append({"event_id": event_id, "captured_at_utc": captured_at,
                        "snapshot_sha256": snapshot_sha, "snapshot": snapshot, "source": source})
        return out

    def list_recent(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("""SELECT event_id,captured_at_utc,snapshot_sha256,source FROM events
                                 ORDER BY captured_at_utc DESC LIMIT ?""", (limit,)).fetchall()
        return [{"event_id": r[0], "captured_at_utc": r[1], "snapshot_sha256": r[2], "source": r[3]} for r in rows]

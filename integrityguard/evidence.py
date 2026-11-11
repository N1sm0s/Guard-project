"""Transactional evidence store linking assessments, features, labels and models."""
from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


SCHEMA_VERSION = 1


class EvidenceStore:
    """SQLite source of provenance links; legacy JSONL remains a readable export."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_versions (
                    model_sha256 TEXT PRIMARY KEY,
                    model_path TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    occurred_at TEXT,
                    package TEXT,
                    version TEXT,
                    fingerprint TEXT,
                    verdict TEXT,
                    analysis_mode TEXT,
                    model_sha256 TEXT,
                    event_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_by_time ON events(occurred_at);
                CREATE INDEX IF NOT EXISTS events_by_fingerprint ON events(fingerprint);
                CREATE TABLE IF NOT EXISTS feature_observations (
                    event_id TEXT PRIMARY KEY,
                    feature_sha256 TEXT NOT NULL,
                    feature_schema TEXT NOT NULL,
                    feature_blob BLOB NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS confirmed_labels (
                    label_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    label_schema TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    confirmed_at TEXT NOT NULL,
                    UNIQUE(event_id,label,reviewer)
                );
                CREATE INDEX IF NOT EXISTS labels_by_event ON confirmed_labels(event_id,confirmed_at);
            """)
            db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('schema_version',?)",
                       (str(SCHEMA_VERSION),))

    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=30)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _session(self):
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def sha256_file(path: str | Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def register_model(self, model_sha256: str, model_path: str | Path, metadata: dict) -> None:
        allowed = {"hidden", "use", "threshold", "block_threshold", "candidate_id",
                   "parent_model_sha256", "training_data_sha256", "dataset_sha256", "architecture"}
        safe_metadata = {key: metadata[key] for key in allowed if key in metadata
                         and isinstance(metadata[key], (str, int, float, bool, type(None), list, tuple))}
        with self._session() as db:
            db.execute("""INSERT INTO model_versions
                (model_sha256,model_path,registered_at,metadata_json) VALUES(?,?,?,?)
                ON CONFLICT(model_sha256) DO UPDATE SET model_path=excluded.model_path,
                metadata_json=excluded.metadata_json""",
                (model_sha256, str(Path(model_path).resolve()), time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 json.dumps(safe_metadata, ensure_ascii=False, sort_keys=True, default=str)))

    def record_event(self, event: dict) -> None:
        event_id = event.get("event_id")
        if not event_id:
            raise ValueError("Evidence events require a stable event_id")
        with self._session() as db:
            db.execute("""INSERT OR IGNORE INTO events
                (event_id,occurred_at,package,version,fingerprint,verdict,analysis_mode,model_sha256,event_json,stored_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (event_id, event.get("time"), event.get("package"), event.get("version"),
                 event.get("fingerprint"), event.get("verdict"), event.get("analysis_mode"),
                 event.get("model_sha256"), json.dumps(event, ensure_ascii=False, sort_keys=True, default=str),
                 time.strftime("%Y-%m-%dT%H:%M:%S%z")))

    def backfill_jsonl(self, *paths: str | Path) -> int:
        """Idempotently import legacy event JSONL records into the evidence database."""
        records = []
        for path in paths:
            path = Path(path)
            if not path.is_file():
                continue
            try:
                stream = path.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    event = dict(event)
                    event_id = event.get("event_id")
                    if not event_id:
                        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, default=str)
                        event_id = "legacy-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                        event["event_id"] = event_id
                        event["evidence_origin"] = "legacy_jsonl"
                    records.append((event_id, event))
        inserted = 0
        with self._session() as db:
            for event_id, event in records:
                cursor = db.execute("""INSERT OR IGNORE INTO events
                    (event_id,occurred_at,package,version,fingerprint,verdict,analysis_mode,model_sha256,event_json,stored_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (event_id, event.get("time"), event.get("package"), event.get("version"),
                     event.get("fingerprint"), event.get("verdict"), event.get("analysis_mode"),
                     event.get("model_sha256"), json.dumps(event, ensure_ascii=False, sort_keys=True, default=str),
                     time.strftime("%Y-%m-%dT%H:%M:%S%z")))
                inserted += cursor.rowcount
        return inserted

    def record_features(self, event_id: str, features: dict) -> str:
        arrays = {name: value.detach().cpu().numpy() if hasattr(value, "detach") else np.asarray(value)
                  for name, value in sorted(features.items())
                  if name in {"x", "adj", "layers", "behav"}}
        buffer = io.BytesIO()
        np.savez_compressed(buffer, **arrays)
        blob = buffer.getvalue()
        checksum = hashlib.sha256(blob).hexdigest()
        schema = json.dumps({name: {"shape": list(value.shape), "dtype": str(value.dtype)}
                             for name, value in arrays.items()}, sort_keys=True)
        with self._session() as db:
            db.execute("""INSERT OR IGNORE INTO feature_observations
                (event_id,feature_sha256,feature_schema,feature_blob,stored_at) VALUES(?,?,?,?,?)""",
                (event_id, checksum, schema, sqlite3.Binary(blob), time.strftime("%Y-%m-%dT%H:%M:%S%z")))
        return checksum

    def confirm_label(self, event_id: str, is_attack: bool, reviewer: str = "local_operator") -> None:
        with self._session() as db:
            db.execute("""INSERT OR IGNORE INTO confirmed_labels
                (label_id,event_id,label,label_schema,reviewer,confirmed_at) VALUES(?,?,?,?,?,?)""",
                (uuid.uuid4().hex, event_id, "attack" if is_attack else "benign", "binary_v1", reviewer,
                 datetime.now(timezone.utc).isoformat(timespec="microseconds")))

    def read_events(self) -> list[dict]:
        with self._session() as db:
            rows = db.execute("SELECT event_json FROM events ORDER BY occurred_at,event_id").fetchall()
        events = []
        for (payload,) in rows:
            try:
                item = json.loads(payload)
            except (TypeError, ValueError):
                continue
            if isinstance(item, dict):
                events.append(item)
        return events


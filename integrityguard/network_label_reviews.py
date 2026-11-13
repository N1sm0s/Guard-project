"""Local two-person labeling ledger for real network-flow observations.

Mirrors integrityguard.audit_reviews.AuditReviews, applied to a flow inside a
captured integrityguard.network_evidence.NetworkEventLog snapshot instead of a
package-check event. No automated signal (model decision, DShield match) is
ever accepted as ground truth here: a label is recorded only with a reviewer
identity (from the OS account), a substantive rationale and an evidence
document, and only becomes 'verified_local_review' once two distinct reviewer
accounts independently agree on the same verdict for the same
(event_id, flow_id, snapshot_sha256) triple. One account voting twice never
reaches agreement; disagreement is reported as 'disputed', not resolved.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .audit_reviews import reviewer_identity


class NetworkLabelReviews:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, flow_id TEXT NOT NULL,
                snapshot_sha256 TEXT NOT NULL, reviewer TEXT NOT NULL, label INTEGER NOT NULL,
                rationale TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, evidence BLOB NOT NULL,
                recorded_at TEXT NOT NULL)""")

    def propose(self, event_id: str, flow_id: str, snapshot_sha256: str, is_malicious: bool,
               evidence_path, rationale: str) -> dict:
        if not event_id or not flow_id:
            raise ValueError("Для разметки нужны ID захваченного события и ID наблюдаемого потока")
        if not isinstance(snapshot_sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", snapshot_sha256):
            raise ValueError("Нужен SHA-256 захваченного снимка телеметрии")
        if not isinstance(rationale, str) or len(rationale.strip()) < 20:
            raise ValueError("Укажите содержательное обоснование метки (не менее 20 символов)")
        with Path(evidence_path).open("rb") as stream:
            content = stream.read(4 * 1024 * 1024 + 1)
        if not content or len(content) > 4 * 1024 * 1024:
            raise ValueError("Свидетельство должно быть непустым файлом не больше 4 МиБ")
        reviewer = reviewer_identity()
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""INSERT INTO reviews(event_id,flow_id,snapshot_sha256,reviewer,label,rationale,
                         evidence_sha256,evidence,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                       (event_id, flow_id, snapshot_sha256.lower(), reviewer, int(bool(is_malicious)),
                        rationale.strip(), hashlib.sha256(content).hexdigest(), content,
                        datetime.now(timezone.utc).isoformat()))
        return self.decision(event_id, flow_id, snapshot_sha256)

    def decision(self, event_id: str, flow_id: str, snapshot_sha256: str) -> dict:
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute("""SELECT id,reviewer,label,evidence_sha256,evidence FROM reviews
                                 WHERE event_id=? AND flow_id=? AND snapshot_sha256=? ORDER BY id DESC""",
                              (event_id, flow_id, str(snapshot_sha256).lower())).fetchall()
        latest = {}
        for row in rows:
            latest.setdefault(row[1], row)  # last (highest id) vote per reviewer account
        votes = list(latest.values())
        intact = all(hashlib.sha256(row[4]).hexdigest() == row[3] for row in votes)
        labels = {row[2] for row in votes}
        accepted = intact and len(votes) >= 2 and len(labels) == 1
        return {"status": "verified_local_review" if accepted else
                         "disputed" if len(labels) > 1 else "awaiting_independent_review",
                "accepted": accepted, "label": next(iter(labels)) if accepted else None,
                "review_ids": sorted(row[0] for row in votes), "reviewer_count": len(votes)}

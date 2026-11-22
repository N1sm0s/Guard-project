"""Local ledger for human network-label adjudications.

A single accountable operator may record a label and attach an evidence file.
The ledger verifies the event/flow/snapshot binding, file hash, and absence of
conflicting current decisions. It cannot authenticate the evidence publisher
or prove that the artifact supports the label; the status therefore describes
an evidence-attached adjudication, not independently verified ground truth.

Obvious circular sources (model decisions and threat-intelligence matches) are
rejected. Unknown or conflicting decisions remain excluded from training.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .audit_reviews import reviewer_identity

def _evidence_is_eligible(content: bytes) -> bool:
    """Reject evidence explicitly identified as only a model/app/TI assertion.

    These rows record a prior application/model decision, not an independent
    incident source. Their content hashes preserve provenance but do not make
    the asserted label ground truth.
    This is a circularity check, not publisher authentication.
    """
    normalized = content.lstrip().lower()
    forbidden_prefixes = (
        b"gui label:", b"bulk label:", b"model prediction:",
        b"model score:", b"dshield match:", b"threat-intel match:",
    )
    return not normalized.startswith(forbidden_prefixes)


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
            db.execute("""CREATE INDEX IF NOT EXISTS idx_network_reviews_lookup
                         ON reviews(event_id,flow_id,snapshot_sha256,id)""")

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

    def propose_simple(self, event_id: str, flow_id: str, snapshot_sha256: str,
                       is_malicious: bool, rationale: str) -> dict:
        """Reject rationale-only labels: a self-written note cannot prove an incident."""
        raise ValueError("Для разметки нужен файл внешнего свидетельства; текст обоснования не является доказательством.")

    def decision(self, event_id: str, flow_id: str, snapshot_sha256: str) -> dict:
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute("""SELECT id,reviewer,label,evidence_sha256,evidence FROM reviews
                                 WHERE event_id=? AND flow_id=? AND snapshot_sha256=? ORDER BY id DESC""",
                              (event_id, flow_id, str(snapshot_sha256).lower())).fetchall()
        latest = {}
        for row in rows:
            latest.setdefault(row[1], row)  # last (highest id) vote per reviewer account
        votes = list(latest.values())
        evidence_valid = all(hashlib.sha256(row[4]).hexdigest() == row[3]
                             and _evidence_is_eligible(row[4]) for row in votes)
        labels = {row[2] for row in votes}
        accepted = evidence_valid and bool(votes) and len(labels) == 1
        status = ("invalid_evidence" if votes and not evidence_valid else
                  "evidence_attached_adjudication" if accepted else
                  "disputed" if len(labels) > 1 else "awaiting_evidence")
        return {"status": status,
                "accepted": accepted, "label": next(iter(labels)) if accepted else None,
                "review_ids": sorted(row[0] for row in votes),
                "evidence_sha256": sorted({row[3] for row in votes}) if accepted else []}

    def status_counts(self) -> dict:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("""SELECT event_id,flow_id,snapshot_sha256,reviewer,label,
                                 evidence_sha256,evidence FROM reviews ORDER BY id""").fetchall()
        groups: dict[tuple, dict] = {}
        for event_id, flow_id, snapshot_sha256, reviewer, label, evidence_sha256, evidence in rows:
            groups.setdefault((event_id, flow_id, snapshot_sha256), {})[reviewer] = (
                label, evidence_sha256, evidence)
        counts = {"awaiting_evidence": 0, "disputed": 0,
                  "evidence_attached_adjudication": 0, "invalid_evidence": 0}
        for latest in groups.values():
            votes = list(latest.values())
            evidence_valid = all(hashlib.sha256(v[2]).hexdigest() == v[1]
                                 and _evidence_is_eligible(v[2]) for v in votes)
            labels = {v[0] for v in votes}
            accepted = evidence_valid and bool(votes) and len(labels) == 1
            status = ("invalid_evidence" if votes and not evidence_valid else
                      "evidence_attached_adjudication" if accepted else
                      "disputed" if len(labels) > 1 else "awaiting_evidence")
            counts[status] += 1
        return {"items": len(groups), **counts}

    def adjudicated_snapshot_labels(self, event_log) -> list[dict]:
        """Build conservative snapshot labels from evidence-attached decisions.

        A snapshot is BLOCK if any observed remote endpoint has an intact,
        agreed malicious label. It is ALLOW only when every observed remote
        endpoint has an intact, agreed benign label. Partial, disputed, stale,
        or unlabeled snapshots are excluded.
        """
        events = {event["event_id"]: event for event in event_log.all_events()}
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute("""SELECT id,event_id,flow_id,snapshot_sha256,reviewer,label,
                                        evidence_sha256,evidence
                                 FROM reviews ORDER BY id""").fetchall()
        # Group the ledger in one pass. Calling decision() once per distinct flow
        # repeatedly scanned this whole (potentially large) table and made a
        # background candidate refresh take minutes on accumulated review data.
        latest: dict[tuple[str, str, str], dict[str, tuple[int, int, str, bytes]]] = {}
        for row_id, event_id, flow_id, snapshot_sha, reviewer, label, evidence_sha, evidence in rows:
            event = events.get(event_id)
            normalized_sha = str(snapshot_sha).lower()
            if event is None or event.get("snapshot_sha256", "").lower() != normalized_sha:
                continue
            key = (event_id, flow_id, normalized_sha)
            latest.setdefault(key, {})[reviewer] = (row_id, int(label), evidence_sha, evidence)
        votes: dict[tuple[str, str], int] = {}
        for (event_id, flow_id, _snapshot_sha), reviewers in latest.items():
            if not reviewers:
                continue
            current_votes = list(reviewers.values())
            intact = all(hashlib.sha256(evidence).hexdigest() == digest and _evidence_is_eligible(evidence)
                         for _row_id, _label, digest, evidence in current_votes)
            labels = {label for _row_id, label, _digest, _evidence in current_votes}
            if intact and len(labels) == 1:
                votes[(event_id, flow_id)] = next(iter(labels))

        labeled = []
        for event_id, event in events.items():
            flows = event["snapshot"].get("remote_endpoints") or []
            flow_ids = {str(flow.get("id")) for flow in flows
                        if isinstance(flow, dict) and flow.get("id")}
            if not flow_ids:
                continue
            accepted = {flow_id: votes[(event_id, flow_id)] for flow_id in flow_ids
                        if (event_id, flow_id) in votes}
            if any(label == 1 for label in accepted.values()):
                label = "BLOCK"
            elif len(accepted) == len(flow_ids) and all(value == 0 for value in accepted.values()):
                label = "ALLOW"
            else:
                continue
            labeled.append({**event, "label": label,
                            "reviewed_flow_count": len(accepted),
                            "observed_flow_count": len(flow_ids)})
        return labeled

    def all_labels_for_event(self, event_id: str) -> list[dict]:
        """Return all review records for a given event_id (for GUI display)."""
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute("""SELECT id,flow_id,snapshot_sha256,reviewer,label,rationale,recorded_at
                                 FROM reviews WHERE event_id=? ORDER BY id""",
                              (event_id,)).fetchall()
        return [{"id": r[0], "flow_id": r[1], "snapshot_sha256": r[2],
                 "reviewer": r[3], "label": r[4], "rationale": r[5],
                 "recorded_at": r[6]} for r in rows]

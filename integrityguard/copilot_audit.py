"""Append-only, hash-chained local audit for assistant turns and tool calls.

Question and answer text are never stored; only hashes and source/tool metadata.
This is tamper-evident within the SQLite file, not a signature or remote ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


_ZERO_HASH = "0" * 64
_SHA = re.compile(r"^[a-f0-9]{64}$")


class CopilotAudit:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS turns (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    question_sha256 TEXT NOT NULL,
                    answer_sha256 TEXT NOT NULL,
                    model TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    tools_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS turns_no_update BEFORE UPDATE ON turns
                BEGIN SELECT RAISE(ABORT, 'assistant audit rows are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS turns_no_delete BEFORE DELETE ON turns
                BEGIN SELECT RAISE(ABORT, 'assistant audit rows are append-only'); END;
            """)

    def append(self, *, principal: str, question: str, answer: str, model: str,
               status: str, source_hashes: list[str], tool_calls: list[dict]) -> str:
        if not principal or len(principal) > 256 or len(model) > 128 or status not in {"answered", "insufficient_evidence", "error"}:
            raise ValueError("Invalid audit metadata")
        hashes = sorted(set(source_hashes))
        if any(not isinstance(value, str) or not _SHA.fullmatch(value) for value in hashes):
            raise ValueError("Invalid source hash in audit metadata")
        safe_tools = []
        for tool in tool_calls[:4]:
            if not isinstance(tool, dict):
                raise ValueError("Invalid tool audit record")
            safe_tools.append({"name": str(tool.get("name", ""))[:80],
                               "status": str(tool.get("status", ""))[:40],
                               "result_sha256": str(tool.get("result_sha256", ""))[:64]})
        question_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()
        answer_hash = hashlib.sha256(answer.encode("utf-8")).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        sources_json = json.dumps(hashes, separators=(",", ":"))
        tools_json = json.dumps(safe_tools, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with closing(sqlite3.connect(self.path, timeout=30, isolation_level=None)) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT record_hash FROM turns ORDER BY seq DESC LIMIT 1").fetchone()
            previous = row[0] if row else _ZERO_HASH
            payload = {"timestamp_utc": timestamp, "principal": principal,
                       "question_sha256": question_hash, "answer_sha256": answer_hash,
                       "model": model[:128], "status": status, "sources_json": sources_json,
                       "tools_json": tools_json, "previous_hash": previous}
            record_hash = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                                     separators=(",", ":")).encode("utf-8")).hexdigest()
            db.execute("""INSERT INTO turns(timestamp_utc,principal,question_sha256,answer_sha256,model,status,
                         sources_json,tools_json,previous_hash,record_hash) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                       (timestamp, principal, question_hash, answer_hash, model[:128], status,
                        sources_json, tools_json, previous, record_hash))
            db.commit()
        return record_hash

    def verify(self) -> dict:
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute("SELECT timestamp_utc,principal,question_sha256,answer_sha256,model,status,"
                              "sources_json,tools_json,previous_hash,record_hash FROM turns ORDER BY seq").fetchall()
        return self.verify_rows(rows)

    @staticmethod
    def verify_rows(rows) -> dict:
        previous = _ZERO_HASH
        for row in rows:
            timestamp, principal, question_hash, answer_hash, model, status, sources, tools, recorded_prev, digest = row
            if recorded_prev != previous:
                return {"valid": False, "checked_records": len(rows), "reason": "chain_mismatch"}
            payload = {"timestamp_utc": timestamp, "principal": principal,
                       "question_sha256": question_hash, "answer_sha256": answer_hash,
                       "model": model, "status": status, "sources_json": sources,
                       "tools_json": tools, "previous_hash": previous}
            expected = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                                   separators=(",", ":")).encode("utf-8")).hexdigest()
            if not _SHA.fullmatch(question_hash) or not _SHA.fullmatch(answer_hash) or expected != digest:
                return {"valid": False, "checked_records": len(rows), "reason": "record_hash_mismatch"}
            previous = digest
        return {"valid": True, "checked_records": len(rows), "head_hash": previous}

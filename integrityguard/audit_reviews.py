"""Local two-person audit ledger; no prediction is treated as a true label."""
import ctypes
import hashlib
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def reviewer_identity():
    if os.name == 'nt':
        size = ctypes.c_ulong(256)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
            raise OSError('Не удалось определить учётную запись проверяющего')
        return buffer.value.casefold()
    return str(os.getuid())


class AuditReviews:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                reviewer TEXT NOT NULL, label INTEGER NOT NULL, rationale TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL, evidence BLOB NOT NULL, recorded_at TEXT NOT NULL)''')

    def propose(self, event_id, fingerprint, is_attack, evidence_path, rationale):
        if not event_id or not isinstance(fingerprint, str) or not re.fullmatch('[a-fA-F0-9]{64}', fingerprint):
            raise ValueError('Для разметки нужны ID события и SHA-256 артефакта')
        if not isinstance(rationale, str) or len(rationale.strip()) < 20:
            raise ValueError('Укажите содержательное обоснование метки (не менее 20 символов)')
        with Path(evidence_path).open('rb') as stream:
            content = stream.read(4 * 1024 * 1024 + 1)
        if not content or len(content) > 4 * 1024 * 1024:
            raise ValueError('Свидетельство должно быть непустым файлом не больше 4 МиБ')
        reviewer = reviewer_identity()
        with closing(sqlite3.connect(self.path, timeout=30)) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('INSERT INTO reviews(event_id,fingerprint,reviewer,label,rationale,evidence_sha256,evidence,recorded_at) VALUES(?,?,?,?,?,?,?,?)',
                       (event_id, fingerprint.lower(), reviewer, int(bool(is_attack)), rationale.strip(),
                        hashlib.sha256(content).hexdigest(), content, datetime.now(timezone.utc).isoformat()))
        return self.decision(event_id, fingerprint)

    def decision(self, event_id, fingerprint):
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            rows = db.execute('''SELECT id,reviewer,label,evidence_sha256,evidence FROM reviews
                                 WHERE event_id=? AND fingerprint=? ORDER BY id DESC''',
                              (event_id, str(fingerprint).lower())).fetchall()
        latest = {}
        for row in rows:
            latest.setdefault(row[1], row)
        votes = list(latest.values())
        intact = all(hashlib.sha256(row[4]).hexdigest() == row[3] for row in votes)
        labels = {row[2] for row in votes}
        accepted = intact and len(votes) >= 2 and len(labels) == 1
        return {'status': 'verified_local_review' if accepted else
                         'disputed' if len(labels) > 1 else 'awaiting_independent_review',
                'accepted': accepted, 'label': next(iter(labels)) if accepted else None,
                'review_ids': sorted(row[0] for row in votes), 'reviewer_count': len(votes)}

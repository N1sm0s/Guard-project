"""Versioned evidence intake. Imported claims never become verified labels."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .spec import CLASSES

MAX_DOCUMENT = 4 * 1024 * 1024


def _read_bounded(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_DOCUMENT + 1)
    if len(data) > MAX_DOCUMENT:
        raise ValueError('Документ разметки превышает 4 МиБ')
    return data


class LabelRegistry:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS sources (
                    sha256 TEXT PRIMARY KEY, content BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS case_revisions (
                    revision INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL, document_sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL, payload TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL REFERENCES sources(sha256));
                CREATE INDEX IF NOT EXISTS case_history ON case_revisions(case_id, revision);
            ''')

    @contextmanager
    def _session(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def import_catalog(self, path):
        path = Path(path).resolve()
        catalog = json.loads(_read_bounded(path))
        if not isinstance(catalog, dict) or catalog.get('format') != 'integrityguard-label-evidence-v1':
            raise ValueError('Неподдерживаемый каталог свидетельств')
        cases = catalog.get('cases')
        if not isinstance(cases, list) or len(cases) > 10000:
            raise ValueError('Неверный список карточек')
        seen = set()
        prepared = []
        for original in cases:
            if not isinstance(original, dict):
                raise ValueError('Карточка должна быть объектом')
            for key in ('case_id', 'incident_group', 'project_id', 'version', 'source_url', 'source_snapshot', 'source_sha256'):
                if not isinstance(original.get(key), str) or not original[key].strip():
                    raise ValueError(f'В карточке отсутствует {key}')
            if original['case_id'] in seen:
                raise ValueError('Повторный case_id в каталоге')
            seen.add(original['case_id'])
            proposed = original.get('proposed_classes')
            if not isinstance(proposed, list) or not proposed or any(c not in CLASSES for c in proposed):
                raise ValueError('Неизвестные или отсутствующие классы разметки')
            if len(set(proposed)) != len(proposed) or ('clean' in proposed and len(proposed) > 1):
                raise ValueError('Противоречащие или повторные классы')
            source = (path.parent / original['source_snapshot']).resolve()
            if not source.is_relative_to(path.parent):
                raise ValueError('Свидетельство должно находиться внутри каталога')
            content = _read_bounded(source)
            sha = hashlib.sha256(content).hexdigest()
            if sha != original['source_sha256']:
                raise ValueError('SHA-256 свидетельства не совпадает')
            case = dict(original)
            # Keep the original assertion for audit but do not trust its status.
            case['imported_claims'] = {k: original.get(k) for k in
                                       ('label_status', 'verified_classes', 'training_eligible', 'independent_reviewer')}
            case.update(label_status='proposed', verified_classes=[], training_eligible=False,
                        independent_reviewer=None)
            payload = json.dumps(case, ensure_ascii=False, sort_keys=True)
            digest = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            prepared.append((case['case_id'], sha, content, digest, payload))
        inserted = 0
        with self._session() as db:
            db.execute('BEGIN IMMEDIATE')
            for case_id, sha, content, digest, payload in prepared:
                current = db.execute('SELECT document_sha256 FROM case_revisions WHERE case_id=? ORDER BY revision DESC LIMIT 1',
                                     (case_id,)).fetchone()
                if current and current[0] == digest:
                    continue
                db.execute('INSERT OR IGNORE INTO sources VALUES (?,?)', (sha, content))
                db.execute('INSERT INTO case_revisions(case_id,document_sha256,imported_at,payload,source_sha256) VALUES (?,?,?,?,?)',
                           (case_id, digest, datetime.now(timezone.utc).isoformat(), payload, sha))
                inserted += 1
        return {'imported_revisions': inserted, 'case_count': len(prepared), 'training_eligible': 0}

    def coverage(self):
        with self._session() as db:
            rows = db.execute('''SELECT payload FROM case_revisions WHERE revision IN
                                 (SELECT MAX(revision) FROM case_revisions GROUP BY case_id)''').fetchall()
        cases = [json.loads(row[0]) for row in rows]
        return {'cases': len(cases), 'incidents': len({c['incident_group'] for c in cases}),
                'training_eligible': 0,
                'classes': {name: {'proposed_cases': sum(name in c['proposed_classes'] for c in cases),
                                   'verified_cases': 0, 'status': 'not_evaluated'} for name in CLASSES},
                'limitation': 'Импорт свидетельств; независимые решения разметки и обучающие признаки ещё не подтверждены'}

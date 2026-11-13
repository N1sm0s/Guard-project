"""Verify artifact identity against PyPI, without claiming publisher trust."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Перенаправление запроса PyPI запрещено")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pypi_wheel(path, facts):
    """Only name/version leave the host. Errors never grant verified status."""
    name, version = facts['name'], facts['version']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name) or not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}', version):
        raise ValueError('Недопустимые имя или версия для запроса PyPI')
    url = f'https://pypi.org/pypi/{quote(name, safe="")}/{quote(version, safe="")}/json'
    request = Request(url, headers={'Accept': 'application/json',
                                   'User-Agent': 'IntegrityGuard/1.0 (artifact-verification)'})
    with build_opener(_NoRedirect()).open(request, timeout=10) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('Ответ PyPI превышает допустимый размер')
    metadata = json.loads(raw)
    rows = metadata.get('urls') if isinstance(metadata, dict) else None
    if not isinstance(rows, list):
        raise ValueError('В ответе PyPI отсутствует список артефактов')
    matches = [row for row in rows if isinstance(row, dict)
               and row.get('filename') == Path(path).name and row.get('packagetype') == 'bdist_wheel']
    if len(matches) != 1:
        raise ValueError('Точный файл wheel не найден в релизе PyPI')
    published = matches[0]
    expected = published.get('digests', {}).get('sha256')
    if not isinstance(expected, str) or not re.fullmatch('[a-fA-F0-9]{64}', expected):
        raise ValueError('PyPI не предоставил корректный SHA-256')
    actual = file_sha256(path)
    if actual != facts['sha256'] or actual != expected.lower():
        raise ValueError('SHA-256 локального wheel не совпадает с опубликованным PyPI')
    if published.get('yanked') is not False:
        raise ValueError('Артефакт отозван или статус отзыва не подтверждён')
    return {'status': 'pypi_hash_verified', 'checked_at': datetime.now(timezone.utc).isoformat(),
            'metadata_url': url, 'metadata_sha256': hashlib.sha256(raw).hexdigest(),
            'artifact_sha256': actual, 'filename': published['filename'],
            'uploaded_at': published.get('upload_time_iso_8601'), 'yanked': False,
            'publisher_signature_verified': False,
            'meaning': 'Совпадение с файлом PyPI; не доказательство безопасности или подписи издателя'}

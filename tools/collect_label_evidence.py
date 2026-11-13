"""Snapshot primary incident reports; never download or execute affected packages."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

REPORTS = (
    ('pypi-num2words-202507', 'num2words', ['0.5.15', '0.5.16'],
     'https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/'),
    ('elementary-202604', 'elementary-data', ['0.23.3'],
     'https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3'),
)

ARCHIVES = {
    ('num2words', '0.5.15'): ('2025-07-28-num2words-v0.5.15.zip',
                           'd9b676fab404fb05781907a5ef639bb9defe347c6851dbef0e00f5ce3fddc0a1'),
    ('elementary-data', '0.23.3'): ('2026-04-24-elementary-data-v0.23.3.zip',
                                  '07cb429d3deff04af059e94273ee1b1525fba41182d3a3238fbc720fa067d45c'),
}


def bind_existing_archives(catalog, sample_root):
    """Bind archived metadata, not reconstructed weights or executed code."""
    for case in catalog['cases']:
        entry = ARCHIVES.get((case['project_id'], case['version']))
        if entry is None:
            continue
        filename, recorded_sha = entry
        path = sample_root / filename
        if not path.is_file():
            continue
        with path.open('rb') as stream:
            actual_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual_sha != recorded_sha:
            raise ValueError(f'Previously recorded archive digest mismatch: {filename}')
        with zipfile.ZipFile(path) as archive:
            infos = [i for i in archive.infolist() if Path(i.filename).name.startswith('package_info-')
                     and i.filename.endswith('.json') and not i.is_dir()]
            if len(infos) != 1 or infos[0].file_size > 1024 * 1024:
                raise ValueError('Ambiguous or oversized archive metadata')
            metadata_raw = archive.read(infos[0], pwd=b'infected')
        metadata = json.loads(metadata_raw)
        info = metadata['info']
        if info['name'].replace('_', '-').lower() != case['project_id'] or info['version'] != case['version']:
            raise ValueError('Archived release identity does not match the incident')
        case['archive_evidence'] = {
            'path': str(path.resolve()), 'sha256': actual_sha,
            'kind': 'dataset_archive_not_original_wheel',
            'hash_check_scope': 'matches_previously_recorded_local_digest_not_fresh_remote_verification',
            'metadata_sha256': hashlib.sha256(metadata_raw).hexdigest(),
            'claimed_original_wheels': [{'filename': row['filename'], 'sha256': row['digests']['sha256']}
                                        for row in metadata.get('urls', []) if row.get('packagetype') == 'bdist_wheel'],
            'original_wheel_bytes_verified': False,
            'code_executed': False, 'source_extracted_to_disk': False}
    return catalog


def collect(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    for incident_id, project, versions, url in REPORTS:
        requested_at = datetime.now(timezone.utc).isoformat()
        request = Request(url, headers={'User-Agent': 'IntegrityGuard/1.0 evidence-collection'})
        with urlopen(request, timeout=20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            resolved_url = response.geturl()
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('Evidence document exceeds 4 MiB')
        sha = hashlib.sha256(raw).hexdigest()
        # Plain-text extension prevents accidental rendering of active HTML.
        filename = f'{incident_id}-{sha}.html.txt'
        path = output / filename
        if not path.exists():
            path.write_bytes(raw)
        for version in versions:
            cases.append({'case_id': f'{incident_id}-{version}', 'incident_group': incident_id,
                          'project_id': project, 'version': version,
                          'scope': 'published_incident_not_bound_to_local_artifact',
                          'proposed_classes': ['dependency'], 'verified_classes': [],
                          'label_status': 'proposed', 'artifact_sha256': None,
                          'source_url': url, 'resolved_source_url': resolved_url,
                          'source_snapshot': filename, 'source_sha256': sha,
                          'retrieved_at': requested_at, 'independent_reviewer': None,
                          'training_eligible': False,
                          'missing': ['hash-bound original artifact', 'independent label review',
                                      'real compatible model features without fabricated weights'],
                          'basis': 'Primary report identifies this release as containing malicious code; '
                                   'mapping to dependency is a proposed IntegrityGuard taxonomy assignment.'})
    catalog = {'format': 'integrityguard-label-evidence-v1', 'cases': cases,
               'scope': 'Two primary incident reports; three affected release records, not three independent incidents',
               'training_eligible_count': 0}
    temporary = output / 'catalog.json.tmp'
    temporary.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(output / 'catalog.json')
    return catalog


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--existing-samples', type=Path)
    args = parser.parse_args()
    result = collect(args.out)
    if args.existing_samples:
        bind_existing_archives(result, args.existing_samples)
        temporary = args.out / 'catalog.json.tmp'
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(args.out / 'catalog.json')
    print(f"Saved {len(result['cases'])} proposed release records; training-eligible: 0")

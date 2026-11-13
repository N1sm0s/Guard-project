"""Registry regressions using collected real reports, not generated packages."""
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from integrityguard.label_registry import LabelRegistry

SOURCE = Path(__file__).resolve().parents[1] / 'outputs/labeling-readiness/primary-evidence'


@unittest.skipUnless((SOURCE / 'catalog.json').is_file(), 'Collected primary reports required')
class RealEvidenceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = json.loads((SOURCE / 'catalog.json').read_text(encoding='utf-8'))
        for case in self.catalog['cases']:
            shutil.copyfile(SOURCE / case['source_snapshot'], self.root / case['source_snapshot'])
        self.path = self.root / 'catalog.json'
        self.registry = LabelRegistry(self.root / 'labels.sqlite')

    def save(self):
        self.path.write_text(json.dumps(self.catalog), encoding='utf-8')

    def test_repeat_import_and_revision_history(self):
        self.save()
        self.assertEqual(self.registry.import_catalog(self.path)['imported_revisions'], 3)
        self.assertEqual(self.registry.import_catalog(self.path)['imported_revisions'], 0)
        self.catalog['cases'][0]['basis'] += ' Additional review pending.'
        self.save()
        self.assertEqual(self.registry.import_catalog(self.path)['imported_revisions'], 1)
        with closing(sqlite3.connect(self.registry.path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM case_revisions').fetchone()[0], 4)
        self.assertEqual(self.registry.coverage()['incidents'], 2)

    def test_import_does_not_trust_verification_claims(self):
        self.catalog['cases'][0].update(label_status='verified', verified_classes=['dependency'], training_eligible=True)
        self.save()
        self.registry.import_catalog(self.path)
        self.assertEqual(self.registry.coverage()['training_eligible'], 0)
        with closing(sqlite3.connect(self.registry.path)) as db:
            for row in db.execute('SELECT payload FROM case_revisions'):
                value = json.loads(row[0])
                self.assertFalse(value['training_eligible'])
                self.assertEqual(value['verified_classes'], [])

    def test_bad_evidence_rejects_whole_import(self):
        self.catalog['cases'][-1]['source_sha256'] = '0' * 64
        self.save()
        with self.assertRaises(ValueError):
            self.registry.import_catalog(self.path)
        self.assertEqual(self.registry.coverage()['cases'], 0)

    def test_path_escape_rejected(self):
        self.catalog['cases'][0]['source_snapshot'] = '../outside.txt'
        self.save()
        with self.assertRaises(ValueError):
            self.registry.import_catalog(self.path)
        self.assertEqual(self.registry.coverage()['cases'], 0)


if __name__ == '__main__':
    unittest.main()

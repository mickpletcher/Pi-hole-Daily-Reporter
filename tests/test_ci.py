"""Synthetic regressions for CI tooling and all frozen CSV versions."""
import csv
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pihole_report import research_csv as c
from pihole_report.delivery import BackupConfig, DeliveryError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_docs', ROOT/'scripts/check_docs.py')
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)


class CITests(unittest.TestCase):
    def test_all_csv_schemas_reproduce_and_preserve_edited_collisions(self):
        detail = {'research': {'research_needed_count': 1, 'research_needed': [
            dict(hostname='click.example.com', cache_status='uncached',
                 new_to_history=True, reason='fixture', action='manual review')]},
            'daily_totals': {'window_start':'2026-01-01T00:00:00Z',
                             'window_end_exclusive':'2026-01-02T00:00:00Z'}}
        for version in (1, 2, 3):
            with self.subTest(schema=version), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                artifact = c.render_csv(detail, 'fixture', schema_version=version)
                self.assertEqual(artifact['data'], c.render_csv(
                    detail, 'fixture', schema_version=version)['data'])
                columns = next(csv.reader(io.StringIO(artifact['data'].decode('utf-8-sig'))))
                self.assertEqual(columns, list(c.COLUMNS if version == 3 else
                                 c.LEGACY_COLUMNS if version == 2 else c.LEGACY_COLUMNS[1:]))
                config = BackupConfig('owner@example.invalid',root,root,root/'prefs',14)
                with patch.object(c, 'preflight_backup', return_value={'status':'ready'}):
                    c.export_csv(artifact['data'],artifact['filename'],config,export=True)
                    self.assertTrue(c.export_csv(artifact['data'],artifact['filename'],config,export=True)['reconciled'])
                    path = root/artifact['filename']
                    edited = artifact['data'] + b'owner-edited-fixture\r\n'
                    path.write_bytes(edited)
                    with self.assertRaises(DeliveryError):
                        c.export_csv(artifact['data'],artifact['filename'],config,export=True)
                    self.assertEqual(path.read_bytes(), edited)

    def test_docs_links_and_fences(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(docs, 'ROOT', Path(temp)):
            root = Path(temp)
            target = root/'target.md'; target.write_text('# Valid heading\n')
            page = root/'page.md'
            page.write_text('[ok](target.md#valid-heading)\n[external](https://example.invalid/no-fetch)\n')
            self.assertEqual(docs.check(page), [])
            page.write_text('[missing](missing.md)\n[anchor](target.md#absent)\n```python\n')
            errors = docs.check(page)
            self.assertEqual(len(errors), 3)

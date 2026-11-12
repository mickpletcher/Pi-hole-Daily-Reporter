import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pihole_report import research_csv as c
from pihole_report.delivery import BackupConfig,DeliveryError


def detail(rows=None):
    rows=[] if rows is None else rows
    return dict(research=dict(research_needed=rows,research_needed_count=len(rows)),daily_totals=dict(window_start='2026-01-01T01:00:00Z',window_end_exclusive='2026-01-02T01:00:00Z'))
def row(host='a.example',new=None):return dict(hostname=host,new_to_history=new,cache_status='uncached',reason='no evidence',action='manual research')

class CSVTests(unittest.TestCase):
    def test_format_sort_counts_window_formula(self):
        data=c.render_csv(detail([row('z.example',True),row('=evil',False)]),'a'*64)
        self.assertTrue(data['data'].startswith(b'\xef\xbb\xbf'))
        rows=list(csv.DictReader(io.StringIO(data['data'].decode('utf-8-sig'))))
        self.assertEqual(rows[0]['hostname'],"'=evil")
        self.assertEqual(rows[0]['new_to_history'],'no');self.assertEqual(rows[1]['new_to_history'],'yes')
        self.assertEqual(rows[0]['window_start_utc'],'2026-01-01T01:00:00Z')
        self.assertEqual(data['filename'],'pihole-research-needed-2026-01-02-aaaaaaaaaaaaaaaa.csv')
        for value in ('=1',' +2','-3','@x','\tx','\rx','\nx'):self.assertTrue(c.safe_cell(value).startswith("'"))
    def test_zero_rows_and_count_mismatch_duplicates(self):
        artifact=c.render_csv(detail(),'fixture');self.assertEqual(artifact['row_count'],0)
        self.assertEqual(len(list(csv.reader(io.StringIO(artifact['data'].decode('utf-8-sig'))))),1)
        for data in (detail([row(),row()]),dict(research=dict(research_needed=[],research_needed_count=1),daily_totals=detail()['daily_totals'])):
            with self.assertRaises(ValueError):c.render_csv(data,'fixture')
    def test_export_idempotency_collision_symlink_and_no_pruning(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();config=BackupConfig('owner@example.invalid',root,root,root/'prefs',14)
            artifact=c.render_csv(detail([row()]),'a'*64)
            preserved=root/'old.sqlite';preserved.write_bytes(b'preserved')
            with patch.object(c,'preflight_backup',return_value={'status':'ready'}) as preflight:
                self.assertFalse(c.export_csv(artifact['data'],artifact['filename'],config)['exported']);preflight.assert_not_called()
                first=c.export_csv(artifact['data'],artifact['filename'],config,export=True)
                self.assertFalse(first['reconciled'])
                self.assertTrue(c.export_csv(artifact['data'],artifact['filename'],config,export=True)['reconciled'])
                with self.assertRaises(DeliveryError):c.export_csv(b'different',artifact['filename'],config,export=True)
                target=root/artifact['filename'];target.unlink();target.symlink_to(preserved)
                with self.assertRaises(ValueError):c.export_csv(artifact['data'],artifact['filename'],config,export=True)
            self.assertEqual(preserved.read_bytes(),b'preserved')
    def test_sqlite_retention_prunes_only_marked_backups_and_preserves_csv(self):
        import sqlite3
        from pihole_report.delivery import _prune_snapshots, MARKER
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            artifact=c.render_csv(detail([row()]),'a'*64)
            csv_path=root/artifact['filename'];csv_path.write_bytes(artifact['data'])
            snapshots=[]
            for day in (1,2,3):
                path=root/f'pihole-history-2026-01-{day:02d}T00-00-00-000Z.sqlite'
                with sqlite3.connect(path) as db:
                    db.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)')
                    db.execute('INSERT INTO metadata VALUES(?,?)',('snapshot_generator',MARKER))
                snapshots.append(path)
            unowned=root/'pihole-history-2000-01-01T00-00-00-000Z.sqlite'
            with sqlite3.connect(unowned) as db:
                db.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)')
                db.execute('INSERT INTO metadata VALUES(?,?)',('snapshot_generator','different-generator'))
            removed=_prune_snapshots(root,retention=2)
            self.assertEqual(removed,[snapshots[0].name])
            self.assertFalse(snapshots[0].exists())
            self.assertTrue(all(path.exists() for path in snapshots[1:]))
            self.assertTrue(unowned.exists())
            self.assertEqual(csv_path.read_bytes(),artifact['data'])

    def test_worker_uses_bounded_owned_transport(self):
        with patch.object(c,'run_backup_worker',return_value={}) as worker:
            c.run_csv_worker({'local_date':'2026-01-02','sha256':'a'*64},timeout=20)
        self.assertEqual(worker.call_args.kwargs['_worker_module'],'pihole_report.research_csv')
        self.assertEqual(worker.call_args.kwargs['timeout'],20)
    def test_account_failure_no_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();config=BackupConfig('owner@example.invalid',root,root,root/'prefs',14)
            artifact=c.render_csv(detail(),'fixture')
            with patch.object(c,'preflight_backup',side_effect=DeliveryError('backup_account_mismatch')):
                with self.assertRaises(DeliveryError):c.export_csv(artifact['data'],artifact['filename'],config,export=True)
            self.assertEqual(list(root.iterdir()),[])

if __name__=='__main__':unittest.main()

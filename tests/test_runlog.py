from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from pihole_report.cli import PROJECT
from pihole_report import runlog


class RunLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=PROJECT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 1800000000

    def make_log(self, age):
        return runlog.write_log(self.root, {"status": "complete"}, self.now-age-1, self.now-age)

    def test_retention_boundary(self):
        boundary = self.make_log(30*86400)
        older = self.make_log(31*86400)
        younger = self.make_log(30*86400-1)
        future = self.make_log(-1)
        result = runlog.prune_logs(self.root, self.now)
        self.assertEqual(result['deleted_count'], 2)
        self.assertFalse(boundary.exists())
        self.assertFalse(older.exists())
        self.assertTrue(younger.exists())
        self.assertTrue(future.exists())

    def test_unrecognized_and_symlink_files_survive(self):
        wrong_schema = self.make_log(40*86400)
        data = json.loads(wrong_schema.read_text())
        data['schema'] = 'other-app'
        wrong_schema.write_text(json.dumps(data))
        wrong_identity = self.make_log(40*86400)
        data = json.loads(wrong_identity.read_text())
        data['run_id'] = 'wrong'
        wrong_identity.write_text(json.dumps(data))
        malformed = self.make_log(40*86400)
        malformed.write_text('{')
        directory = wrong_schema.parent
        unrelated = directory/'unrelated.log'
        unrelated.write_text('keep')
        link = self.make_log(40*86400)
        link.unlink()
        link.symlink_to(unrelated)
        subdirectory = self.make_log(40*86400)
        subdirectory.unlink()
        subdirectory.mkdir()
        wrong_timestamp = self.make_log(40*86400)
        data = json.loads(wrong_timestamp.read_text())
        data['finished_at'] = '2000-01-01T00:00:00Z'
        wrong_timestamp.write_text(json.dumps(data))
        result = runlog.prune_logs(self.root, self.now)
        self.assertEqual(result['deleted_count'], 0)
        self.assertTrue(all(p.exists() for p in (wrong_schema,wrong_identity,malformed,unrelated,link,subdirectory,wrong_timestamp)))

    def test_matching_old_fifo_is_skipped_without_open(self):
        path = self.make_log(40*86400)
        path.unlink()
        os.mkfifo(path, 0o600)
        result = runlog.prune_logs(self.root, self.now)
        self.assertEqual(result['deleted_count'], 0)
        self.assertEqual(result['skipped_count'], 1)
        self.assertTrue(path.exists())

    def test_deeply_nested_malformed_log_is_preserved(self):
        path = self.make_log(40*86400)
        path.write_text('[' * 2000 + '0' + ']' * 2000)
        result = runlog.prune_logs(self.root, self.now)
        self.assertEqual(result['deleted_count'], 0)
        self.assertTrue(path.exists())

    def test_private_log_and_reserved_fields(self):
        path = runlog.write_log(self.root, {'schema':'spoof','run_id':'spoof'}, self.now-3, self.now)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        data = json.loads(path.read_text())
        self.assertEqual(data['schema'],runlog.SCHEMA)
        self.assertEqual(data['duration_seconds'],3)
        self.assertNotEqual(data['run_id'],'spoof')
        with self.assertRaises(ValueError):
            runlog.write_log(self.root,{},self.now+1,self.now)

    def test_directory_symlink_rejected(self):
        (self.root/'logs').symlink_to('/tmp',target_is_directory=True)
        with self.assertRaises(ValueError):
            runlog.write_log(self.root,{},self.now,self.now)
        with self.assertRaises(ValueError):
            runlog.prune_logs(self.root,self.now)

    def test_snapshot_counts_do_not_double_count_names(self):
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript("CREATE TABLE snapshots(id,site,from_time,until_time); CREATE TABLE snapshot_counts(snapshot_id,domain,outcome,queries);")
        db.execute("INSERT INTO snapshots VALUES('s','test',0,86400)")
        db.executemany("INSERT INTO snapshot_counts VALUES('s',?,?,?)", [('both.com','allowed',10),('both.com','blocked',3),('block.com','blocked',7),('allow.com','allowed',5)])
        totals=runlog.snapshot_totals(db,'s')
        self.assertEqual(totals['total_recorded_queries'],25)
        self.assertEqual(totals['unique_hostnames'],3)
        self.assertEqual(totals['unique_allowed_hostnames'],2)
        self.assertEqual(totals['unique_blocked_hostnames'],2)
        self.assertEqual(totals['hostnames_both_allowed_and_blocked'],1)
        text = runlog.render_totals(totals)
        self.assertIn('## Daily DNS activity totals', text)
        self.assertIn('not full URLs or proven website visits', text)
        self.assertIn('not available from this rolling inventory', text)

    def test_verified_evidence_and_research_distinctions(self):
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE domain_research_cache(domain,status,result_json)')
        good={'status':'researched','evidence_checked':True,'evidence_quality':'primary','provenance':'fixture','researched_at':'2026-01-01T00:00:00Z','blocking_impact_caveats':'untested','purpose':{'text':'service','evidence':[{'url':'https://vendor.com/docs','excerpt':'published evidence','source_kind':'primary'}]}}
        db.executemany('INSERT INTO domain_research_cache VALUES(?,?,?)', [('good.com','researched',json.dumps(good)),('bad.com','researched','{}'),('hold.com','unresolved','{}')])
        result=runlog.research_status(db,['good.com','bad.com','hold.com','new.com','printer.local'],new_to_catalog=['new.com','printer.local'])
        self.assertEqual(result['new_to_history_count'],2)
        self.assertEqual(result['verified_exact_research_count'],1)
        self.assertEqual(result['missing_verified_research_count'],4)
        self.assertEqual(result['research_needed_count'],3)
        self.assertEqual(result['existing_hostnames_missing_verified_research_count'],2)
        self.assertEqual(result['excluded_from_external_research_count'],1)
        self.assertIn('hold',[r['action'] for r in result['research_needed'] if r['hostname']=='hold.com'][0])
        self.assertEqual(db.execute("SELECT status FROM domain_research_cache WHERE domain='hold.com'").fetchone()[0],'unresolved')
        bad=dict(good,evidence_checked=False)
        self.assertFalse(runlog.verified_research(bad))
        self.assertFalse(runlog.verified_research({'status':'researched'}))
        replay = runlog.research_status(db, ['new.com'])
        self.assertIsNone(replay['new_to_history_count'])
        self.assertFalse(replay['new_to_history_evaluated'])

if __name__ == '__main__':
    unittest.main()

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from pihole_report.storage import connect, feedback, import_report, ingest_queries, transaction
from pihole_report.collector import collect, collector_lock

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.db = connect(self.path/'history.sqlite')
    def tearDown(self):
        self.db.close(); self.tmp.cleanup()
    def query(self, ident=1, status='CACHE', stamp=1000):
        return {'id':ident, 'time':stamp, 'domain':'Example.COM.', 'client':{'ip':'192.0.2.1'}, 'status':status, 'type':'A'}
    def test_dedup_and_status_rollback(self):
        with transaction(self.db):
            self.assertEqual(ingest_queries(self.db,'s',[self.query(),self.query()],0,2000),1)
        with self.assertRaises(ValueError), transaction(self.db):
            ingest_queries(self.db,'s',[self.query(2),self.query(status='GRAVITY')],0,2000)
        self.assertEqual(self.db.execute('SELECT sum(queries) FROM daily').fetchone()[0],1)
    def test_unknown_and_utc_day(self):
        with transaction(self.db):
            ingest_queries(self.db,'s',[self.query(status='IN_PROGRESS',stamp=86400)],0,90000)
        row=self.db.execute('SELECT day,outcome FROM daily').fetchone()
        self.assertEqual(tuple(row),('1970-01-02','unknown'))
    def test_csv_idempotence(self):
        f=self.path/'feedback.csv'; f.write_text('domain,decision,note,date\nexample.com,allow,"a, b",2026-11-12\n')
        feedback(self.db,f); feedback(self.db,f)
        self.assertEqual(self.db.execute('SELECT count(*),note FROM decisions').fetchone()[0],1)
    def test_snapshot_replay(self):
        f=self.path/'report.md'; f.write_text('Generated: 2026-11-12T00:00:00Z\n## Complete allowed-domain\n| `example.com` | 3 |\n')
        self.assertEqual(import_report(self.db,f),1); self.assertEqual(import_report(self.db,f),0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM daily').fetchone()[0],0)
    def test_collect_cursor_and_aggregate_replay(self):
        self.db.execute("INSERT INTO metadata VALUES('storage_mode','aggregate-first')")
        pages=[]
        def transport(base,route,method,payload,sid):
            if route=='/api/auth': return {'session':{'sid':'fixture'}}
            params=parse_qs(urlsplit(route).query); pages.append(params)
            return {'queries': [self.query(4), self.query(3)] if 'cursor' not in params else [], 'recordsFiltered':2,'earliest_timestamp_disk':900}
        self.assertEqual(collect(self.db,'s','https://pihole.example.invalid',transport,'synthetic',now=2300),2)
        self.assertEqual(pages[1]['cursor'],['2'])
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0],0)
        with transaction(self.db):
            self.assertEqual(ingest_queries(self.db,'s',[self.query(4)],0,2000),0)
    def test_incomplete_collect_rolls_back(self):
        def transport(base,route,method,payload,sid):
            if route=='/api/auth': return {'session':{'sid':'fixture'}}
            return {'queries':[],'recordsFiltered':3}
        with self.assertRaises(ValueError): collect(self.db,'s','https://pihole.example.invalid',transport,'synthetic',now=2300)
        self.assertEqual(self.db.execute('SELECT count(*) FROM sources').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT status FROM runs').fetchone()[0],'failed')
    def test_partial_page_failure_rolls_back_all_counts(self):
        self.db.execute("INSERT INTO metadata VALUES('storage_mode','aggregate-first')")
        def transport(base,route,method,payload,sid):
            if route=='/api/auth': return {'session':{'sid':'fixture'}}
            params=parse_qs(urlsplit(route).query)
            return {'queries':[self.query(4)] if 'cursor' not in params else [],'recordsFiltered':2}
        with self.assertRaises(ValueError): collect(self.db,'s','https://pihole.example.invalid',transport,'synthetic',now=2300)
        for table in ('daily','domains','coverage','sources'):
            self.assertEqual(self.db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
    def test_descending_id_violation(self):
        def transport(base,route,method,payload,sid):
            if route=='/api/auth': return {'session':{'sid':'fixture'}}
            return {'queries':[self.query(2), self.query(3)],'recordsFiltered':2}
        with self.assertRaisesRegex(ValueError,'descending'):
            collect(self.db,'s','https://pihole.example.invalid',transport,'synthetic',now=2300)
        self.assertEqual(self.db.execute('SELECT count(*) FROM daily').fetchone()[0],0)
    def test_schema_reopen_preserves_metadata(self):
        self.db.execute("INSERT INTO metadata VALUES('fixture','preserved')")
        other=connect(self.path/'history.sqlite')
        try: self.assertEqual(other.execute("SELECT value FROM metadata WHERE key='fixture'").fetchone()[0],'preserved')
        finally: other.close()
    def test_live_lock_blocks(self):
        with collector_lock(self.db):
            with self.assertRaises(RuntimeError), collector_lock(self.db): pass
    def test_readonly_does_not_initialize(self):
        other=connect(self.path/'history.sqlite',read_only=True)
        try:
            with self.assertRaises(sqlite3.OperationalError): other.execute("INSERT INTO metadata VALUES('x','y')")
        finally: other.close()

class TimestampTests(unittest.TestCase):
    def test_legacy_zones_have_explicit_offsets(self):
        from pihole_report.storage import parse_timestamp
        expected = parse_timestamp('2026-11-11T12:00:00Z')
        for text in ('2026-11-11 12:00:00 UTC', '2026-11-11 12:00:00 GMT',
                     '2026-11-11 06:00:00 CST', '2026-11-11 07:00:00 CDT',
                     '2026-11-11 06:00:00 -0600'):
            self.assertEqual(parse_timestamp(text), expected)

if __name__=='__main__': unittest.main()

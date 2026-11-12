import json
import sqlite3
import unittest
from urllib.parse import parse_qs, urlsplit

from pihole_report.collector import collect
from pihole_report.coverage import run_coverage, window_coverage
from pihole_report.storage import initialize


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.db.row_factory = sqlite3.Row
        initialize(self.db)
        self.db.execute("INSERT INTO metadata VALUES('storage_mode','aggregate-first')")
        self.db.execute("INSERT INTO sources VALUES('s','https://pihole.example.invalid',NULL,1000)")

    def tearDown(self):
        self.db.close()

    def transport(self, earliest=1500, queries=None, expected=None):
        queries = queries or []
        def request(base, route, method, payload, sid):
            if route == '/api/auth':
                return {'session': {'sid': 'synthetic'}}
            params = parse_qs(urlsplit(route).query)
            return {'queries': queries if 'cursor' not in params else [],
                    'recordsFiltered': len(queries) if expected is None else expected,
                    'earliest_timestamp_disk': earliest}
        return request

    def run_collect(self, earliest=1500, **kwargs):
        collect(self.db, 's', 'https://pihole.example.invalid', self.transport(earliest, **kwargs), 'synthetic', now=2300)
        run = self.db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 1').fetchone()
        return run, run_coverage(self.db, run['id'])

    def prior(self, left, right):
        run = self.db.execute("INSERT INTO runs(site,started,from_time,until_time,status) VALUES('s',0,?,?,'complete')", (left,right)).lastrowid
        self.db.execute("INSERT INTO coverage VALUES('s',?,?,?)", (left,right,run))
        return run

    def test_retention_gap_is_partial_and_highwater_advances(self):
        run, evidence = self.run_collect()
        self.assertEqual(run['status'], 'partial')
        self.assertEqual(evidence['fetch_status'], 'complete')
        self.assertEqual(evidence['covered_seconds'], 500)
        self.assertEqual(evidence['gaps'], [{'from_time':1000, 'until_time':1500}])
        self.assertEqual(evidence['retention_cutoff'], 1500)
        self.assertEqual(self.db.execute('SELECT last_complete_until FROM sources').fetchone()[0],2000)
        # The immutable lost-gap evidence survives subsequent successful windows.
        collect(self.db, 's', 'https://pihole.example.invalid', self.transport(1500), 'synthetic', now=3300)
        second = self.db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 1').fetchone()
        self.assertEqual(second['from_time'],2000)
        self.assertEqual(second['status'],'complete')
        self.assertEqual(run_coverage(self.db,run['id']),evidence)

    def test_retained_history_covers_expired_prefix(self):
        self.prior(900,1600)
        run, evidence = self.run_collect()
        self.assertEqual(run['status'],'complete')
        self.assertEqual(evidence['covered_seconds'],1000)
        self.assertEqual(evidence['gaps'],[])
        self.assertEqual(evidence['network_completeness'],'unknown')
        self.assertEqual(evidence['api_filter_completeness'],'unknown')

    def test_unknown_disk_bound_does_not_invent_empty_coverage(self):
        for bound in (None,0,-1,True,float('nan'),float('inf'),'1000'):
            with self.subTest(bound=bound):
                self.db.execute('DELETE FROM runs')
                self.db.execute('DELETE FROM metadata WHERE key LIKE ?',('collection_coverage:%',))
                self.db.execute('UPDATE sources SET last_complete_until=1000')
                run, evidence = self.run_collect(bound)
                self.assertEqual(run['status'],'unknown')
                self.assertEqual(evidence['covered_seconds'],0)
                self.assertEqual(self.db.execute('SELECT count(*) FROM coverage').fetchone()[0],0)

    def test_unknown_bound_can_use_previously_retained_coverage(self):
        self.prior(1000,2000)
        run, evidence = self.run_collect(None)
        self.assertEqual(run['status'],'complete')
        self.assertIsNone(evidence['retention_cutoff'])

    def test_empty_known_window_is_covered(self):
        run, evidence = self.run_collect(1000)
        self.assertEqual(run['status'],'complete')
        self.assertEqual(evidence['covered_seconds'],1000)
        self.assertEqual(evidence['received_queries'],0)

    def test_cutoff_at_or_after_end_is_entire_gap(self):
        run, evidence = self.run_collect(2100)
        self.assertEqual(run['status'],'partial')
        self.assertEqual(evidence['covered_seconds'],0)
        self.assertEqual(evidence['gaps'],[{'from_time':1000,'until_time':2000}])

    def test_union_clipping_overlap_adjacency_and_gaps(self):
        for left,right in ((900,1200),(1100,1400),(1400,1600),(1800,2500)):
            self.prior(left,right)
        evidence = window_coverage(self.db,'s',1000,2000)
        self.assertEqual(evidence['covered_seconds'],800)
        self.assertEqual(evidence['gaps'],[{'from_time':1600,'until_time':1800}])
        self.assertEqual(window_coverage(self.db,'other',1000,2000)['covered_seconds'],0)
        self.assertEqual(window_coverage(self.db,'s',1000,1000)['requested_seconds'],0)

    def test_failed_pagination_publishes_nothing(self):
        with self.assertRaises(ValueError):
            self.run_collect(expected=3)
        self.assertEqual(self.db.execute('SELECT status FROM runs').fetchone()[0],'failed')
        self.assertEqual(self.db.execute('SELECT count(*) FROM coverage').fetchone()[0],0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM metadata WHERE key LIKE 'collection_coverage:%'").fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT last_complete_until FROM sources').fetchone()[0],1000)

    def test_half_open_boundaries_and_aggregate_first(self):
        query = {'id':4,'time':1000,'domain':'example.com','client':{'ip':'192.0.2.1'},'status':'CACHE','type':'A'}
        run, evidence = self.run_collect(1000,queries=[query])
        self.assertEqual(evidence['newly_stored_queries'],1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0],0)
        # End-exclusive query is rejected atomically, rather than silently double-counted.
        query['time'] = 3000
        with self.assertRaises(ValueError):
            collect(self.db,'s','https://pihole.example.invalid',self.transport(1000,[query]),'synthetic',now=3300)
        self.assertEqual(self.db.execute('SELECT sum(queries) FROM daily').fetchone()[0],1)

    def test_legacy_reconstruction_never_rewrites_history(self):
        run = self.prior(1500,2000)
        self.db.execute('UPDATE runs SET from_time=1000 WHERE id=?',(run,))
        before = list(self.db.iterdump())
        evidence = run_coverage(self.db,run)
        self.assertEqual(evidence['temporal_status'],'partial')
        self.assertEqual(evidence['network_completeness'],'unknown')
        self.assertEqual(list(self.db.iterdump()), before)

    def test_epoch_durations_are_dst_independent(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        tz=ZoneInfo('America/Chicago')
        start=datetime(2026,11,1,tzinfo=tz).timestamp()
        end=datetime(2026,11,2,tzinfo=tz).timestamp()
        self.prior(start,end)
        self.assertEqual(window_coverage(self.db,'s',start,end)['covered_seconds'],25*3600)

    def test_advancing_retention_bound_is_conservative(self):
        query = {'id':4,'time':1600,'domain':'example.com','client':{'ip':'192.0.2.1'},'status':'CACHE','type':'A'}
        def transport(base,route,method,payload,sid):
            if route == '/api/auth':
                return {'session':{'sid':'synthetic'}}
            later = 'cursor=' in route
            return {'queries':[] if later else [query], 'recordsFiltered':1,
                    'earliest_timestamp_disk':1700 if later else 1500}
        collect(self.db,'s','https://pihole.example.invalid',transport,'synthetic',now=2300)
        evidence=run_coverage(self.db,1)
        self.assertEqual(evidence['retention_cutoff'],1700)
        self.assertEqual(evidence['covered_seconds'],300)
        self.assertEqual(evidence['newly_stored_queries'],1)

    def test_no_elapsed_window_does_not_make_a_new_claim(self):
        self.assertEqual(collect(self.db,'s','https://pihole.example.invalid',None,'synthetic',now=1300),0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM runs').fetchone()[0],0)

    def test_null_legacy_highwater_is_initialized(self):
        self.db.execute('UPDATE sources SET last_complete_until=NULL')
        self.run_collect(1000)
        self.assertEqual(self.db.execute('SELECT last_complete_until FROM sources').fetchone()[0],2000)


if __name__ == '__main__':
    unittest.main()

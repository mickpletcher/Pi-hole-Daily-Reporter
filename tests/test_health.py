import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pihole_report import health
from pihole_report.cli import PROJECT, main
from pihole_report.storage import connect
from pihole_report.report import FILES


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=PROJECT)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.now=1800000000
        self.db=connect(self.root/'history.sqlite')
        self.addCleanup(self.db.close)
        self.start=self.now-86400
        self.end=self.now-300
        self.db.execute('INSERT INTO runs(id,site,started,finished,from_time,until_time,status) VALUES(1,?,?,?,?,?,?)',('Fixture',self.now,self.now,self.start,self.end,'complete'))
        self.db.execute('INSERT INTO coverage VALUES(?,?,?,?)',('Fixture',self.start,self.end,1))
        self.totals={'site':'Fixture','window_start':health.iso(self.start),'window_end_exclusive':health.iso(self.now),'snapshot_id':'fixture'}
        self.scope={'status':'verified','exclude_domains':[],'exclude_clients':[],'privacy_level':0}
        self.inv={'generatedAt':health.iso(self.now-3600),'clients':[{}]}
        directory=self.root/'config/list-snapshots'/('a'*40)
        directory.mkdir(parents=True)
        for filename in FILES:(directory/filename).write_text('fixture.example\n')
        (self.root/'config/curated-list-state.json').write_text(json.dumps({'commit':'a'*40,'checked_at':self.now-10}))
    def result(self,**kwargs):
        options=dict(latest_run=None,import_succeeded=True,inventory=self.inv,inventory_refresh_attempted=False,api_scope=self.scope,now=self.now)
        options.update(kwargs)
        return health.data_health(self.db,self.root,self.totals,**options)
    def test_intentional_lag_is_not_old_gap(self):
        result=self.result()
        self.assertEqual(result['status'],'healthy')
        self.assertEqual(result['mature_history_coverage']['gaps'],[])
        self.assertEqual(result['full_report_history_coverage']['gaps'],[{'from_time':self.end,'until_time':self.now}])
        self.assertEqual(result['intentional_recent_delay_seconds'],300)
        text=health.render_data_health(result)
        self.assertIn('86100 of 86100',text)
        self.assertIn('300 seconds are intentionally deferred',text)
        self.assertNotIn('all network activity is complete',text)
    def test_old_gap_explicit(self):
        self.db.execute('DELETE FROM coverage')
        self.db.execute('INSERT INTO coverage VALUES(?,?,?,?)',('Fixture',self.start+60,self.end,1))
        result=self.result()
        self.assertEqual(result['status'],'limited')
        self.assertEqual(result['mature_history_coverage']['covered_seconds'],86040)
        self.assertIn('Uncovered:',health.render_data_health(result))
    def test_filtered_counts_remain_visible_scope(self):
        result=self.result(api_scope={**self.scope,'exclude_domains':['hidden.example']})
        self.assertEqual(result['api_scope']['filter_status'],'filtered')
        self.assertTrue(any('exclusions' in s for s in result['warnings']))
        self.assertTrue(any('privacy settings' in s for s in self.result(api_scope={**self.scope,'privacy_level':2})['warnings']))
    def test_missing_scope_not_no_filters(self):
        result=self.result(api_scope={'status':'partial','exclude_domains':[],'exclude_clients':None,'privacy_level':0})
        self.assertEqual(result['api_scope']['filter_status'],'unverified')
        self.assertEqual(result['status'],'limited')
    def test_failure_and_stale_inputs_are_separate(self):
        (self.root/'config/curated-list-state.json').write_text(json.dumps({'commit':'a'*40,'checked_at':self.now-10,'last_error':'http_503'}))
        result=self.result(import_succeeded=False,inventory={'generatedAt':health.iso(self.now-200000),'clients':[]})
        self.assertFalse(result['collection_import_succeeded'])
        self.assertEqual(result['inventory']['status'],'stale')
        self.assertEqual(result['curated_lists']['status'],'refresh_failed')
    def test_missing_selected_lists_not_fresh(self):
        (self.root/'config/curated-list-state.json').write_text(json.dumps({'commit':'b'*40,'checked_at':self.now}))
        self.assertEqual(self.result()['curated_lists']['status'],'unavailable')
    def test_timestamp_and_freshness_boundaries(self):
        self.assertEqual(health.freshness(self.now-100,self.now,100)['status'],'recent')
        self.assertEqual(health.freshness(self.now-101,self.now,100)['status'],'stale')
        for value in (None,True,'bad','2026-11-12T06:05:00',float('nan'),1e99):
            self.assertEqual(health.freshness(value,self.now,100)['status'],'unavailable')
        self.assertEqual(health.freshness(self.now+301,self.now,100)['status'],'clock_skew')
    def test_readonly_health_no_credentials_network_or_writes(self):
        path=self.root/'state/production/current-health.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({'schema':'pihole-operational-health.v1','local_date':'2027-01-15','status':'running','updated_at_epoch':self.now-1300,'stages':{'backup':{'status':'running'}}}))
        before=path.read_bytes()
        result=health.read_operational_health(self.root,now=self.now)
        self.assertEqual(result['network_calls'],0)
        self.assertIn('more than 20 minutes',health.health_text(result))
        self.assertEqual(path.read_bytes(),before)
    def test_fifo_symlink_invalid_json_fail_without_blocking(self):
        for kind in ('fifo','symlink','json'):
            path=self.root/('input-'+kind)
            if kind=='fifo':os.mkfifo(path)
            elif kind=='symlink':path.symlink_to('/dev/null')
            else:path.write_text('[]')
            with self.assertRaises(ValueError):health.read_json(path)
    def test_attribution_shared_sample_diagnostics_count_once(self):
        common=dict(domain='same.example',sample_status='sampled',unknown_status_queries=2,excluded_queries=3)
        rows=[dict(common,state='allowed',invalid_client_queries=4),dict(common,state='blocked',invalid_client_queries=1),
              dict(domain='unavailable.example',state='allowed',sample_status='unavailable')]
        result=self.result(attribution=rows)
        self.assertEqual(result['attribution']['unknown_status_records'],2)
        self.assertEqual(result['attribution']['excluded_records'],3)
        self.assertEqual(result['attribution']['invalid_client_records'],5)
        self.assertEqual(result['attribution']['unavailable_samples'],1)
        self.assertEqual(result['status'],'limited')
    def test_bounded_json_and_invalid_privacy(self):
        path=self.root/'input.json'
        path.write_text('{"padding":"'+'x'*100+'"}')
        with self.assertRaises(ValueError):health.read_json(path,limit=30)
        self.assertEqual(self.result(api_scope={**self.scope,'privacy_level':4})['api_scope']['filter_status'],'unverified')
    def test_absent_health_command_does_not_create_state(self):
        output=io.StringIO()
        with patch('pihole_report.cli.PROJECT',self.root),contextlib.redirect_stdout(output):
            self.assertEqual(main(['health']),1)
        self.assertIn('No operational health',output.getvalue())
        self.assertFalse((self.root/'state').exists())

if __name__=='__main__':unittest.main()

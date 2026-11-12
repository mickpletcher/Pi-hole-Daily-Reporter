import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pihole_report.cli import PROJECT
from pihole_report.pipeline import run_daily
from pihole_report.storage import connect


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=PROJECT)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'config/lists').mkdir(parents=True)
        (self.root/'memory').mkdir()
        (self.root/'config/lists/curated-blocklist-policy.txt').write_text('ads.widget.com\n')
        (self.root/'config/lists/curated-blocklist-device.txt').write_text('ads.widget.com\n')
        (self.root/'config/lists/curated-whitelist.txt').write_text('')
        (self.root/'config/recommendation-feedback.csv').write_text('domain,decision,note,date\n')
        (self.root/'memory/unifi-clients.json').write_text(json.dumps({'generatedAt':'2026-01-01T00:00:00Z','clients':[]}))
        self.dbpath=self.root/'data/pihole-history/history.sqlite'
        db=connect(self.dbpath)
        db.execute("INSERT INTO metadata VALUES('storage_mode','aggregate-first')")
        db.close()
        self.now=1800000000
        self.requests=[]

    def transport(self,base,route,method='GET',payload=None,sid=None):
        self.requests.append((route,method))
        if route=='/api/auth':
            return {'session':{'sid':'synthetic-session'}} if method=='POST' else {}
        if route.startswith('/api/stats/database/top_domains'):
            return {'domains':[] if 'blocked=true' in route else [{'domain':'ads.widget.com','count':1}]}
        if route=='/api/clients':
            return {'clients':[]}
        if route.startswith('/api/queries?'):
            if 'domain=' in route or 'cursor=' in route:
                return {'queries':[],'recordsFiltered':1,'earliest_timestamp_disk':self.now-100000}
            return {'queries':[{'id':1,'time':self.now-400,'domain':'ads.widget.com','client':{'ip':'192.0.2.1'},'status':'FORWARDED','type':'A'}],'recordsFiltered':1,'earliest_timestamp_disk':self.now-100000}
        raise AssertionError('Unexpected operation: '+route)

    def test_complete_pipeline_and_replay(self):
        first=run_daily(self.root,self.transport,'synthetic-password',now=self.now,log_root=self.root)
        self.assertEqual(first['collection_status'],'complete')
        self.assertEqual(first['new_measured_queries'],1)
        self.assertEqual(first['research_newly_queued'],1)
        text=Path(first['report']).read_text()
        self.assertIn('ads.widget.com',text)
        self.assertIn('1 newly queued locally',text)
        second=run_daily(self.root,self.transport,'synthetic-password',now=self.now,log_root=self.root)
        self.assertEqual(second['new_measured_queries'],0)
        db=connect(self.dbpath,read_only=True)
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT sum(queries) FROM daily').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT count(*) FROM snapshots').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT count(*) FROM screenings').fetchone()[0],1)
        self.assertFalse(first['email_sent'])
        log=json.loads(Path(first['log_file']).read_text())
        self.assertEqual(log['research']['new_to_history_count'],1)
        self.assertEqual(log['research']['research_needed_count'],1)
        self.assertIn('## Daily DNS activity totals',text)
        self.assertEqual(first['hosted_calls'],0)
        self.assertTrue(all(m=='GET' or r=='/api/auth' for r,m in self.requests))

    def test_collector_and_unifi_failure_preserve_report_and_history(self):
        inv=self.root/'memory/unifi-clients.json'
        old=hashlib.sha256(inv.read_bytes()).hexdigest()
        def flaky(base,route,method='GET',payload=None,sid=None):
            if route.startswith('/api/queries?') and 'domain=' not in route:
                raise RuntimeError('secret-from-provider-not-safe-to-log')
            return self.transport(base,route,method,payload,sid)
        def unifi(*args,**kwargs):
            raise RuntimeError('secret-from-provider-not-safe-to-log')
        result=run_daily(self.root,flaky,'synthetic-password',now=self.now,unifi_transport=unifi,unifi_base='https://controller.invalid',unifi_api_key='synthetic-api-key',log_root=self.root)
        self.assertEqual(result['collection_status'],'failed')
        self.assertTrue(Path(result['report']).is_file())
        self.assertEqual(hashlib.sha256(inv.read_bytes()).hexdigest(),old)
        self.assertNotIn('secret-from-provider',Path(result['report']).read_text())
        self.assertIn('stale: refresh failed',Path(result['report']).read_text())
        db=connect(self.dbpath,read_only=True)
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT count(*) FROM daily').fetchone()[0],0)
        self.assertEqual(db.execute('SELECT count(*) FROM coverage').fetchone()[0],0)

    def test_failure_gets_sanitized_log(self):
        def fail(*args,**kwargs):
            raise RuntimeError('secret-auth-payload')
        with self.assertRaises(RuntimeError) as caught:
            run_daily(self.root,fail,'synthetic-password',now=self.now,log_root=self.root)
        log=json.loads(Path(caught.exception.pihole_log_path).read_text())
        self.assertEqual(log['status'],'failed')
        self.assertNotIn('secret-auth-payload',json.dumps(log))

    def test_config_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as external:
            (self.root/'config/list-snapshots').symlink_to(external,target_is_directory=True)
            with self.assertRaises(ValueError):
                run_daily(self.root,self.transport,'synthetic-password',now=self.now,log_root=self.root)
            self.assertEqual(self.requests,[])

    def test_production_run_refused_before_transport(self):
        with self.assertRaises(ValueError):
            run_daily(PROJECT.parent,self.transport,'synthetic-password')
        self.assertEqual(self.requests,[])

if __name__=='__main__':
    unittest.main()

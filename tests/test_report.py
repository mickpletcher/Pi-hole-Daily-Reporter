import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from pihole_report import report

class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); (self.root/'config/lists').mkdir(parents=True)
        for name in report.FILES: (self.root/'config/lists'/name).write_text('')
        (self.root/'config/lists'/report.FILES[0]).write_text('ads.vendor.com\nunknown.vendor.com\namazon.com\n')
        (self.root/'config/protected-domains.txt').write_text('safe.vendor.com\n')
        self.db=sqlite3.connect(':memory:'); self.addCleanup(self.db.close)
        self.db.executescript('''CREATE TABLE domains(domain TEXT,first_observed REAL,last_observed REAL,observation_precision TEXT);
        CREATE TABLE snapshots(id TEXT,site TEXT,from_time REAL,until_time REAL,provenance TEXT,precision TEXT);
        CREATE TABLE snapshot_counts(snapshot_id TEXT,domain TEXT,outcome TEXT,queries INT);
        CREATE TABLE decisions(id TEXT,domain TEXT,decision TEXT,imported REAL);
        CREATE TABLE protection_evidence(domain TEXT,observed_date TEXT);
        CREATE TABLE daily(site TEXT,day TEXT,domain TEXT,client_ip TEXT,outcome TEXT,queries INT,first_seen REAL,last_seen REAL);
        CREATE TABLE coverage(site TEXT,from_time REAL,until_time REAL,run_id INT);
        CREATE TABLE metadata(key TEXT,value TEXT);
        CREATE TABLE runs(id INT,status TEXT,error TEXT,from_time REAL,until_time REAL,query_count INT);
        CREATE TABLE domain_research_cache(domain TEXT,status TEXT,result_json TEXT);
        CREATE TABLE domain_research_control(key TEXT,value TEXT);
        CREATE TABLE email_history_sources(source_id TEXT,generated_at TEXT);
        CREATE TABLE email_history_records(domain TEXT,source_id TEXT);
        CREATE TABLE email_history_supplementary(domain TEXT,source_id TEXT,source_date TEXT);''')
        self.db.execute("INSERT INTO snapshots VALUES('s','Primary',0,86400,'fixture','window')")
    def add(self,d,out='allowed',count=1):
        self.db.execute('INSERT INTO domains VALUES(?,0,86400,?)',(d,'window_bound'))
        self.db.execute("INSERT INTO snapshot_counts VALUES('s',?,?,?)",(d,out,count))
    def test_screening_safety(self):
        for d in ['a.ads.vendor.com','unknown.vendor.com','video.amazon.com','safe.vendor.com','sub.protected.example','protected.example']: self.add(d)
        self.db.execute("INSERT INTO protection_evidence VALUES('protected.example','2000-01-01')")
        self.db.execute("INSERT INTO decisions VALUES('d','unknown.vendor.com','ignore',1)")
        result={r['domain']:r for r in report.classify(self.db,{'id':'s','site':'Primary','until_time':86400},self.root)['rows']}
        self.assertEqual(result['a.ads.vendor.com']['bucket'],'tracking_review')
        self.assertEqual(result['video.amazon.com']['bucket'],'service_risk')
        self.assertEqual(result['unknown.vendor.com']['bucket'],'decided')
        self.assertEqual(result['protected.example']['bucket'],'protected')
        self.assertIsNone(result['sub.protected.example']['protection'])
        self.assertTrue(all(r['current_rule_status']=='unknown' for r in result.values()))
        self.assertEqual(result['a.ads.vendor.com']['match_domain'],'ads.vendor.com')
    def test_inventory_keeps_unknown_and_history_separate(self):
        self.add('measured.com'); self.add('catalog.com')
        self.db.execute("INSERT INTO daily VALUES('Primary','1970-01-01','measured.com','192.0.2.1','allowed',3,1,2)")
        self.db.execute("INSERT INTO email_history_sources VALUES('e','1970-01-01T00:00:00Z')")
        self.db.execute("INSERT INTO email_history_records VALUES('old.com','e')")
        self.db.execute("INSERT INTO email_history_records VALUES('measured.com','e')")
        self.db.execute("INSERT INTO email_history_supplementary VALUES('claim.com','e','1970-01-01T00:00:00Z')")
        result={r['hostname']:r for r in report.inventory_rows(self.db)}
        self.assertEqual(result['measured.com']['query_count'],3)
        self.assertEqual(result['measured.com']['coverage_kind'],'measured+historical')
        self.assertIsNone(result['old.com']['query_count'])
        self.assertEqual(result['claim.com']['coverage_kind'],'supplementary-claim-only')
        self.assertEqual(result['catalog.com']['coverage_kind'],'catalog-only')
    def test_render_read_only_deterministic(self):
        self.add('ads.vendor.com'); self.db.commit()
        self.db.execute('PRAGMA query_only=ON')
        a=report.render(self.db,'s',self.root,'## UniFi device inventory\n\nCached at known time.\n')
        b=report.render(self.db,'s',self.root,'## UniFi device inventory\n\nCached at known time.\n')
        self.assertEqual(a,b); self.assertIn('Cached at known time.',a)
        self.assertIn('No external',report.research_section(sqlite3.connect(':memory:'),[]))
        self.assertIn('unknown for all rows',a)
    def test_novelty_is_history_not_first_network_use(self):
        self.add('ads.vendor.com'); self.add('new.com')
        self.db.execute("INSERT INTO snapshots VALUES('old','Primary',0,10,'fixture','window')")
        self.db.execute("INSERT INTO snapshot_counts VALUES('old','ads.vendor.com','blocked',100)")
        result={r['domain']:r for r in report.classify(self.db,{'id':'s','site':'Primary','until_time':86400},self.root)['rows']}
        self.assertEqual(result['ads.vendor.com']['novelty'],'seen in previous snapshot')
        self.assertEqual(result['new.com']['novelty'],'new to collected history')
    def test_corrupt_cache_does_not_block_report(self):
        self.add("ads.vendor.com")
        self.db.execute("INSERT INTO domain_research_cache VALUES(?,?,?)",("ads.vendor.com","researched","{broken"))
        text=report.render(self.db,"s",self.root)
        self.assertIn("Local research cache unavailable",text)
        self.assertIn("All encountered hostnames",text)

    def test_markdown_escaping(self):
        self.assertEqual(report.safe('a|b\nc'),'a\\|b\\u000ac')

if __name__=='__main__': unittest.main()

class PreparationTests(unittest.TestCase):
    def test_prepare_is_local_idempotent_and_preserves_cached_research(self):
        from pihole_report.storage import connect, domain
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'config/lists').mkdir(parents=True)
            db=connect(root/'history.sqlite')
            try:
                db.execute("INSERT INTO snapshots VALUES('s','Primary',0,10,'fixture','window')")
                for d in ['ads.vendor.com','host.local','token-secret.vendor.com']:
                    domain(db,d,0,10,'window_bound'); db.execute("INSERT INTO snapshot_counts VALUES('s',?,'allowed',1)",(d,))
                first=report.prepare_report(db,'s',root,now=20)
                self.assertEqual(first,{'added':1,'excluded':2,'screened':3})
                db.execute("UPDATE domain_research_cache SET status='unresolved',attempts=3,result_json=?",(json.dumps({'status':'unresolved','reason':'Insufficient evidence'}),))
                second=report.prepare_report(db,'s',root,now=30)
                self.assertEqual(second['added'],0)
                cached=dict(db.execute('SELECT * FROM domain_research_cache').fetchone())
                self.assertEqual(cached['status'],'unresolved'); self.assertEqual(cached['attempts'],3)
                self.assertEqual(cached['last_seen'],30)
                self.assertEqual(db.execute('SELECT count(*) FROM screenings').fetchone()[0],3)
                self.assertEqual(db.execute("SELECT value FROM domain_research_control WHERE key='external_enabled'").fetchone()[0],'false')
                db.execute('PRAGMA query_only=ON')
                rendered=report.render(db,'s',root,newly_queued=first['added'])
                self.assertIn('1 newly queued locally',rendered)
            finally: db.close()
    def test_eligibility_conservative(self):
        for d in ['192.0.2.1','host.local','example.com','a.example.org','token-secret.vendor.com','x'*32+'.vendor.com','a.unknownsuffix']:
            self.assertFalse(report.eligibility(d)[1],d)
        self.assertTrue(report.eligibility('WWW.VENDOR.COM.')[1])

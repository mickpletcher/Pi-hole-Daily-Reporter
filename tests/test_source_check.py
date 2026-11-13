import csv
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pihole_report import source_check as s, research_csv as c
from test_research_csv import detail,row

class SourceCheckTests(unittest.TestCase):
    def test_exact_domains_and_hosts_not_parent_or_substring(self):
        names=['ads.example.com','child.ads.example.com','badads.example.com','example.com']
        hits,rules,unsupported=s.scan(b'0.0.0.0 ads.example.com\n127.0.0.1 localhost\n',names)
        self.assertEqual(hits,['ads.example.com']);self.assertEqual(unsupported,0)
    def test_suffix_and_exceptions(self):
        names=['ads.example.com','child.ads.example.com','ok.ads.example.com','badads.example.com']
        hits,_,_=s.scan(b'||ads.example.com^\n@@||ok.ads.example.com^\n',names)
        self.assertEqual(hits,['ads.example.com','child.ads.example.com'])
    def test_unsupported_exception_suppresses_source(self):
        hits,_,unsupported=s.scan(b'||ads.example.com^\n@@||*.example.com^\n',['ads.example.com'])
        self.assertEqual(hits,[]);self.assertEqual(unsupported,1)
    def test_paths_regex_modifiers_not_promoted(self):
        hits,_,unsupported=s.scan(b'good.example.com\n||other.example.com^$third-party\n/ads.*/\nhttps://path.example.com/x\n',['other.example.com','path.example.com'])
        self.assertEqual(hits,[]);self.assertEqual(unsupported,3)
    def test_failed_feed_incomplete_even_when_other_matches(self):
        urls=['https://example.com/one','https://example.org/two']
        def fetch(url):
            if url==urls[1]:raise OSError('secret detail')
            return b'ads.example.com\n'
        result=s.check_sources(urls,['ads.example.com','good.example.com'],fetch)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['rows']['ads.example.com']['recommended_block'],'1')
        self.assertEqual(result['rows']['good.example.com']['recommended_block'],'')
        self.assertNotIn('secret detail',str(result))
    def test_html_empty_and_oversize_rejected(self):
        for raw in (b'<html>ads.example.com</html>',b'# no domains',b'x'*(s.MAX_BYTES+1)):
            result=s.check_sources(['https://example.com/list'],['ads.example.com'],lambda _:raw)
            self.assertEqual(result['status'],'incomplete')
    def test_load_sources_dedup_comments_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'sources.txt';p.write_text('# header\nhttps://example.com/list\nhttps://example.com/list\n')
            self.assertEqual(s.load_sources(p),['https://example.com/list'])
            link=p.with_name('link');link.symlink_to(p)
            with self.assertRaises(ValueError):s.load_sources(link)
    def test_invalid_urls(self):
        for url in ('http://example.com/x','https://user:pass@example.com/x','https://localhost/x','https://localhost./x','https://foo.local./x','https://127.0.0.1/x','https://example.com:444/x','https://example.com/x#frag'):
            with self.assertRaises(ValueError):s.validate_url(url)
    def test_worker_timeout_never_marks_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'sources.txt';p.write_text('https://example.com/list\n')
            def run(*args,**kwargs):
                self.assertEqual(kwargs['timeout'],240)
                raise subprocess.TimeoutExpired('worker',240)
            result=s.run_check(p,['ads.example.com'],runner=run)
            self.assertEqual(result['status'],'incomplete');self.assertEqual(result['rows'],{})
    def test_csv_recommendation_distinct_from_manual_block(self):
        value=detail([row('ads.example.com')]);value['research']['research_needed'][0]['Block']='0'
        value['source_check']=s.check_sources(['https://example.com/list'],['ads.example.com'],lambda _:b'ads.example.com')
        result=c.render_csv(value,'fixture')
        records=list(csv.DictReader(io.StringIO(result['data'].decode('utf-8-sig'))))
        self.assertEqual(records[0]['Block'],'');self.assertEqual(records[0]['RecommendedBlock'],'1')
        self.assertEqual(records[0]['MatchedSources'],'https://example.com/list')
        old=c.render_csv(value,'fixture',schema_version=2)
        self.assertNotIn(b'RecommendedBlock',old['data'])
        self.assertEqual(old['schema_version'],2)

    def test_private_dns_not_fetched(self):
        with patch.object(s.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]), patch.object(s,'HTTPSClient') as client:
            with self.assertRaisesRegex(ValueError,'non_public_address_refused'):
                s.fetch_public('https://public.example/list')
            client.assert_not_called()
    def test_supported_headers_underscore_and_ipv4_not_promoted(self):
        hits,rules,unsupported=s.scan(b'[Adblock Plus]\n||ads.example.com^\nfoo_bar.example.com\n192.0.2.1\n',['foo_bar.example.com','child.ads.example.com','192.0.2.1'])
        self.assertEqual(hits,['child.ads.example.com','foo_bar.example.com'])
        self.assertEqual(unsupported,1)

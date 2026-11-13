import unittest
from pihole_report.domains import registrable_domain
from pihole_report.research_csv import render_csv
import csv, io

class DomainTests(unittest.TestCase):
    def test_domains(self):
        for source, expected in {
            'click.apple.com':'apple.com', 'apple.com':'apple.com',
            'a.shop.example.co.uk':'example.co.uk', 'co.uk':'',
            'a.user.github.io':'user.github.io', 'github.io':'',
            'a.b.ck':'a.b.ck', 'x.www.ck':'www.ck',
            'www.city.kawasaki.jp':'city.kawasaki.jp',
            'https://CLICK.Apple.com:443/path?q=1':'apple.com',
            'click.apple.com.':'apple.com', 'www.bücher.de':'xn--bcher-kva.de',
            '192.168.1.2':'', '[2001:db8::1]':'', 'printer.local':'',
            'localhost':'', '=formula':'', 'a..com':'',
        }.items():
            with self.subTest(source=source): self.assertEqual(registrable_domain(source), expected)
    def test_csv_column_order_and_blank_block(self):
        detail={'research':{'research_needed_count':1,'research_needed':[{'hostname':'click.apple.com','cache_status':'pending','new_to_history':True,'reason':'unknown','action':'review'}]},'daily_totals':{'window_start':'2026-01-01T00:00:00Z','window_end_exclusive':'2026-01-02T00:00:00Z'}}
        rows=list(csv.reader(io.StringIO(render_csv(detail,'example')['data'].decode('utf-8-sig'))))
        self.assertEqual(rows[0][:2],['domain','hostname'])
        self.assertEqual(rows[1][:2],['apple.com','click.apple.com'])
        self.assertEqual(rows[1][-1],'')

class LegacySchemaTests(unittest.TestCase):
    def test_legacy_frozen_csv_bytes_remain_recoverable(self):
        from importlib.util import spec_from_file_location, module_from_spec
        # A known v1 CSV header and payload retain their exact byte contract.
        detail={'research':{'research_needed_count':0,'research_needed':[]},'daily_totals':{'window_start':'2026-01-01T00:00:00Z','window_end_exclusive':'2026-01-02T00:00:00Z'}}
        old=render_csv(detail,'fixture',schema_version=1)
        expected='"hostname","cache_status","new_to_history","review_reason","review_action","window_start_utc","window_end_exclusive_utc","Block"\r\n'
        self.assertEqual(old['data'],expected.encode('utf-8-sig'))
        self.assertEqual(old['schema_version'],1)
        self.assertEqual(render_csv(detail,'fixture')['schema_version'],2)

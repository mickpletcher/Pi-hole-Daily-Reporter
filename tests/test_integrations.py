import datetime as dt
import gzip
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from pihole_report.integrations import (HTTPSClient, IntegrationError, rolling_snapshot, refresh_unifi, inventory_section, validate_list, refresh_lists, build_email, local_backup, FILES, _NoRedirect)


class IntegrationsTests(unittest.TestCase):
    def test_https_only_and_cross_origin(self):
        client = HTTPSClient()
        with self.assertRaisesRegex(IntegrationError, 'https_origin'):
            client.request('http://example.com','/api')
        with self.assertRaisesRegex(IntegrationError, 'cross_origin'):
            client.request('https://example.com','https://elsewhere.example/api',sid='secret')
        with self.assertRaisesRegex(IntegrationError, 'redirect_refused'):
            _NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
        self.assertTrue(client.context.check_hostname)

    def test_snapshot_fixed_window_and_logout(self):
        calls = []
        def transport(base,route,method='GET',payload=None,sid=None):
            calls.append((route,method))
            if route == '/api/auth':
                return {'session': {'sid':'fake'}}
            if route.startswith('/api/stats'):
                self.assertIn('from=13600&until=100000', route)
                return {'domains':[{'domain':'ads.example.com','count':20}]}
            if route == '/api/clients':
                return {'clients':[]}
            return {'queries':[{'client':{'ip':'192.0.2.1'}, 'domain':'ads.example.com', 'time':99999, 'status':'FORWARDED'}], 'recordsFiltered':1}
        text, inputs = rolling_snapshot(transport,'https://example.com','fake',now=100000)
        self.assertIn('| `ads.example.com` | 20 |',text)
        self.assertEqual(inputs['attribution'][0]['clients'],'192.0.2.1 (1)')
        self.assertEqual(calls[-1],('/api/auth','DELETE'))


    def attribution_snapshot(self, queries, total=None, fail=False):
        calls = []
        def transport(base, route, method='GET', payload=None, sid=None):
            calls.append((route, method))
            if route == '/api/auth':
                return {'session': {'sid': 'synthetic'}}
            if route.startswith('/api/stats'):
                return {'domains': [{'domain':'shared.example', 'count':700}]}
            if route == '/api/clients':
                return {'clients': []}
            if fail:
                raise RuntimeError('provider secret must not leak')
            return {'queries': queries, 'recordsFiltered': total}
        text, inputs = rolling_snapshot(transport, 'https://example.com', 'synthetic', now=100000)
        return text, inputs, calls

    def query(self, status='FORWARDED', client=None, **kwargs):
        return dict(domain='shared.example', time=99999, status=status,
                    client={'ip':'192.0.2.1'} if client is None else client, **kwargs)

    def test_attribution_exact_outcomes_and_deduplicated_fetch(self):
        queries = [self.query(status, {'name':name}) for status, name in [
            ('FORWARDED','allowed-only'), (3,'allowed-only'), ('17','allowed-only'),
            ('GRAVITY','blocked-only'), (4,'blocked-only'), ('16','blocked-only'),
            ('RETRIED','both'), ('DENYLIST','both')]]
        text, inputs, calls = self.attribution_snapshot(queries, len(queries))
        allowed, blocked = inputs['attribution']
        self.assertEqual(allowed['clients'], 'allowed-only (3), both (1)')
        self.assertEqual(blocked['clients'], 'blocked-only (3), both (1)')
        self.assertEqual(allowed['matching_state_queries'], 4)
        self.assertEqual(blocked['attributed_queries'], 4)
        self.assertEqual(sum(route.startswith('/api/queries?') for route, _ in calls), 1)
        route = next(route for route, _ in calls if route.startswith('/api/queries?'))
        self.assertIn('from=13600&until=100000', route)
        self.assertIn('length=500&domain=shared.example', route)
        self.assertEqual(inputs['allowed'], [{'domain':'shared.example','count':700}])
        self.assertEqual(inputs['blocked'], inputs['allowed'])
        self.assertIn('| `shared.example` | 700 |', text)
        self.assertEqual(calls[-1], ('/api/auth','DELETE'))

    def test_attribution_unknown_statuses_and_malformed_clients(self):
        queries = [self.query(status) for status in (None, 'UNKNOWN', 14, '15', 999, True, [], {}, 'future')]
        missing = self.query()
        del missing['status']
        queries += [missing, self.query(client='bad'), self.query(client={}),
                    self.query(client={'name':[], 'ip':[]} ),
                    self.query(client={'name':[], 'ip':'192.0.2.9'})]
        _, inputs, _ = self.attribution_snapshot(queries, len(queries))
        row = inputs['attribution'][0]
        self.assertEqual(row['unknown_status_queries'], 10)
        self.assertEqual(row['invalid_client_queries'], 3)
        self.assertEqual(row['matching_state_queries'], 4)
        self.assertEqual(row['attributed_queries'], 1)
        self.assertEqual(row['clients'], '192.0.2.9 (1)')
        self.assertEqual(inputs['attribution'][1]['clients'], 'none identified in sample')

    def test_attribution_enforces_domain_and_half_open_window(self):
        queries = [self.query()]
        for key, val in [('time',13600), ('time',13599), ('time',100000), ('time',float('nan')),
                         ('time',True), ('time','99999'), ('domain','other.example'), ('domain',None)]:
            query = self.query()
            query[key] = val
            queries.append(query)
        queries += [None, ['bad']]
        _, inputs, _ = self.attribution_snapshot(queries, len(queries))
        row = inputs['attribution'][0]
        self.assertEqual(row['attributed_queries'], 2)
        self.assertEqual(row['excluded_queries'], 9)

    def test_attribution_truncation_missing_totals_and_escaping(self):
        _, inputs, _ = self.attribution_snapshot([self.query(client={'name':'[click](url)|<img>\n`x`'})] * 500, 701)
        row = inputs['attribution'][0]
        self.assertTrue(row['truncated'])
        self.assertEqual(row['sample_size'], 500)
        self.assertEqual(row['attributed_queries'], 500)
        rendered = inventory_section({}, attribution=inputs['attribution'])
        self.assertNotIn('<img>', rendered)
        self.assertNotIn('[click](url)', rendered)
        self.assertIn('across all states', rendered)
        self.assertIn('not complete or cumulative counts', rendered)
        self.assertIn('recordsFiltered exceeds 500', rendered)
        for total in (None, -1, True, '2'):
            _, inputs, _ = self.attribution_snapshot([self.query()], total)
            self.assertIsNone(inputs['attribution'][0]['truncated'])

    def test_attribution_api_failure_and_oversized_sample_fail_closed(self):
        for queries, fail in [([],True), ([self.query()]*501,False), (None,False)]:
            _, inputs, calls = self.attribution_snapshot(queries, 1000, fail)
            for row in inputs['attribution']:
                self.assertEqual(row['sample_status'], 'unavailable')
                self.assertIsNone(row['attributed_queries'])
                self.assertNotIn('secret', str(row))
            self.assertEqual(sum(route.startswith('/api/queries?') for route, _ in calls), 1)
            self.assertEqual(calls[-1],('/api/auth','DELETE'))


    def test_api_scope_verified_filtered_partial_and_unavailable(self):
        from pihole_report.integrations import _api_scope
        responses = {
            '/api/config/webserver/api/excludeDomains': {'config':{'webserver':{'api':{'excludeDomains':['hidden.example']}}}},
            '/api/config/webserver/api/excludeClients': {'config':{'webserver':{'api':{'excludeClients':[]}}}},
            '/api/config/misc/privacylevel': {'config':{'misc':{'privacylevel':2}}},
        }
        calls = []
        def transport(base, route, method, payload, sid):
            calls.append(route)
            self.assertEqual((method, payload, sid), ('GET', None, 'synthetic'))
            return responses[route]
        result = _api_scope(transport, 'https://example.com', 'synthetic', 100000)
        self.assertEqual(set(calls), set(responses))
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['exclude_domains'], ['hidden.example'])
        self.assertEqual(result['exclude_domains_count'], 1)
        self.assertEqual(result['exclude_clients_count'], 0)
        self.assertEqual(result['privacy_level'], 2)
        self.assertIsNotNone(result['verified_at'])
        responses['/api/config/misc/privacylevel'] = {'config':{'misc':{'privacylevel':False}}}
        result = _api_scope(transport, 'https://example.com', 'synthetic', 100000)
        self.assertEqual(result['status'], 'partial')
        self.assertIsNone(result['privacy_level'])
        responses.clear()
        result = _api_scope(transport, 'https://example.com', 'synthetic', 100000)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['exclude_domains_count'])
        self.assertIsNone(result['exclude_clients_count'])
        self.assertIsNone(result['verified_at'])

    def test_snapshot_failure_still_logs_out(self):
        calls=[]
        def transport(base,route,method='GET',payload=None,sid=None):
            calls.append(method)
            return {'session':{'sid':'fake'}} if route=='/api/auth' else {}
        with self.assertRaisesRegex(IntegrationError,'missing_domains'):
            rolling_snapshot(transport,'https://example.com','fake')
        self.assertEqual(calls[-1],'DELETE')

    def test_unifi_pages_all_sites_and_clients(self):
        def transport(base,route,**kwargs):
            self.assertEqual(kwargs['headers']['X-API-Key'],'fake')
            if '/sites?' in route:
                return {'data':[{'id':'one'}],'count':1,'totalCount':1}
            return {'data':[{'name':'Device','ipAddress':'192.0.2.1'}],'count':1,'totalCount':1}
        result=refresh_unifi(transport,'https://example.com','fake',now=100000)
        self.assertEqual(result['clients'][0]['siteId'],'one')
        self.assertNotIn('fake',json.dumps(result))
        text=inventory_section(result,[{'client':'192.0.2.1','groups':[0]}])
        self.assertIn('Device',text)
        self.assertIn('do not prove historical',text)

    def test_unifi_incomplete_fails(self):
        with self.assertRaisesRegex(IntegrationError,'incomplete_unifi'):
            refresh_unifi(lambda *a,**k:{'data':[],'count':0,'totalCount':1},'https://example.com','fake')

    def test_list_validation(self):
        self.assertEqual(validate_list('B.example\na.example # comment\n','curated-blocklist-policy.txt'),('a.example\nb.example\n',2))
        for content in ['<html>error</html>','https://example.com','']:
            with self.assertRaises(IntegrationError):
                validate_list(content,'curated-blocklist-policy.txt')
        self.assertEqual(validate_list('','curated-whitelist.txt'),('',0))
        with self.assertRaisesRegex(IntegrationError,'count_drop'):
            validate_list('a.example','curated-blocklist-policy.txt',4)

    def test_list_refresh_cache_and_failure_retains_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            calls=[]
            def transport(url,limit):
                calls.append(url)
                if 'api.github.com' in url:
                    return json.dumps({'sha':'a'*40,'commit':{'committer':{'date':'2026-11-11T00:00:00Z'}}})
                return '' if url.endswith('whitelist.txt') else 'a.example\nb.example\n'
            (root/'config').mkdir(exist_ok=True)
            (root/'config/list-source.json').write_text(json.dumps({'repository':'example/blocklists','ref':'generated'}))
            (root/'config/list-source.json').chmod(0o600)
            result=refresh_lists(root,transport,now=100000)
            self.assertEqual(result['status'],'updated')
            self.assertEqual(len(calls),4)
            self.assertEqual(refresh_lists(root,transport,now=100001)['status'],'cached')
            state=root/'config/curated-list-state.json'
            before=json.loads(state.read_text())
            with self.assertRaises(IntegrationError):
                refresh_lists(root,lambda *a: (_ for _ in ()).throw(RuntimeError('secret')),now=200000)
            after=json.loads(state.read_text())
            self.assertEqual(before['commit'],after['commit'])
            self.assertEqual(after['last_error'],'transport_or_filesystem_error')
            for filename in FILES:
                self.assertTrue((root/'config/list-snapshots'/('a'*40)/filename).is_file())

    def test_email_is_mime_only_with_roundtrip_attachment(self):
        report='# Report\n\nSample\n'
        email=build_email(report,'sender@example.com','recipient@example.com',dt.datetime(2026,11,12,tzinfo=dt.timezone.utc))
        part=next(email.iter_attachments())
        self.assertEqual(gzip.decompress(part.get_payload(decode=True)).decode(),report)
        self.assertEqual(part.get_filename(),'pihole-domain-review.md.gz')

    def test_local_backup_readonly_source_integrity_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'source.sqlite'
            target=Path(temp)/'copy.sqlite'
            with sqlite3.connect(source) as db:
                db.execute('CREATE TABLE example(value)')
                db.execute('INSERT INTO example VALUES(42)')
            before=source.read_bytes()
            local_backup(source,target)
            with sqlite3.connect(target) as db:
                self.assertEqual(db.execute('SELECT value FROM example').fetchone()[0],42)
            self.assertEqual(source.read_bytes(),before)
            with self.assertRaises(IntegrationError):
                local_backup(source,target)
            with self.assertRaisesRegex(IntegrationError,'cloud_export'):
                local_backup(source,Path(temp)/'OneDrive'/'copy.sqlite')

class ReadRetryTests(unittest.TestCase):
    def test_get_retries_only_safe_read_failures(self):
        from unittest.mock import patch
        from pihole_report.integrations import HTTPSClient, IntegrationError
        client = HTTPSClient(get_retries=2)
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'{}'
        class Opener:
            def __init__(self): self.calls = 0
            def open(self, *args, **kwargs):
                self.calls += 1
                if self.calls < 2: raise TimeoutError('sensitive provider text')
                return Response()
        client.opener = Opener()
        with patch('pihole_report.integrations.time.sleep'):
            self.assertEqual(client.request('https://pihole.example.invalid','/api/queries'), {})
        self.assertEqual(client.opener.calls, 2)
        client.opener = Opener()
        with self.assertRaises(IntegrationError) as caught:
            client.request('https://pihole.example.invalid','/api/auth','POST',{'password':'synthetic'})
        self.assertEqual(client.opener.calls,1)
        self.assertEqual(str(caught.exception),'transport_timeout')
        self.assertNotIn('sensitive',str(caught.exception))

class PinnedEndpointTests(unittest.TestCase):
    def test_fixed_address_keeps_tls_hostname_and_verification(self):
        import ssl
        from unittest.mock import Mock, patch
        from pihole_report.integrations import _PinnedHTTPSConnection
        context = Mock()
        raw = Mock()
        with patch('pihole_report.integrations.socket.create_connection', return_value=raw) as connector:
            connection = _PinnedHTTPSConnection('pihole.example.invalid', connect_address='192.0.2.53', expected_hostname='pihole.example.invalid', context=context, timeout=12)
            connection.connect()
        self.assertEqual(connector.call_args.args[0], ('192.0.2.53',443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname='pihole.example.invalid')
        from pihole_report.integrations import HTTPSClient
        client = HTTPSClient(connect_address='192.0.2.53', expected_hostname='pihole.example.invalid')
        self.assertTrue(client.context.check_hostname)
        self.assertEqual(client.context.verify_mode,ssl.CERT_REQUIRED)

    def test_pinned_target_cannot_change_or_bypass_proxy(self):
        from unittest.mock import patch
        from pihole_report.integrations import HTTPSClient, IntegrationError
        client = HTTPSClient(connect_address='192.0.2.53', expected_hostname='pihole.example.invalid')
        with self.assertRaises(IntegrationError):
            client.request('https://other.example','/api/auth','POST',{'password':'synthetic'})
        with patch('pihole_report.integrations.urllib.request.getproxies', return_value={'https':'http://proxy.invalid'}), patch('pihole_report.integrations.urllib.request.proxy_bypass', return_value=False):
            with self.assertRaises(IntegrationError) as caught:
                client.request('https://pihole.example.invalid','/api/auth','POST',{'password':'synthetic'})
        self.assertEqual(str(caught.exception),'pinned_endpoint_proxy_not_supported')
        with self.assertRaises(ValueError):
            HTTPSClient(connect_address='192.0.2.53')

if __name__=='__main__':
    unittest.main()

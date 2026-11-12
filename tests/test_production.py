from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pihole_report.cli import PROJECT
from pihole_report.delivery import DeliveryError
from pihole_report import production as p


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=PROJECT)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'root'
        for name in ('config','memory','data/pihole-history'):
            (self.root/name).mkdir(parents=True)
        from pihole_report.storage import connect
        fixture_db=connect(self.root/'data/pihole-history/history.sqlite')
        fixture_db.close()
        self.scope = __import__("pihole_report.deployment",fromlist=["example_deployment"]).example_deployment()["scope"]
        self.scope.update(root=str(self.root), database=str(self.root/'data/pihole-history/history.sqlite'),
            report=str(self.root/'memory/pihole-domain-review.md'), state_directory=str(self.base/'state/production'),
            legacy_stdout=str(self.base/'legacy.log'))
        self.manifest={'scope':self.scope,'refresh_lists':False}
        self.now=1800000000
        self.day=datetime.fromtimestamp(self.now).astimezone().date().isoformat()
        self.calls=[]
        self.collection='complete'
        self.smtp_error=None
        self.backup_error=None
        self.crash=False
        self.recoveries=[]
        def recover(*args):
            self.recoveries.append('recover')
            return {'import_succeeded':True,'coverage_status':'complete','run_id':2}
        self.recover=recover
    def engine(self,root,db,transport,secret,**kwargs):
        self.calls.append('engine')
        self.assertIsNone(kwargs['unifi_transport'])
        kwargs['write_text'](Path(self.scope['report']), '# fixture report\n')
        return {'collection_status':self.collection,'snapshot_id':'fixture'}, {'research':{'research_needed_count':1}}
    def send(self,*args,**kwargs):
        self.calls.append('send')
        state=json.loads(self.state.read_text())
        self.assertEqual(state['dates'][self.day]['status'],'reserved')
        self.assertTrue(kwargs['send'])
        if self.crash:
            raise KeyboardInterrupt('simulated hard interruption')
        if self.smtp_error:
            raise self.smtp_error
        return {'submitted':True,'status':'submitted'}
    def backup(self,*args,**kwargs):
        self.calls.append('backup')
        self.assertTrue(kwargs['export'])
        if self.backup_error:
            raise self.backup_error
        return {'exported':True,'status':'published_locally'}
    @property
    def state(self):
        return Path(self.scope['state_directory'])/'delivery-state.json'
    def run_it(self):
        return p._execute(self.manifest,engine=self.engine,transport=lambda *a:None,
            send=self.send,backup=self.backup,secret_reader=lambda *a:'synthetic',
            now=self.now,log_root=self.base,recover_collection=self.recover)

    def test_success_and_repeat_date(self):
        first=self.run_it()
        self.assertEqual(first['status'],'complete')
        self.assertTrue(first['smtp_submitted'])
        self.assertNotIn('email_sent',first)
        self.assertFalse(first['inbox_delivery_confirmed'])
        self.assertTrue(first['backup_published_locally'])
        self.assertFalse(first['cloud_upload_confirmed'])
        second=self.run_it()
        self.assertEqual(second['status'],'delivery_suppressed')
        self.assertEqual(self.calls,['engine','send','backup'])
        self.assertTrue(Path(second['log_file']).is_file())
        self.assertNotIn('email_sent',json.loads(Path(first['log_file']).read_text()))
        self.assertEqual(self.state.stat().st_mode&0o777,0o600)

    def test_collection_failure_keeps_partial_report_delivery(self):
        self.collection='failed'
        first=self.run_it()
        self.assertEqual(first['status'],'partial')
        self.assertEqual(first['stages']['collection'],'failed')
        self.assertTrue(first['smtp_submitted'])
        self.assertEqual(self.calls,['engine','send','backup'])

    def test_pre_send_engine_failure_can_retry_same_date(self):
        original=self.engine
        def fail(*args,**kwargs):
            kwargs['write_text'](Path(self.scope['report']), 'Generated: '+datetime.fromtimestamp(self.now,timezone.utc).isoformat()+'\n')
            raise RuntimeError('failed before delivery')
        self.engine=fail
        first=self.run_it()
        self.assertEqual(first['status'],'failed')
        self.engine=original
        second=self.run_it()
        self.assertEqual(second['status'],'complete')
        self.assertEqual(self.calls,['engine','send','backup'])

    def test_uncertain_send_never_retries(self):
        self.smtp_error=DeliveryError('smtp_submission_uncertain',uncertain=True)
        first=self.run_it()
        self.assertEqual(first['status'],'partial')
        self.assertTrue(first['smtp_outcome_uncertain'])
        second=self.run_it()
        self.assertEqual(second['suppression_reason'],'uncertain')
        self.assertEqual(self.calls.count('send'),1)

    def test_crash_after_reservation_blocks_restart(self):
        self.crash=True
        with self.assertRaises(KeyboardInterrupt):
            self.run_it()
        self.crash=False
        result=self.run_it()
        self.assertEqual(result['suppression_reason'],'reserved')
        self.assertEqual(self.calls.count('send'),1)

    def test_known_send_failure_is_safe_to_retry(self):
        self.smtp_error=DeliveryError('smtp_recipient_refused')
        self.run_it()
        self.smtp_error=None
        result=self.run_it()
        self.assertEqual(result['status'],'complete')
        self.assertEqual(self.calls.count('send'),2)

    def test_backup_failure_does_not_claim_upload_or_block_email(self):
        self.backup_error=DeliveryError('backup_health_unavailable')
        result=self.run_it()
        self.assertEqual(result['status'],'partial')
        self.assertTrue(result['smtp_submitted'])
        self.assertFalse(result['backup_published_locally'])

    def test_legacy_baseline_and_ambiguous_report_suppress_delivery(self):
        stamp=datetime.fromtimestamp(self.now,timezone.utc).isoformat()
        Path(self.scope['report']).write_text('Generated: '+stamp+'\n')
        result=self.run_it()
        self.assertEqual(result['suppression_reason'],'legacy_delivery_unconfirmed')
        self.assertEqual(self.calls,[])

    def test_confirmed_legacy_submission_is_seeded(self):
        stamp=datetime.fromtimestamp(self.now,timezone.utc).isoformat()
        Path(self.scope['legacy_stdout']).write_text('PIHOLE_DOMAIN_REPORT_OK report='+self.scope['report']+' generated='+stamp+'\nPIHOLE_REPORT_EMAIL_SENT recipient='+self.scope['smtp_recipient']+'\n')
        result=self.run_it()
        self.assertEqual(result['suppression_reason'],'legacy_submitted')
        self.assertEqual(self.calls,[])

    def test_corrupt_state_fails_closed_and_logs(self):
        self.state.parent.mkdir(parents=True,mode=0o700)
        self.state.parent.parent.chmod(0o700)
        self.state.write_text('{')
        self.state.chmod(0o600)
        result=self.run_it()
        self.assertEqual(result['status'],'failed')
        self.assertEqual(self.calls,[])
        self.assertTrue(Path(result['log_file']).is_file())
        self.assertEqual(self.state.read_text(),'{')

    def test_symlink_input_and_scope_writer_refused(self):
        (self.root/'config/list-snapshots').symlink_to('/tmp',target_is_directory=True)
        result=self.run_it()
        self.assertEqual(result['status'],'failed')
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):
            p._scope_writer(self.scope)(self.base/'unapproved','bad')

    def test_whole_run_lock_blocks_overlap(self):
        with p._whole_run_lock(self.scope):
            with self.assertRaises(BlockingIOError):
                self.run_it()
        self.assertEqual(self.calls,[])

    def test_failed_backup_recovers_without_repeating_email_or_report(self):
        self.backup_error=DeliveryError('backup_preflight_failed')
        first=self.run_it()
        ledger=json.loads(self.state.read_text())
        operation=ledger['dates'][self.day]['stages']['backup']['operation_id']
        self.backup_error=None
        second=self.run_it()
        self.assertEqual(second['status'],'complete')
        self.assertEqual(self.calls,['engine','send','backup','backup'])
        stage=json.loads(self.state.read_text())['dates'][self.day]['stages']['backup']
        self.assertEqual(stage['operation_id'],operation)
        self.assertEqual(stage['status'],'complete')

    def test_collection_recovers_after_submission_without_changing_frozen_report(self):
        self.collection='failed'
        first=self.run_it()
        artifact=json.loads(self.state.read_text())['dates'][self.day]['artifact']
        before=Path(artifact['report_path']).read_bytes()
        second=self.run_it()
        self.assertEqual(self.recoveries,['recover'])
        self.assertEqual(self.calls,['engine','send','backup'])
        self.assertEqual(Path(artifact['report_path']).read_bytes(),before)
        health=json.loads((self.state.parent/'current-health.json').read_text())
        self.assertEqual(health['schema'],'pihole-operational-health.v1')
        self.assertEqual(health['data_health_scope'],'frozen_report_artifact')
        self.assertEqual(health['recovered_history']['run_id'],2)

    def test_retention_gap_does_not_trigger_recollection_forever(self):
        self.collection='partial'
        self.run_it(); result=self.run_it()
        self.assertEqual(self.recoveries,[])
        self.assertEqual(self.calls,['engine','send','backup'])
        self.assertEqual(result['stage_details']['collection']['coverage_status'],'partial')
        self.assertEqual(result['stage_details']['collection']['status'],'complete')

    def test_frozen_report_reused_after_known_email_failure(self):
        self.smtp_error=DeliveryError('smtp_connection_or_authentication_failed')
        self.run_it()
        artifact=json.loads(self.state.read_text())['dates'][self.day]['artifact']
        original=Path(artifact['report_path']).read_text()
        Path(self.scope['report']).write_text('changed canonical report')
        self.smtp_error=None
        captured=[]
        original_send=self.send
        def send(text,*args,**kwargs):
            captured.append(text)
            return original_send(text,*args,**kwargs)
        self.send=send
        self.run_it()
        self.assertEqual(captured,[original])
        self.assertEqual(self.calls.count('engine'),1)
        self.assertEqual(self.calls.count('backup'),1)

    def test_changed_frozen_report_stops_retry(self):
        self.smtp_error=DeliveryError('smtp_connection_or_authentication_failed')
        self.run_it()
        artifact=json.loads(self.state.read_text())['dates'][self.day]['artifact']
        Path(artifact['report_path']).write_text('tampered')
        self.smtp_error=None
        result=self.run_it()
        self.assertEqual(result['status'],'failed')
        self.assertEqual(self.calls.count('send'),1)

    def test_old_submitted_ledger_migrates_without_repeating_any_stage(self):
        self.state.parent.mkdir(parents=True,mode=0o700)
        self.state.parent.parent.chmod(0o700)
        self.state.write_text(json.dumps({'schema':'pihole-delivery-state.v1',
            'dates':{self.day:{'status':'submitted','recorded_at':self.now}},
            'legacy_baseline_initialized':True}))
        self.state.chmod(0o600)
        result=self.run_it()
        self.assertEqual(self.calls,[])
        self.assertEqual(result['suppression_reason'],'submitted')
        ledger=json.loads(self.state.read_text())
        self.assertEqual(ledger['schema'],'pihole-delivery-state.v2')
        self.assertEqual(ledger['dates'][self.day]['stages']['backup']['status'],'legacy_untracked')

    def test_new_date_starts_a_new_report_and_email(self):
        self.run_it()
        self.now+=86400
        self.day=datetime.fromtimestamp(self.now).astimezone().date().isoformat()
        result=self.run_it()
        self.assertEqual(result['status'],'complete')
        self.assertEqual(self.calls.count('send'),2)
        self.assertEqual(self.calls.count('engine'),2)

    def test_uncertain_backup_reconciles_identity_without_exporting_again(self):
        requests=[]
        def worker(request,on_start):
            requests.append(dict(request))
            on_start(99999999)
            if len(requests)==1:
                raise DeliveryError('backup_worker_timeout',uncertain=True)
            self.assertEqual(request['mode'],'inspect')
            return {'status':'published_locally','exported':True,'reconciled':True,
                    'snapshot':json.loads(self.state.read_text())['dates'][self.day]['stages']['backup']['snapshot']}
        def run():
            return p._execute(self.manifest,engine=self.engine,transport=lambda *a:None,
                send=self.send,backup=None,backup_worker=worker,secret_reader=lambda *a:'fixture',
                now=self.now,log_root=self.base,recover_collection=self.recover)
        first=run(); second=run()
        self.assertEqual(first['stage_details']['backup']['status'],'uncertain')
        self.assertEqual(second['stage_details']['backup']['status'],'complete')
        self.assertEqual([r['mode'] for r in requests],['export','inspect'])
        self.assertEqual(requests[0]['operation_id'],requests[1]['operation_id'])
        self.assertEqual(self.calls.count('send'),1)

    def test_live_uncertain_worker_is_not_retried_or_killed(self):
        import os
        requests=[]
        def worker(request,on_start):
            requests.append(request)
            on_start(os.getpid())
            raise DeliveryError('backup_worker_termination_unconfirmed',uncertain=True)
        def run():
            return p._execute(self.manifest,engine=self.engine,transport=lambda *a:None,
                send=self.send,backup=None,backup_worker=worker,secret_reader=lambda *a:'fixture',
                now=self.now,log_root=self.base,recover_collection=self.recover)
        run(); result=run()
        self.assertEqual(len(requests),1)
        self.assertEqual(result['stage_details']['backup']['error_code'],'previous_backup_worker_may_be_running')
        self.assertEqual(self.calls.count('send'),1)

    def test_manifest_scope_hash_and_permissions(self):
        config=self.base/'production.json'
        manifest={"schema":p.SCHEMA,"enabled":False,"scope":self.scope,"refresh_lists":False,"code_sha256":p.code_hashes()}
        manifest['enabled']=True
        config.write_text(json.dumps(manifest)); config.chmod(0o600)
        with patch.object(p,'CONFIG',config), patch.object(p,'expected_scope',return_value=self.scope):
            self.assertEqual(p.load_manifest(config),manifest)
            changed=dict(manifest,scope={**manifest['scope'],'smtp_recipient':'other@example.com'})
            config.write_text(json.dumps(changed))
            with self.assertRaises(ValueError): p.load_manifest(config)
            config.write_text(json.dumps({**manifest,'code_sha256':{}}))
            with self.assertRaises(ValueError): p.load_manifest(config)
            config.write_text(json.dumps(manifest)); config.chmod(0o644)
            with self.assertRaises(ValueError): p.load_manifest(config)

class ProductionEndToEndTests(unittest.TestCase):
    def test_real_pipeline_with_fixture_transport_and_mock_delivery(self):
        from pihole_report.pipeline import _run_daily
        from pihole_report.storage import connect

        # Put the synthetic production root OUTSIDE PROJECT so this catches
        # any accidental remaining use of the shadow-only atomic writer.
        with tempfile.TemporaryDirectory() as external, tempfile.TemporaryDirectory(dir=PROJECT) as local:
            root = Path(external).resolve()
            local = Path(local).resolve()
            (root/'config/lists').mkdir(parents=True)
            (root/'memory').mkdir()
            for filename in ('curated-blocklist-policy.txt', 'curated-blocklist-device.txt'):
                (root/'config/lists'/filename).write_text('shared.widget.com\n')
            (root/'config/lists/curated-whitelist.txt').write_text('')
            (root/'config/recommendation-feedback.csv').write_text('domain,decision,note,date\n')
            (root/'memory/unifi-clients.json').write_text(json.dumps({
                'generatedAt':'2026-01-01T00:00:00Z', 'clients':[]}))
            database = root/'data/pihole-history/history.sqlite'
            db = connect(database)
            db.execute("INSERT INTO metadata VALUES('storage_mode','aggregate-first')")
            db.close()
            scope = __import__("pihole_report.deployment",fromlist=["example_deployment"]).example_deployment()["scope"]
            scope.update(root=str(root), database=str(database),
                report=str(root/'memory/pihole-domain-review.md'),
                state_directory=str(local/'state/production'), legacy_stdout=str(local/'legacy.log'))
            manifest = {'scope':scope, 'refresh_lists':False}
            now = 1800000000
            requests, sends, backups = [], [], []

            def transport(base, route, method='GET', payload=None, sid=None):
                requests.append((route, method))
                if route == '/api/auth':
                    return {'session':{'sid':'fixture-session'}} if method == 'POST' else {}
                if route.startswith('/api/stats/database/top_domains'):
                    return {'domains': ([{'domain':'shared.widget.com','count':1}]
                        if 'blocked=true' in route else [
                            {'domain':'shared.widget.com','count':2},
                            {'domain':'new.widget.com','count':1}])}
                if route == '/api/clients':
                    return {'clients':[]}
                if route.startswith('/api/queries?'):
                    if 'domain=' in route or 'cursor=' in route:
                        return {'queries':[], 'recordsFiltered':4}
                    query_rows = [
                        {'id':4, 'domain':'shared.widget.com', 'status':'FORWARDED'},
                        {'id':3, 'domain':'new.widget.com', 'status':'FORWARDED'},
                        {'id':2, 'domain':'shared.widget.com', 'status':'GRAVITY'},
                        {'id':1, 'domain':'shared.widget.com', 'status':'CACHE'},
                    ]
                    return {'queries': [{**row, 'time':now-400,
                        'client':{'ip':'192.0.2.1'}, 'type':'A'} for row in query_rows],
                        'recordsFiltered':4}
                raise AssertionError('Unexpected fixture operation: '+route)

            def smtp(report, config, password_file, *, send):
                self.assertTrue(send)
                self.assertIn('Recorded DNS queries: **4**', report)
                state = json.loads((local/'state/production/delivery-state.json').read_text())
                day = datetime.fromtimestamp(now).astimezone().date().isoformat()
                self.assertEqual(state['dates'][day]['status'], 'reserved')
                sends.append(report)
                return {'submitted':True, 'status':'submitted'}

            def backup(source, config, *, export):
                self.assertTrue(export)
                self.assertTrue(source.is_relative_to(local/'state/production/artifacts'))
                self.assertTrue(source.is_file())
                backups.append(str(source))
                return {'exported':True, 'status':'published_locally',
                        'snapshot':str(local/'synthetic-backup.sqlite'), 'pruned':[]}

            def execute():
                return p._execute(manifest, engine=_run_daily, transport=transport,
                    send=smtp, backup=backup, secret_reader=lambda path:'fixture-password',
                    now=now, log_root=local)

            first = execute()
            self.assertEqual(first['status'], 'partial', first)
            text = Path(scope['report']).read_text()
            self.assertIn('Distinct observed hostnames: **2**', text)
            self.assertIn('Allowed queries: **3**', text)
            self.assertIn('Blocked queries: **1**', text)
            log = json.loads(Path(first['log_file']).read_text())
            self.assertEqual(log['daily_totals']['total_recorded_queries'], 4)
            self.assertEqual(log['daily_totals']['unique_hostnames'], 2)
            self.assertEqual(log['daily_totals']['hostnames_both_allowed_and_blocked'], 1)
            self.assertEqual(log['research']['new_to_history_count'], 2)
            self.assertEqual(log['research']['research_needed_count'], 2)
            self.assertEqual({row['hostname'] for row in log['research']['research_needed']},
                             {'shared.widget.com', 'new.widget.com'})
            self.assertTrue(log['smtp_submitted'])
            self.assertFalse(log['inbox_delivery_confirmed'])
            self.assertEqual(log['hosted_calls'], 0)
            with connect(database, read_only=True) as db:
                self.assertEqual(db.execute('SELECT sum(queries) FROM daily').fetchone()[0], 4)
                self.assertEqual(db.execute('SELECT count(*) FROM screenings').fetchone()[0], 2)
            requests_before = len(requests)
            second = execute()
            self.assertIn(second['status'], ('delivery_suppressed','partial'))
            self.assertEqual(len(requests), requests_before)
            self.assertEqual(len(sends), 1)
            self.assertEqual(len(backups), 1)
            self.assertTrue(all(method == 'GET' or route == '/api/auth'
                                for route, method in requests))


class ProductionEntrypointLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=PROJECT)
        self.addCleanup(self.temp.cleanup)
        self.local = Path(self.temp.name)

    def capture_main(self, config):
        import contextlib
        import io
        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(io.StringIO()):
            code = p.main(['--config', str(config)])
        return code, json.loads(output.getvalue())

    def test_invalid_manifest_gets_sanitized_log_in_known_project(self):
        config = self.local/'production.json'
        config.write_text(json.dumps({'schema':'invalid','secret':'NEVER_LOG_THIS'}))
        config.chmod(0o600)
        with patch.object(p,'CONFIG',config), patch.object(p,'PROJECT',self.local):
            code, result = self.capture_main(config)
        self.assertEqual(code,1)
        log_path = Path(result['log_file'])
        self.assertTrue(log_path.is_relative_to(self.local/'logs/pihole-report'))
        log = log_path.read_text()
        self.assertNotIn('NEVER_LOG_THIS',log)
        self.assertEqual(json.loads(log)['stage'],'entrypoint')
        self.assertEqual(len(list(log_path.parent.glob('pihole-report-*.json'))),1)

    def test_overlapping_main_run_is_logged_without_starting_engine(self):
        scope = __import__("pihole_report.deployment",fromlist=["example_deployment"]).example_deployment()["scope"]
        scope['state_directory'] = str(self.local/'state/production')
        manifest = {'scope':scope,'refresh_lists':False}
        with p._whole_run_lock(scope), patch.object(p,'load_manifest',return_value=manifest), patch.object(p,'PROJECT',self.local):
            code, result = self.capture_main(self.local/'not-read.json')
        self.assertEqual(code,1)
        self.assertEqual(result['error_code'],'production_run_already_active')
        log = json.loads(Path(result['log_file']).read_text())
        self.assertEqual(log['error_type'],'BlockingIOError')
        self.assertEqual(log['status'],'blocked')
        self.assertFalse((self.local/'state/production/delivery-state.json').exists())

    def test_existing_run_log_is_not_duplicated(self):
        import contextlib
        import io
        from pihole_report.runlog import write_log
        path = write_log(self.local,{'status':'failed'},1800000000,1800000001)
        result = {'status':'failed','log_file':str(path)}
        with patch.object(p,'load_manifest',return_value={}), patch.object(p,'_execute',return_value=result), patch.object(p,'PROJECT',self.local), contextlib.redirect_stdout(io.StringIO()):
            code = p.main(['--config',str(self.local/'not-read.json')])
        self.assertEqual(code,1)
        self.assertEqual(len(list(path.parent.glob('pihole-report-*.json'))),1)


if __name__=='__main__':
    unittest.main()

import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import smtplib
import sqlite3
import ssl
import tempfile
from types import SimpleNamespace
import unittest

from pihole_report.delivery import BackupConfig, DeliveryError, SMTPConfig, export_backup, preflight_backup, send_report


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.calls = []
        self.failure = None
    def ehlo(self):
        self.calls.append('ehlo')
        return 250, b'hello'
    def starttls(self, context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        self.calls.append('starttls')
    def login(self, user, password):
        self.calls.append('login')
        assert user == 'sender@example.com' and password == 'synthetic-password'
    def send_message(self, msg, from_addr, to_addrs):
        self.calls.append('send')
        self.message, self.sender, self.recipients = msg, from_addr, to_addrs
        if self.failure:
            raise self.failure
        return {}
    def quit(self):
        self.calls.append('quit')
    def close(self):
        self.calls.append('close')


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.secret = self.root/'password'
        self.secret.write_text('synthetic-password\n')
        self.secret.chmod(0o600)
        self.smtp = SMTPConfig('sender@example.com', 'recipient@example.com')
        self.calls = []
        self.client = FakeSMTP()
        def factory(*args, **kwargs):
            self.calls.append((args, kwargs))
            return self.client
        self.factory = factory

    def test_dry_run_never_reads_credentials_or_connects(self):
        result = send_report('fixture report', self.smtp, self.root/'missing', smtp_factory=self.factory)
        self.assertEqual(result['status'], 'dry_run')
        self.assertEqual(self.calls, [])

    def test_verified_starttls_before_login_and_submission(self):
        result = send_report('fixture report', self.smtp, self.secret, send=True, smtp_factory=self.factory)
        self.assertTrue(result['submitted'])
        self.assertFalse(result['inbox_delivery_confirmed'])
        self.assertEqual(self.client.calls, ['ehlo','starttls','ehlo','login','send','quit'])
        self.assertEqual(self.client.sender, self.smtp.sender)
        self.assertEqual(self.client.recipients, [self.smtp.recipient])
        part = list(self.client.message.iter_attachments())[0]
        self.assertEqual(gzip.decompress(part.get_payload(decode=True)).decode(), 'fixture report')

    def test_credentials_permissions_and_symlink(self):
        self.secret.chmod(0o644)
        with self.assertRaises(DeliveryError):
            send_report('fixture',self.smtp,self.secret,send=True,smtp_factory=self.factory)
        self.secret.chmod(0o600)
        link=self.root/'link'; link.symlink_to(self.secret)
        with self.assertRaises(DeliveryError):
            send_report('fixture',self.smtp,link,send=True,smtp_factory=self.factory)
        self.assertEqual(self.calls,[])

    def test_uncertain_submission_is_sanitized_not_retried(self):
        self.client.failure=RuntimeError('SECRET provider echo')
        with self.assertRaises(DeliveryError) as caught:
            send_report('fixture',self.smtp,self.secret,send=True,smtp_factory=self.factory)
        self.assertTrue(caught.exception.uncertain)
        self.assertNotIn('SECRET',str(caught.exception))
        self.assertEqual(self.client.calls.count('send'),1)

    def test_explicit_recipient_rejection_is_not_uncertain(self):
        self.client.failure=smtplib.SMTPRecipientsRefused({'recipient@example.com':(550,b'no')})
        with self.assertRaises(DeliveryError) as caught:
            send_report('fixture',self.smtp,self.secret,send=True,smtp_factory=self.factory)
        self.assertFalse(caught.exception.uncertain)

    def test_tls_failure_never_authenticates(self):
        def fail(context):
            raise RuntimeError('secret TLS provider echo')
        self.client.starttls=fail
        with self.assertRaises(DeliveryError) as caught:
            send_report('fixture',self.smtp,self.secret,send=True,smtp_factory=self.factory)
        self.assertFalse(caught.exception.uncertain)
        self.assertNotIn('secret',str(caught.exception))
        self.assertNotIn('login',self.client.calls)
        self.assertNotIn('send',self.client.calls)

    def test_address_injection_rejected(self):
        with self.assertRaises(DeliveryError):
            send_report('fixture',SMTPConfig('sender@example.com','recipient@example.com\nBcc: other@example.com'))


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve()
        self.root=self.base/'fake-provider'; self.root.mkdir()
        self.dest=self.root/'Pi-hole Backups/Primary'
        self.pref=self.base/'prefs.plist'
        self.pref.write_bytes(plistlib.dumps({'UserEmail':'owner@example.com'}))
        self.config=BackupConfig('owner@example.com',self.root,self.dest,self.pref,retention=2)
        self.source=self.base/'source.sqlite'
        with sqlite3.connect(self.source) as db:
            db.executescript("CREATE TABLE metadata(key PRIMARY KEY,value); CREATE TABLE sample(n); INSERT INTO sample VALUES(7);")
        self.before=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.now=1800000000
        self.health='isSyncPaused = 0; isExcludedFromSync = 0; hasUnresolvedConflicts = 0; isTrashed = 0;'
        self.calls=[]
    def runner(self,args,**kwargs):
        self.calls.append(args)
        return SimpleNamespace(returncode=0,stdout=self.health)

    def test_export_default_is_no_io(self):
        bad=BackupConfig('x',self.base/'absent',self.base/'absent/dest',self.base/'absentpref')
        result=export_backup(self.base/'absent.sqlite',bad,runner=self.runner)
        self.assertEqual(result['status'],'dry_run')
        self.assertEqual(self.calls,[])
        self.assertFalse(self.dest.exists())

    def test_account_health_and_paths_fail_closed(self):
        self.pref.write_bytes(plistlib.dumps({'UserEmail':'wrong@example.com'}))
        with self.assertRaises(DeliveryError):
            preflight_backup(self.config,runner=self.runner)
        self.pref.write_bytes(plistlib.dumps({'UserEmail':'owner@example.com'}))
        self.health='isSyncPaused = 1;'
        with self.assertRaises(DeliveryError):
            preflight_backup(self.config,runner=self.runner)
        self.health='isSyncPaused = 0; isExcludedFromSync = 0; hasUnresolvedConflicts = 0; isTrashed = 0;'
        (self.root/'Pi-hole Backups').symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(DeliveryError):
            preflight_backup(self.config,runner=self.runner)
        outside=BackupConfig('owner@example.com',self.root,self.base/'outside',self.pref)
        with self.assertRaises(DeliveryError):
            preflight_backup(outside,runner=self.runner)

    def test_snapshot_restore_source_preservation_and_retention(self):
        first=export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now)
        one=Path(first['snapshot'])
        self.assertEqual(one.stat().st_mode&0o777,0o600)
        self.assertFalse(first['cloud_upload_confirmed'])
        with sqlite3.connect(one) as db:
            self.assertEqual(db.execute('SELECT n FROM sample').fetchone()[0],7)
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='snapshot_generator'").fetchone()[0],'pihole-history-v2')
        unrelated=self.dest/'notes.txt'; unrelated.write_text('keep')
        fifo=self.dest/'pihole-history-2002-01-01T00-00-00-000Z.sqlite'
        os.mkfifo(fifo)
        self.assertEqual(self.dest.stat().st_mode&0o777,0o700)
        self.assertEqual(self.dest.parent.stat().st_mode&0o777,0o700)
        fake=self.dest/'pihole-history-2000-01-01T00-00-00-000Z.sqlite'
        with sqlite3.connect(fake) as db:
            db.executescript("CREATE TABLE metadata(key,value); INSERT INTO metadata VALUES('snapshot_generator','other-app');")
        link=self.dest/'pihole-history-2001-01-01T00-00-00-000Z.sqlite'; link.symlink_to(self.source)
        second=export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now+1)
        third=export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now+2)
        self.assertFalse(one.exists())
        self.assertTrue(Path(second['snapshot']).exists())
        self.assertTrue(Path(third['snapshot']).exists())
        self.assertTrue(unrelated.exists() and fake.exists() and link.is_symlink() and fifo.exists())
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.before)
        self.assertFalse(list(self.dest.glob('.publishing-*')))

    def test_validation_export_can_preserve_every_existing_snapshot(self):
        copies = [export_backup(self.source,self.config,export=True,runner=self.runner,
                                now=self.now+i,prune=False) for i in range(4)]
        self.assertTrue(all(Path(row['snapshot']).is_file() for row in copies))
        self.assertTrue(all(row['pruned'] == [] for row in copies))
        with self.assertRaises(DeliveryError):
            export_backup('unused',None,prune='false')

    def test_duplicate_timestamp_never_overwrites(self):
        first=export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now)
        before=Path(first['snapshot']).read_bytes()
        with self.assertRaises(DeliveryError):
            export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now)
        self.assertEqual(Path(first['snapshot']).read_bytes(),before)
        self.assertFalse(list(self.dest.glob('.publishing-*')))

    def test_invalid_source_never_publishes(self):
        self.source.write_bytes(b'not sqlite')
        with self.assertRaises(DeliveryError):
            export_backup(self.source,self.config,export=True,runner=self.runner,now=self.now)
        self.assertFalse(self.dest.exists())

    def test_health_change_after_backup_prevents_publication(self):
        count=0
        def runner(*args,**kwargs):
            nonlocal count
            count+=1
            return SimpleNamespace(returncode=0,stdout=self.health if count==1 else 'isSyncPaused = 1;')
        with self.assertRaises(DeliveryError):
            export_backup(self.source,self.config,export=True,runner=runner,now=self.now)
        self.assertFalse(self.dest.exists())

class ExplicitEnableTests(unittest.TestCase):
    def test_truthy_strings_cannot_enable_delivery(self):
        from pihole_report.delivery import SMTPConfig, send_report, export_backup, DeliveryError
        for value in ('false', 'true', 1, None):
            with self.assertRaises(DeliveryError):
                send_report('synthetic', SMTPConfig('sender@example.com','recipient@example.com'), send=value)
            with self.assertRaises(DeliveryError):
                export_backup('unused', None, export=value)

class BackupWorkerTests(unittest.TestCase):
    def test_child_registration_precedes_work_and_environment_is_minimal(self):
        from pihole_report.delivery import run_backup_worker
        events=[]
        captured={}
        class Child:
            pid=99999999
            returncode=0
            def communicate(self, content=None, timeout=None):
                events.append('work')
                captured['input']=json.loads(content)
                return json.dumps({'status':'published_locally','exported':True}), None
        def popen(command,**kwargs):
            captured.update(command=command,kwargs=kwargs)
            return Child()
        result=run_backup_worker({'operation_id':'a'*32},popen=popen,
            on_start=lambda pid:events.append('registered'))
        self.assertTrue(result['exported'])
        self.assertEqual(events,['registered','work'])
        self.assertEqual(set(captured['kwargs']['env']),{'PATH','HOME','PYTHONPATH','PYTHONDONTWRITEBYTECODE'})
        self.assertTrue(captured['kwargs']['start_new_session'])
        self.assertNotIn('operation_id',' '.join(captured['command']))
        self.assertEqual(captured['kwargs']['stderr'],__import__('subprocess').DEVNULL)

    def test_timeout_stops_only_owned_child_and_remains_uncertain(self):
        import subprocess
        from pihole_report.delivery import run_backup_worker
        events=[]
        class Child:
            pid=99999999
            returncode=-15
            def communicate(self, content=None, timeout=None):
                if content is not None:
                    raise subprocess.TimeoutExpired('fixture',timeout)
                events.append('joined')
                return '',None
            def terminate(self): events.append('terminate')
            def kill(self): events.append('kill')
        with self.assertRaises(DeliveryError) as caught:
            run_backup_worker({},timeout=.1,popen=lambda *a,**k:Child(),killpg=lambda pid,sig:events.append(('group',pid,sig)))
        self.assertEqual(caught.exception.code,'backup_worker_timeout')
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(events,[('group',99999999,15),'joined',('group',99999999,9),'joined'])

    def test_callback_failure_cleans_owned_group_before_work(self):
        import io
        from pihole_report.delivery import run_backup_worker
        signals=[]
        class Child:
            pid=99999998
            stdin=io.StringIO()
            def communicate(self, content=None, timeout=None):
                self_test.assertIsNone(content)
                return '',None
        self_test=self
        def refused(pid): raise RuntimeError('synthetic state failure')
        with self.assertRaises(DeliveryError) as caught:
            run_backup_worker({},popen=lambda *a,**k:Child(),on_start=refused,
                killpg=lambda pid,sig:signals.append((pid,sig)))
        self.assertEqual(caught.exception.code,'backup_worker_state_unavailable')
        self.assertEqual(signals,[(99999998,15),(99999998,9)])

    def test_timeout_cannot_exceed_bound(self):
        from pihole_report.delivery import run_backup_worker
        with self.assertRaises(ValueError):
            run_backup_worker({},timeout=301,popen=lambda *a,**k:self.fail('must not start'))

    def test_worker_rejects_arbitrary_request_fields(self):
        import contextlib
        import io
        from unittest.mock import patch
        from pihole_report import delivery
        from pihole_report import production
        output=io.StringIO()
        with patch.object(production,'load_manifest',return_value={'scope':{}}), patch('sys.stdin',io.StringIO(json.dumps({'source':'/unapproved','password':'NEVER_LOG'}))), contextlib.redirect_stdout(output):
            self.assertEqual(delivery._backup_worker_main(),0)
        self.assertEqual(json.loads(output.getvalue())['error_code'],'invalid_backup_worker_request')
        self.assertNotIn('NEVER_LOG',output.getvalue())


class BackupIdentityTests(BackupTests):
    def test_operation_identity_reconciles_existing_snapshot(self):
        from pihole_report.delivery import inspect_backup
        operation='a'*32
        exported=export_backup(self.source,self.config,export=True,runner=self.runner,
            now=self.now,operation_id=operation,source_digest=self.before)
        reconciled=inspect_backup(self.config,self.now,operation,self.before)
        self.assertTrue(reconciled['reconciled'])
        self.assertEqual(reconciled['snapshot'],exported['snapshot'])
        with self.assertRaises(DeliveryError) as caught:
            inspect_backup(self.config,self.now,'b'*32,self.before)
        self.assertTrue(caught.exception.uncertain)
        self.assertTrue(Path(exported['snapshot']).exists())


if __name__=='__main__':
    unittest.main()

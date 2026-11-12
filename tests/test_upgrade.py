"""Offline synthetic upgrade/rollback tests. No production operations."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch
from pihole_report import upgrade as u
from pihole_report import migration as m
NOW=datetime(2026,11,12,12,tzinfo=timezone.utc)
def idle(*args): return dict(loaded=True,running=False,active_pids=[])

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()); self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        for name in ('project','project/pihole_report','project/config','project/state','project/state/production','candidate'):
            (self.root/name).mkdir(mode=0o700)
        for directory,body in [('project/pihole_report','old'),('candidate','new')]:
            for name in ('__init__.py','production.py'):
                (self.root/directory/name).write_text('# '+body)
        self.manifest=self.root/'project/config/production.json'
        self.write(self.manifest,dict(schema='pihole-production.v1',enabled=True,scope={'fixture':True},code_sha256=u.package_hashes(self.root/'project/pihole_report')))
        self.wrapper=self.root/'wrapper';self.wrapper.write_text('unchanged');self.wrapper.chmod(0o700)
        self.plist=self.root/'job.plist';self.plist.write_bytes(plistlib.dumps(dict(Label='test.job',ProgramArguments=[str(self.wrapper)],RunAtLoad=True,StartCalendarInterval=dict(Hour=6,Minute=5))))
        self.db=self.root/'history.sqlite';self.db.write_bytes(b'never-open-database')
        self.spec=dict(project=str(self.root/'project'),manifest=str(self.manifest),wrapper=str(self.wrapper),plist=str(self.plist),database=str(self.db),python=str(Path(os.sys.executable).resolve()),backup_root=str(self.root/'archives'),snapshot_roots=[],metadata_only=[])
        self.scope=patch.object(u,'validate_scope');self.scope.start();self.addCleanup(self.scope.stop)
    def write(self,p,value): p.write_text(json.dumps(value));p.chmod(0o600)
    def plan(self): return u.create_plan(self.spec,self.root/'candidate',probe=idle,now=NOW)
    def execute(self,plan=None):return u.execute_plan(plan or self.plan(),execute=True,probe=idle,now=NOW)
    def test_plan_read_only_and_execute_opt_in(self):
        before=set(self.root.rglob('*'));p=self.plan();self.assertEqual(u.execute_plan(p,probe=idle,now=NOW)['status'],'planned');self.assertEqual(before,set(self.root.rglob('*')))
    def test_upgrade_and_latest_ledger_rollback_preserves_database(self):
        p=self.plan();before=[x.read_bytes() for x in (self.db,self.wrapper,self.plist)]
        result=self.execute(p);self.assertEqual(u.package_hashes(self.root/'project/pihole_report'),p['new_hashes'])
        ledger=dict(schema='pihole-delivery-state.v2',dates={f'2026-11-{i+1:02}':dict(stages=dict(email=dict(status=status)),artifact='preserved') for i,status in enumerate(('pending','not_submitted','reserved','uncertain','submitted'))})
        self.write(u.ledger_path(self.spec),ledger)
        rolled=u.rollback(result['archive'],execute=True,probe=idle,now=NOW)
        projected=u.private_json(u.ledger_path(self.spec));self.assertTrue(all(x['status']=='rollback_held' for x in projected['dates'].values()))
        self.assertEqual(u.private_json(Path(rolled['archive'])/'latest-ledger.json'),ledger)
        self.assertEqual(u.package_hashes(self.root/'project/pihole_report'),p['old_hashes'])
        self.assertEqual([x.read_bytes() for x in (self.db,self.wrapper,self.plist)],before)
        self.assertEqual(projected['dates']['2026-11-01']['original_email_status'],'pending')
    def test_v1_projection_unchanged(self):
        state=dict(schema='pihole-delivery-state.v1',dates={'2026-11-12':dict(status='submitted')});self.assertEqual(u.project_ledger(state),state)
    def test_source_changed_refused(self):
        p=self.plan();(self.root/'candidate/production.py').write_text('changed')
        with self.assertRaises(m.MigrationError):self.execute(p)
    def test_symlink_refused(self):
        (self.root/'candidate/evil.py').symlink_to(self.db)
        with self.assertRaises(m.MigrationError):self.plan()
    def test_non_python_refused(self):
        (self.root/'candidate/secret.txt').write_text('not copied')
        with self.assertRaises(m.MigrationError):self.plan()
    def test_busy_or_near_schedule(self):
        with self.assertRaises(m.MigrationError):u.create_plan(self.spec,self.root/'candidate',probe=lambda *a:dict(loaded=True,running=True,active_pids=[]),now=NOW)
        with self.assertRaises(m.MigrationError):u.create_plan(self.spec,self.root/'candidate',probe=idle,now=NOW.replace(hour=6))
    def test_live_worker_or_uncertain_backup_refused(self):
        for backup in (dict(status='complete',worker_pid=os.getpid()),dict(status='uncertain')):
            self.write(u.ledger_path(self.spec),dict(schema='pihole-delivery-state.v2',dates={'today':dict(stages=dict(backup=backup))}))
            with self.assertRaises(m.MigrationError):self.plan()
    def test_interrupted_swap_disabled_and_no_blind_retry(self):
        p=self.plan()
        with patch.object(u.os,'rename',side_effect=OSError('synthetic crash')):
            with self.assertRaises(OSError):self.execute(p)
        self.assertFalse(u.private_json(self.manifest)['enabled']);self.assertTrue(u.marker(self.spec).exists())
        with self.assertRaises(m.MigrationError):self.execute(p)
    def test_manifest_mismatch(self):
        manifest=u.private_json(self.manifest);manifest['code_sha256']={};self.write(self.manifest,manifest)
        with self.assertRaises(m.MigrationError):self.plan()
    def test_expired_plan(self):
        with self.assertRaises(m.MigrationError):u.execute_plan(self.plan(),execute=True,probe=idle,now=NOW.replace(hour=13))
    def test_existing_collector_lock(self):
        Path(str(self.db)+'.collector-lock').write_text('existing')
        with self.assertRaises(m.MigrationError):self.plan()

if __name__=='__main__':unittest.main()

"""Synthetic-only migration exercises. Never reference production locations."""
from datetime import datetime, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from pihole_report import migration as m

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)

def idle(spec, schedule):
    return {'loaded': True, 'running': False, 'active_pids': []}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Inject only the production-path/manifest validator for synthetic fixtures.
        validator = patch.object(m, 'validate_manifest')
        self.validator = validator.start()
        self.addCleanup(validator.stop)
        for name in ('bin', 'config', 'project', 'project/pihole_report', 'project/config', 'credentials', 'launchd'):
            (self.root / name).mkdir(mode=0o700)
        self.wrapper = self.root / 'bin/run-daily-review'
        self.old_wrapper = b'#!/bin/sh\nlegacy-command\n'
        self.wrapper.write_bytes(self.old_wrapper)
        self.wrapper.chmod(0o700)
        (self.root / 'bin/old.js').write_text('legacy code')
        (self.root / 'config/settings.json').write_text('{"ordinary":true}')
        (self.root / 'project/pihole_report/production.py').write_text('# synthetic runner\n')
        (self.root / 'project/pyproject.toml').write_text('[project]\nname="test"\n')
        self.manifest = self.root / 'project/config/production.json'
        self.manifest.write_text('{"enabled":true}')
        self.manifest.chmod(0o600)
        self.credential = self.root / 'credentials/app-password'
        self.credential.write_text('synthetic-secret-never-read')
        self.credential.chmod(0o600)
        self.plist = self.root / 'launchd/job.plist'
        self.plist.write_bytes(plistlib.dumps({'Label':'test.pihole', 'ProgramArguments':[str(self.wrapper)],
            'RunAtLoad':True, 'StartCalendarInterval':{'Hour':6, 'Minute':5}}))
        self.db = self.root / 'history.sqlite'
        with sqlite3.connect(self.db) as db:
            db.executescript('CREATE TABLE history(value TEXT); INSERT INTO history VALUES("old");')
        self.db.chmod(0o600)
        self.spec = dict(project=str(self.root/'project'), database=str(self.db),
            wrapper=str(self.wrapper), plist=str(self.plist), python=str(Path(os.sys.executable).resolve()),
            manifest=str(self.manifest), backup_root=str(self.root/'rollback'),
            snapshot_roots=[str(self.root/'bin'), str(self.root/'config')],
            metadata_only=[str(self.root/'credentials')])

    def plan(self):
        return m.create_plan(self.spec, probe=idle, now=NOW)

    def execute(self, plan=None):
        return m.execute_plan(plan or self.plan(), execute=True, probe=idle, now=NOW)

    def test_default_plan_does_not_write_or_read_credentials(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path == self.credential:
                self.fail('credential opened')
            return original(path, *args, **kwargs)
        before = set(self.root.rglob('*'))
        with patch.object(Path, 'open', guarded):
            plan = self.plan()
            result = m.execute_plan(plan, probe=idle, now=NOW)
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(set(self.root.rglob('*')), before)
        credential = next(x for x in plan['files'] if x['path'] == str(self.credential))
        self.assertFalse(credential['copy'])
        self.assertNotIn('sha256', credential)
        self.assertNotIn('synthetic-secret', json.dumps(plan))

    def test_full_transition_and_rollback_preserve_new_history(self):
        db_before, plist_before = self.db.read_bytes(), self.plist.read_bytes()
        result = self.execute()
        self.assertEqual(result['status'], 'switched')
        self.assertEqual(self.db.read_bytes(), db_before)
        self.assertEqual(self.plist.read_bytes(), plist_before)
        self.assertFalse(Path(str(self.db)+'.collector-lock').exists())
        self.assertEqual(stat.S_IMODE(self.wrapper.stat().st_mode), 0o700)
        self.assertIn(b' -m pihole_report.production --manifest ', self.wrapper.read_bytes())
        archive = Path(result['archive'])
        receipt = json.loads((archive/'receipt.json').read_text())
        self.assertTrue(receipt['database']['restored_logical_match'])
        for file in archive.rglob('*'):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o700 if file.is_dir() else 0o600)
        self.assertFalse(any(b'synthetic-secret' in file.read_bytes() for file in (archive/'files').iterdir()))
        with sqlite3.connect(self.db) as db:
            db.execute('INSERT INTO history VALUES("new")')
        new_database = self.db.read_bytes()
        proposed = m.rollback(archive, probe=idle, now=NOW)
        self.assertEqual(proposed['status'], 'rollback_planned')
        self.assertFalse(proposed['database_restore'])
        self.assertNotEqual(self.wrapper.read_bytes(), self.old_wrapper)
        done = m.rollback(archive, execute=True, probe=idle, now=NOW)
        self.assertEqual(done['status'], 'rolled_back')
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertEqual(self.db.read_bytes(), new_database)
        self.assertEqual(self.plist.read_bytes(), plist_before)

    def test_changed_wrapper_refuses_before_archive(self):
        plan = self.plan()
        self.wrapper.write_text('different')
        with self.assertRaisesRegex(m.MigrationError, 'baseline_changed'):
            self.execute(plan)
        self.assertFalse((self.root/'rollback').exists())

    def test_changed_database_refuses(self):
        plan = self.plan()
        with sqlite3.connect(self.db) as db:
            db.execute('INSERT INTO history VALUES("changed")')
        with self.assertRaisesRegex(m.MigrationError, 'baseline_changed'):
            self.execute(plan)
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)

    def test_any_new_input_file_refuses(self):
        plan = self.plan()
        (self.root/'bin/new.js').write_text('new code')
        with self.assertRaisesRegex(m.MigrationError, 'baseline_changed'):
            self.execute(plan)

    def test_active_job_process_or_lock_refuses(self):
        for status in ({'loaded':True, 'running':True, 'active_pids':[]},
                       {'loaded':True, 'running':False, 'active_pids':[123]},
                       {'loaded':False, 'running':False, 'active_pids':[]}):
            with self.subTest(status=status), self.assertRaisesRegex(m.MigrationError, 'not_idle'):
                m.create_plan(self.spec, probe=lambda *a:status, now=NOW)
        lock = Path(str(self.db)+'.collector-lock')
        lock.write_text('do not inspect stale locks automatically')
        with self.assertRaisesRegex(m.MigrationError, 'collector_lock_present'):
            self.plan()

    def test_schedule_margin_and_expired_plan_refuse(self):
        for hour, minute in ((6,5), (5,40), (6,30)):
            with self.subTest(hour=hour,minute=minute), self.assertRaisesRegex(m.MigrationError, 'thirty_minutes'):
                m.create_plan(self.spec, probe=idle, now=NOW.replace(hour=hour, minute=minute))
        with self.assertRaisesRegex(m.MigrationError, 'expired'):
            m.execute_plan(self.plan(), execute=True, probe=idle, now=NOW.replace(hour=13))

    def test_symlink_input_and_cloud_destination_refuse(self):
        link=self.root/'config/link'
        link.symlink_to(self.credential)
        with self.assertRaisesRegex(m.MigrationError, 'symlink'):
            self.plan()
        link.unlink()
        for name in ('OneDrive', 'CloudStorage', '.validation'):
            with self.subTest(name=name), self.assertRaisesRegex(m.MigrationError, 'local_outside_validation'):
                m.create_plan(dict(self.spec, backup_root=str(self.root/name/'backup')), probe=idle, now=NOW)

    def test_bad_database_never_changes_wrapper_and_releases_lock(self):
        self.db.write_bytes(b'not a sqlite database')
        with self.assertRaises(sqlite3.DatabaseError):
            self.execute()
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertFalse(Path(str(self.db)+'.collector-lock').exists())

    def test_late_process_check_refuses_after_valid_snapshot(self):
        plan = self.plan()
        calls = 0
        def race(*args):
            nonlocal calls
            calls += 1
            return idle(*args) if calls < 3 else {'loaded':True,'running':True,'active_pids':[]}
        with self.assertRaisesRegex(m.MigrationError, 'not_idle'):
            m.execute_plan(plan, execute=True, probe=race, now=NOW)
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertFalse(Path(str(self.db)+'.collector-lock').exists())

    def test_rollback_refuses_changed_installed_wrapper(self):
        result = self.execute()
        self.wrapper.write_bytes(self.wrapper.read_bytes()+b'# changed\n')
        with self.assertRaisesRegex(m.MigrationError, 'not_exact_installed'):
            m.rollback(result['archive'], execute=True, probe=idle, now=NOW)

    def test_rollback_refuses_changed_original_backup(self):
        result = self.execute()
        archive = Path(result['archive'])
        receipt = json.loads((archive/'receipt.json').read_text())
        entry=next(x for x in receipt['files'] if x['path']==str(self.wrapper))
        (archive/entry['backup']).write_text('changed archive')
        with self.assertRaisesRegex(m.MigrationError, 'backup_invalid'):
            m.rollback(archive, execute=True, probe=idle, now=NOW)

    def test_nonboolean_execute_cannot_switch(self):
        result=m.execute_plan(self.plan(),execute='true',probe=idle,now=NOW)
        self.assertEqual(result['status'],'planned')
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)

    def test_wal_records_are_in_snapshot_without_touching_live_shm(self):
        db=sqlite3.connect(self.db)
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('INSERT INTO history VALUES("wal committed")')
        db.commit()
        plan=self.plan()
        result=self.execute(plan)
        self.assertEqual(m.database_files(self.spec),plan['database'])
        with sqlite3.connect(Path(result['archive'])/'history.sqlite') as check:
            self.assertEqual(check.execute('SELECT value FROM history ORDER BY rowid').fetchall(),[('old',),('wal committed',)])

    def test_precommit_receipt_supports_interrupted_success(self):
        original=m._write_json
        def interrupt(path, value):
            if path.name=='completed.json':
                raise OSError('simulated loss of marker write')
            original(path,value)
        with patch.object(m,'_write_json',interrupt), self.assertRaises(OSError):
            self.execute()
        archive=next((self.root/'rollback').iterdir())
        self.assertTrue((archive/'receipt.json').is_file())
        self.assertEqual(m.rollback(archive,execute=True,probe=idle,now=NOW)['status'],'rolled_back')
        self.assertEqual(self.wrapper.read_bytes(),self.old_wrapper)

    def test_manifest_failure_prevents_any_transition(self):
        self.validator.side_effect = m.MigrationError('production_manifest_invalid_or_code_changed')
        with self.assertRaisesRegex(m.MigrationError, 'manifest_invalid'):
            self.plan()
        self.assertFalse((self.root/'rollback').exists())
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)

    def test_persistent_runner_lock_is_allowed_when_idle_and_refused_when_held(self):
        directory=self.root/'project/state/production'
        directory.mkdir(parents=True,mode=0o700)
        directory.parent.chmod(0o700)
        lock=directory/'runner.lock'
        lock.touch(mode=0o600)
        self.plan()
        with lock.open('a') as handle:
            fcntl.flock(handle.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.MigrationError,'production_run_lock_busy'):
                self.plan()
        result=self.execute()
        self.assertEqual(m.rollback(result['archive'],execute=True,probe=idle,now=NOW)['status'],'rolled_back')

    def test_parent_traversal_refused(self):
        with self.assertRaisesRegex(m.MigrationError,'absolute_single_line_path'):
            m.create_plan(dict(self.spec,backup_root=str(self.root/'x/../rollback')),probe=idle,now=NOW)

"""Offline, fail-closed wrapper transition. Planning never writes or runs the report.

No launchctl mutation, credentials reads, network traffic, or live DB connection.
The shared collector lock is held only during an explicitly executed transition.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid

VERSION = 'pihole-transition.v1'
PROCESS_NAMES = frozenset(('run-daily-review', 'generate-domain-review',
    'generate-domain-review.legacy', 'send-domain-review-email',
    'pihole-history.cjs', 'backup-onedrive.cjs', 'refresh-unifi-inventory.sh',
    'refresh-curated-lists.cjs', 'pihole_report.production', 'pihole_report.pipeline'))
SECRET_NAME = re.compile(r'password|credential|secret|token|(^|[._-])env($|[._-])|private[-_]key', re.I)


class MigrationError(ValueError):
    """Fixed, credential-free reason for refusing an unsafe transition."""


def fail(reason):
    raise MigrationError(reason)


def canonical(path):
    p = Path(path).expanduser()
    if not p.is_absolute() or '..' in p.parts or any(c in str(p) for c in ('\n', '\r', '\0')):
        fail('absolute_single_line_path_required')
    # A symlink in a destination ancestor could redirect writes.
    for part in (p, *p.parents):
        if part.is_symlink():
            fail('symlink_path_refused')
    return p


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def metadata(path, *, content=True):
    p = canonical(path)
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode):
        fail('regular_file_required')
    result = dict(path=str(p), mode=stat.S_IMODE(s.st_mode), uid=s.st_uid,
        gid=s.st_gid, size=s.st_size, mtime_ns=s.st_mtime_ns, inode=s.st_ino)
    if content:
        result['sha256'] = digest(p)
    # Check a file wasn't replaced or modified while its digest was computed.
    after = p.lstat()
    if (s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode) != (after.st_ino,
            after.st_size, after.st_mtime_ns, after.st_mode):
        fail('file_changed_during_inspection')
    return result


def _secret_path(path):
    return any(SECRET_NAME.search(x) or x == 'service-env' for x in path.parts)


def _files_under(path):
    p = canonical(path)
    if p.is_file():
        return [p]
    if not p.is_dir():
        fail('snapshot_input_missing')
    files = []
    for root, dirs, names in os.walk(p, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ('__pycache__', '.git'))
        for name in dirs + sorted(names):
            candidate = Path(root) / name
            canonical(candidate)
            if candidate.is_file():
                files.append(candidate)
    return sorted(files)


def normalize_spec(value):
    required = {'project', 'database', 'wrapper', 'plist', 'python', 'manifest',
        'backup_root', 'snapshot_roots', 'metadata_only'}
    if not isinstance(value, dict) or set(value) != required:
        fail('invalid_spec_fields')
    spec = dict(value)
    for key in required - {'snapshot_roots', 'metadata_only', 'python'}:
        spec[key] = str(canonical(spec[key]))
    # Homebrew's public interpreter is a symlink; fingerprint its resolved target.
    interpreter = Path(spec['python']).expanduser()
    if not interpreter.is_absolute() or any(c in str(interpreter) for c in '\n\r\0'):
        fail('absolute_python_required')
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        fail('python_not_executable')
    spec['python'] = str(interpreter)
    for key in ('snapshot_roots', 'metadata_only'):
        if not isinstance(spec[key], list):
            fail('invalid_spec_paths')
        spec[key] = sorted({str(canonical(p)) for p in spec[key]})
    backup = Path(spec['backup_root'])
    if any(x.lower() in ('cloudstorage', 'onedrive', '.validation', 'mobile documents',
                          'dropbox', 'google drive', 'googledrive')
           or x.lower().startswith(('onedrive-', 'googledrive-')) for x in backup.parts):
        fail('backup_must_be_local_outside_validation')
    for source in ('project', 'database', 'wrapper', 'plist', 'manifest'):
        path = Path(spec[source])
        if path == backup or backup in path.parents:
            fail('backup_overlaps_production_input')
    if not Path(spec['project']).is_dir():
        fail('project_missing')
    for root in spec['snapshot_roots'] + spec['metadata_only']:
        if backup == Path(root) or Path(root) in backup.parents:
            fail('backup_overlaps_snapshot_input')
    return spec


def validate_manifest(spec):
    """Use the runner's exact approved destination and code-binding validator."""
    from . import production
    from .deployment import load_deployment
    deployment = load_deployment()
    approved = deployment['scheduler']
    if any(spec[key] != approved[key] for key in ('project','manifest','database','wrapper','plist','python')):
        fail('exact_production_paths_required')
    try:
        production.load_manifest(spec['manifest'])
    except (ValueError, OSError) as exc:
        raise MigrationError('production_manifest_invalid_or_code_changed') from exc


def inventory(spec):
    paths = {Path(spec[x]) for x in ('wrapper', 'plist', 'manifest')}
    for root in spec['snapshot_roots']:
        paths.update(_files_under(root))
    paths.update(_files_under(Path(spec['project']) / 'pihole_report'))
    paths.add(Path(spec['project']) / 'pyproject.toml')
    private = set()
    for root in spec['metadata_only']:
        private.update(_files_under(root))
    paths.update(private)
    result = []
    for path in sorted(paths):
        if path == Path(spec['database']) or str(path).startswith(spec['database'] + '-'):
            fail('database_must_not_be_snapshot_input')
        content = path not in private and not _secret_path(path)
        item = metadata(path, content=content)
        item['copy'] = content
        result.append(item)
    if any(not item['copy'] for item in result if item['path'] in
            (spec['wrapper'], spec['plist'], spec['manifest'])):
        fail('entrypoint_cannot_be_metadata_only')
    return result


def database_files(spec):
    files = []
    for suffix in ('', '-wal', '-shm', '-journal'):
        p = Path(spec['database'] + suffix)
        if p.exists() or p.is_symlink():
            files.append(metadata(p))
    if not files or files[0]['path'] != spec['database']:
        fail('database_missing')
    if any(x['path'].endswith('-journal') for x in files):
        fail('rollback_journal_requires_manual_review')
    return files


def settings(spec):
    with Path(spec['plist']).open('rb') as f:
        value = plistlib.load(f)
    if value.get('ProgramArguments') != [spec['wrapper']] or 'Program' in value:
        fail('launchd_entrypoint_mismatch')
    if value.get('RunAtLoad') is not True:
        fail('unexpected_run_at_load_setting')
    interval = value.get('StartCalendarInterval')
    if (not isinstance(interval, dict) or set(interval) != {'Hour', 'Minute'}
            or type(interval['Hour']) is not int or type(interval['Minute']) is not int
            or not 0 <= interval['Hour'] < 24 or not 0 <= interval['Minute'] < 60):
        fail('only_single_daily_calendar_supported')
    if any(key in value for key in ('KeepAlive', 'StartInterval', 'WatchPaths',
            'QueueDirectories', 'StartOnMount')):
        fail('unanticipated_launchd_trigger')
    label = value.get('Label')
    if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', label):
        fail('invalid_launchd_label')
    return dict(label=label, hour=interval['Hour'], minute=interval['Minute'], run_at_load=True)


def system_probe(spec, schedule):
    """Local read-only commands. Never return raw process/environment contents."""
    try:
        result = subprocess.run(['/bin/launchctl', 'print',
            f'gui/{os.getuid()}/{schedule["label"]}'], capture_output=True, text=True,
            timeout=10, check=True)
        output = result.stdout
        program = re.search(r'^\s*program = (.+)$', output, re.M)
        path = re.search(r'^\s*path = (.+)$', output, re.M)
        state = re.search(r'^\s*state = (.+)$', output, re.M)
        if (not program or program[1].strip() != spec['wrapper'] or not path
                or path[1].strip() != spec['plist'] or not state):
            fail('loaded_launchd_definition_mismatch')
        if (f'"Hour" => {schedule["hour"]}' not in output
                or f'"Minute" => {schedule["minute"]}' not in output):
            fail('loaded_launchd_schedule_mismatch')
        ps = subprocess.run(['/bin/ps', '-axo', 'pid=,command='], capture_output=True,
            text=True, check=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as exc:
        raise MigrationError('local_process_inspection_failed') from exc
    active = []
    for line in ps.stdout.splitlines():
        try:
            pid, command = line.strip().split(None, 1)
            args = shlex.split(command)
        except ValueError:
            continue
        if int(pid) != os.getpid() and any(Path(arg).name in PROCESS_NAMES for arg in args):
            active.append(int(pid))
    return dict(loaded=True, running=state[1].strip() != 'not running', active_pids=sorted(active))


def preflight(spec, *, probe=system_probe, now=None, own_lock=None):
    now = now or datetime.now().astimezone()
    if now.tzinfo is None:
        fail('timezone_aware_clock_required')
    schedule = settings(spec)
    # Compare wall-clock minutes, as StartCalendarInterval is local wall time.
    minute = now.hour * 60 + now.minute + now.second / 60
    scheduled = schedule['hour'] * 60 + schedule['minute']
    distance = min((minute - scheduled) % 1440, (scheduled - minute) % 1440)
    if distance <= 30:
        fail('within_thirty_minutes_of_schedule')
    lock = Path(spec['database'] + '.collector-lock')
    if lock.exists() or lock.is_symlink():
        if own_lock is None or lock.read_text() != own_lock:
            fail('collector_lock_present')
    # A persistent lock file is normal. Probe flock rather than its presence.
    if own_lock is None:
        with runner_lock(spec, create=False):
            pass
    status = probe(spec, schedule)
    if status != dict(loaded=True, running=False, active_pids=[]):
        fail('job_or_process_not_idle')
    return schedule


def wrapper_bytes(spec):
    return ('#!/bin/sh\nset -eu\numask 077\nexport PYTHONDONTWRITEBYTECODE=1\n'
        + 'cd ' + shlex.quote(spec['project']) + '\n'
        + 'exec ' + shlex.quote(spec['python'])
        + ' -m pihole_report.production --manifest ' + shlex.quote(spec['manifest']) + '\n').encode()


def create_plan(value, *, probe=system_probe, now=None):
    spec = normalize_spec(value)
    validate_manifest(spec)
    now = now or datetime.now().astimezone()
    schedule = preflight(spec, probe=probe, now=now)
    files = inventory(spec)
    wrapper = next(x for x in files if x['path'] == spec['wrapper'])
    if not wrapper['mode'] & 0o100 or wrapper['uid'] != os.getuid():
        fail('wrapper_not_owned_or_executable')
    return dict(schema=VERSION, created_at=now.isoformat(), spec=spec, schedule=schedule,
        files=files, database=database_files(spec),
        python=metadata(Path(spec['python']).resolve()),
        new_wrapper_sha256=hashlib.sha256(wrapper_bytes(spec)).hexdigest(),
        effects=['Create an owner-only local rollback archive and verified full SQLite snapshot.',
            'Hold the existing collector lock and persistent Python runner flock during execution.',
            'Create owner-only Python state directories and runner.lock if absent; no delivery state is seeded.',
            'Atomically replace only the existing daily wrapper; do not launch the job.',
            'Keep launchd plist, schedule, credentials, database, and legacy scripts unchanged.'])


def check_plan(plan, *, probe=system_probe, now=None, own_lock=None):
    if not isinstance(plan, dict) or plan.get('schema') != VERSION:
        fail('invalid_plan_schema')
    spec = normalize_spec(plan['spec'])
    validate_manifest(spec)
    now = now or datetime.now().astimezone()
    created = datetime.fromisoformat(plan['created_at'])
    if created.tzinfo is None or not 0 <= (now - created).total_seconds() <= 1800:
        fail('plan_expired_or_clock_changed')
    schedule = preflight(spec, probe=probe, now=now, own_lock=own_lock)
    if (schedule != plan['schedule'] or inventory(spec) != plan['files']
            or database_files(spec) != plan['database']
            or metadata(Path(spec['python']).resolve()) != plan['python']
            or hashlib.sha256(wrapper_bytes(spec)).hexdigest() != plan['new_wrapper_sha256']):
        fail('baseline_changed_replan_required')
    return spec


@contextmanager
def runner_lock(spec, *, create=False):
    directory = canonical(Path(spec['project']) / 'state' / 'production')
    path = directory / 'runner.lock'
    if not create and not path.exists() and not path.is_symlink():
        yield
        return
    if create:
        for parent in (directory.parent, directory):
            _owner_directory(parent)
    canonical(path)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'a') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            fail('production_run_lock_not_owner_only')
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MigrationError('production_run_lock_busy') from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_collector_lock(spec):
    with runner_lock(spec, create=True):
        path = Path(spec['database'] + '.collector-lock')
        value = json.dumps(dict(pid=os.getpid(), token=str(uuid.uuid4()),
            created=datetime.now(timezone.utc).isoformat()))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise MigrationError('collector_lock_present') from exc
        with os.fdopen(fd, 'w') as f:
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        try:
            yield value
        finally:
            if path.exists() and path.read_text() == value:
                path.unlink()


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    _sync_directory(Path(path).parent)


def _write_json(path, value):
    _write_new(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def _owner_directory(path):
    canonical(path)
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    _sync_directory(path.parent)
    s = path.stat()
    if not path.is_dir() or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        fail('backup_directory_must_be_owner_only')


def _sqlite_signature(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or db.execute('PRAGMA foreign_key_check').fetchall():
            fail('backup_integrity_failed')
        h = hashlib.sha256()
        for line in db.iterdump():
            h.update(line.encode())
            h.update(b'\n')
        return dict(logical_sha256=h.hexdigest(), user_version=db.execute('PRAGMA user_version').fetchone()[0])


def _backup_private_copy(source, destination):
    _write_new(destination, b'')
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as src, closing(sqlite3.connect(destination)) as out:
        src.backup(out)
        out.execute('PRAGMA journal_mode=DELETE')
    with destination.open('rb') as f:
        os.fsync(f.fileno())


def _snapshot_database(plan, archive):
    raw = archive / 'sqlite-input'
    raw.mkdir(mode=0o700)
    source = Path(plan['spec']['database'])
    # SHM is an ephemeral index; reconstruct it privately from main + WAL.
    for item in plan['database']:
        if item['path'].endswith('-shm'):
            continue
        target = raw / ('history.sqlite' + item['path'][len(str(source)):])
        _write_new(target, b'')
        with Path(item['path']).open('rb') as inp, target.open('wb') as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        if digest(target) != item['sha256']:
            fail('database_changed_during_copy')
    if database_files(plan['spec']) != plan['database']:
        fail('database_changed_during_copy')
    snapshot = archive / 'history.sqlite'
    _backup_private_copy(raw / 'history.sqlite', snapshot)
    signature = _sqlite_signature(snapshot)
    restored = archive / 'restore-verified.sqlite'
    _backup_private_copy(snapshot, restored)
    if _sqlite_signature(restored) != signature:
        fail('restore_verification_failed')
    # Retain both verified copies. No history backup is automatically pruned.
    return dict(snapshot='history.sqlite', restore_test='restore-verified.sqlite',
        sha256=digest(snapshot), restore_sha256=digest(restored), **signature,
        integrity_check='ok', foreign_key_check='ok', restored_logical_match=True)


def _replace_exact(path, expected, data, mode):
    if metadata(path) != expected:
        fail('wrapper_changed_before_atomic_replace')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-transition-', dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        if metadata(path) != expected:
            fail('wrapper_changed_before_atomic_replace')
        os.replace(temp, path)
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if temp.exists():
            temp.unlink()


def execute_plan(plan, *, execute=False, probe=system_probe, now=None):
    spec = check_plan(plan, probe=probe, now=now)
    if execute is not True:
        return dict(status='planned', plan=plan)
    # This directory alone is writable before the wrapper swap. No cloud path.
    root = Path(spec['backup_root'])
    if shutil.disk_usage(root.parent).free < 4 * sum(x['size'] for x in plan['database']) + 100 * 1024 * 1024:
        fail('insufficient_local_backup_space')
    _owner_directory(root)
    archive = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex)
    archive.mkdir(mode=0o700)
    _sync_directory(root)
    _write_json(archive / 'plan.json', plan)
    with exclusive_collector_lock(spec) as lock:
        check_plan(plan, probe=probe, now=now, own_lock=lock)
        copied = []
        folder = archive / 'files'
        folder.mkdir(mode=0o700)
        for index, item in enumerate(plan['files']):
            record = dict(item)
            if item['copy']:
                target = folder / f'{index:04d}'
                _write_new(target, Path(item['path']).read_bytes())
                if digest(target) != item['sha256']:
                    fail('snapshot_file_changed')
                record['backup'] = str(target.relative_to(archive))
            copied.append(record)
        database = _snapshot_database(plan, archive)
        check_plan(plan, probe=probe, now=now, own_lock=lock)
        old = next(x for x in plan['files'] if x['path'] == spec['wrapper'])
        expected = {k: v for k, v in old.items() if k != 'copy'}
        replacement = wrapper_bytes(spec)
        record = dict(schema=VERSION, spec=spec, files=copied, database=database,
            new_wrapper_sha256=hashlib.sha256(replacement).hexdigest(),
            original_wrapper=expected, status='prepared', schedule=plan['schedule'])
        # Precommit receipt allows recovery even if the process exits after rename.
        _write_json(archive / 'receipt.json', record)
        _replace_exact(Path(spec['wrapper']), expected, replacement, old['mode'])
        if digest(spec['wrapper']) != record['new_wrapper_sha256']:
            fail('replacement_verification_failed')
        # Success marker is separate so a failure cannot erase the precommit receipt.
        _write_json(archive / 'completed.json', dict(status='switched', at=datetime.now(timezone.utc).isoformat()))
    return dict(status='switched', archive=str(archive), launchd_changed=False,
        job_started=False, database_changed=False, credentials_read=False)


def rollback(archive, *, execute=False, probe=system_probe, now=None):
    archive = canonical(archive)
    s = archive.stat()
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        fail('rollback_archive_must_be_owner_only')
    receipt = json.loads((archive / 'receipt.json').read_text())
    if receipt.get('schema') != VERSION:
        fail('invalid_receipt_schema')
    spec = normalize_spec(receipt['spec'])
    if archive.parent != Path(spec['backup_root']):
        fail('rollback_archive_location_changed')
    preflight(spec, probe=probe, now=now)
    wrapper = Path(spec['wrapper'])
    current = metadata(wrapper)
    if current['sha256'] != receipt['new_wrapper_sha256']:
        fail('wrapper_not_exact_installed_version')
    # Refuse a changed schedule/plist. Do not put stale scheduling config back.
    original_plist = next(x for x in receipt['files'] if x['path'] == spec['plist'])
    if metadata(spec['plist']) != {k: v for k, v in original_plist.items() if k not in ('copy', 'backup')}:
        fail('plist_changed_since_transition')
    original = next(x for x in receipt['files'] if x['path'] == spec['wrapper'])
    backup = canonical(archive / original['backup'])
    if archive not in backup.parents or digest(backup) != original['sha256']:
        fail('original_wrapper_backup_invalid')
    result = dict(status='rollback_planned', wrapper=str(wrapper),
        database_restore=False, new_observations_preserved=True, job_started=False)
    if execute is not True:
        return result
    with exclusive_collector_lock(spec) as lock:
        preflight(spec, probe=probe, now=now, own_lock=lock)
        _replace_exact(wrapper, current, backup.read_bytes(), original['mode'])
        if digest(wrapper) != original['sha256']:
            fail('rollback_verification_failed')
        _write_json(archive / ('rollback-' + uuid.uuid4().hex + '.json'),
            dict(status='rolled_back', at=datetime.now(timezone.utc).isoformat(), database_restore=False))
    return dict(result, status='rolled_back')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--spec', type=Path, help='Plan from a local JSON spec; stdout is the reviewable plan.')
    source.add_argument('--plan', type=Path, help='Validate a saved plan; execute only with --execute.')
    source.add_argument('--rollback', type=Path, help='Review reversal of a specific local archive.')
    parser.add_argument('--execute', action='store_true', help='Explicitly authorize the wrapper change only.')
    args = parser.parse_args(argv)
    try:
        if args.spec:
            if args.execute:
                fail('save_and_review_plan_before_execute')
            result = create_plan(json.loads(args.spec.read_text()))
        elif args.plan:
            result = execute_plan(json.loads(args.plan.read_text()), execute=args.execute)
        else:
            result = rollback(args.rollback, execute=args.execute)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (MigrationError, OSError, ValueError, KeyError, sqlite3.Error) as exc:
        reason = str(exc) if isinstance(exc, MigrationError) else 'migration_failed_no_automatic_retry'
        print(json.dumps(dict(status='refused_or_incomplete', reason=reason)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

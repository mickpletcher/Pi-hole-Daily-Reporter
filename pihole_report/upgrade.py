"""Reviewed, offline source swaps. Never starts a job or restores a database.

An interrupted operation is intentionally not retryable: inspect its durable receipt
and package/manifest hashes. Rollback defers EVERY recorded date to the next day.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime
import json
import os
from pathlib import Path
import stat
import uuid
from . import migration as m

SCHEMA = 'pihole-source-upgrade.v1'


def package_hashes(path):
    path = m.canonical(path)
    if not path.is_dir():
        m.fail('package_missing')
    result = {}
    for p in sorted(path.iterdir()):
        if p.name == '__pycache__' and p.is_dir() and not p.is_symlink():
            continue  # Never copied; interpreter caches are not deployed sources.
        info = m.metadata(p)
        if p.suffix != '.py' or info['uid'] != os.getuid():
            m.fail('only_owned_regular_python_sources_allowed')
        result[p.name] = info['sha256']
    if 'production.py' not in result or '__init__.py' not in result:
        m.fail('incomplete_package')
    return result


def private_json(path):
    info = m.metadata(path)
    if info['uid'] != os.getuid() or info['mode'] not in (0o400, 0o600) or info['size'] > 16*1024*1024:
        m.fail('private_json_required')
    return json.loads(Path(path).read_text())


def marker(spec):
    return Path(spec['project']) / 'state/production/source-operation.json'


def ledger_path(spec):
    return Path(spec['project']) / 'state/production/delivery-state.json'


def guarded_probe(spec, schedule):
    # Include detached backup workers, even if their parent runner already died.
    previous = m.PROCESS_NAMES
    try:
        m.PROCESS_NAMES = previous | {'pihole_report.delivery', '--backup-worker'}
        return m.system_probe(spec, schedule)
    finally:
        m.PROCESS_NAMES = previous


def worker_guard(spec):
    path = ledger_path(spec)
    if not path.exists():
        return
    state = private_json(path)
    for entry in state.get('dates', {}).values():
        for backup in (entry.get('stages', {}).get('backup', {}), entry.get('csv', {})):
            pid = backup.get('worker_pid')
            if isinstance(pid, int) and pid > 0:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    m.fail('possible_backup_worker_alive')
                else:
                    m.fail('possible_backup_worker_alive')
            if backup.get('status') in ('reserved', 'uncertain', 'preparing', 'running'):
                m.fail('backup_outcome_requires_inspection')


def baseline(spec):
    return {key: m.metadata(spec[key]) for key in ('wrapper', 'plist', 'manifest')}


def validate_scope(spec):
    # Exact real paths and installed code validation, independent of this staged module.
    from . import production
    from .deployment import load_deployment
    deployment = load_deployment()
    approved = deployment['scheduler']
    if any(spec[key] != approved[key] for key in ('project','manifest','database','wrapper','plist','python')):
        m.fail('exact_production_scope_required')
    expected = deployment['scope']
    manifest = private_json(spec['manifest'])
    if (set(manifest) != {'schema','enabled','scope','refresh_lists','code_sha256'}
            or manifest.get('schema') != 'pihole-production.v1'
            or type(manifest.get('refresh_lists')) is not bool
            or manifest.get('scope') != expected):
        m.fail('exact_manifest_scope_required')


def create_plan(spec, candidate, *, probe=guarded_probe, now=None):
    spec = m.normalize_spec(spec)
    validate_scope(spec)
    return _plan(spec, candidate, probe=probe, now=now)


def _plan(spec, candidate, *, probe, now=None):
    now = now or datetime.now().astimezone()
    if marker(spec).exists() or marker(spec).is_symlink():
        m.fail('prior_operation_requires_inspection')
    m.preflight(spec, probe=probe, now=now)
    worker_guard(spec)
    current = package_hashes(Path(spec['project'])/'pihole_report')
    manifest = private_json(spec['manifest'])
    if (manifest.get('schema') != 'pihole-production.v1' or manifest.get('enabled') is not True
            or manifest.get('code_sha256') != current):
        m.fail('installed_manifest_code_mismatch')
    candidate = m.canonical(candidate)
    new = package_hashes(candidate)
    updated = dict(manifest, code_sha256=new)
    return dict(schema=SCHEMA, created_at=now.isoformat(), spec=spec, candidate=str(candidate),
        old_hashes=current, new_hashes=new, old_manifest=manifest, new_manifest=updated,
        baseline=baseline(spec), schedule=m.settings(spec))


def check(plan, *, probe, now=None, own_lock=None):
    if plan.get('schema') != SCHEMA:
        m.fail('invalid_upgrade_plan')
    spec = m.normalize_spec(plan['spec'])
    validate_scope(spec)
    now = now or datetime.now().astimezone()
    age = (now-datetime.fromisoformat(plan['created_at'])).total_seconds()
    if not 0 <= age <= 1800:
        m.fail('plan_expired')
    if marker(spec).exists() or marker(spec).is_symlink():
        m.fail('prior_operation_requires_inspection')
    m.preflight(spec, probe=probe, now=now, own_lock=own_lock)
    worker_guard(spec)
    if (baseline(spec) != plan['baseline'] or m.settings(spec) != plan['schedule']
            or package_hashes(Path(spec['project'])/'pihole_report') != plan['old_hashes']
            or package_hashes(plan['candidate']) != plan['new_hashes']
            or private_json(spec['manifest']) != plan['old_manifest']
            or dict(plan['old_manifest'], code_sha256=plan['new_hashes']) != plan['new_manifest']):
        m.fail('reviewed_plan_changed')
    return spec


def copy_package(source, target, hashes):
    target.mkdir(mode=0o700)
    for name, digest in hashes.items():
        if Path(name).name != name or not name.endswith('.py'):
            m.fail('invalid_source_name')
        m._write_new(target/name, (Path(source)/name).read_bytes())
    if package_hashes(target) != hashes:
        m.fail('source_changed_during_archive')


def project_ledger(state):
    if state.get('schema') == 'pihole-delivery-state.v1':
        return copy.deepcopy(state)
    if state.get('schema') != 'pihole-delivery-state.v2' or not isinstance(state.get('dates'), dict):
        m.fail('unknown_ledger_schema')
    result = dict(schema='pihole-delivery-state.v1', legacy_baseline_initialized=True, dates={})
    for date, entry in state['dates'].items():
        if not isinstance(entry, dict) or not isinstance(entry.get('stages', {}).get('email'), dict):
            m.fail('invalid_stage_ledger')
        result['dates'][date] = dict(status='rollback_held', original_email_status=entry['stages']['email'].get('status'),
            reason='Source rollback: defer this recorded date; never automatically resend.')
    if len(json.dumps(result,indent=2).encode()) >= 1024*1024:
        m.fail('projected_ledger_exceeds_legacy_limit')
    return result


def execute_plan(plan, *, execute=False, probe=guarded_probe, now=None):
    spec = check(plan, probe=probe, now=now)
    if execute is not True:
        return dict(status='planned', plan=plan)
    with m.exclusive_collector_lock(spec) as lock:
        check(plan, probe=probe, now=now, own_lock=lock)
        root = Path(spec['backup_root'])
        m._owner_directory(root)
        archive = root / ('source-'+uuid.uuid4().hex)
        archive.mkdir(mode=0o700)
        m._sync_directory(root)
        # Prepare same-filesystem rename input; archives remain independently intact.
        package = Path(spec['project'])/'pihole_report'
        staged = package.parent / ('.source-ready-'+uuid.uuid4().hex)
        copy_package(package, archive/'old-package', plan['old_hashes'])
        copy_package(plan['candidate'], archive/'candidate-package', plan['new_hashes'])
        copy_package(archive/'candidate-package', staged, plan['new_hashes'])
        m._write_json(archive/'plan.json', plan)
        m._write_new(archive/'old-manifest.json', Path(spec['manifest']).read_bytes())
        m._write_json(archive/'new-manifest.json', plan['new_manifest'])
        m._write_json(archive/'receipt.json', dict(schema=SCHEMA, status='prepared', plan=plan))
        m._write_json(marker(spec), dict(archive=str(archive), status='incomplete'))
        # Disable first; interrupted swaps cannot execute against either package.
        m._replace_exact(Path(spec['manifest']), plan['baseline']['manifest'],
            (json.dumps(dict(plan['old_manifest'], enabled=False))+'\n').encode(), 0o600)
        disabled_manifest = m.metadata(spec['manifest'])
        displaced = package.parent / ('.source-displaced-'+uuid.uuid4().hex)
        os.rename(package, displaced)
        m._sync_directory(package.parent)
        os.rename(staged, package)
        m._sync_directory(package.parent)
        m._replace_exact(Path(spec['manifest']), disabled_manifest,
            (json.dumps(plan['new_manifest'], indent=2)+'\n').encode(), 0o600)
        if package_hashes(package) != plan['new_hashes']:
            m.fail('post_swap_hash_mismatch')
        m._write_json(archive/'completed.json', dict(status='upgraded', displaced=str(displaced)))
        marker(spec).unlink()
        m._sync_directory(marker(spec).parent)
    return dict(status='upgraded', archive=str(archive), database_changed=False, job_started=False)


def rollback(archive, *, execute=False, probe=guarded_probe, now=None):
    archive = m.canonical(archive)
    receipt = private_json(archive/'receipt.json')
    plan = receipt['plan']; spec = m.normalize_spec(plan['spec'])
    validate_scope(spec)
    if receipt.get('schema') != SCHEMA or archive.parent != Path(spec['backup_root']):
        m.fail('invalid_archive')
    if not (archive/'completed.json').exists() or marker(spec).exists():
        m.fail('incomplete_operation_requires_inspection')
    def validate(own_lock=None):
        m.preflight(spec, probe=probe, now=now, own_lock=own_lock)
        worker_guard(spec)
        if (package_hashes(Path(spec['project'])/'pihole_report') != plan['new_hashes']
                or private_json(spec['manifest']) != plan['new_manifest']
                or package_hashes(archive/'old-package') != plan['old_hashes']
                or private_json(archive/'old-manifest.json') != plan['old_manifest']
                or any(m.metadata(spec[k]) != plan['baseline'][k] for k in ('wrapper','plist'))):
            m.fail('rollback_baseline_changed')
    validate()
    if execute is not True:
        return dict(status='rollback_planned', recorded_dates_deferred=True, database_restore=False)
    with m.exclusive_collector_lock(spec) as lock:
        validate(lock)
        attempt = archive / ('rollback-'+uuid.uuid4().hex)
        attempt.mkdir(mode=0o700)
        statepath = ledger_path(spec)
        state_info = m.metadata(statepath) if statepath.exists() else None
        if state_info:
            raw = statepath.read_bytes()
            state = private_json(statepath)
            m._write_new(attempt/'latest-ledger.json', raw)
            projected = project_ledger(state)
            m._write_json(attempt/'projected-ledger.json', projected)
        package = Path(spec['project'])/'pihole_report'
        staged = package.parent / ('.source-rollback-'+uuid.uuid4().hex)
        copy_package(archive/'old-package', staged, plan['old_hashes'])
        m._write_json(attempt/'receipt.json', dict(status='prepared', schema=SCHEMA, database_restore=False))
        m._write_json(marker(spec), dict(status='rollback_incomplete', archive=str(attempt)))
        m._replace_exact(Path(spec['manifest']), m.metadata(spec['manifest']),
            (json.dumps(dict(plan['new_manifest'], enabled=False))+'\n').encode(),0o600)
        if state_info and projected != state:
            m._replace_exact(statepath, state_info, (json.dumps(projected,indent=2)+'\n').encode(),0o600)
        current_manifest = m.metadata(spec['manifest'])
        displaced = package.parent/('.source-rollback-displaced-'+uuid.uuid4().hex)
        os.rename(package, displaced); m._sync_directory(package.parent)
        os.rename(staged, package); m._sync_directory(package.parent)
        m._write_json(attempt/'completed.json',dict(status='rollback_prepared',displaced=str(displaced)))
        m._replace_exact(Path(spec['manifest']), current_manifest, (archive/'old-manifest.json').read_bytes(),0o600)
        m._write_json(attempt/'enabled.json',dict(status='rolled_back'))
        marker(spec).unlink(); m._sync_directory(marker(spec).parent)
    return dict(status='rolled_back', archive=str(attempt), recorded_dates_deferred=True, database_restore=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--spec',type=Path); group.add_argument('--plan',type=Path); group.add_argument('--rollback',type=Path)
    p.add_argument('--candidate',type=Path); p.add_argument('--execute',action='store_true')
    args=p.parse_args(argv)
    try:
        if args.spec:
            if args.execute or not args.candidate: m.fail('save_reviewed_plan_first')
            result=create_plan(private_json(args.spec),args.candidate)
        elif args.plan: result=execute_plan(private_json(args.plan),execute=args.execute)
        else: result=rollback(args.rollback,execute=args.execute)
        print(json.dumps(result,indent=2)); return 0
    except (ValueError,OSError,KeyError,TypeError):
        print(json.dumps(dict(status='refused_or_incomplete',reason='inspect_receipt_and_current_hashes_before_any_retry')))
        return 1

if __name__=='__main__': raise SystemExit(main())

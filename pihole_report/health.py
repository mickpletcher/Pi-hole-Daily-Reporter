"""Local data-quality summaries. No network requests, model calls or writes."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import math
import os
import re
from pathlib import Path
import stat
import time

from .coverage import run_coverage, window_coverage

SCHEMA = 'pihole-data-health.v1'


def timestamp(value):
    if type(value) in (int, float) and math.isfinite(value):
        return float(value)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is not None:
            return parsed.timestamp()
    raise ValueError('A finite timestamp with an explicit timezone is required')


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def freshness(value, now, threshold):
    try:
        moment = timestamp(value)
        rendered = iso(moment)
    except (ValueError, TypeError, OverflowError):
        return {'status': 'unavailable', 'last_success_at': None, 'age_seconds': None,
                'stale_after_seconds': threshold}
    age = now - moment
    status = 'clock_skew' if age < -300 else 'stale' if age > threshold else 'recent'
    return {'status': status, 'last_success_at': rendered, 'age_seconds': round(age, 3),
            'stale_after_seconds': threshold}


def read_json(path, limit=4*1024*1024):
    """Bounded regular-file read; never wait on a FIFO or follow a link."""
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('Linked health input refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Invalid health input')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('Health input exceeds size limit')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Health object required')
        return result


def data_health(db, root, totals, *, latest_run, import_succeeded, inventory,
                inventory_refresh_attempted, api_scope, attribution=(), now=None):
    """Distinguish collection success, time coverage, filtering, and freshness."""
    now = time.time() if now is None else timestamp(now)
    start = timestamp(totals['window_start'])
    end = timestamp(totals['window_end_exclusive'])
    # The collector deliberately lags five minutes behind the rolling snapshot.
    mature_end = min(end, max(start, math.floor(now - 300)))
    mature = window_coverage(db, totals['site'], start, mature_end)
    whole = window_coverage(db, totals['site'], start, end)
    latest = run_coverage(db, latest_run['id']) if latest_run else None
    inv = freshness(inventory.get('generatedAt'), now, 36*3600)
    inv['mode'] = 'refresh-attempted' if inventory_refresh_attempted else 'cached; refresh not attempted'
    inv['client_count'] = len(inventory.get('clients', []))
    try:
        state = read_json(Path(root)/'config/curated-list-state.json')
    except (OSError, ValueError, RecursionError):
        state = {}
    revision = state.get('commit')
    from .report import FILES
    selected = (isinstance(revision, str) and re.fullmatch('[a-f0-9]{40}', revision)
                and all((Path(root)/'config/list-snapshots'/revision/name).is_file() for name in FILES))
    lists = freshness(state.get('checked_at') if selected else None, now, 48*3600)
    lists['validated_selection_present'] = bool(selected)
    lists['revision'] = state.get('commit') if isinstance(state.get('commit'), str) else None
    lists['last_refresh_failed'] = bool(state.get('last_error'))
    if lists['last_refresh_failed']:
        lists['status'] = 'refresh_failed'
    scope = dict(api_scope or {'status': 'unavailable'})
    # Missing config is not proof the API exposed every recorded query.
    domain_filters = scope.get('exclude_domains')
    client_filters = scope.get('exclude_clients')
    privacy = scope.get('privacy_level')
    verified = (scope.get('status') == 'verified' and isinstance(domain_filters, list)
                and isinstance(client_filters, list) and type(privacy) is int and 0 <= privacy <= 3)
    filter_status = ('filtered' if domain_filters or client_filters or privacy != 0 else 'no_configured_exclusions') if verified else 'unverified'
    scope['filter_status'] = filter_status
    scope['network_completeness'] = 'not established; only queries recorded and exposed by this Pi-hole'
    warnings = []
    if not import_succeeded:
        warnings.append('Detailed collection failed; cumulative history was not advanced by this attempt.')
    if mature['gaps']:
        warnings.append('Detailed history has uncovered intervals before the intentional five-minute collection delay.')
    if latest and latest.get('temporal_status') == 'unknown':
        warnings.append('The API did not establish its oldest retained timestamp; collection coverage is unverified.')
    if filter_status == 'filtered':
        warnings.append('Pi-hole API exclusions or privacy settings limit the visible data; totals describe that scope.')
    elif filter_status == 'unverified':
        warnings.append('Pi-hole API exclusion and privacy scope could not be fully verified.')
    if inv['status'] != 'recent':
        warnings.append('UniFi inventory is '+inv['status'].replace('_',' ')+'; device mappings are not current evidence.')
    if lists['status'] != 'recent':
        warnings.append('Curated-list freshness is '+lists['status'].replace('_',' ')+'.')
    samples = list(attribution)
    # One domain response can supply two state rows. Count shared response
    # diagnostics once per hostname, and state-specific invalid clients once.
    unique = {}
    states = {}
    for row in samples:
        name = str(row.get('domain', '')).lower().removesuffix('.')
        unique.setdefault(name, row)
        states.setdefault((name, row.get('state')), row)
    excluded = sum(int(r.get('excluded_queries', 0) or 0) for r in unique.values())
    invalid = sum(int(r.get('invalid_client_queries', 0) or 0) for r in states.values())
    unknown = sum(int(r.get('unknown_status_queries', 0) or 0) for r in unique.values())
    unavailable = sum(r.get('sample_status') == 'unavailable' for r in unique.values())
    if unavailable:
        warnings.append('Client attribution samples were unavailable for '+str(unavailable)+' hostname(s).')
    return {'schema': SCHEMA, 'evaluated_at': iso(now), 'status': 'limited' if warnings else 'healthy',
            'snapshot_id': totals.get('snapshot_id'), 'window_start': iso(start), 'window_end_exclusive': iso(end),
            'collection_import_succeeded': import_succeeded, 'latest_import': latest,
            'mature_history_coverage': mature, 'full_report_history_coverage': whole,
            'intentional_recent_delay_seconds': end-mature_end, 'api_scope': scope,
            'inventory': inv, 'curated_lists': lists,
            'attribution': {'rows': len(samples), 'sampled_not_complete': True,
                            'sampled_hostnames': len(unique), 'unavailable_samples': unavailable,
                            'invalid_client_records': invalid, 'excluded_records': excluded,
                            'unknown_status_records': unknown},
            'warnings': warnings, 'hosted_calls': 0}


def _age(value):
    age = value.get('age_seconds')
    return 'age unknown' if age is None else f'{max(age,0)/3600:.1f} hours old'


def render_data_health(health):
    mature = health['mature_history_coverage']
    needed = mature['requested_seconds']
    covered = mature['covered_seconds']
    lines = ['## Operational health and data coverage', '',
             '- Detailed collection: '+('available records imported' if health['collection_import_succeeded'] else 'failed; previous history retained')+'.',
             f'- Detailed history covers {covered:.0f} of {needed:.0f} mature window seconds; {len(mature["gaps"])} uncovered interval(s).',
             f'- Latest {health["intentional_recent_delay_seconds"]:.0f} seconds are intentionally deferred by the detailed collector; rolling totals have a separate window.',
             '- Pi-hole data scope: '+health['api_scope']['filter_status'].replace('_',' ')+'. Counts are not proof of all network activity.',
             '- UniFi inventory: '+health['inventory']['mode']+', '+_age(health['inventory'])+'; '+health['inventory']['status']+'.',
             '- Curated lists: '+_age(health['curated_lists'])+'; '+health['curated_lists']['status']+'.',
             '- Client attribution uses status-filtered samples, not complete device traffic totals.']
    for gap in mature['gaps'][:8]:
        lines.append('  - Uncovered: '+iso(gap['from_time'])+' through '+iso(gap['until_time'])+' (end exclusive).')
    if len(mature['gaps']) > 8:
        lines.append('  - Additional intervals are recorded in the local run log.')
    for warning in health['warnings']:
        lines.append('- Notice: '+warning)
    lines.extend(['', 'Email and backup outcomes are recorded after generation in the local operational health summary.', ''])
    return '\n'.join(lines)+'\n'


def read_operational_health(project, now=None):
    """Read only. No credential access, provider probes, cleanup or retries."""
    now = time.time() if now is None else timestamp(now)
    path = Path(project)/'state/production/current-health.json'
    try:
        result = read_json(path)
        if result.get('schema') != 'pihole-operational-health.v1':
            raise ValueError('Unrecognized health schema')
    except FileNotFoundError:
        return {'status': 'unavailable', 'message': 'No operational health snapshot has been recorded by this version.', 'network_calls': 0}
    except (OSError, ValueError, RecursionError):
        return {'status': 'unavailable', 'message': 'Operational health snapshot is unreadable or invalid.', 'network_calls': 0}
    updated = result.get('updated_at', result.get('updated_at_epoch'))
    result = dict(result)
    result['health_file_freshness'] = freshness(updated, now, 36*3600)
    result['network_calls'] = 0
    return result


def health_text(result):
    if result.get('status') == 'unavailable':
        return result['message']
    lines = ['Pi-hole operational health: '+str(result.get('status','unknown')),
             'Report date: '+str(result.get('local_date','unknown'))]
    for name, value in (result.get('stages') or {}).items():
        status = value.get('status','unknown') if isinstance(value,dict) else str(value)
        lines.append(name.replace('_',' ').capitalize()+': '+status)
    fresh = result.get('health_file_freshness', {})
    lines.append('Health record: '+_age(fresh)+'; '+fresh.get('status','unknown'))
    if result.get('status') == 'running' and fresh.get('age_seconds') is not None and fresh['age_seconds'] > 1200:
        lines.append('Notice: no stage update for more than 20 minutes; inspect the existing process before retrying.')
    if isinstance(result.get('data_health'),dict):
        for warning in result['data_health'].get('warnings',[]):
            lines.append('Notice: '+warning)
    lines.append('Read-only check; no network requests or model calls.')
    return '\n'.join(lines)

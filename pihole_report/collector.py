"""Atomic incremental Pi-hole collection with an explicitly injected transport."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import time
from urllib.parse import urlencode
import uuid

from .storage import aggregate_mode, ingest_queries, transaction
from .coverage import window_coverage

class CollectionError(ValueError):
    """Known, credential-free validation failure safe to persist."""

@contextmanager
def collector_lock(db):
    """Coordinate with the existing Node collector's PID/token lock format."""
    file = next((r[2] for r in db.execute('PRAGMA database_list') if r[1] == 'main'), '')
    if not file:
        yield
        return
    lock = Path(file+'.collector-lock'); token = str(uuid.uuid4())
    acquired = False
    for attempt in range(2):
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                owner = json.loads(lock.read_text())
            except (ValueError, OSError) as exc:
                raise RuntimeError('Collector lock requires manual inspection') from exc
            pid = owner.get('pid')
            if type(pid) is not int or pid < 1:
                raise RuntimeError('Invalid collector lock')
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                if attempt == 0:
                    # Check that the stale file was not replaced before removal.
                    if json.loads(lock.read_text()).get('token') != owner.get('token'):
                        raise RuntimeError('Collector lock changed; retry later')
                    lock.unlink()
            else:
                raise RuntimeError('History database is in use by another collector/migration')
        else:
            with os.fdopen(fd, 'w') as handle:
                json.dump({'pid': os.getpid(), 'token': token, 'created': datetime.now(timezone.utc).isoformat()}, handle)
            acquired = True
            break
    if not acquired:
        raise RuntimeError('Unable to acquire collector lock')
    try:
        yield
    finally:
        try:
            if json.loads(lock.read_text()).get('token') == token:
                lock.unlink()
        except (ValueError, OSError):
            pass

def collect(db, site, base, transport, password, now=None):
    """Transport accepts (base, route, method, payload, sid); never log its payload."""
    with collector_lock(db):
        return _collect(db, site, base, transport, password, time.time() if now is None else now)

def _collect(db, site, base, transport, password, now):
    previous = db.execute('SELECT * FROM sources WHERE site=?', (site,)).fetchone()
    until = math.floor(now-300)
    start = previous['last_complete_until'] if previous and previous['last_complete_until'] is not None else until-86400
    if until <= start:
        return 0
    run = db.execute('INSERT INTO runs(site,started,from_time,until_time,status) VALUES(?,?,?,?,?)', (site, now, start, until, 'running')).lastrowid
    sid = None
    try:
        if previous and previous['endpoint'] != base:
            raise CollectionError('Source endpoint changed; explicit migration required')
        auth = transport(base, '/api/auth', 'POST', {'password': password}, None)
        sid = auth.get('session', {}).get('sid')
        if not sid:
            raise CollectionError('API authentication failed')
        cursor = None; total = 0; received = 0; earliest = None; expected = None
        with transaction(db):
            # A connection may have retried after a failed window: TEMP data must
            # not carry successful uncommitted identities into a new window.
            if aggregate_mode(db):
                db.execute('CREATE TEMP TABLE IF NOT EXISTS aggregate_event_stage(event_key TEXT PRIMARY KEY,outcome TEXT NOT NULL)')
                db.execute('DELETE FROM temp.aggregate_event_stage')
            for page in range(2000):
                params = {'disk':'true', 'from':str(start), 'until':str(until), 'length':'10000'}
                if cursor is not None:
                    params['cursor'] = str(cursor)
                result = transport(base, '/api/queries?'+urlencode(params), 'GET', None, sid)
                queries = result.get('queries')
                if not isinstance(queries, list):
                    raise CollectionError('Missing queries')
                disk_start = result.get('earliest_timestamp_disk')
                if type(disk_start) in (int, float) and math.isfinite(disk_start) and disk_start > 0:
                    earliest = max(earliest or disk_start, disk_start)
                if expected is None:
                    expected = result.get('recordsFiltered')
                    if type(expected) is not int or not 0 <= expected <= 2**53-1:
                        raise CollectionError('Missing filtered query count')
                if not queries:
                    break
                prior = math.inf if cursor is None else cursor+1
                for query in queries:
                    ident = query.get('id')
                    if type(ident) is not int or not 0 <= ident <= 2**53-1 or ident >= prior:
                        raise CollectionError('Query IDs are not strictly descending')
                    prior = ident
                received += len(queries)
                if received > expected:
                    raise CollectionError('Query window exceeds filtered count')
                total += ingest_queries(db, site, queries, start, until)
                cursor = prior-1
                if cursor < 0:
                    break
            else:
                raise CollectionError('Pagination limit reached')
            if received != expected:
                raise CollectionError(f'Incomplete query window: received {received} of {expected}')
            db.execute('''INSERT INTO sources VALUES(?,?,?,?) ON CONFLICT(site) DO UPDATE SET
                earliest_available=excluded.earliest_available,
                last_complete_until=max(coalesce(sources.last_complete_until,excluded.last_complete_until),excluded.last_complete_until)''', (site, base, earliest, until))
            # A successful fetch advances the attempted highwater, not a claim
            # that expired or API-excluded history was recovered. A missing
            # disk bound cannot establish even an empty window's coverage.
            coverage_start = max(start, earliest) if earliest is not None else until
            if coverage_start < until:
                db.execute('INSERT OR REPLACE INTO coverage VALUES(?,?,?,?)', (site, coverage_start, until, run))
            evidence = window_coverage(db, site, start, until)
            if earliest is None and evidence['gaps']:
                evidence['temporal_status'] = 'unknown'
            evidence.update({'fetch_status': 'complete', 'retention_cutoff': earliest,
                             'api_filter_completeness': 'unknown',
                             'received_queries': received, 'newly_stored_queries': total,
                             'evidence': 'successful pagination and retained coverage intervals'})
            db.execute('INSERT INTO metadata(key,value) VALUES(?,?)',
                       ('collection_coverage:'+str(run), json.dumps(evidence, sort_keys=True)))
            db.execute('UPDATE runs SET finished=?,status=?,query_count=? WHERE id=?',
                       (time.time(), evidence['temporal_status'], total, run))
            if aggregate_mode(db):
                db.execute('DELETE FROM temp.aggregate_event_stage')
            else:
                db.execute('DELETE FROM events WHERE time<?', (until-35*86400,))
        return total
    except Exception as exc:
        # Avoid recording provider exceptions which could echo an auth payload.
        message = str(exc)[:200] if isinstance(exc, CollectionError) else 'Collection transport or database failure; no window committed'
        db.execute('UPDATE runs SET finished=?,status=?,error=? WHERE id=?', (time.time(), 'failed', message, run))
        raise
    finally:
        if sid:
            try:
                transport(base, '/api/auth', 'DELETE', None, sid)
            except Exception:
                pass

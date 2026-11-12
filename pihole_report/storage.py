"""Compatible local SQLite persistence; no network access or credentials."""
SCHEMA = """BEGIN IMMEDIATE;
 CREATE TABLE domains(domain TEXT PRIMARY KEY,first_observed REAL NOT NULL,last_observed REAL NOT NULL,observation_precision TEXT NOT NULL);
 CREATE TABLE sources(site TEXT PRIMARY KEY,endpoint TEXT NOT NULL,earliest_available REAL,last_complete_until REAL);
 CREATE TABLE runs(id INTEGER PRIMARY KEY,site TEXT NOT NULL,started REAL NOT NULL,finished REAL,from_time REAL,until_time REAL,status TEXT NOT NULL,query_count INTEGER DEFAULT 0,error TEXT);
 CREATE TABLE events(event_key TEXT PRIMARY KEY,site TEXT NOT NULL,source_id INTEGER NOT NULL,time REAL NOT NULL,domain TEXT NOT NULL REFERENCES domains(domain),client_ip TEXT NOT NULL,status TEXT NOT NULL,outcome TEXT NOT NULL,query_type TEXT NOT NULL);
 CREATE INDEX events_time ON events(time);
 CREATE TABLE daily(site TEXT NOT NULL,day TEXT NOT NULL,domain TEXT NOT NULL REFERENCES domains(domain),client_ip TEXT NOT NULL,outcome TEXT NOT NULL,queries INTEGER NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL,PRIMARY KEY(site,day,domain,client_ip,outcome));
 CREATE TABLE coverage(site TEXT NOT NULL,from_time REAL NOT NULL,until_time REAL NOT NULL,run_id INTEGER NOT NULL REFERENCES runs(id),PRIMARY KEY(site,from_time,until_time));
 CREATE TABLE devices(site TEXT NOT NULL,client_ip TEXT NOT NULL,name TEXT,mac TEXT,inventory_observed REAL NOT NULL,provenance TEXT NOT NULL,PRIMARY KEY(site,client_ip,inventory_observed));
 CREATE TABLE snapshots(id TEXT PRIMARY KEY,site TEXT NOT NULL,from_time REAL NOT NULL,until_time REAL NOT NULL,provenance TEXT NOT NULL,precision TEXT NOT NULL);
 CREATE TABLE snapshot_counts(snapshot_id TEXT NOT NULL REFERENCES snapshots(id),domain TEXT NOT NULL REFERENCES domains(domain),outcome TEXT NOT NULL,queries INTEGER NOT NULL,PRIMARY KEY(snapshot_id,domain,outcome));
 CREATE TABLE assessments(domain TEXT NOT NULL REFERENCES domains(domain),evidence_key TEXT NOT NULL,observed REAL NOT NULL,provenance TEXT NOT NULL,evidence TEXT NOT NULL,confidence REAL,breakage_risk TEXT NOT NULL DEFAULT 'unknown',recommendation TEXT NOT NULL,research_status TEXT NOT NULL DEFAULT 'unresearched',PRIMARY KEY(domain,evidence_key));
 CREATE TABLE research(id TEXT PRIMARY KEY,domain TEXT NOT NULL REFERENCES domains(domain),service TEXT,purpose TEXT,category TEXT,source_url TEXT,evidence_summary TEXT NOT NULL,researched_at REAL NOT NULL,confidence REAL CHECK(confidence BETWEEN 0 AND 1),breakage_risk TEXT NOT NULL CHECK(breakage_risk IN ('unknown','low','medium','high')),risk_rationale TEXT,recommendation TEXT NOT NULL,provenance TEXT NOT NULL);
 CREATE TABLE decisions(id TEXT PRIMARY KEY,domain TEXT NOT NULL REFERENCES domains(domain),decision TEXT NOT NULL,note TEXT,decided_at TEXT,imported REAL NOT NULL,provenance TEXT NOT NULL);
 CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 PRAGMA user_version=1; COMMIT;"""

import csv
import hashlib
import json
import math
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import time

BLOCK = frozenset('GRAVITY REGEX DENYLIST EXTERNAL_BLOCKED_IP EXTERNAL_BLOCKED_NULL EXTERNAL_BLOCKED_NXRA GRAVITY_CNAME REGEX_CNAME DENYLIST_CNAME SPECIAL_DOMAIN'.split())
ALLOW = frozenset('FORWARDED CACHE RETRIED RETRIED_DNSSEC CACHE_STALE'.split())

def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def js_json(value):
    # Match JSON.stringify's integer representation for legacy event/decision keys.
    def numbers(v):
        if isinstance(v, float) and v.is_integer():
            return int(v)
        if isinstance(v, list):
            return [numbers(x) for x in v]
        return v
    return json.dumps(numbers(value), ensure_ascii=False, separators=(',', ':'))

def normalize(value):
    value = str(value)
    return value if value == '.' else value.lower().removesuffix('.')

def connect(path, read_only=False):
    path = Path(path).expanduser().resolve()
    if not read_only and any(x in str(path).lower() for x in ('cloudstorage', 'onedrive')):
        raise ValueError('Active database must be outside synced storage')
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, isolation_level=None) if read_only else sqlite3.connect(path, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA temp_store=MEMORY')
        if not read_only:
            os.chmod(path, 0o600)
            db.execute('PRAGMA journal_mode=WAL')
            initialize(db)
        elif db.execute('PRAGMA user_version').fetchone()[0] > 2:
            raise ValueError('Database schema is newer than this program')
        return db
    except Exception:
        db.close()
        raise

def initialize(db):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version > 2:
        raise ValueError('Database schema is newer than this program')
    if version == 0:
        db.executescript(SCHEMA)
    # Screening migrations belong to screening.py. Existing schema 2 is untouched.

@contextmanager
def transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield db
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise

def domain(db, name, first, last, precision):
    name = normalize(name)
    if not name or len(name) > 253 or re.search(r'[\s|\x00-\x1f]', name):
        raise ValueError('Invalid domain')
    db.execute('''INSERT INTO domains VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET
        first_observed=min(first_observed,excluded.first_observed),
        last_observed=max(last_observed,excluded.last_observed),
        observation_precision=CASE WHEN observation_precision=excluded.observation_precision
        THEN observation_precision ELSE 'mixed' END''', (name, first, last, precision))
    return name

def aggregate_mode(db):
    row = db.execute("SELECT value FROM metadata WHERE key='storage_mode'").fetchone()
    return row is not None and row[0] == 'aggregate-first'

def ingest_queries(db, site, queries, from_time, until_time):
    """Call inside a transaction; complete-window publication is the caller's job."""
    aggregate = aggregate_mode(db)
    if aggregate:
        db.execute('CREATE TEMP TABLE IF NOT EXISTS aggregate_event_stage(event_key TEXT PRIMARY KEY,outcome TEXT NOT NULL)')
    table = 'temp.aggregate_event_stage' if aggregate else 'events'
    count = 0
    for q in queries:
        ident, stamp = q.get('id'), q.get('time')
        if (type(ident) is not int or abs(ident) > 2**53-1 or type(stamp) not in (int, float)
                or not math.isfinite(stamp) or not from_time <= stamp < until_time
                or not isinstance(q.get('client'), dict) or not q['client'].get('ip')
                or not isinstance(q.get('status'), str) or not isinstance(q.get('domain'), str)):
            raise ValueError('Malformed query record')
        name = domain(db, q['domain'], stamp, stamp, 'query_time')
        outcome = 'blocked' if q['status'] in BLOCK else 'allowed' if q['status'] in ALLOW else 'unknown'
        key = digest(js_json([site, ident, stamp, name, q['client']['ip'], q.get('type')]))
        old = db.execute('SELECT outcome FROM '+table+' WHERE event_key=?', (key,)).fetchone()
        if old:
            if old[0] != outcome:
                raise ValueError('Previously imported query changed status; reconciliation required')
            continue
        if db.execute('SELECT 1 FROM coverage WHERE site=? AND from_time<=? AND until_time>? LIMIT 1', (site, stamp, stamp)).fetchone():
            continue
        if aggregate:
            db.execute('INSERT INTO temp.aggregate_event_stage VALUES(?,?)', (key, outcome))
        else:
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)', (key, site, ident, stamp, name, q['client']['ip'], q['status'], outcome, str(q.get('type', 'undefined'))))
        day = datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%d')
        db.execute('''INSERT INTO daily VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(site,day,domain,client_ip,outcome)
            DO UPDATE SET queries=queries+1,first_seen=min(first_seen,excluded.first_seen),
            last_seen=max(last_seen,excluded.last_seen)''', (site, day, name, q['client']['ip'], outcome, stamp, stamp))
        count += 1
    return count

def parse_timestamp(text):
    """Read ISO timestamps and the legacy shell's explicit US zone labels."""
    text = text.strip()
    try:
        return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()
    except ValueError:
        pass
    try:
        return datetime.strptime(text, '%Y-%m-%d %H:%M:%S %z').timestamp()
    except ValueError:
        pass
    # %Z parses a name without setting tzinfo. Avoid silently shifting UTC
    # imports into the Mac's current local timezone (and ignoring DST labels).
    from datetime import timedelta
    offsets = {'UTC': 0, 'GMT': 0, 'EST': -5, 'EDT': -4, 'CST': -6,
               'CDT': -5, 'MST': -7, 'MDT': -6, 'PST': -8, 'PDT': -7}
    stamp, separator, zone = text.rpartition(' ')
    if separator and zone in offsets:
        try:
            parsed = datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
            return parsed.replace(tzinfo=timezone(timedelta(hours=offsets[zone]))).timestamp()
        except ValueError:
            pass
    raise ValueError('Unrecognized report timestamp')

def import_report(db, file, site='Primary'):
    raw = Path(file).read_text()
    generated = re.search(r'^Generated: (.+?)\s*$', raw, re.MULTILINE)
    if not generated:
        raise ValueError('Missing report timestamp')
    end = parse_timestamp(generated[1]); start = end - 86400; ident = digest(raw)
    if db.execute('SELECT 1 FROM snapshots WHERE id=?', (ident,)).fetchone():
        return 0
    count = 0
    with transaction(db):
        db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)', (ident, site, start, end, Path(file).name, 'rolling_24h; may overlap; not additive'))
        section = ''
        for line in raw.split('\n'):
            if line.startswith('## '):
                section = line
            match = re.match(r'^\| `([^`]+)` \| (\d+) \|(?: (\d+)/100 \| (.*?) \|)?$', line)
            if not match:
                continue
            name = domain(db, match[1], start, end, 'window_bound')
            if re.search(r'Complete (allowed|blocked)-domain', section):
                outcome = 'allowed' if 'allowed-domain' in section else 'blocked'
                db.execute('INSERT INTO snapshot_counts VALUES(?,?,?,?)', (ident, name, outcome, int(match[2])))
                count += 1
            elif 'Suggested' in section and match[4]:
                recommendation = 'review_block' if 'block candidates' in section else 'review_unblock'
                end_string = str(int(end)) if end.is_integer() else str(end)
                db.execute('INSERT OR IGNORE INTO assessments VALUES(?,?,?,?,?,?,?,?,?)', (name, digest(match[4]+end_string), end, 'legacy_report_heuristic', match[4], int(match[3])/100, 'unknown', recommendation, 'unresearched; legacy score is not calibrated confidence'))
    return count

def feedback(db, file):
    file = Path(file)
    if not file.exists():
        return
    with file.open(newline='') as handle:
        rows = list(csv.reader(handle, strict=True))
    with transaction(db):
        for row in rows[1:]:
            if not row or not row[0] or row[0].startswith('#'):
                continue
            if len(row) < 2 or row[1] not in ('allow', 'block', 'ignore', 'review'):
                raise ValueError('Invalid feedback decision')
            name = normalize(row[0]); now = time.time()
            if not db.execute('SELECT domain FROM domains WHERE domain=?', (name,)).fetchone():
                domain(db, name, now, now, 'decision_only')
            db.execute('INSERT OR IGNORE INTO decisions VALUES(?,?,?,?,?,?,?)', (digest(js_json(row)), name, row[1], row[2] if len(row)>2 else '', row[3] if len(row)>3 else '', now, file.name))

def inventory(db, file, site='Primary'):
    file = Path(file)
    if not file.exists():
        return
    data = json.loads(file.read_text()); stamp = file.stat().st_mtime
    with transaction(db):
        for client in data.get('clients', []):
            if client.get('ipAddress'):
                db.execute('INSERT OR IGNORE INTO devices VALUES(?,?,?,?,?,?)', (site, client['ipAddress'], client.get('name') or None, client.get('macAddress') or None, stamp, 'UniFi inventory snapshot; IP mapping only at snapshot time'))

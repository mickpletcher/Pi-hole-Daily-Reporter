"""Explicit, injectable integrations. No background research or email delivery.

Credentials are supplied by callers, never persisted or included in exceptions.
All network calls verify TLS and reject redirects (including same-origin ones).
"""
from __future__ import annotations
import collections
from contextlib import closing
import datetime as dt
import gzip
import http.client
import html
import ipaddress
import socket
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import format_datetime

from .storage import ALLOW, BLOCK, normalize

FILES = ('curated-blocklist-policy.txt', 'curated-blocklist-device.txt', 'curated-whitelist.txt')
MAX_BYTES = 16 * 1024 * 1024


def iso(timestamp):
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class IntegrationError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IntegrationError('redirect_refused')


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Use a specific TCP address while retaining the original TLS hostname."""
    def __init__(self, host, *, connect_address, expected_hostname, **kwargs):
        super().__init__(host, **kwargs)
        if self.host.lower() != expected_hostname.lower():
            raise IntegrationError('pinned_endpoint_origin_mismatch')

        def connect_socket(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
            if address[0].lower() != expected_hostname.lower() or self._tunnel_host:
                raise IntegrationError('pinned_endpoint_proxy_not_supported')
            return socket.create_connection((connect_address, address[1]), timeout, source_address)

        # HTTPSConnection still performs its own wrap_socket call with
        # server_hostname=self.host and the supplied verified SSLContext.
        self._create_connection = connect_socket


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context, connect_address, expected_hostname):
        super().__init__(context=context)
        self.connect_address = connect_address
        self.expected_hostname = expected_hostname

    def https_open(self, request):
        def connection(host, **kwargs):
            return _PinnedHTTPSConnection(
                host, connect_address=self.connect_address,
                expected_hostname=self.expected_hostname, **kwargs,
            )
        return self.do_open(connection, request, context=self._context,
                            check_hostname=self._check_hostname)


class HTTPSClient:
    def __init__(self, ca_file=None, timeout=60, max_bytes=32_000_000, get_retries=2,
                 connect_address=None, expected_hostname=None):
        if type(get_retries) is not int or not 0 <= get_retries <= 3:
            raise ValueError("GET retries must be between zero and three")
        if (connect_address is None) != (expected_hostname is None):
            raise ValueError("Pinned connections require an IP address and TLS hostname")
        if connect_address is not None:
            ipaddress.ip_address(connect_address)
            if not expected_hostname or re.search(r'[\s/:]', expected_hostname):
                raise ValueError("Invalid expected TLS hostname")
        self.connect_address = connect_address
        self.expected_hostname = expected_hostname
        self.get_retries = get_retries
        self.context = ssl.create_default_context(cafile=ca_file)
        self.timeout, self.max_bytes = timeout, max_bytes
        handler = (_PinnedHTTPSHandler(self.context, connect_address, expected_hostname)
                   if connect_address else urllib.request.HTTPSHandler(context=self.context))
        self.opener = urllib.request.build_opener(_NoRedirect(), handler)

    def get_bytes(self, url, headers=None, max_bytes=None):
        return self._request(url, 'GET', None, headers or {}, max_bytes or self.max_bytes)

    def _request(self, url, method, payload, headers, limit):
        u = urllib.parse.urlsplit(url)
        if u.scheme != 'https' or not u.hostname or u.username or u.password:
            raise IntegrationError('https_origin_required')
        if self.connect_address:
            if u.hostname.lower() != self.expected_hostname.lower():
                raise IntegrationError('pinned_endpoint_origin_mismatch')
            proxies = urllib.request.getproxies()
            if (proxies.get('https') or proxies.get('all')) and not urllib.request.proxy_bypass(u.hostname):
                raise IntegrationError('pinned_endpoint_proxy_not_supported')
        attempts = 1 + self.get_retries if method == 'GET' else 1
        transient = {'transport_timeout', 'transport_connection_reset', 'transport_incomplete_read'}
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method=method)
                with self.opener.open(req, timeout=self.timeout) as response:
                    raw = response.read(limit + 1)
                    if len(raw) > limit:
                        raise IntegrationError('response_too_large')
                    return raw
            except IntegrationError:
                raise
            except urllib.error.HTTPError as exc:
                raise IntegrationError('http_' + str(exc.code)) from None
            except Exception as exc:
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
                if isinstance(reason, (TimeoutError, socket.timeout)):
                    code = 'transport_timeout'
                elif isinstance(reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                    code = 'transport_connection_reset'
                elif isinstance(reason, http.client.IncompleteRead):
                    code = 'transport_incomplete_read'
                elif isinstance(reason, ssl.SSLCertVerificationError):
                    code = 'tls_certificate_verification_failed'
                elif isinstance(reason, ConnectionRefusedError):
                    code = 'transport_connection_refused'
                else:
                    code = 'transport_failed'
                if code in transient and attempt + 1 < attempts:
                    time.sleep(attempt + 1)
                    continue
                failure = IntegrationError(code)
                if isinstance(reason, ssl.SSLCertVerificationError):
                    failure.verify_code = reason.verify_code
                    failure.verify_message = reason.verify_message
                raise failure from None

    def request(self, base, route, method='GET', payload=None, sid=None, headers=None):
        origin = urllib.parse.urlsplit(base)
        url = urllib.parse.urljoin(base.rstrip('/') + '/', route)
        target = urllib.parse.urlsplit(url)
        if (target.scheme, target.hostname, target.port) != (origin.scheme, origin.hostname, origin.port):
            raise IntegrationError('cross_origin_refused')
        h = {'Content-Type': 'application/json', **(headers or {})}
        if sid:
            h['X-FTL-SID'] = sid
        raw = self._request(url, method, json.dumps(payload).encode() if payload is not None else None, h, self.max_bytes)
        try:
            result = json.loads(raw or b'{}')
            if not isinstance(result, dict) or result.get('error'):
                raise ValueError()
            return result
        except (ValueError, UnicodeError):
            raise IntegrationError('invalid_api_response') from None


def _domains(response):
    rows = response.get('domains')
    if not isinstance(rows, list):
        raise IntegrationError('missing_domains')
    result = []
    seen = set()
    for row in rows:
        name, count = row.get('domain'), row.get('count')
        if not isinstance(name, str) or not name or len(name) > 253 or re.search(r'[\s|`\x00-\x1f]', name):
            raise IntegrationError('invalid_domain')
        if type(count) is not int or count < 0 or name in seen:
            raise IntegrationError('invalid_domain_count')
        seen.add(name)
        result.append({'domain': name, 'count': count})
    if len(result) >= 100000:
        raise IntegrationError('domain_inventory_may_be_truncated')
    return result


# FTL query_status enum, normalized to the same outcome sets as persisted events.
_QUERY_STATUS = dict(enumerate(('UNKNOWN', 'GRAVITY', 'FORWARDED', 'CACHE', 'REGEX',
    'DENYLIST', 'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA',
    'GRAVITY_CNAME', 'REGEX_CNAME', 'DENYLIST_CNAME', 'RETRIED', 'RETRIED_DNSSEC',
    'IN_PROGRESS', 'DBBUSY', 'SPECIAL_DOMAIN', 'CACHE_STALE')))


def _query_outcome(status):
    if type(status) is int:
        status = _QUERY_STATUS.get(status)
    elif isinstance(status, str) and status.isascii() and status.isdecimal():
        status = _QUERY_STATUS.get(int(status)) if len(status) < 4 else None
    if not isinstance(status, str):
        return 'unknown'
    return 'blocked' if status in BLOCK else 'allowed' if status in ALLOW else 'unknown'


def _attribution_sample(response, domain, start, end):
    queries = response.get('queries')
    if not isinstance(queries, list) or len(queries) > 500:
        raise IntegrationError('invalid_attribution_sample')
    total = response.get('recordsFiltered')
    if type(total) is not int or total < len(queries):
        total = None
    result = dict(sample_size=len(queries), records_filtered=total,
                  truncated=(total > 500 if total is not None else None),
                  sample_status='sampled', unknown_status_queries=0, excluded_queries=0,
                  counts={state: collections.Counter() for state in ('allowed', 'blocked')},
                  state_queries={'allowed': 0, 'blocked': 0}, invalid_clients={'allowed': 0, 'blocked': 0})
    for query in queries:
        if not isinstance(query, dict):
            result['excluded_queries'] += 1
            continue
        stamp = query.get('time')
        if (not isinstance(query.get('domain'), str) or normalize(query['domain']) != domain
                or type(stamp) not in (int, float) or not math.isfinite(stamp) or not start <= stamp < end):
            result['excluded_queries'] += 1
            continue
        state = _query_outcome(query.get('status'))
        if state == 'unknown':
            result['unknown_status_queries'] += 1
            continue
        result['state_queries'][state] += 1
        client = query.get('client')
        if not isinstance(client, dict):
            result['invalid_clients'][state] += 1
            continue
        name, ip = client.get('name'), client.get('ip')
        label = name if isinstance(name, str) and name.strip() else ip
        if not isinstance(label, str) or not label.strip():
            result['invalid_clients'][state] += 1
            continue
        result['counts'][state][label] += 1
    return result


def _api_scope(transport, base, sid, verified_at):
    """Read only the three relevant scope settings, never the full configuration."""
    result = {'verified_at': None, 'status': 'unavailable', 'exclude_domains': None,
              'exclude_clients': None, 'exclude_domains_count': None,
              'exclude_clients_count': None, 'privacy_level': None}
    succeeded = 0
    for key, path in (('exclude_domains', ('webserver', 'api', 'excludeDomains')),
                      ('exclude_clients', ('webserver', 'api', 'excludeClients')),
                      ('privacy_level', ('misc', 'privacylevel'))):
        try:
            value = transport(base, '/api/config/' + '/'.join(path), 'GET', None, sid)['config']
            for part in path:
                value = value[part]
            if key == 'privacy_level':
                if type(value) is not int or not 0 <= value <= 3:
                    raise ValueError()
            elif not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError()
            result[key] = value
            if key != 'privacy_level':
                result[key + '_count'] = len(value)
            succeeded += 1
        except Exception:
            pass
    result['status'] = 'verified' if succeeded == 3 else 'partial' if succeeded else 'unavailable'
    result['verified_at'] = iso(verified_at) if succeeded else None
    return result


def rolling_snapshot(transport, base, password, now=None):
    """Fetch one fixed rolling window, fail closed on absent domain inventories."""
    end = int(time.time() if now is None else now)
    start = end - 86400
    sid = None
    try:
        sid = transport(base, '/api/auth', 'POST', {'password': password}).get('session', {}).get('sid')
        if not sid:
            raise IntegrationError('authentication_failed')
        inputs = {'api_scope': _api_scope(transport, base, sid, end)}
        for name, blocked in [('allowed', 'false'), ('blocked', 'true')]:
            route = '/api/stats/database/top_domains?' + urllib.parse.urlencode({'from': start, 'until': end, 'blocked': blocked, 'count': 100000})
            inputs[name] = _domains(transport(base, route, 'GET', None, sid))
        try:
            inputs['clients'] = transport(base, '/api/clients', 'GET', None, sid).get('clients', [])
            if not isinstance(inputs['clients'], list):
                raise ValueError()
        except Exception:
            inputs['clients'] = []
            inputs['clients_error'] = 'Client correlation unavailable'
        inputs['attribution'] = []
        samples = {}
        for state in ('allowed', 'blocked'):
            for row in inputs[state][:5]:
                domain = row['domain']
                key = normalize(domain)
                if key not in samples:
                    route = '/api/queries?' + urllib.parse.urlencode({'from': start, 'until': end, 'disk': 'true', 'length': 500, 'domain': domain})
                    try:
                        samples[key] = _attribution_sample(transport(base, route, 'GET', None, sid), key, start, end)
                    except Exception:
                        # Keep inventories usable without representing failure as zero clients.
                        samples[key] = None
                sample = samples[key]
                if sample is None:
                    attribution = {k: None for k in ('sample_size', 'matching_state_queries', 'attributed_queries',
                        'unknown_status_queries', 'excluded_queries', 'invalid_client_queries', 'records_filtered', 'truncated')}
                    attribution.update(clients='unknown; sample unavailable', sample_status='unavailable')
                else:
                    counts = sample['counts'][state]
                    attribution = {k: v for k, v in sample.items() if k not in ('counts', 'state_queries', 'invalid_clients')}
                    attribution.update(
                        clients=', '.join(f'{name} ({count})' for name, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:5]) or 'none identified in sample',
                        matching_state_queries=sample['state_queries'][state],
                        attributed_queries=sum(counts.values()),
                        invalid_client_queries=sample['invalid_clients'][state])
                inputs['attribution'].append({'domain': domain, 'state': state, **attribution})
        text = '# Pi-hole domain review\n\nGenerated: ' + iso(end) + '  \nWindow: previous 24 hours\n\n'
        for state in ('allowed', 'blocked'):
            text += f'## Complete {state}-domain inventory\n\n| Domain | Queries |\n|---|---:|\n'
            text += ''.join(f"| `{r['domain']}` | {r['count']} |\n" for r in inputs[state]) + '\n'
        inputs.update(from_time=start, until_time=end)
        return text, inputs
    finally:
        if sid:
            try:
                transport(base, '/api/auth', 'DELETE', None, sid)
            except Exception:
                pass


def refresh_unifi(transport, base, api_key, now=None):
    """Transport accepts request(..., headers=...). Does not write inventory."""
    headers = {'X-API-Key': api_key, 'Accept': 'application/json'}
    root = '/proxy/network/integration/v1'
    def pages(route):
        offset = 0
        for _ in range(2000):
            page = transport(base, route + '?' + urllib.parse.urlencode({'offset': offset, 'limit': 200}), headers=headers)
            data = page.get('data')
            if not isinstance(data, list):
                raise IntegrationError('invalid_unifi_page')
            count = page.get('count', len(data))
            total = page.get('totalCount', count)
            if type(count) is not int or type(total) is not int or count != len(data) or total < 0:
                raise IntegrationError('invalid_unifi_count')
            if not count and offset < total:
                raise IntegrationError('incomplete_unifi_page')
            yield from data
            offset += count
            if offset >= total:
                return
        raise IntegrationError('unifi_pagination_limit')
    clients = []
    for site in pages(root + '/sites'):
        site_id = site.get('id')
        if not isinstance(site_id, str) or not site_id:
            raise IntegrationError('invalid_unifi_site')
        for client in pages(root + '/sites/' + urllib.parse.quote(site_id, safe='') + '/clients'):
            allowed = ('id', 'name', 'type', 'macAddress', 'ipAddress', 'networkId', 'vlanId', 'connectedAt', 'lastSeenAt')
            clients.append({**{k: client.get(k) for k in allowed}, 'siteId': site_id})
    return {'generatedAt': iso(time.time() if now is None else now), 'access': 'read-only', 'clients': sorted(clients, key=lambda c: (c['name'] or '', c['macAddress'] or ''))}


def _cell(value):
    value = html.escape(str(value if value is not None else 'Unknown'), quote=False)
    value = re.sub(r'[|\r\n`\x00-\x1f\x7f]', ' ', value)
    return re.sub(r'([\\*_[\]])', r'\\\1', value)


def inventory_section(inventory, clients=(), attribution=(), status='cached; no refresh attempted'):
    devices = (inventory or {}).get('clients', [])
    text = '## UniFi device inventory\n\nInventory status: ' + _cell(status) + '. UniFi access is read-only. Only currently connected clients are guaranteed to appear.\n\n| Device | Type | IP address | MAC address | VLAN | Site |\n|---|---|---|---|---|---|\n'
    for c in devices:
        text += '| ' + ' | '.join(_cell(c.get(k)) for k in ('name','type','ipAddress','macAddress','vlanId','siteId')) + ' |\n'
    if not devices:
        text += '| _Pending_ | Unknown | Unknown | Unknown | Unknown | Inventory unavailable |\n'
    text += '\n## Pi-hole and UniFi client correlation\n\nCurrent inventory mappings do not prove historical device identity.\n\n| Pi-hole client | UniFi device | Current IP | Pi-hole groups |\n|---|---|---|---|\n'
    for p in clients:
        name = str(p.get('client') or '')
        u = next((c for c in devices if name and (str(c.get('macAddress') or '').lower() == name.lower() or c.get('ipAddress') == name)), {})
        text += '| ' + ' | '.join(map(_cell, (name, u.get('name','Unmatched'), u.get('ipAddress'), ','.join(map(str,p.get('groups') or []))))) + ' |\n'
    text += '\n## Device attribution\n\nTop observed domains with requesting clients (up to five clients per state and domain). At most 500 domain-matching queries across all states are requested per domain in the fixed window, then locally filtered by exact allowed/blocked outcome. Unknown or missing statuses are excluded from both states; invalid domain/time records and unusable clients are excluded. Counts are sampled observations, not complete or cumulative counts; no representativeness is assumed. A sample is truncated when recordsFiltered exceeds 500; missing totals leave truncation unknown.\n\n| Domain | State | Clients |\n|---|---|---|\n'
    for row in attribution:
        text += '| ' + ' | '.join(_cell(row[k]) for k in ('domain','state','clients')) + ' |\n'
    for row in attribution:
        if 'sample_status' in row:
            text += '\nSample detail: ' + _cell(row['domain']) + ' (' + _cell(row['state']) + '): ' + ', '.join(_cell(k) + '=' + _cell(row.get(k)) for k in ('sample_status', 'sample_size', 'matching_state_queries', 'attributed_queries', 'unknown_status_queries', 'excluded_queries', 'invalid_client_queries', 'records_filtered', 'truncated')) + '.\n'
    return text + '\n'


def _atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def validate_list(raw, filename, previous_count=0):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        raise IntegrationError('invalid_size')
    domains = set()
    for line in raw.splitlines():
        line = line.split('#', 1)[0].strip().lower()
        if not line:
            continue
        if len(line) > 253 or '.' not in line or not all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', p) for p in line.split('.')):
            raise IntegrationError('invalid_content')
        domains.add(line)
    if filename != 'curated-whitelist.txt' and not domains:
        raise IntegrationError('empty_blocklist')
    if previous_count and len(domains) < previous_count * .5:
        raise IntegrationError('unexpected_count_drop')
    return '\n'.join(sorted(domains)) + ('\n' if domains else ''), len(domains)


def refresh_lists(root, transport=None, now=None, force=False):
    """Refresh a complete commit-pinned set; failed refresh keeps the last-good pointer."""
    import fcntl
    root = Path(root)
    now = time.time() if now is None else now
    config = root / 'config'
    config.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_path = config / 'curated-list-state.json'
    lock_fd = os.open(config / '.python-list-refresh.lock', os.O_CREAT | os.O_RDWR, 0o600)
    stage = None
    with os.fdopen(lock_fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            state = json.loads(state_path.read_text())
        except (OSError, ValueError):
            state = {}
        try:
            complete_cache = bool(re.fullmatch(r'[a-f0-9]{40}', str(state.get('commit', '')))) and all((config / 'list-snapshots' / state['commit'] / filename).is_file() for filename in FILES)
            if not force and state.get('last_attempt_at') and now - state['last_attempt_at'] < 3600:
                return {'status': 'cached' if complete_cache else 'backoff', 'commit': state.get('commit')}
            if not force and complete_cache and state.get('checked_at') and now - state['checked_at'] < 86400 and not state.get('last_error'):
                return {'status': 'cached', 'commit': state.get('commit')}
            from .production import _private_json
            repository = _private_json(config / 'list-source.json')
            if (set(repository) != {'repository', 'ref'}
                    or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository['repository'])
                    or not re.fullmatch(r'[A-Za-z0-9_.-]+', repository['ref'])):
                raise IntegrationError('invalid_list_source')
            repo, ref = repository['repository'], repository['ref']
            client = HTTPSClient()
            def fetch(url, limit=MAX_BYTES):
                if urllib.parse.urlsplit(url).hostname not in ('api.github.com', 'raw.githubusercontent.com'):
                    raise IntegrationError('unexpected_origin')
                raw = transport(url, limit) if transport else client.get_bytes(url, {'User-Agent':'Pi-hole-local-report-list-refresh', 'Accept':'application/vnd.github+json'}, limit)
                return raw.decode() if isinstance(raw, bytes) else raw
            revision = json.loads(fetch(f'https://api.github.com/repos/{repo}/commits/{ref}', 1024*1024))
            commit = revision['sha']
            published = revision['commit']['committer']['date']
            if not re.fullmatch(r'[a-f0-9]{40}', commit):
                raise IntegrationError('invalid_revision')
            dt.datetime.fromisoformat(published.replace('Z', '+00:00'))
            storage = config / 'list-snapshots'
            storage.mkdir(exist_ok=True, mode=0o700)
            target = storage / commit
            old = storage / str(state.get('commit',''))
            current = old if re.fullmatch(r'[a-f0-9]{40}', str(state.get('commit',''))) and all((old/f).is_file() for f in FILES) else config / 'lists'
            stage = Path(tempfile.mkdtemp(prefix='.refresh-python-', dir=storage))
            files = {}
            for filename in FILES:
                previous = validate_list((current/filename).read_text(), filename)[1] if (current/filename).exists() else 0
                raw = fetch(f'https://raw.githubusercontent.com/{repo}/{commit}/Lists/{filename}')
                checked, count = validate_list(raw, filename, previous)
                _atomic(stage/filename, checked.encode())
                files[filename] = {'count':count, 'sha256':hashlib.sha256(checked.encode()).hexdigest()}
            if target.exists():
                if target.is_symlink() or any(hashlib.sha256((target/f).read_bytes()).hexdigest() != files[f]['sha256'] for f in FILES):
                    raise IntegrationError('invalid_snapshot')
            else:
                os.rename(stage,target)
                stage = None
            state = dict(commit=commit,published_at=published,checked_at=now,last_attempt_at=now,last_error=None,files=files)
            _atomic(state_path, (json.dumps(state,indent=2)+'\n').encode())
            return {'status':'updated','commit':commit,'counts':{f:v['count'] for f,v in files.items()}}
        except Exception as exc:
            code = str(exc) if isinstance(exc, IntegrationError) else 'transport_or_filesystem_error'
            _atomic(state_path, (json.dumps({**state,'last_attempt_at':now,'last_error':code},indent=2)+'\n').encode())
            raise IntegrationError(code) from None
        finally:
            if stage is not None:
                shutil.rmtree(stage)


def build_email(report, sender, recipient, date=None):
    """Build only. This module intentionally has no SMTP send operation."""
    date = date or dt.datetime.now().astimezone()
    msg = EmailMessage()
    msg['From'] = f'Pi-hole Reports <{sender}>'
    msg['To'] = recipient
    msg['Subject'] = 'Daily Pi-hole domain review - ' + date.date().isoformat()
    msg['Date'] = format_datetime(date)
    msg.set_content('\n'.join(report.splitlines()[:6]).replace('`','') + '\n\nThe complete deduplicated report is attached as pihole-domain-review.md.gz.\n')
    msg.add_attachment(gzip.compress(report.encode(),mtime=0),maintype='application',subtype='gzip',filename='pihole-domain-review.md.gz')
    return msg


def local_backup(source_path, destination_path):
    """Online SQLite snapshot to a new local file only. No pruning/cloud export."""
    source, dest = Path(source_path).resolve(), Path(destination_path).absolute()
    if source == dest.resolve() or dest.exists() or dest.is_symlink():
        raise IntegrationError('backup_destination_exists_or_matches_source')
    if re.search(r'CloudStorage|OneDrive', str(dest.resolve()), re.I):
        raise IntegrationError('cloud_export_not_enabled')
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.snapshot-', dir=dest.parent)
    os.close(fd)
    try:
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as src, closing(sqlite3.connect(temp)) as out:
            src.backup(out)
            out.execute('PRAGMA journal_mode=DELETE')
            if out.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or out.execute('PRAGMA foreign_key_check').fetchall():
                raise IntegrationError('backup_integrity_failed')
        with open(temp,'rb') as f:
            os.fsync(f.fileno())
        os.link(temp,dest)  # Exclusive publication; never overwrite an existing snapshot.
        return str(dest)
    finally:
        os.unlink(temp)

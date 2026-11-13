"""Local-only, bounded blocklist screening. Membership is not a safety verdict.

No DNS history is sent to providers. The worker downloads public source URLs,
then compares locally. It never writes Block decisions or changes Pi-hole.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import socket
import subprocess
import sys
from urllib.parse import urlsplit
from .integrations import HTTPSClient, IntegrationError

SOURCE_FILE = 'blocklist-sources.txt'
MAX_BYTES = 64 * 1024 * 1024
MAX_SOURCES = 128
MAX_INPUT = 8 * 1024 * 1024


def hostname(value):
    value = value.strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    if len(value) > 253 or '.' not in value:
        return None
    labels = value.split('.')
    if all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', p) for p in labels):
        return value
    return None


def validate_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.port not in (None,443) or any(c.isspace() for c in url)):
        raise ValueError('public_https_source_required')
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        name = parsed.hostname.rstrip('.').lower()
        if '.' in name and not name.endswith(('.local','.internal','.localhost')):
            return url
    raise ValueError('public_https_source_required')


def load_sources(path):
    path = Path(path)
    if path.resolve() != path.absolute():
        raise ValueError('source_file_symlink_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 131072:
            raise ValueError('invalid_source_file')
        text = stream.read(131073).decode('utf-8-sig')
    urls = [validate_url(line.strip()) for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    urls = list(dict.fromkeys(urls))
    if not 1 <= len(urls) <= MAX_SOURCES:
        raise ValueError('invalid_source_count')
    return urls


def scan(raw, names):
    """Plain domains/hosts are exact; ||domain^ rules include descendants.

    Exceptions suppress matches only within their source. Unsupported syntax
    makes coverage partial; it is never silently converted to a broad rule.
    """
    text = raw.decode('utf-8-sig')
    if '<html' in text[:4096].lower() or '<!doctype' in text[:4096].lower():
        raise ValueError('html_not_blocklist')
    normalized = {n: hostname(n) for n in names}
    exact = {}
    suffix = {}
    for original, name in normalized.items():
        if name:
            exact.setdefault(name, []).append(original)
            labels = name.split('.')
            for i in range(len(labels)-1):
                suffix.setdefault('.'.join(labels[i:]), []).append(original)
    matches, exceptions = set(), set()
    rules = unsupported = 0
    unsupported_exception = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#','!')) or line in ('[Adblock Plus]','[Adblock Plus 2.0]','[Adblock Plus 3.0]'):
            continue
        exception = line.startswith('@@')
        if exception: line = line[2:]
        abp = re.fullmatch(r'\|\|([^\^]+)\^', line)
        if abp and hostname(abp[1]):
            rules += 1
            (exceptions if exception else matches).update(suffix.get(hostname(abp[1]), ()))
            continue
        if exception:
            unsupported_exception = True
            unsupported += 1
            continue
        parts = line.split('#',1)[0].split()
        if not parts:
            continue
        if line in ('255.255.255.255 broadcasthost','fe80::1%lo0 localhost','ff00::0 ip6-localnet','ff00::0 ip6-mcastprefix','ff02::1 ip6-allnodes','ff02::2 ip6-allrouters','ff02::3 ip6-allhosts','0.0.0.0 0.0.0.0'):
            continue
        if parts[0] in ('0.0.0.0','127.0.0.1','::','::1'):
            domains = parts[1:]
        elif len(parts) == 1:
            domains = parts
        else:
            unsupported += 1
            continue
        for domain in domains:
            if domain in ('localhost','localhost.localdomain','local','ip6-localhost','ip6-loopback','broadcasthost'):
                continue
            name = hostname(domain)
            if name:
                rules += 1
                matches.update(exact.get(name, ()))
            else:
                unsupported += 1
    if not rules:
        raise ValueError('no_supported_domain_rules')
    # Unsupported exceptions could negate a match: don't recommend from this feed.
    if unsupported_exception:
        matches.clear()
    return sorted(matches - exceptions), rules, unsupported


def fetch_public(url):
    validate_url(url)
    name = urlsplit(url).hostname
    addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(name,443,type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError('non_public_address_refused')
    return HTTPSClient(timeout=15,max_bytes=MAX_BYTES,get_retries=0,
        connect_address=addresses[0],expected_hostname=name).get_bytes(url)


def check_sources(urls, names, fetch=None):
    fetch = fetch or fetch_public
    def one(url):
        try:
            validate_url(url)
            raw = fetch(url)
            if not isinstance(raw,bytes) or len(raw)>MAX_BYTES:
                raise ValueError('source_too_large')
            matched, rules, ignored = scan(raw,names)
            return dict(url=url,status='partial' if ignored else 'complete',sha256=hashlib.sha256(raw).hexdigest(),
                        supported_rules=rules,unsupported_lines=ignored,matched_hostnames=matched)
        except Exception as error:
            code = str(error) if isinstance(error,(IntegrationError,ValueError)) and re.fullmatch(r'[a-z_0-9]+',str(error)) else type(error).__name__
            return dict(url=url,status='failed',error=code,matched_hostnames=[])
    with ThreadPoolExecutor(max_workers=4) as pool:
        sources=list(pool.map(one,urls))
    complete=sum(s['status']=='complete' for s in sources)
    rows={name:dict(recommended_block='',matched_sources=[],check_status='complete' if complete==len(urls) else 'incomplete') for name in names}
    for source in sources:
        for name in source['matched_hostnames']:
            rows[name]['recommended_block']='1'
            rows[name]['matched_sources'].append(source['url'])
    for source in sources:
        source['matched_count']=len(source.pop('matched_hostnames'))
    for name in names:
        if not hostname(name): rows[name]['check_status']='invalid_hostname'
    return dict(status='complete' if complete==len(urls) else 'incomplete',checked_at=datetime.now(timezone.utc).isoformat(),
                source_count=len(urls),complete_sources=complete,sources=sources,rows=rows)


def run_check(path, names, *, runner=subprocess.run):
    """Hard worker deadline also bounds slow-drip responses/DNS stalls."""
    try:
        urls=load_sources(path)
    except FileNotFoundError:
        return dict(status='not_configured',source_count=0,rows={})
    except Exception:
        return dict(status='incomplete',error='source_inventory_invalid',source_count=0,rows={})
    request=json.dumps(dict(urls=urls,names=names))
    if len(request.encode())>MAX_INPUT:
        return dict(status='incomplete',error='input_too_large',source_count=len(urls),rows={})
    try:
        result=runner([sys.executable,'-m','pihole_report.source_check'],input=request,text=True,capture_output=True,timeout=240,check=True)
        return json.loads(result.stdout)
    except Exception:
        return dict(status='incomplete',error='source_worker_failed_or_timed_out',source_count=len(urls),rows={})


def render_summary(check):
    rows=check.get('rows',{})
    diagnostics=''.join(f"- {source['url']}: {source['status']}; {source.get('supported_rules',0)} supported rules; {source.get('unsupported_lines',0)} unsupported entries" + (f"; {source['error']}" if 'error' in source else '') + '\n' for source in check.get('sources',[]))
    return ('\n## External blocklist comparison\n\n'
        f"Status: {check['status']}; {check.get('complete_sources',0)}/{check.get('source_count',0)} sources fully checked. "
        f"{sum(r.get('recommended_block')=='1' for r in rows.values())} research-needed hostnames matched.\n\n"
        'See the CSV recommendation and matching-source columns. Block remains your manual decision. '
        'A match is a list recommendation, not proof of malware; no match is not proof of safety. '
        'Overlapping sources are not independent votes. Incomplete checks leave unresolved coverage.\n\n'+diagnostics)


if __name__ == '__main__':
    request=json.loads(sys.stdin.read(MAX_INPUT+1))
    if set(request)!= {'urls','names'} or not 1<=len(request['urls'])<=MAX_SOURCES:
        raise SystemExit(2)
    print(json.dumps(check_sources(request['urls'],request['names'])))

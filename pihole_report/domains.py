"""Offline registrable-domain extraction (ICANN and private PSL rules)."""
from functools import lru_cache
from ipaddress import ip_address
from urllib.parse import urlsplit
from .public_suffix_data import RULES

@lru_cache(maxsize=1)
def _rules():
    exact, wildcard, exception = set(), set(), set()
    for line in RULES.splitlines():
        rule = line.strip()
        if not rule or rule.startswith('//'):
            continue
        target = exception if rule.startswith('!') else wildcard if rule.startswith('*.') else exact
        rule = rule.removeprefix('!').removeprefix('*.')
        target.add(rule.encode('idna').decode('ascii').lower())
    return exact, wildcard, exception

def registrable_domain(value):
    """Return eTLD+1; blank for IPs, suffix-only, local/invalid names.

    Includes private suffixes to keep separate tenants (e.g. github.io) distinct.
    Accepts a hostname or URL; never resolves or requests it. Unknown suffixes
    use the PSL default wildcard rule. Output uses ASCII IDNA form.
    """
    try:
        text = str(value).strip()
        host = urlsplit(text if '://' in text else '//' + text).hostname
        if not host:
            return ''
        host = host.rstrip('.').encode('idna').decode('ascii').lower()
        try:
            ip_address(host)
            return ''
        except ValueError:
            pass
        labels = host.split('.')
        if (len(labels) < 2 or len(host) > 253 or
            any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or
                not all(c.isascii() and (c.isalnum() or c == '-') for c in label) for label in labels) or
            labels[-1] in {'local', 'localhost', 'internal', 'lan', 'home', 'invalid', 'test'} or host.endswith('.home.arpa')):
            return ''
        exact, wildcard, exception = _rules()
        suffix_len = 1
        for i in range(len(labels)):
            suffix = '.'.join(labels[i:])
            if suffix in exception:
                suffix_len = len(labels) - i - 1
                break
            if suffix in exact:
                suffix_len = max(suffix_len, len(labels) - i)
            if i > 0 and suffix in wildcard:
                suffix_len = max(suffix_len, len(labels) - i + 1)
        return '.'.join(labels[-suffix_len-1:]) if len(labels) > suffix_len else ''
    except (ValueError, UnicodeError):
        return ''

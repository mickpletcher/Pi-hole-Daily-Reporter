"""Local deterministic review. No network, model, email, or rule-writing code."""
from __future__ import annotations
import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

Row = dict[str, Any]

GUARDS = (
    'icloud-content.com icloud.com apple.com apple-dns.net '
    'itunes.apple.com.edgesuite.net itunes.apple.com.akadns.net amazon.com '
    'amazonvideo.com media-amazon.com amazonaws.com samsungqbe.com '
    'samsungcloudsolution.com samsungcloudsolution.net'
).split()
TRACKING = {}  # No installation-specific policy or asserted audit history.

FILES = [
    'curated-blocklist-policy.txt', 'curated-blocklist-device.txt', 'curated-whitelist.txt',
]


def iso(value: float) -> str:
    """Format an epoch timestamp exactly like the legacy UTC report."""
    return (
        datetime.fromtimestamp(value, timezone.utc)
        .isoformat(timespec='milliseconds')
        .replace('+00:00', 'Z')
    )


def rows(db: sqlite3.Connection, sql: str, args: Sequence[Any] = ()) -> list[Row]:
    """Run a query and return plain mappings independent of row_factory."""
    cursor = db.execute(sql, args)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def one(db: sqlite3.Connection, sql: str, args: Sequence[Any] = ()) -> Row | None:
    """Return the first result, or None when the query is empty."""
    result = rows(db, sql, args)
    return result[0] if result else None


def exists(db: sqlite3.Connection, name: str) -> bool:
    """Check whether an optional table or view exists."""
    return one(db, 'SELECT 1 FROM sqlite_master WHERE name=?', (name,)) is not None


def clean(value: Any) -> str:
    """Sanitize a plain Markdown table value."""
    return re.sub(r'[|\r\n]', ' ', str('unknown' if value is None else value))


def safe(value: Any) -> str:
    """Escape historical text without silently losing control characters."""
    return re.sub(
        r'[\x00-\x1f]', lambda match: '\\u%04x' % ord(match[0]), str(value)
    ).replace('|', '\\|')


def below(domain: str, parent: str) -> bool:
    """Match an exact domain or a dot-delimited subdomain."""
    return domain == parent or domain.endswith('.' + parent)


def matches(domain: str, entries: set[str]) -> list[str]:
    """Find matching suffixes from most specific to least specific."""
    result = []
    while '.' in domain:
        if domain in entries:
            result.append(domain)
        domain = domain.split('.', 1)[1]
    return result


def list_config(root: str | Path, now: float | None = None) -> tuple[list[Row], str]:
    """Read validated local list selection and describe its freshness."""
    root = Path(root)
    now = time.time() if now is None else now
    state = None
    try:
        state = json.loads((root / 'config/curated-list-state.json').read_text())
    except (OSError, ValueError):
        pass
    directory = root / 'config/lists'
    if state and re.fullmatch('[a-f0-9]{40}', state.get('commit', '')):
        candidate = root / 'config/list-snapshots' / state['commit']
        if all((candidate / filename).exists() for filename in FILES):
            directory = candidate
    freshness = 'list freshness unverified; using legacy local copies'
    if state and state.get('checked_at') and directory != root / 'config/lists':
        stale = now - state['checked_at'] > 172800 or state.get('last_error')
        freshness = (
            'curated lists ' + ('stale/refresh failed' if stale else 'verified')
            + '; checked ' + iso(state['checked_at'])
            + '; published ' + str(state.get('published_at'))
            + '; revision ' + state['commit'][:12]
        )
        if state.get('last_error'):
            freshness += '; last refresh error: ' + state['last_error']
    inputs = [
        ('policy', 'lists/' + FILES[0]),
        ('device', 'lists/' + FILES[1]),
        ('protected', 'protected-domains.txt'),
        ('allow', 'lists/' + FILES[2]),
    ]
    configs = []
    for name, filename in inputs:
        path = (
            directory / Path(filename).name if filename.startswith('lists/')
            else root / 'config' / filename
        )
        entries = set()
        digest = 'missing'
        status = 'missing'
        if path.exists():
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            for line in raw.decode().splitlines():
                line = line.split('#', 1)[0].strip().lower()
                if line and not line.startswith('!') and not re.search(r'[\s/]', line):
                    entries.add(line.removesuffix('.'))
            status = 'loaded' if entries else 'empty'
        configs.append({
            'name': name, 'file': filename, 'set': entries, 'digest': digest, 'state': status,
        })
    return configs, freshness


def classify(
    db: sqlite3.Connection,
    snapshot: Mapping[str, Any],
    root: str | Path,
    now: float | None = None,
) -> Row:
    """Apply conservative local policies without changing database or network state."""
    snapshot = dict(snapshot)
    configs, freshness = list_config(root, now)
    by_name = {config['name']: config for config in configs}
    deny = by_name['policy']['set'] | by_name['device']['set']
    state = '; '.join(config['name'] + ': ' + config['state'] for config in configs)
    state += '; ' + freshness
    digest = json.dumps(
        [[config['file'], config['digest']] for config in configs],
        separators=(',', ':'),
    ) + 'screening-v2'

    historical_protection = {}
    if exists(db, 'protection_evidence'):
        historical_protection = {
            row['domain']: row for row in rows(db, 'SELECT * FROM protection_evidence')
        }
    previous = one(
        db,
        'SELECT id FROM snapshots WHERE site=? AND until_time<? '
        'ORDER BY until_time DESC LIMIT 1',
        (snapshot['site'], snapshot['until_time']),
    )
    previous_domains = set()
    if previous:
        previous_domains = {
            row['domain']
            for row in rows(
                db,
                'SELECT DISTINCT domain FROM snapshot_counts WHERE snapshot_id=?',
                (previous['id'],),
            )
        }
    seen = {
        row['domain']
        for row in rows(
            db,
            'SELECT DISTINCT c.domain FROM snapshot_counts c '
            'JOIN snapshots s ON s.id=c.snapshot_id '
            'WHERE s.site=? AND s.until_time<?',
            (snapshot['site'], snapshot['until_time']),
        )
    }
    decisions = {}
    for row in rows(db, 'SELECT * FROM decisions ORDER BY imported DESC,id DESC'):
        decisions.setdefault(row['domain'], row['decision'])
    source = rows(
        db,
        "SELECT domain,"
        "sum(CASE WHEN outcome='allowed' THEN queries ELSE 0 END) allowed,"
        "sum(CASE WHEN outcome='blocked' THEN queries ELSE 0 END) blocked "
        "FROM snapshot_counts WHERE snapshot_id=? GROUP BY domain",
        (snapshot['id'],),
    )
    for query in source:
        domain = query['domain']
        hits = matches(domain, deny)
        nearest = hits[0] if hits else None
        guards = sorted(
            (suffix for suffix in GUARDS if below(domain, suffix)),
            key=len,
            reverse=True,
        )
        guard = guards[0] if guards else None
        protect = next(iter(matches(domain, by_name['protected']['set'])), None)
        allow = next(iter(matches(domain, by_name['allow']['set'])), None)
        historical = historical_protection.get(domain)
        tracking = next((suffix for suffix in TRACKING if below(domain, suffix)), None)
        decision = decisions.get(domain)

        protection = None
        if historical:
            protection = (
                'historically verified exact allow exception ('
                + historical['observed_date'] + '); current status unknown'
            )
        elif allow:
            protection = 'local curated allow entry: ' + allow
        elif protect:
            protection = 'configured protected suffix: ' + protect

        bucket = 'no_review'
        risk = 'unknown; no functional test'
        evidence = 'No curated deny-list match'
        match_kind = None
        if nearest:
            match_kind = 'exact' if nearest == domain else 'suffix'
            evidence = ('Exact' if nearest == domain else 'Suffix')
            evidence += ' curated deny-list match: ' + nearest

        if protection:
            bucket = 'protection_review' if query['blocked'] else 'protected'
            risk = 'possible service breakage; preserve protection pending review'
        elif guard:
            bucket = 'service_risk' if nearest else 'no_review'
            risk = (
                'possible service dependency; conservative family guard, '
                'not verified functionality'
            )
        elif nearest and query['allowed']:
            signal = tracking or re.search(
                r'(^|[.-])(ad|ads|adserver|adservice|adtrack|adtracker|track|'
                r'tracking|telemetry|analytics|metrics)([.-]|$)',
                domain,
            )
            bucket = 'tracking_review' if signal else 'unknown_review'
            if tracking:
                evidence += '; ' + TRACKING[tracking]
            elif signal:
                evidence += '; ad/telemetry word in hostname (lexical hint only)'

        if decision in ('block', 'allow', 'ignore'):
            bucket = 'decided'
        elif decision == 'review' and bucket == 'no_review':
            bucket = 'unknown_review'

        if not previous:
            novelty = 'baseline'
        elif domain not in seen:
            novelty = 'new to collected history'
        elif domain in previous_domains:
            novelty = 'seen in previous snapshot'
        else:
            novelty = 'seen before; returned'

        family = guard or protect or allow or tracking or (hits[-1] if hits else domain)
        query.update(
            family=family,
            novelty=novelty,
            bucket=bucket,
            match_domain=nearest,
            match_kind=match_kind,
            evidence=evidence,
            risk=risk,
            protection=protection,
            decision=decision,
            current_rule_status='unknown',
        )
    return {
        'rows': source,
        'state': state,
        'previous': bool(previous),
        'policyHash': hashlib.sha256(digest.encode()).hexdigest(),
    }


def groups(source: list[Row], bucket: str) -> list[Row]:
    """Group reviews by family, prioritizing new names and observed volume."""
    by_family = {}
    for row in source:
        if row['bucket'] == bucket:
            by_family.setdefault(row['family'], []).append(row)
    result = [
        {
            'family': family,
            'members': members,
            'queries': sum(row['allowed'] + row['blocked'] for row in members),
            'new': any(row['novelty'] == 'new to collected history' for row in members),
        }
        for family, members in by_family.items()
    ]
    return sorted(result, key=lambda group: (
        not group['new'], -group['queries'], group['family']
    ))


def shortlist(data: Row) -> str:
    """Render conservative review leads and suppressed prior decisions."""
    source = data['rows']
    new_count = sum(row['novelty'] == 'new to collected history' for row in source)
    decided = [row for row in source if row['bucket'] == 'decided']
    text = '## Daily review shortlist\n\n'
    if data['previous']:
        text += (
            f'{new_count} domains are new to this collected history; '
            f'{len(source) - new_count} were seen before.'
        )
    else:
        text += (
            'Baseline snapshot: new-versus-seen comparison begins after another '
            'successful report snapshot.'
        )
    text += (
        ' This is collection history, not proof of when a device first used a service.\n\n'
        'Current Pi-hole rule status: **unknown for all rows**. Query outcomes describe '
        'the report window; stored approvals and old allowlist checks do not establish '
        'current rules.\n\nLocal screening uses list matches, explicit safeguards and '
        'user decisions. No independent research or calibrated confidence is claimed. '
        'Query volume orders reviews within a category; it does not increase confidence. '
        'Source files: ' + data['state'] + '.\n\n'
    )
    sections = [
        ('tracking_review', 'Ad/telemetry review leads — local evidence only'),
        ('service_risk', 'Service dependency risk — hold for manual review'),
        ('unknown_review', 'Unknown-purpose matches — research needed'),
        ('protection_review', 'Protected domains with blocked observations — investigate'),
    ]
    for bucket, title in sections:
        all_groups = groups(source, bucket)
        shown = all_groups[:5]
        text += '### ' + title + '\n\n'
        if not shown:
            text += 'None.\n\n'
            continue
        text += (
            '| Family | Domains / window queries | New / seen | '
            'Most-specific evidence samples | Breakage risk |\n'
            '|---|---:|---|---|---|\n'
        )
        for group in shown:
            sample = sorted(
                group['members'], key=lambda row: -(row['allowed'] + row['blocked'])
            )[:2]
            evidence = [
                row['domain'] + ' → ' + row['evidence']
                + ('; ' + row['protection'] if row['protection'] else '')
                for row in sample
            ]
            values = [
                group['family'],
                f"{len(group['members'])} / {group['queries']}",
                '; '.join(dict.fromkeys(row['novelty'] for row in group['members'])),
                '; '.join(evidence),
                sample[0]['risk'],
            ]
            text += '| ' + ' | '.join(map(clean, values)) + ' |\n'
        text += (
            f'\nShowing {len(shown)} of {len(all_groups)} families, '
            'at most two evidence examples per family. Every individual most-specific '
            'match remains in SQLite screenings. Family grouping is for review only; '
            'it never recommends wildcard rules.\n\n'
        )
    text += '### Previously decided — suppressed from new recommendations\n\n'
    if decided:
        text += '\n'.join(
            '- ' + clean(row['domain']) + ': ' + row['decision']
            + '; current rule status unknown.'
            for row in decided[:10]
        )
    else:
        text += 'None.'
    text += '\n\n'
    if len(decided) > 10:
        text += f'{len(decided) - 10} additional decisions retained in SQLite.\n\n'
    protected_count = sum(bool(row['protection']) for row in source)
    text += (
        f'{protected_count} observed domains have configured or historically verified '
        'protection evidence. An exact historical exception protects that name only; '
        'it is not silently expanded to subdomains.\n\n'
    )
    return text


def inventory_rows(db: sqlite3.Connection) -> list[Row]:
    """Unify measured totals and nonadditive historical evidence without writes."""
    norm = "CASE WHEN domain='.' THEN '.' ELSE lower(rtrim(domain,'.')) END"
    historical = (
        'SELECT NULL hostname,0 report_sources,NULL first_report,NULL last_report WHERE 0'
    )
    if exists(db, 'email_history_records'):
        historical = f"""
            SELECT {norm} hostname,
                   count(DISTINCT r.source_id) report_sources,
                   min(s.generated_at) first_report,
                   max(s.generated_at) last_report
            FROM email_history_records r
            JOIN email_history_sources s USING(source_id)
            GROUP BY {norm}
        """
    claims = 'SELECT NULL hostname,0 claims,NULL first_claim,NULL last_claim WHERE 0'
    if exists(db, 'email_history_supplementary'):
        claims = f"""
            SELECT {norm} hostname, count(*) claims,
                   min(source_date) first_claim, max(source_date) last_claim
            FROM email_history_supplementary
            WHERE domain IS NOT NULL
            GROUP BY {norm}
        """
    return rows(db, f"""
        WITH client AS (
            SELECT {norm} hostname, client_ip, sum(queries) query_count,
                   sum(CASE WHEN outcome='allowed' THEN queries ELSE 0 END) allowed,
                   sum(CASE WHEN outcome='blocked' THEN queries ELSE 0 END) blocked,
                   sum(CASE WHEN outcome='unknown' THEN queries ELSE 0 END) unknown,
                   min(first_seen) first_seen, max(last_seen) last_seen
            FROM daily
            GROUP BY {norm}, client_ip
        ), m AS MATERIALIZED (
            SELECT hostname, sum(query_count) query_count,
                   sum(allowed) allowed, sum(blocked) blocked, sum(unknown) unknown,
                   count(*) distinct_client_ips,
                   min(first_seen) first_seen, max(last_seen) last_seen,
                   json_group_array(client_ip) client_ips
            FROM (SELECT * FROM client ORDER BY hostname, client_ip)
            GROUP BY hostname
        ), h AS MATERIALIZED ({historical}),
        c AS MATERIALIZED ({claims}),
        names AS (
            SELECT {norm} hostname FROM domains
            UNION SELECT hostname FROM m
            UNION SELECT hostname FROM h
            UNION SELECT hostname FROM c
        )
        SELECT n.hostname,
               CASE WHEN m.hostname IS NOT NULL THEN
                        CASE WHEN h.hostname IS NOT NULL OR c.hostname IS NOT NULL
                             THEN 'measured+historical' ELSE 'measured' END
                    WHEN h.hostname IS NOT NULL THEN 'historical-report-only'
                    WHEN c.hostname IS NOT NULL THEN 'supplementary-claim-only'
                    ELSE 'catalog-only' END coverage_kind,
               m.query_count, m.allowed, m.blocked, m.unknown,
               m.distinct_client_ips, m.client_ips, m.first_seen, m.last_seen,
               coalesce(h.report_sources,0) historical_report_sources,
               h.first_report, h.last_report,
               coalesce(c.claims,0) supplementary_claims, c.first_claim, c.last_claim,
               CASE WHEN n.hostname GLOB '*[^a-z0-9._-]*' OR n.hostname=''
                    THEN 'unusual source text; not a validated DNS target'
                    ELSE 'hostname text' END name_quality
        FROM names n
        LEFT JOIN m ON m.hostname=n.hostname
        LEFT JOIN h ON h.hostname=n.hostname
        LEFT JOIN c ON c.hostname=n.hostname
        ORDER BY query_count IS NULL, query_count DESC, n.hostname
    """)


def full_inventory(db: sqlite3.Connection) -> str:
    """Render every stored hostname with distinct measured/history coverage."""
    data = inventory_rows(db)
    measured = sum(row['query_count'] is not None for row in data)
    coverage = one(
        db, 'SELECT min(from_time) first,max(until_time) last,count(*) windows FROM coverage'
    )
    mode = one(db, "SELECT value FROM metadata WHERE key='storage_mode'")
    aggregate = mode and mode['value'] == 'aggregate-first'
    text = (
        '## All encountered hostnames — one row per name\n\n'
        f'{len(data)} unique stored names: {measured} with measured cumulative counts '
        f'and {len(data) - measured} without measured cumulative counts. '
        '“Not collected” means unknown, not zero. Coverage labels distinguish measured, '
        'measured+historical, historical-report-only, supplementary-claim-only and '
        'catalog-only names. Supplementary claims do not prove that a hostname was '
        'queried. Unusual source strings remain flagged historical text.\n\n'
        'Measured totals accumulate over successfully collected windows using durable '
        'daily aggregates. Storage mode: '
    )
    if aggregate:
        text += 'aggregate-first; individual raw query events are not retained'
    else:
        text += '35-day raw-query retention; cumulative aggregates survive expiry'
    text += (
        '. Repeated imports are deduplicated. Overlapping email/report counts are never '
        'summed into these totals. Each measured requesting IP is listed once; per-IP '
        'counts and first/last times are available in domain lookup and the '
        'domain_client_counts view. Historical sampled IP attribution remains separate '
        'evidence. Different subdomains remain separate.\n\n'
    )
    if coverage['first'] is not None:
        text += (
            'Measured-window bounds: ' + iso(coverage['first']) + ' through '
            + iso(coverage['last']) + f" (end exclusive), {coverage['windows']} stored "
            'windows. Bounds do not imply uninterrupted coverage.\n\n'
        )
    text += (
        '| Hostname | Coverage | Measured queries | Allowed | Blocked | Unknown | '
        'Distinct measured IPs | Measured requesting IPs | Historical reports / claims |\n'
        '|---|---|---:|---:|---:|---:|---:|---|---|\n'
    )
    measured_fields = ['query_count', 'allowed', 'blocked', 'unknown', 'distinct_client_ips']
    for row in data:
        coverage_label = row['coverage_kind']
        if row['name_quality'].startswith('unusual'):
            coverage_label += '; unusual source text'
        values = [row['hostname'], coverage_label]
        values += [
            row[key] if row[key] is not None else 'Not collected'
            for key in measured_fields
        ]
        values += [
            ', '.join(json.loads(row['client_ips'])) if row['client_ips'] else 'Not collected',
            f"{row['historical_report_sources']} / {row['supplementary_claims']}",
        ]
        text += '| ' + ' | '.join(map(safe, values)) + ' |\n'
    return text + '\n'


def _research_section(
    db: sqlite3.Connection, domains: Iterable[str], newly_queued: int = 0,
) -> str:
    # Rendering never modifies queue timestamps or starts external research.
    if not exists(db, 'domain_research_cache'):
        return (
            '\n## Domain purpose research\n\nLocal research cache unavailable; '
            'the DNS report remains available. No external research was attempted.\n\n'
        )
    states = dict.fromkeys(['pending', 'researched', 'unresolved', 'error', 'excluded'], 0)
    done = []
    for domain in dict.fromkeys(domains):
        cached = one(db, 'SELECT * FROM domain_research_cache WHERE domain=?', (domain,))
        if cached:
            states[cached['status']] += 1
            if cached['status'] == 'researched':
                done.append(cached)
        elif eligibility(domain)[1]:
            states['uncached'] = states.get('uncached', 0) + 1
        else:
            states['excluded'] += 1

    enabled = None
    if exists(db, 'domain_research_control'):
        enabled = one(
            db, "SELECT value FROM domain_research_control WHERE key='external_enabled'"
        )
    text = (
        '## Domain purpose research\n\nScheduled reports are local/cache-only '
        'and make no hosted AI calls. '
    )
    if enabled and enabled['value'] == 'true':
        text += (
            'Explicitly requested manual research is available for selected eligible '
            'hostnames, capped at three per America/Chicago day.'
        )
    else:
        text += 'External research is paused or not enabled.'
    text += (
        ' Completed exact-domain research is reused without a daily lookup or automatic '
        'expiry. Domain presence in history and old heuristic recommendations do not '
        'count as completed research.\n\nCurrent report: '
    )
    text += '; '.join(str(count) + ' ' + status for status, count in states.items())
    text += (
        '. ' + str(newly_queued) + ' newly queued locally. Unresolved entries stay on '
        'hold; transient errors allow at most three attempts with backoff. Excluded '
        'private/reserved or credential-like names remain local.\n\n'
    )
    if done:
        text += (
            '| Domain | Description / purpose | Organization | Evidence / researched '
            'date | Blocking caveats |\n|---|---|---|---|---|\n'
        )
        for cached in done[:20]:
            result = json.loads(cached['result_json'])
            urls = list(dict.fromkeys(
                evidence['url']
                for key in ['description', 'purpose', 'organization']
                for evidence in (result.get(key) or {}).get('evidence', [])
            ))
            descriptions = [
                (result.get(key) or {}).get('text', '')
                for key in ['description', 'purpose']
                if (result.get(key) or {}).get('text')
            ]
            values = [
                cached['domain'],
                '; '.join(descriptions),
                (result.get('organization') or {}).get('text') or 'Unknown',
                result['evidence_quality'] + '; ' + result['researched_at']
                + '; ' + ' '.join(urls),
                result['blocking_impact_caveats'],
            ]
            text += '| ' + ' | '.join(
                re.sub(r'[<>|\r\n\x00-\x1f]', ' ', str(value)) for value in values
            ) + ' |\n'
        if len(done) > 20:
            text += '\nAdditional cached descriptions are available through domain lookup.\n'
    else:
        text += (
            'No completed, evidence-checked descriptions are cached for this report '
            'yet. Missing purpose, organization and blocking impact remain unknown.\n'
        )
    return text + '\n'


def appendix(db: sqlite3.Connection) -> str:
    """Describe durable collection coverage and its limits."""
    domains = one(db, 'SELECT count(*) n FROM domains')['n']
    daily = one(db, 'SELECT count(*) n FROM daily')['n']
    latest = one(db, 'SELECT * FROM runs ORDER BY id DESC LIMIT 1') or {}
    text = (
        '\n## Durable local history\n\n'
        f'SQLite inventory: {domains} distinct domains; {daily} daily per-client '
        f"aggregate rows. Latest detailed import: {latest.get('status', 'not yet collected')}"
    )
    if latest.get('error'):
        text += ' (' + latest['error'] + ')'
    text += '. '
    if latest.get('status') == 'complete':
        text += (
            'Latest completed window: ' + iso(latest['from_time']) + ' to '
            + iso(latest['until_time'])
            + f" (end exclusive); {latest['query_count']} newly stored queries."
        )
    else:
        text += 'No new complete coverage is claimed for a failed import.'
    return text + (
        '\n\nRolling report snapshots are retained separately and must not be added '
        'together. First/last observations from them are window bounds, not exact '
        'query times. Detailed counts use UTC days and Pi-hole client IP; current '
        'UniFi names are time-stamped inventory evidence, not proof of historic '
        'device identity. Only observed retained queries are recoverable; gaps and '
        'expired Pi-hole history cannot be reconstructed.\n\nLegacy recommendation '
        'scores are uncalibrated list-match heuristics. Breakage risk remains unknown '
        'pending research; high volume alone does not establish that a domain should '
        'be blocked. User decisions are retained separately from recommendations.\n'
    )


def email_appendix(db: sqlite3.Connection) -> str:
    """Describe retained historical email evidence without treating it as approval."""
    if not exists(db, 'email_history_sources'):
        return ''
    sources = one(
        db, 'SELECT count(*) n,min(generated_at) first,max(generated_at) last '
        'FROM email_history_sources'
    )
    records = one(
        db, 'SELECT count(DISTINCT domain) n,count(*) records FROM email_history_records'
    )
    supplementary = one(
        db, 'SELECT count(*) n,count(DISTINCT source_id) emails '
        'FROM email_history_supplementary'
    )
    return (
        '\n## Recovered email history\n\n'
        f"{sources['n']} dated reports ({sources['first']} through {sources['last']}), "
        f"{records['n']} distinct reported domains, {records['records']} historical "
        f"records, and {supplementary['n']} supplementary claims/list sources from "
        f"{supplementary['emails']} emails are retained with exact excerpts and source "
        'provenance. Historical rolling counts are not added to detailed query events '
        'or daily totals. Device attribution is sampled. Report scores remain '
        'uncalibrated heuristics; supplementary bot-review claims are unverified and '
        'are not user approvals. No researched owner/purpose/category/breakage-risk '
        'fields were present in these reports. Query a domain with the local lookup '
        'command to see its dated email evidence.\n'
    )


def render(
    db: sqlite3.Connection,
    snapshot_id: str,
    root: str | Path,
    inventory_text: str = '',
    newly_queued: int = 0,
) -> str:
    """Render one complete snapshot using only SELECT queries and local files."""
    snapshot = one(db, 'SELECT * FROM snapshots WHERE id=?', (snapshot_id,))
    if not snapshot:
        raise ValueError('Report snapshot not found')
    data = classify(db, snapshot, root)
    text = (
        '# Pi-hole domain review\n\nGenerated: ' + iso(snapshot['until_time'])
        + '  \nSource: local SQLite; rolling 24-hour snapshot, separate from cumulative '
        'daily counts.\nPolicy: recommendations only; no Pi-hole rules changed.\n'
        '<!-- pihole-snapshot: ' + snapshot['id'] + ' -->\n\n'
    )
    text += shortlist(data)
    text += research_section(db, [row['domain'] for row in data['rows']], newly_queued)
    text += full_inventory(db)
    marker = inventory_text.find('## UniFi device inventory')
    if marker >= 0:
        text += '\n' + inventory_text[marker:].split('## Durable local history')[0]
    return text + appendix(db) + email_appendix(db)


PUBLIC_TLDS = set((
    'com net org edu gov mil int io ai app dev co uk us ca de fr au nz jp eu me '
    'tv info biz xyz cloud tech online site store digital solutions services '
    'systems network media news live pro ly it nl se no ch es in br mx za sg hk '
    'kr tw id cc gg fm space world agency group company support software mobi '
    'name travel museum'
).split())
PRIVATE_LABELS = set((
    'localhost local internal intranet lan home home.arpa arpa corp private '
    'test invalid example onion alt'
).split())


def eligibility(value: str) -> tuple[str, bool, str | None]:
    """Return normalized name and local research eligibility, never resolving DNS."""
    import ipaddress

    domain = str(value or '').lower().removesuffix('.')
    parts = domain.split('.')
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        is_ip = False

    labels_valid = all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in parts
    )
    if not domain or len(domain) > 253 or len(parts) < 2 or is_ip or not labels_valid:
        return domain, False, 'non-public or malformed name'

    private = any(part in PRIVATE_LABELS for part in parts)
    reserved = any(below(domain, parent) for parent in (
        'example.com', 'example.net', 'example.org'
    ))
    if private or parts[-1] not in PUBLIC_TLDS or reserved:
        return domain, False, 'private/reserved or unreviewed suffix'

    identifier_heavy = any(
        len(part) >= 32
        or re.fullmatch('[a-f0-9]{16,}', part)
        or re.fullmatch('[0-9]{9,}', part)
        or (re.search('[a-z]', part) and re.search('[0-9]', part) and len(part) >= 24)
        or re.match(
            r'^(?:token|secret|password|passwd|apikey|api-key|authkey|sessionid|'
            r'session-id|bearer|credential)(?:-|$)',
            part,
        )
        for part in parts
    )
    if len(parts) > 7 or identifier_heavy:
        return domain, False, 'credential-like or identifier-heavy name; manual review required'
    return domain, True, None


def prepare_report(
    db: sqlite3.Connection,
    snapshot_id: str,
    root: str | Path,
    now: float | None = None,
) -> dict[str, int]:
    """Explicit local persistence, separate from the SELECT-only renderer.

    Caller owns writable-database authorization and a collector lock. This
    function never migrates, opens or selects a production database itself.
    """
    now = time.time() if now is None else now
    if db.in_transaction:
        raise ValueError('prepare_report requires no active transaction')
    snapshot = one(db, 'SELECT * FROM snapshots WHERE id=?', (snapshot_id,))
    if not snapshot:
        raise ValueError('Report snapshot not found')
    db.execute('BEGIN IMMEDIATE')
    try:
        statements = [
            (
                'CREATE TABLE IF NOT EXISTS screening_runs(snapshot_id TEXT NOT NULL REFERENCES'
                ' snapshots(id),policy_hash TEXT NOT NULL,evaluated REAL NOT NULL,config_state '
                'TEXT NOT NULL,policy_version TEXT NOT NULL,PRIMARY '
                'KEY(snapshot_id,policy_hash))'
            ),
            (
                'CREATE TABLE IF NOT EXISTS screenings(snapshot_id TEXT NOT NULL REFERENCES '
                'snapshots(id),domain TEXT NOT NULL REFERENCES domains(domain),family TEXT NOT '
                'NULL,allowed INTEGER NOT NULL,blocked INTEGER NOT NULL,novelty TEXT NOT '
                'NULL,bucket TEXT NOT NULL,match_domain TEXT,match_kind TEXT,evidence TEXT NOT '
                'NULL,risk TEXT NOT NULL,protection TEXT,decision TEXT,current_rule_status TEXT'
                ' NOT NULL,PRIMARY KEY(snapshot_id,domain))'
            ),
            (
                'CREATE TABLE IF NOT EXISTS protection_evidence(domain TEXT PRIMARY KEY,scope '
                'TEXT NOT NULL,observed_date TEXT NOT NULL,provenance TEXT NOT NULL)'
            ),
            (
                'CREATE TABLE IF NOT EXISTS domain_research_cache(domain TEXT PRIMARY '
                'KEY,status TEXT NOT NULL CHECK(status IN '
                "('pending','researched','unresolved','error')),queued_at REAL NOT "
                'NULL,last_seen REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT '
                '0,next_attempt_at REAL,last_error_code TEXT,result_json TEXT,researched_at '
                'REAL,refresh_reason TEXT)'
            ),
            (
                'CREATE TABLE IF NOT EXISTS domain_research_exclusions(domain TEXT PRIMARY '
                'KEY,reason TEXT NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL)'
            ),
            (
                'CREATE TABLE IF NOT EXISTS domain_research_revisions(id TEXT PRIMARY '
                'KEY,domain TEXT NOT NULL,recorded_at REAL NOT NULL,result_json TEXT NOT NULL)'
            ),
            (
                'CREATE TABLE IF NOT EXISTS domain_research_control(key TEXT PRIMARY KEY,value '
                'TEXT NOT NULL)'
            ),
            (
                'CREATE INDEX IF NOT EXISTS domain_research_due ON '
                'domain_research_cache(status,next_attempt_at)'
            ),
        ]
        for statement in statements:
            db.execute(statement)
        for key, value in [('external_enabled', 'false'), ('provider', 'unselected')]:
            db.execute(
                'INSERT OR IGNORE INTO domain_research_control VALUES(?,?)', (key, value)
            )
        data = classify(db, snapshot, root, now)
        db.execute(
            'INSERT OR REPLACE INTO screening_runs VALUES(?,?,?,?,?)',
            (snapshot_id, data['policyHash'], now, data['state'], 'screening-v2'),
        )
        added = excluded = 0
        fields = [
            'domain', 'family', 'allowed', 'blocked', 'novelty', 'bucket',
            'match_domain', 'match_kind', 'evidence', 'risk', 'protection',
            'decision', 'current_rule_status',
        ]
        for row in data['rows']:
            db.execute(
                'INSERT OR REPLACE INTO screenings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                [snapshot_id] + [row[key] for key in fields],
            )
            domain, eligible, reason = eligibility(row['domain'])
            if not eligible:
                db.execute(
                    'INSERT INTO domain_research_exclusions VALUES(?,?,?,?) '
                    'ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen',
                    (domain, reason, now, now),
                )
                excluded += 1
                continue
            added += db.execute(
                'INSERT OR IGNORE INTO domain_research_cache'
                '(domain,status,queued_at,last_seen,next_attempt_at) '
                "VALUES(?,'pending',?,?,?)",
                (domain, now, now, now),
            ).rowcount
            db.execute(
                'UPDATE domain_research_cache SET last_seen=? WHERE domain=?', (now, domain)
            )
        db.execute('PRAGMA user_version=2')
        db.commit()
        return {'added': added, 'excluded': excluded, 'screened': len(data['rows'])}
    except BaseException:
        db.rollback()
        raise


def research_section(
    db: sqlite3.Connection, domains: Iterable[str], newly_queued: int = 0,
) -> str:
    """Render cached evidence, retaining the DNS report if cached content is malformed."""
    try:
        return _research_section(db, domains, newly_queued)
    except (ValueError, KeyError, TypeError, sqlite3.Error):
        return (
            '\n## Domain purpose research\n\nLocal research cache unavailable; the DNS '
            'report remains available. No external research was attempted.\n\n'
        )

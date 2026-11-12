"""Read-only temporal coverage accounting, independent of API filter completeness.

Intervals are UTC epoch seconds, start inclusive and end exclusive. Coverage
means successfully paginated *API-visible* history, never all network traffic.
"""
import json
import math


def window_coverage(db, site, start, until):
    if not all(type(x) in (int, float) and math.isfinite(x) for x in (start, until)) or until < start:
        raise ValueError('Invalid coverage window')
    intervals = []
    for row in db.execute('SELECT from_time,until_time FROM coverage WHERE site=? AND from_time<? AND until_time>? ORDER BY from_time,until_time', (site, until, start)):
        left, right = max(start, row[0]), min(until, row[1])
        if left >= right:
            continue
        if intervals and left <= intervals[-1][1]:
            intervals[-1][1] = max(intervals[-1][1], right)
        else:
            intervals.append([left, right])
    cursor = start
    gaps = []
    for left, right in intervals:
        if cursor < left:
            gaps.append({'from_time': cursor, 'until_time': left})
        cursor = right
    if cursor < until:
        gaps.append({'from_time': cursor, 'until_time': until})
    covered = sum(right-left for left, right in intervals)
    return {'from_time': start, 'until_time': until, 'requested_seconds': until-start,
            'covered_seconds': covered, 'gaps': gaps,
            'temporal_status': 'partial' if gaps else 'complete',
            'coverage_scope': 'API-visible retained history',
            'network_completeness': 'unknown'}


def run_coverage(db, run_id):
    """Immutable evidence for new runs; conservative reconstruction for old runs."""
    row = db.execute('SELECT value FROM metadata WHERE key=?', ('collection_coverage:'+str(run_id),)).fetchone()
    if row:
        return json.loads(row[0])
    run = db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
    if run is None or run['from_time'] is None or run['until_time'] is None:
        return None
    result = window_coverage(db, run['site'], run['from_time'], run['until_time'])
    result.update({'evidence': 'legacy coverage intervals; reconstructed from current retained history',
                   'retention_cutoff': None, 'api_filter_completeness': 'unknown',
                   'fetch_status': 'complete' if run['status'] == 'complete' else run['status']})
    return result

"""One Python daily pipeline, restricted to isolated migration roots.

Transports and credentials are caller-injected. There is no SMTP delivery,
hosted research, cloud publication, scheduler or Pi-hole rule editing here.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time

from .cli import PROJECT, atomic_text, isolated_path
from .collector import collect, collector_lock
from .integrations import IntegrationError, inventory_section, refresh_lists, refresh_unifi, rolling_snapshot
from .report import list_config, prepare_report, render
from .health import data_health, render_data_health
from .runlog import prune_logs, render_totals, research_status, snapshot_totals, write_log
from .source_check import run_check, render_summary, SOURCE_FILE
from .storage import connect, feedback, import_report, inventory, normalize


def validate_shadow_paths(root: Path) -> None:
    """Reject links anywhere a daily run can write, including existing inputs."""
    for relative in ("config", "memory", "data", ".python-report.lock"):
        path = root / relative
        isolated_path(path)
        if path.is_symlink():
            raise ValueError("Shadow working paths must not be symbolic links")
        if path.is_dir():
            for directory, dirs, files in os.walk(path, followlinks=False):
                for name in dirs + files:
                    candidate = Path(directory) / name
                    if candidate.is_symlink():
                        raise ValueError("Shadow working paths must not be symbolic links")
                    isolated_path(candidate)


@contextmanager
def run_lock(root: Path):
    """Prevent overlapping Python runs from racing report publication."""
    path = isolated_path(root) / ".python-report.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def run_daily(root, transport, password, *, base="https://pihole.example.invalid", site="Primary",
              now=None, list_transport=None, unifi_transport=None,
              unifi_base=None, unifi_api_key=None, log_root=None):
    """Run with injected live/fixture transports and log every report attempt.

    Missing optional transports mean reuse caches. No external research is
    triggered. Production paths are refused before any side effect.
    """
    root = isolated_path(root)
    validate_shadow_paths(root)
    dbpath = isolated_path(root / "data/pihole-history/history.sqlite")
    if not dbpath.is_file():
        raise ValueError("Create a shadow history copy before running the daily pipeline")
    started = time.time()
    log_root = PROJECT if log_root is None else log_root
    retention = prune_logs(log_root, now=started)
    try:
        with run_lock(root):
            result, payload = _run_daily(
                root, dbpath, transport, password, base=base, site=site,
                now=time.time() if now is None else now, list_transport=list_transport,
                unifi_transport=unifi_transport, unifi_base=unifi_base,
                unifi_api_key=unifi_api_key,
            )
    except Exception as error:
        path = write_log(log_root, {
            "event": "daily_report", "mode": "isolated-shadow", "status": "failed",
            "site": site, "error_code": "report_generation_failed",
            "error_type": type(error).__name__, "retention": retention,
            "hosted_calls": 0, "email_sent": False, "production_writes": 0,
        }, started, now=time.time())
        error.pihole_log_path = str(path)
        raise
    payload["retention"] = retention
    path = write_log(log_root, payload, started, now=time.time())
    result["log_file"] = str(path)
    result["logs_deleted_30_days"] = retention["deleted_count"]
    atomic_text(root / "memory/python-run.json", json.dumps(result, indent=2) + "\n")
    return result


def _run_daily(root, dbpath, transport, password, *, base, site, now,
               list_transport, unifi_transport, unifi_base, unifi_api_key,
               write_text=atomic_text):
    warnings = []
    if list_transport is not None:
        try:
            refresh_lists(root, transport=list_transport, now=now)
        except IntegrationError:
            warnings.append("Curated list refresh failed; last-good inputs retained")
    inv_file = root / "memory/unifi-clients.json"
    try:
        cached = json.loads(inv_file.read_text())
        if not isinstance(cached, dict) or not isinstance(cached.get("clients"), list):
            raise ValueError()
    except (OSError, ValueError):
        cached = {"clients": []}
    inv_status = "cached: no refresh attempted; inventory from " + str(cached.get("generatedAt", "unknown"))
    if unifi_transport is not None:
        try:
            if not unifi_base or not unifi_api_key:
                raise IntegrationError("unifi_configuration_missing")
            fresh = refresh_unifi(unifi_transport, unifi_base, unifi_api_key, now)
            write_text(inv_file, json.dumps(fresh, indent=2) + "\n")
            cached = fresh
            inv_status = "current"
        except Exception:
            inv_status = "stale: refresh failed; retained last successful inventory from " + str(cached.get("generatedAt", "unknown"))
            warnings.append("UniFi refresh failed; cached inventory retained")
    raw, inputs = rolling_snapshot(transport, base, password, now)
    input_file = root / "memory/python-rolling-input.md"
    write_text(input_file, raw)
    snapshot_id = hashlib.sha256(raw.encode()).hexdigest()
    db = connect(dbpath)
    try:
        incoming = {normalize(row["domain"]) for state in ("allowed", "blocked") for row in inputs[state]}
        with collector_lock(db):
            existing = {row[0] for row in db.execute("SELECT domain FROM domains")}
            new_names = incoming - existing
            imported = import_report(db, input_file, site)
            feedback(db, root / "config/recommendation-feedback.csv")
            inventory(db, inv_file, site)
        try:
            measured = collect(db, site, base, transport, password, now=now)
            collection_status = "complete"
            collection_import_succeeded = True
        except Exception:
            measured = 0
            collection_status = "failed"
            collection_import_succeeded = False
            warnings.append("Detailed history collection failed; no partial counts published")
        with collector_lock(db):
            prepared = prepare_report(db, snapshot_id, root, now)
            inv_text = inventory_section(cached, inputs["clients"], inputs["attribution"], inv_status)
            if inputs.get("clients_error"):
                inv_text += "\nClient correlation unavailable for this report; cached inventory is not a substitute for a successful client lookup.\n"
            totals = snapshot_totals(db, snapshot_id)
            _, list_freshness = list_config(root, now)
            last_import = db.execute("SELECT id,site,status,from_time,until_time,query_count,error FROM runs WHERE site=? ORDER BY id DESC LIMIT 1", (site,)).fetchone()
            last_import = dict(last_import) if last_import else None
            if collection_import_succeeded and last_import and last_import['status'] in ('complete', 'partial', 'unknown'):
                collection_status = last_import['status']
            totals['snapshot_id'] = snapshot_id
            quality = data_health(db, root, totals, latest_run=last_import,
                import_succeeded=collection_import_succeeded, inventory=cached,
                inventory_refresh_attempted=unifi_transport is not None,
                api_scope=inputs.get('api_scope'), attribution=inputs.get('attribution', []), now=now)
            totals['api_scope_status'] = quality['api_scope']['filter_status']
            if inputs.get('clients_error'):
                quality['warnings'].append('Pi-hole client correlation was unavailable; cached device inventory is not a substitute.')
                quality['status'] = 'limited'
            warnings = list(dict.fromkeys(warnings + quality['warnings']))
            research = research_status(db, incoming, new_to_catalog=new_names)
            source_check = run_check(root / 'config' / SOURCE_FILE, [r['hostname'] for r in research['research_needed']])
            if source_check['status'] == 'incomplete':
                warnings.append('External blocklist comparison incomplete; see source diagnostics')
            report = render(db, snapshot_id, root, inv_text, newly_queued=prepared["added"])
            summary = render_data_health(quality)
            marker = '## Daily review shortlist'
            if marker in report:
                report = report.replace(marker, summary + marker, 1)
            else:
                report += '\n' + summary
            report += render_totals(totals)
            report += render_summary(source_check)
            output = root / "memory/pihole-domain-review.md"
            write_text(output, report)
    finally:
        db.close()
    result = {
        "report": str(output), "snapshot_id": snapshot_id,
        "snapshot_rows_imported": imported, "new_measured_queries": measured,
        "collection_status": collection_status, "collection_import_succeeded": collection_import_succeeded,
        "data_health": quality, "research_newly_queued": prepared["added"],
        "research_needed_count": research["research_needed_count"],
        "new_to_history_count": research["new_to_history_count"], "daily_totals": totals,
        "warnings": warnings, "email_sent": False, "cloud_backup_published": False,
        "hosted_calls": 0, "production_schedule_changed": False, "mode": "isolated-shadow",
    }
    payload = {
        "event": "daily_report", "mode": "isolated-shadow",
        "status": "partial" if warnings else "complete", "snapshot_id": snapshot_id,
        "site": site, "daily_totals": totals, "research": research, "source_check": source_check,
        "collection_status": collection_status, "collection_import_succeeded": collection_import_succeeded,
        "data_health": quality, "new_measured_queries": measured,
        "inventory_status": inv_status, "curated_list_freshness": list_freshness,
        "latest_detailed_import": last_import, "warnings": warnings, "hosted_calls": 0,
        "email_sent": False, "production_writes": 0,
    }
    return result, payload

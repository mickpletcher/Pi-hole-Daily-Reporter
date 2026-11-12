"""Private execution logs and narrowly scoped 30-day retention.

DNS hostnames are not full URLs, queries are not website visits, and the
absence of verified exact-host research is distinct from a new catalog name.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from .cli import PROJECT, isolated_path
from .report import eligibility

SCHEMA = "pihole-report-run.v1"
RETENTION_SECONDS = 30 * 86400
MAX_LOG_BYTES = 32 * 1024 * 1024
NAME = re.compile(r"pihole-report-(\d{8}T\d{12}Z)-([0-9a-f]{32})\.json\Z")


def _timestamp(value):
    value = time.time() if value is None else value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("A finite timestamp is required")
    return datetime.fromtimestamp(value, timezone.utc)


def _iso(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _directory(root, create=False):
    root = Path(root).expanduser().resolve()
    if root != PROJECT:
        root = isolated_path(root)
    directory = root
    for part in ("logs", "pihole-report"):
        directory /= part
        if directory.is_symlink():
            raise ValueError("Log directories must not be symbolic links")
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        if directory.exists() and not directory.is_dir():
            raise ValueError("Log destination is not a directory")
    return directory


def snapshot_totals(db, snapshot_id):
    snapshot = db.execute(
        "SELECT site,from_time,until_time FROM snapshots WHERE id=?", (snapshot_id,)
    ).fetchone()
    if snapshot is None:
        raise ValueError("Report snapshot not found")
    counts = {"allowed": 0, "blocked": 0, "unknown": 0}
    names = {key: set() for key in counts}
    for domain, outcome, queries in db.execute(
        "SELECT domain,outcome,queries FROM snapshot_counts WHERE snapshot_id=?", (snapshot_id,)
    ):
        if outcome not in counts:
            outcome = "unknown"
        counts[outcome] += queries
        names[outcome].add(domain)
    return {
        "site": snapshot[0],
        "window_start": _iso(_timestamp(snapshot[1])),
        "window_end_exclusive": _iso(_timestamp(snapshot[2])),
        "window_seconds": snapshot[2] - snapshot[1],
        "allowed_queries": counts["allowed"],
        "blocked_queries": counts["blocked"],
        "unknown_queries_recorded": counts["unknown"],
        "unknown_outcomes_available": bool(names["unknown"]),
        "total_recorded_queries": sum(counts.values()),
        "unique_hostnames": len(set.union(*names.values())),
        "unique_allowed_hostnames": len(names["allowed"]),
        "unique_blocked_hostnames": len(names["blocked"]),
        "unique_unknown_hostnames": len(names["unknown"]),
        "hostnames_both_allowed_and_blocked": len(names["allowed"] & names["blocked"]),
        "definition": "Rolling snapshot DNS observations, not website visits or full URLs. Allowed means not blocked by Pi-hole, not proof a website loaded. Unknown outcomes absent from the snapshot are not proven zero.",
    }


def verified_research(record):
    """Require the existing cache's checked evidence contract, not its label alone."""
    if not isinstance(record, dict) or record.get("status") != "researched":
        return False
    if record.get("evidence_checked") is not True or record.get("evidence_quality") not in ("primary", "corroborated"):
        return False
    if not all(isinstance(record.get(k), str) and record[k].strip() for k in ("provenance", "blocking_impact_caveats", "researched_at")):
        return False
    try:
        researched = datetime.fromisoformat(record["researched_at"].replace("Z", "+00:00"))
        if researched.tzinfo is None:
            return False
    except ValueError:
        return False
    if not record.get("description") and not record.get("purpose"):
        return False
    for key in ("description", "purpose", "organization"):
        field = record.get(key)
        if field is None:
            continue
        if not isinstance(field, dict) or not isinstance(field.get("text"), str) or not field["text"].strip():
            return False
        evidence = field.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            return False
        for item in evidence:
            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                return False
            try:
                url = urlsplit(item["url"])
                if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
                    return False
            except ValueError:
                return False
            if item.get("source_kind") not in ("primary", "independent") or not isinstance(item.get("excerpt"), str) or not item["excerpt"].strip():
                return False
    return True


def research_status(db, domains, new_to_catalog=None):
    domains = sorted(set(domains))
    evaluated = new_to_catalog is not None
    newly_seen = sorted(set(new_to_catalog or ()) & set(domains))
    cached = {}
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='domain_research_cache'").fetchone():
        cached = {row[0]: (row[1], row[2]) for row in db.execute("SELECT domain,status,result_json FROM domain_research_cache")}
    needed = []
    excluded = []
    verified = 0
    missing_names = []
    for domain in domains:
        normalized, eligible, reason = eligibility(domain)
        state, raw = cached.get(normalized, ("uncached", None))
        try:
            result = json.loads(raw) if raw else None
        except (ValueError, TypeError):
            result = None
        if state == "researched" and verified_research(result):
            verified += 1
            continue
        missing_names.append(domain)
        if not eligible:
            excluded.append({"hostname": domain, "reason": reason})
            continue
        needed.append({
            "hostname": domain,
            "cache_status": state,
            "new_to_history": domain in newly_seen if evaluated else None,
            "action": "manual review required; unresolved stays on hold" if state == "unresolved" else "manual research only; no automatic lookup",
            "reason": "cached result lacks verified evidence" if state == "researched" else "no verified exact-hostname research",
        })
    return {
        "new_to_history": newly_seen,
        "new_to_history_count": len(newly_seen) if evaluated else None,
        "new_to_history_evaluated": evaluated,
        "verified_exact_research_count": verified,
        "missing_verified_research_count": len(missing_names),
        "existing_hostnames_missing_verified_research_count": len(set(missing_names) - set(newly_seen)) if evaluated else None,
        "research_needed": needed,
        "research_needed_count": len(needed),
        "excluded_from_external_research": excluded,
        "excluded_from_external_research_count": len(excluded),
        "definition": "Research-needed lists eligible public hostnames without verified exact-hostname evidence. A hostname may already be in DNS history. These are hostnames, not full URLs, and no external research is triggered.",
    }


def write_log(root, payload, started_at, now=None):
    finished = _timestamp(now)
    started = _timestamp(started_at)
    if started > finished:
        raise ValueError("Run start cannot be after completion")
    directory = _directory(root, create=True)
    run_id = uuid.uuid4().hex
    filename = f"pihole-report-{finished.strftime('%Y%m%dT%H%M%S%fZ')}-{run_id}.json"
    data = {
        **payload,
        "schema": SCHEMA,
        "run_id": run_id,
        "started_at": _iso(started),
        "finished_at": _iso(finished),
        "duration_seconds": (finished - started).total_seconds(),
        "retention_days": 30,
    }
    raw = (json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError("Run log exceeds size limit")
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        destination = directory / filename
        os.link(temporary, destination)  # Exclusive publish, never overwrite another run.
        return destination
    finally:
        os.unlink(temporary)


def prune_logs(root, now=None):
    """Delete only validated app logs aged at least 30 days; leave everything else."""
    moment = _timestamp(now)
    directory = _directory(root)
    removed = []
    skipped = 0
    if not directory.exists():
        return {"deleted": removed, "deleted_count": 0, "skipped_count": 0}
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in os.listdir(directory_fd):
            match = NAME.fullmatch(name)
            if not match:
                skipped += 1
                continue
            try:
                stamp = datetime.strptime(match[1], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
                if (moment - stamp).total_seconds() < RETENTION_SECONDS:
                    skipped += 1
                    continue
                preliminary = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(preliminary.st_mode) or preliminary.st_size > MAX_LOG_BYTES or preliminary.st_uid != os.getuid():
                    skipped += 1
                    continue
                # A path can change after lstat. NONBLOCK avoids hanging if a
                # regular file is swapped for a FIFO before this open.
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as handle:
                    original = os.fstat(handle.fileno())
                    if not stat.S_ISREG(original.st_mode) or original.st_size > MAX_LOG_BYTES or original.st_uid != os.getuid() or (original.st_dev, original.st_ino) != (preliminary.st_dev, preliminary.st_ino):
                        skipped += 1
                        continue
                    data = json.loads(handle.read(MAX_LOG_BYTES + 1))
                if not isinstance(data, dict) or data.get("schema") != SCHEMA or data.get("run_id") != match[2] or data.get("finished_at") != _iso(stamp):
                    skipped += 1
                    continue
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns):
                    skipped += 1
                    continue
                os.unlink(name, dir_fd=directory_fd)
                removed.append(name)
            except (OSError, ValueError, TypeError, RecursionError):
                skipped += 1
    finally:
        os.close(directory_fd)
    return {"deleted": sorted(removed), "deleted_count": len(removed), "skipped_count": skipped}


def render_totals(totals):
    """Append human-readable daily DNS counts without inventing website visits."""
    unknown = (
        f"{totals['unknown_queries_recorded']:,} recorded"
        if totals['unknown_outcomes_available']
        else "not available from this rolling inventory; absence is not proven zero"
    )
    scope = totals.get("api_scope_status", "not recorded with this stored snapshot")
    return (
        "\n## Daily DNS activity totals\n\n"
        f"Window: {totals['window_start']} through {totals['window_end_exclusive']} (end exclusive).\n\n"
        f"- Recorded DNS queries: **{totals['total_recorded_queries']:,}**.\n"
        f"- Allowed queries: **{totals['allowed_queries']:,}**.\n"
        f"- Blocked queries: **{totals['blocked_queries']:,}**.\n"
        f"- Distinct observed hostnames: **{totals['unique_hostnames']:,}**.\n"
        f"- Distinct allowed hostnames: **{totals['unique_allowed_hostnames']:,}**.\n"
        f"- Distinct blocked hostnames: **{totals['unique_blocked_hostnames']:,}**.\n"
        f"- Hostnames with both allowed and blocked queries: **{totals['hostnames_both_allowed_and_blocked']:,}**.\n"
        f"- Unknown-outcome queries: {unknown}.\n"
        f"- API exclusion/privacy scope: {scope.replace(chr(95), chr(32))}. Totals cover returned observations only.\n\n"
        "These are DNS hostnames, not full URLs or proven website visits. One website can use many hostnames; apps and background services also make DNS queries. Allowed means Pi-hole did not block the query, not that a website loaded. Hostnames observed in both states are counted once in the distinct total. Rolling-window counts are separate from cumulative measured history.\n"
    )

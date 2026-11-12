"""Safe migration commands. Production writes and delivery are not exposed."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = Path.home() / "pihole-reporter"


def isolated_path(value: str | Path) -> Path:
    """Resolve links before checking containment, refusing live or synced outputs."""
    path = Path(value).expanduser().resolve()
    if not path.is_relative_to(PROJECT) or path == PROJECT:
        raise ValueError("Migration outputs must stay inside the isolated pihole-python project")
    if any("onedrive" in p.lower() or "cloudstorage" in p.lower() for p in path.parts):
        raise ValueError("Migration outputs must not use synced storage")
    return path


def read_database(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA temp_store=MEMORY")
    return db


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_text(path: Path, text: str) -> None:
    path = isolated_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def copy_database(source: Path, destination: Path) -> None:
    """SQLite online backup includes committed WAL data without modifying source."""
    destination = isolated_path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with read_database(source) as src, sqlite3.connect(destination) as target:
        src.backup(target)
        target.execute("PRAGMA journal_mode=DELETE")
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Copied history failed integrity check")
        if target.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Copied history failed foreign-key check")


def make_shadow(source_root: Path) -> Path:
    source_root = source_root.resolve()
    area = isolated_path(PROJECT / ".validation")
    area.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    run = Path(tempfile.mkdtemp(prefix=stamp, dir=area))
    shadow = run / "root"
    shadow.mkdir(mode=0o700)
    # Config contains lists, public CA and owner decisions, never service-env secrets.
    shutil.copytree(source_root / "config", shadow / "config")
    (shadow / "memory").mkdir(mode=0o700)
    for name in ("pihole-domain-review.md", "unifi-clients.json"):
        source = source_root / "memory" / name
        if source.is_file():
            shutil.copy2(source, shadow / "memory" / name)
            (shadow / "memory" / name).chmod(0o600)
    source_db = source_root / "data/pihole-history/history.sqlite"
    before = digest(source_db)
    copy_database(source_db, shadow / "data/pihole-history/history.sqlite")
    after = digest(source_db)
    # Keep an exact legacy program copy for an offline, side-by-side rendering only.
    scripts = run / "legacy-bin"
    scripts.mkdir(mode=0o700)
    checksums = {}
    for source in sorted((source_root / "bin").iterdir()):
        if source.is_file() and (source.suffix == ".cjs" or source.name in {"run-daily-review", "generate-domain-review", "generate-domain-review.legacy", "send-domain-review-email"}):
            shutil.copyfile(source, scripts / source.name)
            checksums[str(source)] = digest(source)
    plist = Path.home() / "Library/LaunchAgents/org.example.pihole-domain-review.plist"
    if plist.is_file():
        checksums[str(plist)] = digest(plist)
    with read_database(shadow / "data/pihole-history/history.sqlite") as db:
        names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        counts = {n: db.execute('SELECT count(*) FROM "' + n.replace('"','""') + '"').fetchone()[0] for n in names}
    manifest = {"source_root": str(source_root), "created_at": datetime.now(timezone.utc).isoformat(),
                "source_database_sha256_before": before, "source_database_sha256_after": after,
                "source_database_byte_hash_unchanged_during_copy": before == after,
                "production_file_hashes": checksums, "copied_table_counts": counts,
                "source_open_mode": "read-only, SQLite online backup", "network_calls": 0,
                "email_sent": False, "backup_exported": False, "schedule_changed": False}
    atomic_text(run / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return run


def inventory_tail(root: Path) -> str:
    source = root / "memory/pihole-domain-review.md"
    if not source.is_file():
        return ""
    raw = source.read_text(encoding="utf-8")
    if "## UniFi device inventory" not in raw:
        return ""
    return raw[raw.index("## UniFi device inventory"):].split("## Durable local history", 1)[0]


def render_file(database: Path, root: Path, output: Path, snapshot_id: str | None = None) -> dict:
    from .report import render
    from .runlog import prune_logs, render_totals, research_status, snapshot_totals, write_log
    started = time.time()
    output = isolated_path(output)
    retention = prune_logs(PROJECT, now=started)
    with read_database(database) as db:
        if snapshot_id is None:
            row = db.execute("SELECT id FROM snapshots ORDER BY until_time DESC, rowid DESC LIMIT 1").fetchone()
            if row is None:
                raise ValueError("No stored report snapshot available")
            snapshot_id = row[0]
        result = render(db, snapshot_id, root, inventory_tail(root))
        totals = snapshot_totals(db, snapshot_id)
        domains = [row[0] for row in db.execute("SELECT DISTINCT domain FROM snapshot_counts WHERE snapshot_id=?", (snapshot_id,))]
        research = research_status(db, domains)
        result += render_totals(totals)
    atomic_text(output, result)
    log = write_log(PROJECT, {
        "event": "offline_render", "status": "complete", "snapshot_id": snapshot_id,
        "daily_totals": totals, "research": research, "retention": retention,
        "source_mode": "stored snapshot replay; new-to-catalog detection not applicable",
        "network_calls": 0, "hosted_calls": 0, "email_sent": False, "production_writes": 0,
    }, started, now=time.time())
    return {"snapshot_id": snapshot_id, "report": str(output), "bytes": len(result.encode()),
            "network_calls": 0, "research_mode": "cached evidence only", "email_sent": False,
            "daily_totals": totals, "research_needed_count": research["research_needed_count"],
            "log_file": str(log), "logs_deleted_30_days": retention["deleted_count"]}


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Isolated Python Pi-hole rebuild. No delivery, production writes, or hosted calls.")
    sub = parser.add_subparsers(dest="command", required=True)
    health = sub.add_parser("health", help="Read local operational status without network, credentials or changes")
    health.add_argument("--json", action="store_true", help="Show machine-readable local status")
    shadow = sub.add_parser("shadow", help="Copy history safely, then render offline with Python")
    shadow.add_argument("--source-root", type=Path, default=DEFAULT_ROOT)
    render = sub.add_parser("render", help="Render a stored snapshot read-only")
    render.add_argument("--db", type=Path, required=True)
    render.add_argument("--root", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--snapshot-id")
    live = sub.add_parser("run-shadow", help="Collect live Pi-hole data into a private copied root; never send or export")
    live.add_argument("--root", type=Path, required=True)
    live.add_argument("--allow-network", action="store_true", help="Explicitly enable read-only Pi-hole API access")
    live.add_argument("--host", default="pihole.example.invalid", help="Verified TLS/HTTP hostname")
    live.add_argument("--connect-address", default="192.0.2.53", help="Primary TCP address; does not change DNS")
    live.add_argument("--ca-file", type=Path)
    live.add_argument("--password-file", type=Path, default=Path.home()/"pihole-reporter/secrets/pihole-app-password")
    live.add_argument("--refresh-lists", action="store_true", help="Refresh public curated lists into the copy")
    lookup = sub.add_parser("lookup", help="Read one hostname's measured aggregates and cached evidence")
    lookup.add_argument("domain")
    lookup.add_argument("--db", type=Path, required=True)
    args = parser.parse_args(argv)
    started = time.time()
    try:
        if args.command == "health":
            from .health import read_operational_health, health_text
            result = read_operational_health(PROJECT)
            if not args.json:
                print(health_text(result))
                return 0 if result.get('status') != 'unavailable' else 1
        elif args.command == "shadow":
            run = make_shadow(args.source_root)
            root = run / "root"
            result = render_file(root / "data/pihole-history/history.sqlite", root, run / "python-report.md")
            result["validation_directory"] = str(run)
        elif args.command == "render":
            result = render_file(args.db, args.root, isolated_path(args.output), args.snapshot_id)
        elif args.command == "run-shadow":
            from .delivery import read_secret
            from .integrations import HTTPSClient
            from .pipeline import run_daily, validate_shadow_paths
            if not args.allow_network:
                raise ValueError("run-shadow requires --allow-network; no API request was made")
            root = isolated_path(args.root)
            validate_shadow_paths(root)
            if not (root/"data/pihole-history/history.sqlite").is_file():
                raise ValueError("Create a shadow history copy first")
            ca = args.ca_file or root/"config/pihole-collector-ca.pem"
            client = HTTPSClient(ca_file=str(ca), connect_address=args.connect_address, expected_hostname=args.host)
            password = read_secret(args.password_file)
            list_transport = None
            if args.refresh_lists:
                public = HTTPSClient()
                def list_transport(url, limit):
                    return public.get_bytes(url, {"User-Agent":"Pi-hole-local-report-list-refresh", "Accept":"application/vnd.github+json"}, limit)
            try:
                result = run_daily(root, client.request, password, base="https://"+args.host, list_transport=list_transport)
                result["tcp_endpoint"] = args.connect_address
                result["tls_hostname"] = args.host
            finally:
                password = None
        else:
            domain = args.domain.lower().rstrip(".") if args.domain != "." else "."
            with read_database(args.db) as db:
                result = {"domain": domain, "daily": [dict(r) for r in db.execute("SELECT * FROM daily WHERE domain=? ORDER BY day DESC,client_ip", (domain,))]}
                for table in ("domains", "decisions", "research", "domain_research_cache"):
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                        result[table] = [dict(r) for r in db.execute("SELECT * FROM " + table + " WHERE domain=?", (domain,))]
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        if args.command in {"shadow", "render", "run-shadow"} and not getattr(error, "pihole_log_path", None):
            from .runlog import prune_logs, write_log
            retention = prune_logs(PROJECT)
            write_log(PROJECT, {"event": args.command, "status": "failed",
                "error_code": "offline_report_failed", "error_type": type(error).__name__,
                "retention": retention, "network_calls": 0, "hosted_calls": 0,
                "email_sent": False, "production_writes": 0}, started)
        # Provider exceptions may contain private request data. Known local
        # validation errors have safe messages; otherwise print only the type.
        from .integrations import IntegrationError
        from .delivery import DeliveryError
        message = str(error) if isinstance(error, (ValueError, IntegrationError, DeliveryError)) else type(error).__name__
        print(f"Pi-hole report: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

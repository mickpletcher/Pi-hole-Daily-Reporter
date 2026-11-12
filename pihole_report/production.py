"""Manifest-gated Primary runner. Importing this module performs no I/O.

This entry point is deliberately separate from the confined shadow commands.
An explicit owner-only manifest with the exact pre-existing production scope is
required. No environment variables can override its destinations or TLS policy.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import uuid

from .cli import PROJECT
from .delivery import BackupConfig, DeliveryError, SMTPConfig, read_secret, export_backup, send_report, backup_target, run_backup_worker
from .integrations import HTTPSClient, IntegrationError, local_backup
from .pipeline import _run_daily
from .runlog import prune_logs, write_log
from .storage import parse_timestamp

from .research_csv import render_csv, run_csv_worker, inspect_csv

CONFIG = PROJECT / "config/production.json"
SCHEMA = "pihole-production.v1"


def expected_scope() -> dict:
    from .deployment import load_deployment
    return load_deployment()["scope"]


def code_hashes() -> dict:
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(__file__).parent.glob("*.py"))}


def manifest_template() -> dict:
    return {"schema": SCHEMA, "enabled": False, "scope": expected_scope(),
            "refresh_lists": False, "code_sha256": code_hashes()}


def _reject_links(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.resolve() != path:
        raise ValueError("Symbolic-link or noncanonical production path refused")
    return path


def _private_json(path: Path, *, missing=None, max_bytes=1024 * 1024):
    path = _reject_links(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing is not None:
            return missing
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_size > max_bytes):
            raise ValueError("Owner-only regular JSON file required")
        return json.load(stream)


def load_manifest(path=CONFIG) -> dict:
    if Path(path).expanduser().absolute() != CONFIG:
        raise ValueError("Use the exact production manifest path")
    operation = PROJECT / "state/production/source-operation.json"
    if operation.exists() or operation.is_symlink():
        raise ValueError("Source transition requires inspection before running")
    data = _private_json(CONFIG)
    if (not isinstance(data, dict) or set(data) != {"schema", "enabled", "scope", "refresh_lists", "code_sha256"}
            or data["schema"] != SCHEMA or data["enabled"] is not True
            or data["scope"] != expected_scope() or type(data["refresh_lists"]) is not bool
            or data["code_sha256"] != code_hashes()):
        raise ValueError("Production manifest is disabled or does not match the exact approved scope")
    return data


def _atomic(path: Path, value: str):
    path = _reject_links(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_links(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".production-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _scope_writer(scope):
    root = Path(scope["root"])
    allowed = {root / "memory/python-rolling-input.md", root / "memory/unifi-clients.json", Path(scope["report"])}
    def write(path, content):
        if Path(path).absolute() not in allowed:
            raise ValueError("Unexpected production output path")
        _atomic(Path(path), content)
    return write


@contextmanager
def _whole_run_lock(scope):
    directory = _reject_links(Path(scope["state_directory"]))
    for path in (directory.parent, directory):
        path.mkdir(mode=0o700, exist_ok=True)
        if path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise ValueError("Production state directory must be owner-only")
    fd = os.open(directory / "runner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory


def _validate_working_paths(scope):
    root = Path(scope["root"])
    for name in ("config", "memory", "data"):
        path = _reject_links(root / name)
        for directory, dirs, files in os.walk(path, followlinks=False):
            for child in dirs + files:
                candidate = Path(directory) / child
                if candidate.is_symlink():
                    raise ValueError("Linked production input/output refused")
    if not Path(scope["database"]).is_file():
        raise ValueError("Existing production database is required")


def _legacy_baseline(scope, local_date):
    """Suppress a duplicate when existing legacy delivery is known or ambiguous."""
    latest_generated = None
    submitted_dates = set()
    log = Path(scope["legacy_stdout"])
    if log.exists():
        _reject_links(log)
        if log.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Legacy delivery log requires manual inspection")
        with log.open(errors="replace") as stream:
            for line in stream:
                prefix = "PIHOLE_DOMAIN_REPORT_OK report=" + scope["report"] + " generated="
                if line.startswith(prefix):
                    try:
                        latest_generated = datetime.fromtimestamp(parse_timestamp(line[len(prefix):].strip())).astimezone().date().isoformat()
                    except ValueError:
                        latest_generated = None
                if line.strip() == "PIHOLE_REPORT_EMAIL_SENT recipient=" + scope["smtp_recipient"] and latest_generated:
                    submitted_dates.add(latest_generated)
    if local_date in submitted_dates:
        return "legacy_submitted"
    report = Path(scope["report"])
    if report.is_file():
        _reject_links(report)
        with report.open() as stream:
            for _ in range(20):
                line = stream.readline()
                if line.startswith("Generated: "):
                    stamp = parse_timestamp(line[len("Generated: "):].strip())
                    if datetime.fromtimestamp(stamp).astimezone().date().isoformat() == local_date:
                        return "legacy_delivery_unconfirmed"
                    break
    return None


LEDGER_SCHEMA = "pihole-delivery-state.v2"
EMAIL_HOLDS = {"reserved", "uncertain", "unconfirmed", "submitted", "legacy_submitted", "legacy_delivery_unconfirmed"}


def _migrate_ledger(ledger):
    """Retain old guards without inventing outcomes for formerly untracked stages."""
    if not isinstance(ledger, dict) or not isinstance(ledger.get("dates"), dict):
        raise ValueError("Delivery state requires manual inspection")
    if ledger.get("schema") == "pihole-delivery-state.v1":
        for entry in ledger["dates"].values():
            if not isinstance(entry, dict) or not isinstance(entry.get("status"), str):
                raise ValueError("Old delivery state requires manual inspection")
            email = entry["status"]
            entry["stages"] = {name: {"status": "legacy_untracked", "attempts": 0}
                               for name in ("report", "collection", "backup")}
            entry["stages"]["email"] = {"status": email, "attempts": 0}
            entry["migration_note"] = "Prior email guard retained; old collection/backup outcomes not inferred"
        ledger["schema"] = LEDGER_SCHEMA
    if ledger.get("schema") != LEDGER_SCHEMA:
        raise ValueError("Unsupported delivery-state schema")
    for entry in ledger["dates"].values():
        if (not isinstance(entry, dict) or not isinstance(entry.get("stages"), dict)
                or set(entry["stages"]) != {"report", "collection", "backup", "email"}
                or any(not isinstance(stage, dict) or not isinstance(stage.get("status"), str)
                       for stage in entry["stages"].values())):
            raise ValueError("Stage ledger requires manual inspection")
    if type(ledger.get("legacy_baseline_initialized", False)) is not bool:
        raise ValueError("Legacy baseline state requires manual inspection")
    return ledger


def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _frozen_context(entry, state_dir, local_date):
    artifact = entry.get("artifact")
    expected = state_dir / "artifacts" / local_date
    if not isinstance(artifact, dict):
        raise ValueError("Frozen report metadata missing")
    report = expected / "report.md"
    context = expected / "report-context.json"
    if artifact.get("report_path") != str(report) or artifact.get("context_path") != str(context):
        raise ValueError("Frozen artifact path mismatch")
    contents = []
    for path, key in ((report, "report_sha256"), (context, "context_sha256")):
        _reject_links(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
                    or info.st_size > 32 * 1024 * 1024):
                raise ValueError("Frozen artifact is not an owner-only regular file")
            raw = source.read(32 * 1024 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != artifact.get(key):
            raise ValueError("Frozen artifact changed; manual inspection required")
        contents.append(raw)
    return contents[0].decode("utf-8"), json.loads(contents[1])


def _recover_collection(scope, transport, password, now):
    """Recover history only. Never mutate the already emailed report artifact."""
    from .collector import collect
    from .storage import connect
    from .coverage import run_coverage
    db = connect(Path(scope["database"]))
    try:
        count = collect(db, scope["site"], scope["pihole_base"], transport, password, now=now)
        row = db.execute("SELECT id,status FROM runs WHERE site=? ORDER BY id DESC LIMIT 1", (scope["site"],)).fetchone()
        return {"import_succeeded": True, "new_measured_queries": count,
                "coverage_status": row["status"] if row else "unknown",
                "run_id": row["id"] if row else None,
                "coverage": run_coverage(db, row["id"]) if row else None}
    finally:
        db.close()


def _execute(manifest, *, engine=_run_daily, transport=None, send=send_report,
             backup=None, secret_reader=read_secret, now=None, log_root=PROJECT,
             recover_collection=_recover_collection, backup_worker=run_backup_worker, csv_worker=None):
    """Recover independent stages without repeating accepted or uncertain sends.

    `backup` is a test-only synchronous adapter injection. Real operation always
    uses the manifest-scoped, bounded child worker; no credentials cross to it.
    """
    scope = manifest["scope"]
    started = time.time() if now is None else now
    tick = lambda: max(started, time.time())
    local_date = datetime.fromtimestamp(started).astimezone().date().isoformat()
    result = {"mode": "production", "local_date": local_date, "smtp_submitted": False,
              "inbox_delivery_confirmed": False, "backup_published_locally": False,
              "cloud_upload_confirmed": False, "hosted_calls": 0, "stages": {}}
    payload = {"event": "production_daily_report", "mode": "production", "status": "failed"}
    with _whole_run_lock(scope) as state_dir:
        retention = prune_logs(log_root, now=started)
        state_file = state_dir / "delivery-state.json"
        entry = None
        changed = False
        try:
            ledger = _migrate_ledger(_private_json(state_file, missing={
                "schema": LEDGER_SCHEMA, "dates": {}}, max_bytes=16 * 1024 * 1024))
            entry = ledger["dates"].get(local_date)
            if entry is None:
                entry = {"status": "pending", "stages": {name: {"status": "pending", "attempts": 0}
                    for name in ("report", "collection", "email", "backup")}}
                ledger["dates"][local_date] = entry
            if not ledger.get("legacy_baseline_initialized", False):
                baseline = _legacy_baseline(scope, local_date) if entry["stages"]["email"]["status"] == "pending" else None
                ledger["legacy_baseline_initialized"] = True
                if baseline:
                    entry["status"] = baseline
                    entry["stages"]["email"]["status"] = baseline
                    for name in ("report", "collection", "backup"):
                        entry["stages"][name]["status"] = "legacy_untracked"

            def persist(overall="running"):
                entry["status"] = entry["stages"]["email"]["status"]
                _atomic(state_file, json.dumps(ledger, indent=2) + "\n")
                health = {"schema": "pihole-operational-health.v1", "local_date": local_date,
                    "status": overall, "started_at_epoch": started, "updated_at_epoch": tick(),
                    "stages": dict(entry["stages"], csv=entry.get("csv", {"status":"pending"})), "smtp_state": entry["stages"]["email"]["status"],
                    "artifact_snapshot_id": entry.get("artifact", {}).get("snapshot_id"),
                    "data_health": entry.get("artifact_data_health"),
                    "data_health_scope": "frozen_report_artifact",
                    "recovered_history": entry.get("recovered_history"),
                    "recovered_history_scope": "newer history only; emailed report unchanged",
                    "hosted_calls": 0}
                _atomic(state_dir / "current-health.json", json.dumps(health, indent=2) + "\n")

            def begin(name, status="running"):
                stage = entry["stages"][name]
                stage.update(status=status, started_at_epoch=tick(), attempts=stage.get("attempts", 0) + 1)
                stage.pop("finished_at_epoch", None)
                stage.pop("duration_seconds", None)
                persist()

            def finish(name, status, **extra):
                stage = entry["stages"][name]
                ended = tick()
                stage.update(status=status, finished_at_epoch=ended,
                             duration_seconds=max(0, ended - stage.get("started_at_epoch", ended)), **extra)
                persist()

            persist()
            _validate_working_paths(scope)
            stages = entry["stages"]
            frozen_dir = state_dir / "artifacts" / local_date
            requester = None

            def request_transport():
                nonlocal requester
                if requester is None:
                    requester = transport or HTTPSClient(ca_file=scope["pihole_ca"],
                        connect_address=scope["pihole_ip"], expected_hostname=scope["pihole_tls_name"]).request
                return requester

            if stages["report"]["status"] in {"pending", "running", "failed"}:
                if stages["email"]["status"] in EMAIL_HOLDS:
                    raise ValueError("Email holds an unavailable report artifact")
                begin("report")
                begin("collection")
                secret = secret_reader(Path(scope["pihole_password_file"]))
                client = HTTPSClient() if manifest["refresh_lists"] else None
                list_transport = (lambda url, limit: client.get_bytes(url, max_bytes=limit)) if client else None
                produced, detail = engine(Path(scope["root"]), Path(scope["database"]), request_transport(), secret,
                    base=scope["pihole_base"], site=scope["site"], now=started, list_transport=list_transport,
                    unifi_transport=None, unifi_base=None, unifi_api_key=None, write_text=_scope_writer(scope))
                secret = None
                succeeded = produced.get("collection_import_succeeded", produced["collection_status"] != "failed")
                finish("collection", "complete" if succeeded else "failed",
                       import_succeeded=bool(succeeded), coverage_status=produced["collection_status"])
                for directory in (state_dir / "artifacts", frozen_dir):
                    _reject_links(directory)
                    directory.mkdir(mode=0o700, exist_ok=True)
                report_text = Path(scope["report"]).read_text()
                _atomic(frozen_dir / "report.md", report_text)
                _atomic(frozen_dir / "report-context.json", json.dumps({"produced": produced, "detail": detail}, indent=2) + "\n")
                entry["artifact"] = {"report_path": str(frozen_dir / "report.md"),
                    "report_sha256": _digest(frozen_dir / "report.md"),
                    "context_path": str(frozen_dir / "report-context.json"),
                    "context_sha256": _digest(frozen_dir / "report-context.json"),
                    "snapshot_id": produced.get("snapshot_id")}
                entry["artifact_data_health"] = produced.get("data_health", detail.get("data_health"))
                # Freeze the CSV alongside the exact report/context before SMTP.
                # A malformed CSV detail must not suppress the readable email.
                try:
                    frozen_csv = render_csv(detail, produced.get("snapshot_id"))
                    _atomic(frozen_dir / "research-needed.csv", frozen_csv["data"].decode("utf-8"))
                    entry["csv"] = dict(status="pending", attempts=0,
                        **{k:v for k,v in frozen_csv.items() if k != "data"})
                except Exception:
                    entry["csv"] = dict(status="failed", attempts=0,error_code="csv_freeze_failed")
                finish("report", "complete")
                changed = True
            elif stages["report"]["status"] == "complete":
                report_text, frozen = _frozen_context(entry, state_dir, local_date)
                produced, detail = frozen["produced"], frozen["detail"]
                if stages["collection"]["status"] in {"failed", "running"}:
                    begin("collection")
                    try:
                        recovery = recover_collection(scope, request_transport(),
                            secret_reader(Path(scope["pihole_password_file"])), started)
                        entry["recovered_history"] = recovery
                        finish("collection", "complete" if recovery.get("import_succeeded") else "failed",
                            import_succeeded=recovery.get("import_succeeded") is True,
                            coverage_status=recovery.get("coverage_status", "unknown"))
                    except Exception:
                        finish("collection", "failed", import_succeeded=False, error_code="collection_recovery_failed")
                    changed = True
            else:
                # A v1 ledger has no report/backup identity. Preserve its guard,
                # rather than guessing whether a historical export should repeat.
                result.update(status="delivery_suppressed", suppression_reason=stages["email"]["status"],
                              smtp_submitted=stages["email"]["status"] in {"submitted", "legacy_submitted"},
                              backup_published_locally=None,
                              backup={"status": "legacy_untracked", "cloud_upload_confirmed": False},
                              stage_details=stages,
                              migration_note=entry.get("migration_note", "Prior delivery guard retained"))
                entry["csv"] = {"status":"legacy_untracked"}
                result["csv"] = {"status":"legacy_untracked", "cloud_upload_confirmed":False}
                result["csv_published_locally"] = None
                persist(result["status"])
                return result

            payload.update(detail)
            payload.pop("email_sent", None)
            payload.update(mode="production", production_writes=True,
                data_health_scope="frozen_report_artifact", recovered_history=entry.get("recovered_history"))
            result["warnings"] = list(produced.get("warnings", []))
            email_state = stages["email"]["status"]
            if email_state in {"pending", "not_submitted"}:
                # Identity was validated before any retry. Never read the mutable
                # canonical report here: later collection recovery cannot change it.
                report_text, _ = _frozen_context(entry, state_dir, local_date)
                begin("email", "reserved")
                try:
                    sent = send(report_text, SMTPConfig(scope["smtp_sender"], scope["smtp_recipient"],
                        scope["smtp_host"], scope["smtp_port"]), Path(scope["smtp_password_file"]), send=True)
                    finish("email", "submitted" if sent.get("submitted") is True else "unconfirmed")
                except DeliveryError as error:
                    finish("email", "uncertain" if error.uncertain else "not_submitted", error_code=error.code)
                changed = True

            # Email is settled before potentially permission-blocked File Provider
            # access. Only this stage's own short-lived subprocess may be stopped.
            backup_stage = stages["backup"]
            if backup_stage["status"] not in {"complete", "legacy_untracked"}:
                config = BackupConfig(scope["backup_account"], Path(scope["backup_root"]),
                    Path(scope["backup_destination"]), Path(scope["backup_preferences"]), scope["backup_retention"])
                try:
                    if "operation_id" not in backup_stage:
                        backup_stage.update(operation_id=uuid.uuid4().hex, planned_at_epoch=tick())
                        backup_stage["snapshot"] = str(backup_target(config, backup_stage["planned_at_epoch"]))
                        persist()
                    operation = backup_stage["operation_id"]
                    source = frozen_dir / (operation + ".sqlite")
                    if "source_sha256" not in backup_stage:
                        begin("backup", "preparing")
                        if not source.exists():
                            local_backup(Path(scope["database"]), source)
                        _reject_links(source)
                        backup_stage["source_sha256"] = _digest(source)
                        backup_stage["input_captured_at_epoch"] = tick()
                        backup_stage["data_scope"] = "History at backup-input capture; later collection recovery may be newer"
                        persist()
                    request = {"mode": "export", "local_date": local_date,
                        "operation_id": operation, "planned_at": backup_stage["planned_at_epoch"],
                        "source_digest": backup_stage["source_sha256"]}
                    backed = None
                    def worker(mode):
                        def register(pid):
                            backup_stage["worker_pid"] = pid
                            persist()
                        return backup_worker({**request, "mode": mode}, on_start=register)
                    if backup_stage["status"] in {"reserved", "uncertain"}:
                        pid = backup_stage.get("worker_pid")
                        if pid is not None:
                            if type(pid) is not int or pid <= 0:
                                raise DeliveryError("invalid_backup_worker_identity", uncertain=True)
                            try:
                                os.kill(pid, 0)
                            except ProcessLookupError:
                                pass
                            except PermissionError:
                                raise DeliveryError("previous_backup_worker_may_be_running", uncertain=True) from None
                            else:
                                raise DeliveryError("previous_backup_worker_may_be_running", uncertain=True)
                        if backup is not None:
                            raise DeliveryError("backup_reconciliation_required", uncertain=True)
                        backed = worker("inspect")
                        if backed.get("status") == "absent":
                            finish("backup", "failed", error_code="confirmed_not_published")
                            backed = None
                    if backed is None:
                        begin("backup", "reserved")
                        backed = (backup(source, config, export=True) if backup is not None
                                  else worker("export"))
                    if (backed.get("exported") is not True
                            or (backup is None and (backed.get("status") != "published_locally"
                                or backed.get("snapshot") != backup_stage["snapshot"]))):
                        raise DeliveryError("backup_publication_unconfirmed", uncertain=True)
                    finish("backup", "complete", snapshot=backed.get("snapshot", backup_stage["snapshot"]),
                           reconciled=backed.get("reconciled", False), cloud_upload_confirmed=False)
                    # This is the newly created, private operation input only.
                    # Publication has been verified before removing this copy.
                    if source.exists() and _digest(source) == backup_stage["source_sha256"]:
                        source.unlink()
                except DeliveryError as error:
                    finish("backup", "uncertain" if error.uncertain else "failed", error_code=error.code)
                except Exception:
                    finish("backup", "uncertain" if backup_stage["status"] == "reserved" else "failed",
                           error_code="backup_stage_failed")
                changed = True

            # CSV is independently recoverable. No CSV retry can resend SMTP or
            # repeat an already successful SQLite publication.
            csv_stage = entry.setdefault("csv", {"status": "pending", "attempts": 0})
            if (not isinstance(csv_stage, dict)
                    or csv_stage.get("status") not in {"pending","failed","reserved","uncertain","complete","invalid"}
                    or type(csv_stage.get("attempts")) is not int or csv_stage["attempts"] < 0):
                csv_stage = {"status":"invalid", "attempts":0, "error_code":"csv_state_requires_inspection"}
                entry["csv"] = csv_stage
                persist()
            if csv_stage["status"] not in {"complete", "invalid"}:
                try:
                    artifact = render_csv(detail, entry["artifact"]["snapshot_id"])
                    source = frozen_dir / "research-needed.csv"
                    if csv_stage.get("sha256") not in (None, artifact["sha256"]):
                        raise DeliveryError("frozen_csv_changed", uncertain=True)
                    if not source.exists():
                        # Atomic private write; immutable bytes subsequently verified.
                        _atomic(source, artifact["data"].decode("utf-8"))
                    if not inspect_csv(source, artifact["data"]):
                        raise DeliveryError("frozen_csv_missing", uncertain=True)
                    csv_stage.update({k:v for k,v in artifact.items() if k != "data"})
                    csv_stage["path"] = str(Path(scope["backup_destination"]) / artifact["filename"])
                    persist()
                    if csv_stage["status"] in {"reserved", "uncertain"} and csv_stage.get("worker_pid"):
                        try: os.kill(csv_stage["worker_pid"], 0)
                        except ProcessLookupError: pass
                        except PermissionError: raise DeliveryError("previous_csv_worker_may_be_running", uncertain=True) from None
                        else: raise DeliveryError("previous_csv_worker_may_be_running", uncertain=True)
                    csv_stage.update(status="reserved", started_at_epoch=tick(), attempts=csv_stage["attempts"] + 1)
                    persist()
                    def register_csv(pid):
                        csv_stage["worker_pid"] = pid
                        persist()
                    published = (csv_worker or run_csv_worker)({"local_date":local_date,"sha256":artifact["sha256"]}, on_start=register_csv)
                    if (published.get("exported") is not True or published.get("status") != "published_locally"
                            or published.get("path") != csv_stage["path"]):
                        raise DeliveryError("csv_publication_unconfirmed", uncertain=True)
                    csv_stage.update(status="complete", cloud_upload_confirmed=False, reconciled=published.get("reconciled",False))
                except DeliveryError as error:
                    csv_stage.update(status="uncertain" if error.uncertain else "failed",error_code=error.code)
                except Exception:
                    csv_stage.update(status="uncertain" if csv_stage["status"] == "reserved" else "failed", error_code="csv_stage_failed")
                csv_stage["finished_at_epoch"] = tick()
                csv_stage["duration_seconds"] = max(0,tick()-csv_stage.get("started_at_epoch",tick()))
                persist()
                changed = True
            result["csv_published_locally"] = csv_stage["status"] == "complete"
            result["csv"] = dict(csv_stage, cloud_upload_confirmed=False)

            email_state = stages["email"]["status"]
            result.update(smtp_submitted=email_state in {"submitted", "legacy_submitted"},
                smtp_outcome_uncertain=email_state in {"reserved", "uncertain", "unconfirmed"},
                backup_published_locally=stages["backup"]["status"] == "complete",
                backup={"status": stages["backup"]["status"], "snapshot": stages["backup"].get("snapshot"),
                        "cloud_upload_confirmed": False},
                stages={name: stage["status"] for name, stage in stages.items()},
                stage_details=stages, artifact_snapshot_id=entry["artifact"].get("snapshot_id"),
                recovered_history=entry.get("recovered_history"))
            success = (result["smtp_submitted"] and result["backup_published_locally"]
                       and stages["collection"]["status"] == "complete" and result["csv_published_locally"])
            quality_complete = stages["collection"].get("coverage_status") == "complete"
            result["status"] = ("delivery_suppressed" if not changed and success and quality_complete
                                else "complete" if success and quality_complete and not result["warnings"] else "partial")
            if email_state in EMAIL_HOLDS:
                result["suppression_reason"] = email_state
            persist(result["status"])
            return result
        except Exception as error:
            if entry is not None:
                for name in ("report", "collection"):
                    if entry["stages"][name]["status"] == "running":
                        entry["stages"][name].update(status="failed", error_code="stage_interrupted")
                try:
                    persist("failed")
                except Exception:
                    pass
            result.update(status="failed", error_code="production_run_failed", error_type=type(error).__name__)
            return result
        finally:
            payload.update(result)
            if entry is not None:
                payload["stage_details"] = entry.get("stages")
            payload["retention"] = retention
            log = write_log(log_root, payload, started, now=tick())
            result["log_file"] = str(log)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", "--manifest", dest="config", type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    os.umask(0o077)
    started = time.time()
    result = None
    try:
        manifest = load_manifest(args.config)
        result = _execute(manifest)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] in {"complete", "delivery_suppressed"} else 1
    except Exception as error:
        failure = {
            "status": "blocked",
            "error_code": ("production_run_already_active" if isinstance(error, BlockingIOError)
                           else "production_configuration_or_state_invalid"),
            "error_type": type(error).__name__,
        }
        # Manifest contents/paths cannot control fallback logging. Never include
        # raw exception text, credentials, provider responses or guessed send
        # outcomes. If the run got far enough to produce a log, reuse it.
        if isinstance(result, dict) and result.get("log_file"):
            failure["log_file"] = result["log_file"]
        else:
            try:
                retention = prune_logs(PROJECT, now=started)
            except Exception:
                retention = {"status": "cleanup_unavailable"}
            try:
                logged = write_log(PROJECT, {
                    **failure, "event": "production_daily_report", "stage": "entrypoint",
                    "mode": "production", "retention": retention,
                    "outcome_scope": "Entrypoint failure; consult durable delivery state before retrying",
                }, started, now=max(started, time.time()))
                failure["log_file"] = str(logged)
            except Exception:
                failure["log_status"] = "unavailable"
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

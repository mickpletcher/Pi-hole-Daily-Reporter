"""Explicit delivery adapters. Dry-run is the default; neither adapter retries.

Enabling an adapter is a caller responsibility, not authorization to transmit.
Tests must inject SMTP/File Provider doubles and use local synthetic databases.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
import fcntl
import os
from pathlib import Path
import plistlib
import re
import shutil
import smtplib
import sqlite3
import ssl
import stat
import subprocess
import tempfile
import uuid

from .integrations import build_email


class DeliveryError(RuntimeError):
    """Sanitized failure with an explicit uncertain-submission indicator."""

    def __init__(self, code: str, *, uncertain: bool = False):
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain


@dataclass(frozen=True)
class SMTPConfig:
    sender: str
    recipient: str
    host: str = "smtp.mail.yahoo.com"
    port: int = 587
    timeout: float = 30


@dataclass(frozen=True)
class BackupConfig:
    expected_account: str
    root: Path
    destination: Path
    preferences_file: Path
    retention: int = 14


def _address(value: str) -> str:
    if (not isinstance(value, str) or re.search(r"[\s,;<>\r\n]", value)
            or parseaddr(value)[1] != value or value.count("@") != 1
            or not all(value.split("@"))):
        raise DeliveryError("invalid_email_address")
    return value


def read_secret(path: Path) -> str:
    """Read a bounded owner-only regular file without following its final link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
                    or not 0 < info.st_size <= 4096):
                raise DeliveryError("insecure_or_invalid_credential_file")
            raw = handle.read(4097)
        password = "".join(raw.decode("utf-8").split())
        if not password or len(raw) > 4096:
            raise DeliveryError("insecure_or_invalid_credential_file")
        return password
    except DeliveryError:
        raise
    except (OSError, UnicodeError):
        raise DeliveryError("credential_file_unavailable") from None


def send_report(report: str, config: SMTPConfig, password_file=None, *,
                send: bool = False, smtp_factory=smtplib.SMTP, date=None) -> dict:
    """Construct MIME by default; send only with explicit send=True.

    Once DATA may have been transmitted, failures are marked uncertain and
    must not be retried automatically. A successful SMTP submission does not
    confirm recipient inbox delivery.
    """
    if type(send) is not bool:
        raise DeliveryError("explicit_boolean_send_required")
    sender, recipient = _address(config.sender), _address(config.recipient)
    if (not isinstance(config.host, str) or not config.host or "/" in config.host
            or re.search(r"\s", config.host) or type(config.port) is not int
            or not 1 <= config.port <= 65535 or config.timeout <= 0):
        raise DeliveryError("invalid_smtp_configuration")
    if not isinstance(report, str) or not report.strip():
        raise DeliveryError("empty_report")
    message = build_email(report, sender, recipient, date=date)
    if not send:
        return {"status": "dry_run", "submitted": False, "sender": sender,
                "recipient": recipient, "message_bytes": len(message.as_bytes())}
    if password_file is None:
        raise DeliveryError("credential_file_required")
    password = read_secret(Path(password_file))
    client = None
    submission_started = False
    try:
        client = smtp_factory(config.host, config.port, local_hostname="localhost", timeout=config.timeout)
        if client.ehlo()[0] >= 400:
            raise DeliveryError("smtp_greeting_failed")
        # No implicit-TLS downgrade or unverified STARTTLS fallback.
        client.starttls(context=ssl.create_default_context())
        if client.ehlo()[0] >= 400:
            raise DeliveryError("smtp_tls_greeting_failed")
        client.login(sender, password)
        submission_started = True
        refused = client.send_message(message, from_addr=sender, to_addrs=[recipient])
        if refused:
            raise DeliveryError("smtp_recipient_refused")
        return {"status": "submitted", "submitted": True, "sender": sender,
                "recipient": recipient, "inbox_delivery_confirmed": False}
    except DeliveryError:
        raise
    except smtplib.SMTPRecipientsRefused:
        raise DeliveryError("smtp_recipient_refused") from None
    except smtplib.SMTPDataError:
        # Server's explicit rejection differs from a lost connection after DATA.
        raise DeliveryError("smtp_data_rejected") from None
    except Exception:
        raise DeliveryError("smtp_submission_uncertain" if submission_started
                            else "smtp_connection_or_authentication_failed",
                            uncertain=submission_started) from None
    finally:
        password = None
        if client is not None:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass


def _validate_paths(config: BackupConfig, *, require_destination=False):
    root = Path(config.root).expanduser().absolute()
    dest = Path(config.destination).expanduser().absolute()
    if root.resolve() != root or not root.is_dir():
        raise DeliveryError("backup_root_missing_or_changed")
    if dest == root or not dest.is_relative_to(root):
        raise DeliveryError("backup_destination_outside_root")
    # Resolve all existing components, including intermediate directory links.
    if dest.resolve() != dest:
        raise DeliveryError("backup_destination_symlink_or_changed")
    current = root
    for part in dest.relative_to(root).parts:
        current /= part
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise DeliveryError("backup_destination_symlink_or_changed")
    if require_destination and not dest.is_dir():
        raise DeliveryError("backup_destination_missing")
    if type(config.retention) is not int or not 1 <= config.retention <= 100:
        raise DeliveryError("invalid_backup_retention")
    return root, dest


def preflight_backup(config: BackupConfig, *, runner=subprocess.run) -> dict:
    """Read account identity and File Provider health; do not create/export files."""
    root, dest = _validate_paths(config)
    try:
        with Path(config.preferences_file).open("rb") as source:
            preferences = plistlib.load(source)
        emails = set()
        def find_accounts(value):
            if isinstance(value, dict):
                for key, entry in value.items():
                    if key == "UserEmail" and isinstance(entry, str):
                        emails.add(entry)
                    else:
                        find_accounts(entry)
            elif isinstance(value, list):
                for entry in value:
                    find_accounts(entry)
        find_accounts(preferences)
        if emails != {config.expected_account}:
            raise DeliveryError("backup_account_mismatch_or_unavailable")
        result = runner(["/usr/bin/fileproviderctl", "evaluate", str(root)],
                        check=False, capture_output=True, text=True, timeout=20)
        if result.returncode != 0 or not isinstance(result.stdout, str):
            raise DeliveryError("backup_health_unavailable")
        for flag in ("isSyncPaused", "isExcludedFromSync", "hasUnresolvedConflicts", "isTrashed"):
            values = re.findall(r"\b" + flag + r"\s*=\s*(\d+)\s*;", result.stdout)
            if not values or any(value != "0" for value in values):
                raise DeliveryError("backup_health_not_verified_" + flag)
        return {"status": "ready", "account": config.expected_account,
                "destination": str(dest), "cloud_upload_confirmed": False}
    except DeliveryError:
        raise
    except Exception:
        raise DeliveryError("backup_preflight_failed") from None


SNAPSHOT_NAME = re.compile(r"pihole-history-(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)\.sqlite\Z")
MARKER = "pihole-history-v2"


def _prune_snapshots(dest: Path, retention: int) -> list[str]:
    """Only old snapshots bearing this adapter's original generator marker."""
    valid = []
    for path in dest.iterdir():
        match = SNAPSHOT_NAME.fullmatch(path.name)
        if not match:
            continue
        try:
            datetime.strptime(match[1], "%Y-%m-%dT%H-%M-%S-%fZ")
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                continue
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
                marker = db.execute("SELECT value FROM metadata WHERE key='snapshot_generator'").fetchone()
            after = path.lstat()
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
            if marker and marker[0] == MARKER and identity(before) == identity(after):
                valid.append((path, after))
        except (OSError, ValueError, sqlite3.Error):
            continue
    removed = []
    for path, original in sorted(valid, key=lambda item: item[0].name, reverse=True)[retention:]:
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) == (
                original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns):
            path.unlink()
            removed.append(path.name)
    return removed


def export_backup(source, config: BackupConfig, *, export=False,
                  runner=subprocess.run, now=None, prune: bool = True,
                  operation_id: str | None = None, source_digest: str | None = None) -> dict:
    """Default is a no-I/O dry run. Explicit export requires healthy identity.

    Caller must have authorization for the account, destination and full data
    scope. Local publication never establishes successful cloud upload.
    Set prune=False for an authorized one-off validation without deleting backups.
    """
    if type(export) is not bool:
        raise DeliveryError("explicit_boolean_export_required")
    if type(prune) is not bool:
        raise DeliveryError("explicit_boolean_prune_required")
    if not export:
        return {"status": "dry_run", "exported": False, "cloud_upload_confirmed": False}
    if operation_id is not None and not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise DeliveryError("invalid_backup_operation_id")
    if source_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise DeliveryError("invalid_backup_source_digest")
    preflight_backup(config, runner=runner)
    root, dest = _validate_paths(config)
    source = Path(source).expanduser().resolve()
    if source.is_relative_to(root):
        raise DeliveryError("active_database_must_be_local")
    moment = datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now, timezone.utc)
    stamp = moment.strftime("%Y-%m-%dT%H-%M-%S-") + f"{moment.microsecond // 1000:03d}Z"
    target = dest / ("pihole-history-" + stamp + ".sqlite")
    publishing = None
    published = False
    try:
        with tempfile.TemporaryDirectory(prefix="pihole-python-backup-") as staging:
            temp = Path(staging) / "history.sqlite"
            fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src, closing(sqlite3.connect(temp)) as db:
                src.backup(db)
                db.execute("PRAGMA journal_mode=DELETE")
                db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('snapshot_generator',?)", (MARKER,))
                if operation_id is not None:
                    db.execute("INSERT OR REPLACE INTO metadata VALUES('backup_operation_id',?)", (operation_id,))
                if source_digest is not None:
                    db.execute("INSERT OR REPLACE INTO metadata VALUES('backup_source_sha256',?)", (source_digest,))
                db.commit()
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchall():
                    raise DeliveryError("backup_integrity_failed")
            with temp.open("rb") as handle:
                os.fsync(handle.fileno())
            # Recheck account/health after the potentially long SQLite backup.
            preflight_backup(config, runner=runner)
            current = root
            for component in dest.relative_to(root).parts:
                current /= component
                current.mkdir(mode=0o700, exist_ok=True)
                if current.is_symlink() or current.resolve() != current:
                    raise DeliveryError("backup_destination_symlink_or_changed")
            _validate_paths(config, require_destination=True)
            lock_fd = os.open(dest / ".python-backup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            with os.fdopen(lock_fd, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                publishing = dest / (".publishing-python-" + uuid.uuid4().hex)
                out_fd = os.open(publishing, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(out_fd, "wb") as out, temp.open("rb") as inp:
                    shutil.copyfileobj(inp, out)
                    out.flush()
                    os.fsync(out.fileno())
                os.link(publishing, target)  # Exclusive atomic publication, no overwrite.
                published = True
                publishing.unlink()
                publishing = None
                removed = _prune_snapshots(dest, config.retention) if prune else []
            return {"status": "published_locally", "exported": True,
                    "snapshot": str(target), "pruned": removed,
                    "cloud_upload_confirmed": False}
    except DeliveryError:
        raise
    except Exception:
        raise DeliveryError("backup_published_cleanup_failed" if published else "backup_export_failed",
                            uncertain=published) from None
    finally:
        if publishing is not None:
            try:
                publishing.unlink()
            except OSError:
                pass


def backup_target(config, planned_at):
    moment = datetime.fromtimestamp(planned_at, timezone.utc)
    stamp = moment.strftime("%Y-%m-%dT%H-%M-%S-") + f"{moment.microsecond // 1000:03d}Z"
    return Path(config.destination) / ("pihole-history-" + stamp + ".sqlite")


def inspect_backup(config, planned_at, operation_id, source_digest):
    """Read-only identity reconciliation. Caller must bound filesystem waiting."""
    _validate_paths(config)
    target = backup_target(config, planned_at)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return {"status": "absent", "snapshot": str(target), "exported": False}
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise DeliveryError("backup_target_identity_conflict", uncertain=True)
    with closing(sqlite3.connect(target.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        metadata = dict(db.execute("SELECT key,value FROM metadata WHERE key IN ('snapshot_generator','backup_operation_id','backup_source_sha256')"))
        if (metadata.get("snapshot_generator") != MARKER
                or metadata.get("backup_operation_id") != operation_id
                or metadata.get("backup_source_sha256") != source_digest):
            raise DeliveryError("backup_target_identity_conflict", uncertain=True)
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
            raise DeliveryError("backup_target_integrity_failed", uncertain=True)
    return {"status": "published_locally", "snapshot": str(target), "exported": True,
            "reconciled": True, "cloud_upload_confirmed": False}


def run_backup_worker(request, *, timeout=90, popen=subprocess.Popen, on_start=None, killpg=os.killpg):
    """Own a short-lived child; never terminate any pre-existing process.

    The request contains only approved local paths and operation identifiers.
    No password, token, API key or inherited credential environment is passed.
    """
    import json
    import sys
    import signal
    from .cli import PROJECT
    if not 0 < timeout <= 300:
        raise ValueError("Backup worker timeout must be bounded")
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                   "PYTHONPATH": str(PROJECT), "PYTHONDONTWRITEBYTECODE": "1"}
    child = popen([sys.executable, "-m", "pihole_report.delivery", "--backup-worker"],
                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                  text=True, cwd=PROJECT, env=environment, start_new_session=True)
    def stop_owned_group():
        # Only this Popen-created session is signalled, never a recovered ledger PID.
        try:
            killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        # Descendants can outlive the leader or ignore TERM. Kill the whole owned
        # group even when the parent has already exited, then bound pipe cleanup.
        try:
            killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            raise DeliveryError("backup_worker_termination_unconfirmed", uncertain=True) from None
    try:
        if on_start is not None:
            on_start(child.pid)
    except Exception:
        child.stdin.close()
        child.stdin = None
        stop_owned_group()
        raise DeliveryError("backup_worker_state_unavailable", uncertain=True) from None
    try:
        output, _ = child.communicate(json.dumps(request), timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_owned_group()
        raise DeliveryError("backup_worker_timeout", uncertain=True) from None
    if child.returncode != 0:
        raise DeliveryError("backup_worker_outcome_unconfirmed", uncertain=True)
    try:
        if len(output.encode()) > 65536:
            raise ValueError()
        data = json.loads(output)
        if not isinstance(data, dict):
            raise ValueError()
    except (ValueError, TypeError):
        raise DeliveryError("backup_worker_invalid_result", uncertain=True) from None
    if data.get("error_code"):
        raise DeliveryError(data["error_code"], uncertain=data.get("uncertain") is True)
    return data


def _backup_worker_main():
    """Only callable with the same validated production manifest as the parent."""
    import hashlib
    import json
    import sys
    from .production import load_manifest
    try:
        manifest = load_manifest()
        scope = manifest["scope"]
        request = json.loads(sys.stdin.read(16385))
        if set(request) != {"mode", "local_date", "operation_id", "planned_at", "source_digest"}:
            raise DeliveryError("invalid_backup_worker_request")
        if (request["mode"] not in {"export", "inspect"}
                or not re.fullmatch(r"[0-9a-f]{32}", request["operation_id"])
                or not re.fullmatch(r"[0-9a-f]{64}", request["source_digest"])):
            raise DeliveryError("invalid_backup_worker_request")
        day = datetime.strptime(request["local_date"], "%Y-%m-%d").date().isoformat()
        if (type(request["planned_at"]) not in (int, float)
                or datetime.fromtimestamp(request["planned_at"]).astimezone().date().isoformat() != day):
            raise DeliveryError("invalid_backup_worker_request")
        config = BackupConfig(scope["backup_account"], Path(scope["backup_root"]),
            Path(scope["backup_destination"]), Path(scope["backup_preferences"]), scope["backup_retention"])
        source = Path(scope["state_directory"]) / "artifacts" / day / (request["operation_id"] + ".sqlite")
        if source.resolve() != source or source.is_symlink():
            raise DeliveryError("invalid_backup_source_path")
        existing = inspect_backup(config, request["planned_at"], request["operation_id"], request["source_digest"])
        if request["mode"] == "inspect" or existing["status"] != "absent":
            result = existing
        else:
            digest = hashlib.sha256()
            with source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != request["source_digest"]:
                raise DeliveryError("backup_source_changed")
            result = export_backup(source, config, export=True, now=request["planned_at"],
                operation_id=request["operation_id"], source_digest=request["source_digest"])
        print(json.dumps(result))
        return 0
    except DeliveryError as error:
        print(json.dumps({"error_code": error.code, "uncertain": error.uncertain}))
        return 0
    except Exception:
        print(json.dumps({"error_code": "backup_worker_failed", "uncertain": True}))
        return 0


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--backup-worker"]:
        raise SystemExit("Use the manifest-gated production runner")
    raise SystemExit(_backup_worker_main())

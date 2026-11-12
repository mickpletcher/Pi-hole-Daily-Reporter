# Privacy and operational safety

## Keep private files out of Git

Publish application code, synthetic tests and placeholder examples only. Never
commit deployment manifests, credentials, CA/private-key material, real DNS
history, reports, client names/IPs/MACs, inventory, research caches, log files,
backup snapshots, validation receipts or exported email. The ignore file helps,
but it does not replace review of `git diff --cached` and the complete commit.

Use example domains and documentation IP ranges in shared examples. Inspect
commit author/committer names and email addresses too. A clean working tree says
nothing about files already committed or the contents of older history.

This source distribution contains no copied runtime database or deployment
configuration. Prior installation policy exceptions and personal audit provenance
are not seeded into new databases. Existing repository license/history is outside
the application's runtime data.

## Credentials and transport

Store secrets in owner-only files outside the repository. Do not put passwords,
tokens or keys in command-line arguments, committed JSON, environment dumps or
logs. The application reads its configured credential files only for explicit
operations. Provider exceptions are sanitized before durable logging.

HTTPS and SMTP certificate/hostname verification are required. No plain-HTTP or
certificate-verification bypass is provided. If a local service certificate is
untrusted, fix trust deliberately; do not turn verification off. A scoped TCP
address and TLS hostname are separate configuration values, not a system-DNS edit.

## Scope and authorization

Production is disabled until local configuration and a hash-bound enabled
manifest match. Exact account/destination declarations prevent silent changes
through environment variables. Inspect recipient, backup account, destination,
retention, schedule and complete-history scope before enabling an installation.
Do not infer permission for a new recipient, provider or security setting.

The report does not change Pi-hole filters or rules. Research is local cache only;
there is no scheduled AI or hosted research call. Public curated-list refresh is
optional and requires a configured source. OneDrive and SMTP are optional adapters
which require explicit production setup.

## Recovery

Do not retry an unknown delivery outcome merely to obtain a fresh log. Inspect the
existing process, stage ledger and provider result first. Frozen report identities
and durable email holds are more important than making a status look successful.
An interrupted source transition requires inspection of its receipt and installed
hashes. Do not restore an old database or stale ledger during an ordinary rollback.

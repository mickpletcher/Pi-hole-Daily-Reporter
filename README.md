# Pi-hole-Daily-Reporter
A Python application that collects Pi-hole DNS activity, tracks domain history, and generates daily reports with automated backups.


## What it does

- Collects fixed-window Pi-hole DNS observations into local SQLite history.
- Keeps cumulative measured counts separate from overlapping daily snapshots.
- Reports allowed/blocked query totals, distinct hostnames, time coverage and gaps.
- Attributes sampled client requests to their exact allowed/blocked outcome.
- Reuses verified local research. It does not automatically call an AI service,
  research provider, or change Pi-hole rules.
- Records research-needed hostnames, input freshness and operational stage status.
- Can deliver a compressed report over verified SMTP TLS and export verified
  snapshots to an explicitly configured local OneDrive folder.
- Recovers collection and backup stages independently while conservatively
  preventing duplicate email after known or uncertain submission.

DNS queries are not website visits, and hostnames are not complete URLs.
A hostname can be both allowed and blocked. API exclusions, privacy settings,
retention gaps and the intentional recent collection delay are reported rather
than treated as complete network visibility.

## Requirements and tests

Python 3.11 or newer; the application uses only the Python standard library.
The production scheduler and OneDrive integration are macOS-specific. No local
installation, account, device inventory or DNS history is included here.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 -m pihole_report --help
python3 -m pihole_report health
```

Tests use temporary synthetic data and injected transports. They do not send
email, access real credentials, export a cloud backup or run a scheduled job.
`health` reads a small local status snapshot without network requests or retries;
before a production run creates that snapshot, it reports unavailable.

## Configuration and deployment

This repository is a privacy-clean, portable source distribution. Installation-
specific accounts, addresses, policy exceptions, old audit evidence and operational
records were intentionally excluded. It is not a backup of a live installation.

Start with the disabled example under `examples/`. Local deployment configuration
and the enabled production manifest must never be committed. Use owner-only
permissions, separately stored credential files, a verified CA and an explicit
approved destination. A production manifest must match both the declared local
scope and the reviewed module hashes; source changes invalidate its old hashes.
See [configuration](docs/CONFIGURATION.md) and [safety and privacy](docs/PRIVACY.md).

The ordinary CLI's report-writing commands are confined to private shadow copies
inside this checkout. Start with a consistent copy of an existing compatible
history and validate there. Keep active SQLite databases outside synced storage.
A source checkout or test pass does not authorize a production switch, message,
backup upload, certificate bypass or schedule change.

Do not reload an existing launchd job just to update code. A job with `RunAtLoad`
can execute immediately on reload. Source migration/upgrade helpers have separate
read-only plans, explicit execution, locks and conservative rollback guards.
Always review a plan and preserve the live delivery ledger and newer history.

## Recovery and retention

- Submitted or uncertain email is held instead of automatically resent.
- Known non-submission can reuse a verified frozen report; recovered history does
  not silently change the report already delivered.
- Backup work follows email in a bounded owned process group. An uncertain backup
  is reconciled by operation identity before a retry.
- A new local date has independent stages. There is no automatic retry loop.
- Recognized application run logs are removed at 30 days when a report runs.
  Unrelated files, malformed logs and links are not deleted.
- Historical databases, validation archives and frozen recovery artifacts are not
  subject to that log cleanup. Frozen artifacts currently need a separately
  chosen retention policy.

SMTP acceptance is not proof of inbox receipt. Publication in a synced folder
is not proof of cloud upload. Verify those outcomes separately.

## Source layout

| Module | Responsibility |
|---|---|
| `storage`, `collector`, `coverage` | Transactions, deduplication, bounded collection and interval evidence |
| `report`, `runlog`, `health` | Deterministic reports, cached research, counts, logs and local health |
| `integrations`, `delivery` | Verified HTTPS, snapshots, inventory/list inputs, SMTP and backup adapters |
| `pipeline`, `production`, `cli` | Shadow execution, explicit deployment gates and independent stages |
| `migration`, `upgrade` | Planned source transitions, archival receipts and delivery-safe rollback |

The public source is independently tested after privacy sanitization. It is not
installed into or automatically synchronized with any live deployment.


## Readable daily CSV review list

Each configured daily run also publishes a readable research-needed CSV to its
approved OneDrive backup folder. This uses the exact frozen report window's list,
not the cumulative queue. Columns include hostname, cache status, new-to-history,
review reason/action and UTC window bounds. Hostnames are not converted into
invented full URLs. Files are UTF-8 with a BOM, quoted for Excel, sorted by hostname
and protected against spreadsheet formulas. An empty list still has a header.

Names follow `pihole-research-needed-YYYY-MM-DD-<snapshot-prefix>.csv`. Different
content at an existing name is never overwritten; identical bytes can be verified
and reused. CSV failures recover independently without resending email or repeating
a successful SQLite backup. Local publication is distinct from confirmed upload.

CSVs are retained until explicitly removed. The 30-day JSON-log cleanup and
SQLite-snapshot retention do not delete CSVs. Generated CSVs and all real examples
belong outside Git and are ignored. Version 0.5 adds this behavior; existing private
installations require their own reviewed, manifest-bound deployment.

Version 0.5.1 appends an empty `Block` column to every new CSV. This is a manual
review field: `1` means block, `0` means do not block, and blank means undecided.
The reporter does not infer or apply these decisions, import edited CSVs, or
overwrite existing files. Manual edits remain untouched.

### Research CSV domain column

New research CSVs start with `domain`, then `hostname`; for example `apple.com`, `click.apple.com`. Domain is the registrable domain (eTLD+1), calculated offline using the bundled Public Suffix List including private suffixes. Multi-part suffixes such as `co.uk` and separate private-platform tenants are handled correctly. IP addresses, local/invalid names and public-suffix-only inputs produce an empty domain. The hostname remains unchanged and `Block` remains blank for new exports. Existing edited CSVs are never overwritten or migrated automatically.

The vendored PSL snapshot is MPL-2.0 licensed (see its header); no DNS-history data is sent to a lookup service and no runtime network fetch is needed.

## Source comparison

New research CSVs can screen hostnames locally against a configurable list of current blocklist feeds. See [configuration, matching rules and limitations](docs/SOURCE_COMPARISON.md). Manual Block decisions remain separate.

## Community and contributions

See [contributing](CONTRIBUTING.md), our [Code of Conduct](CODE_OF_CONDUCT.md),
[security policy](SECURITY.md), and [accessibility statement](ACCESSIBILITY.md). Use the
[issue templates](https://github.com/mickpletcher/Pi-hole-Daily-Reporter/issues/new/choose)
for bugs, feature requests, and accessibility barriers. Pull requests include a
review checklist. For vulnerabilities, check the repository's
[Security tab](https://github.com/mickpletcher/Pi-hole-Daily-Reporter/security)
for a private reporting route; never post sensitive details in public issues.
The project is [MIT licensed](LICENSE). The prioritized
[upgrade roadmap](future-upgrades.md) and [contributor guidance](AGENTS.md)
explain how planned improvements are maintained.

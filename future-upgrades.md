# Future upgrades

Prioritized upgrade recommendations for Pi-hole-Daily-Reporter.

Reviewed against version 0.6.0, commit `dfbe0ca`. These are proposed upgrades,
not implemented features or authorization to change a live installation.
Rank numbers are global: complete Tier 1 before expanding into Tiers 2 and 3.
Within each tier, lower numbers have higher importance. Priority reflects data
integrity, trustworthy recommendations and operational reliability before convenience.

## Existing foundation

The package already has manifest-bound deployment, independent recovery stages,
frozen reports, duplicate-email protection, offline registrable-domain extraction,
CSV formula protection and a tested blocklist matcher. New CSVs start with
`domain,hostname`, and recommendations are separate from the blank manual `Block`
field. The example inventory currently contains 23 feeds, not 57.

All upgrades must preserve these boundaries:

- Never overwrite an edited CSV or infer a manual `Block` decision.
- Never change Pi-hole rules as a side effect of report generation.
- A blocklist match is a recommendation, not a malware verdict; no match is not
  proof of safety. Overlapping feeds are not independent votes.
- Keep hostname matching separate from base-domain grouping. A match for
  `click.example.com` must not become a recommendation to block `example.com`.
- Keep DNS history, credentials, deployment details and real reports out of Git.
- Preserve frozen retry content, delivery holds, TLS verification and explicit
  approval for production deployment or new external data sharing.

## Tier 1: Highest importance — reliability and evidence

### 1. Add continuous integration for the existing safety tests

**Why:** The repository has extensive synthetic unit tests but no checked-in
GitHub Actions workflow. Every source change should exercise the existing
collection, delivery, CSV and deployment safeguards automatically.

**Upgrade:** Add an offline test workflow for supported Python versions, including
Python 3.11, and macOS coverage for platform-specific behavior. Keep live feeds,
credentials, email and OneDrive out of CI. Add a lightweight Markdown/local-link
check for documentation-only changes.

**Done when:** Pull requests show test results for their exact commit; fixtures
cover CSV schemas 1–3, edited-file collisions, frozen retries and uncertain email
holds. CI artifacts contain only synthetic data.

**Starting points:** `tests/`, `pyproject.toml`, `README.md`.

### 2. Make feed degradation visible in operational health

**Why:** `source_check.py` records individual feed failures, hashes and partial
parses, but the read-only health interface is oriented around collection,
curated-list freshness and delivery stages. Report delivery can succeed while
external comparison coverage is incomplete.

**Upgrade:** Persist a compact external-comparison health summary: last check,
complete/partial/failed counts, duration and recurring failure reasons. Surface it
in the existing read-only `health` command without fetching feeds or retrying work.
Distinguish unsupported IP entries from parser failures and unsupported exceptions;
do not silently convert partial coverage into complete coverage.

**Done when:** Synthetic timeout, HTTP failure and unsupported-rule cases remain
visible after a successful delivery, and no health check initiates network access.

**Starting points:** `pihole_report/source_check.py`, `pihole_report/health.py`,
`pihole_report/production.py`, `tests/test_source_check.py`.

### 3. Preserve rule-level evidence for each recommendation

**Why:** CSVs currently identify matching source URLs, while feed metadata retains
hashes and rule counts. Reviewers cannot see the exact rule and matching mode that
produced a recommendation.

**Upgrade:** Record bounded evidence for each match: source hash, matched rule,
exact-versus-descendant mode, and the effect of supported exceptions. Expose a
compact explanation in a versioned export or local evidence sidecar. Freeze it
with the report and sanitize all spreadsheet cells.

**Done when:** A reviewer can explain a recommendation without redownloading a
changed feed; unsupported exceptions still suppress that feed's positive matches;
old frozen CSVs reproduce byte-for-byte.

**Starting points:** `pihole_report/source_check.py`,
`pihole_report/research_csv.py`, `docs/SOURCE_COMPARISON.md`.

### 4. Add a safe end-to-end release validation harness

**Why:** Unit tests and source validation do not establish that a complete
scheduled run generates, freezes, delivers and recovers the intended artifacts.
The README correctly distinguishes local publication from confirmed cloud upload.

**Upgrade:** Add a documented release checklist and synthetic end-to-end harness
using injected Pi-hole, SMTP and backup adapters. Cover source-comparison failure,
interrupted CSV export, midnight/date boundaries and restart recovery. Provide a
read-only post-run verification checklist for separately approved live deployments.

**Done when:** A synthetic run proves all artifact identities and independent
recovery paths; live checks report SMTP acceptance and local publication accurately,
without claiming inbox receipt or cloud upload that has not been verified.

**Starting points:** `tests/test_production.py`, `tests/test_pipeline.py`,
`tests/test_delivery.py`, `docs/CONFIGURATION.md`.

## Tier 2: Important — maintainability and review efficiency

### 5. Add feed metadata and conservative change detection

**Why:** The URL inventory is deliberately simple, but URLs alone do not describe
purpose, overlap, ownership or an unexpected collapse in supported rule counts.

**Upgrade:** Keep the line-based URL file compatible and add an optional metadata
sidecar for feed name, category, upstream family, format and maintenance notes.
Compare rule counts and hashes between checks, flagging suspicious changes for
review rather than automatically treating a changed feed as safe or trustworthy.

**Done when:** Ads/tracking, malware and policy-only feeds are distinguishable;
related aggregates are not counted as independent confidence votes; new metadata
cannot silently enable service-wide blocking or change manual decisions.

**Starting points:** `examples/blocklist-sources.txt`,
`pihole_report/source_check.py`, `docs/SOURCE_COMPARISON.md`.

### 6. Establish a reproducible Public Suffix List update process

**Why:** Domain extraction uses an offline vendored snapshot. This preserves
privacy but requires deliberate maintenance as suffix and private-platform rules
change.

**Upgrade:** Add a maintainer-only refresh tool with recorded upstream revision,
checksum and license provenance. Review changes and run wildcard, exception,
IDNA and private-tenant fixtures before publishing a new snapshot. Keep report
execution offline for domain extraction.

**Done when:** A snapshot can be reproduced and reviewed, with tests showing that
private tenants remain separate and old frozen export identities remain recoverable.

**Starting points:** `pihole_report/domains.py`,
`pihole_report/public_suffix_data.py`, `tests/test_domains.py`.

### 7. Add an explicit review-decision ledger

**Why:** The manual `Block` column is intentionally not imported today. Decisions
made in one daily CSV therefore cannot yet become a structured, reusable review
history inside the reporter.

**Upgrade:** Offer a separate opt-in import command with a preview, strict
`blank/0/1` validation, hostname and snapshot identity checks, conflict handling,
and an audit trail. Store decisions separately from generated recommendations.
Show prior decisions in a separate field rather than pre-filling or overwriting
new CSVs' manual `Block` values.

**Done when:** Duplicate imports are idempotent, conflicts require explicit
resolution, source CSVs are untouched, and importing never applies Pi-hole rules.

**Starting points:** `pihole_report/research_csv.py`,
`pihole_report/storage.py`, `pihole_report/cli.py`.

### 8. Define retention and recovery-artifact lifecycle rules

**Why:** Recognized run logs already have 30-day cleanup and SQLite backups have
configured retention, but frozen recovery artifacts and CSVs are retained without
a general cleanup policy.

**Upgrade:** Add a dry-run inventory of artifact size, age and recovery references.
Design separately configured retention with explicit execution and protections for
uncertain delivery, pending recovery and manually edited CSVs. Prefer archiving
before any irreversible removal.

**Done when:** A preview explains every candidate and protected artifact; cleanup
cannot remove evidence required for deduplication or recovery, and CSV deletion
is never included implicitly.

**Starting points:** `pihole_report/production.py`,
`pihole_report/runlog.py`, `pihole_report/delivery.py`, `README.md`.

## Tier 3: Optional — performance and richer analysis

### 9. Optimize feed refresh with explicit freshness semantics

**Why:** Each new report currently downloads every configured feed, with bounded
concurrency and a worker deadline. This is simple and honest but repeats work for
unchanged large feeds.

**Upgrade:** Benchmark synthetic large inventories first. Consider conditional
HTTPS requests using ETag/Last-Modified and integrity-checked local cached bodies.
A successful revalidation may reuse content; a failed refresh must remain marked
incomplete or stale, never presented as a fresh successful check.

**Done when:** Measured runtime/bandwidth improves while existing size limits,
public-address checks, TLS verification, frozen retries and freshness warnings
remain intact. Live feed benchmarking is separate from offline CI.

**Starting points:** `pihole_report/source_check.py`,
`pihole_report/integrations.py`, `tests/test_source_check.py`.

### 10. Add a local, read-only review view

**Why:** CSV remains useful for Excel, but long source URL fields and many
hostnames make manual comparison cumbersome.

**Upgrade:** Generate an optional static HTML view with base-domain grouping,
full-hostname detail, filters for recommendations and incomplete checks, and
links to local evidence. Escape all untrusted values; embed no analytics, remote
scripts or automatic lookups. Keep CSV as the editable decision interface.

**Done when:** The view works offline, does not expose reports on a network
service, and cannot modify Pi-hole or existing review files.

**Starting points:** `pihole_report/report.py`,
`pihole_report/research_csv.py`.

### 11. Add coverage-aware trends and review prioritization

**Why:** SQLite already preserves measured domain history and the package
explicitly tracks coverage gaps. This supports useful trends, provided missing
observations are not confused with lower activity.

**Upgrade:** Add configurable local summaries of newly seen hostnames, recurring
unreviewed entries and changes in measured query volume. Display coverage alongside
comparisons and suppress misleading rankings for incomplete windows. Keep feed
membership separate from behavioral significance.

**Done when:** Tests demonstrate correct handling of overlapping windows, missing
data and hostnames with both allowed and blocked outcomes; DNS counts are never
labeled website visits or proof of malicious activity.

**Starting points:** `pihole_report/storage.py`, `pihole_report/coverage.py`,
`pihole_report/report.py`.

### 12. Improve portable installation and upgrade documentation

**Why:** The source distribution is portable, but production scheduling and
OneDrive integration are macOS-specific and deployment requires reviewed hashes.

**Upgrade:** Document a reproducible package build and upgrade checklist, supported
Python/platform combinations and a clear adapter boundary. Consider other scheduler
or backup adapters only after the current macOS path has repeatable validation.
Do not add an installer that enables production or reloads launchd automatically.

**Done when:** A clean synthetic installation can run offline tests and help/health
commands; a documented upgrade preserves the live ledger and requires deliberate
manifest review before production execution.

**Starting points:** `pyproject.toml`, `pihole_report/deployment.py`,
`pihole_report/upgrade.py`, `docs/CONFIGURATION.md`.

## Maintenance

Reassess this ranking after each release. Move completed work into release notes
with its commit and validation evidence instead of leaving it labeled future work.
Whenever a listed upgrade is implemented, review this roadmap in the same change.
If possible, add a new, useful recommendation grounded in the current package,
with rationale, completion criteria and code references. Place it in the appropriate
tier and rerank the remaining work. Do not add filler or relist completed features
just to preserve the number of recommendations. If no worthwhile replacement is
identified, note that briefly in the change summary. See [contributor and agent
guidance](AGENTS.md).

Implementation, production rollout and any new data-sharing integration are
separate decisions; this roadmap does not enable them.

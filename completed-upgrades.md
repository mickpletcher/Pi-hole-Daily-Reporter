# Completed upgrades

Verified implementations moved from [future upgrades](future-upgrades.md).
Source publication does not imply deployment to a running installation.

## 2026-11-14 — Offline continuous integration

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

**Implemented:** Exact PR-head checkout, Linux and macOS jobs on Python
3.11–3.14, lightweight offline Markdown/local-link checks, read-only workflow
permissions and pinned actions. The clean-home runner strips account settings
and denies real Python network activity, including child workers. No artifacts
are uploaded. See [CI documentation](docs/CI.md).

**Validation:** Commit `71907b2434f0f9e2cf791c9996901537172f95b5` passed all
nine hosted jobs: 199 synthetic tests on each of eight OS/Python combinations,
plus Markdown/local links. [Verified Actions run](https://github.com/mickpletcher/Pi-hole-Daily-Reporter/actions/runs/43578990456).
The first run exposed a macOS temporary-path fixture mismatch, corrected before
completion. Existing fixtures cover frozen retries and uncertain email holds;
added fixtures explicitly exercise all CSV versions and edited collisions.
No live installation, user reports, credentials, email or OneDrive was used.

**Roadmap replacement:** Added safety-branch coverage and mutation resistance,
ranked in Tier 2. This recommendation is not implemented by the CI upgrade.

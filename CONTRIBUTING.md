# Contributing

Thank you for helping improve Pi-hole Daily Reporter. Bug fixes, tests,
documentation, accessibility improvements, and focused feature proposals are
welcome. Follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

Search existing issues and [future upgrades](future-upgrades.md) before proposing
work. Use the appropriate issue template for bugs, features, or accessibility
barriers. Discuss large changes first to avoid unnecessary work. Do not report
vulnerabilities in public issues: read [SECURITY.md](SECURITY.md) and use the repository's Security tab to look for
private reporting. If unavailable, request a private contact route without
publishing vulnerability details.

Read [AGENTS.md](AGENTS.md), the [README](README.md),
[configuration](docs/CONFIGURATION.md), and [privacy guidance](docs/PRIVACY.md).
This public source distribution is not a live installation or its backup.

## Development and validation

Use Python 3.11 or newer. Runtime and tests use the standard library; no live
Pi-hole, email account, credentials, or OneDrive access is needed for unit tests.
Fork the repository, create a focused branch, and run from the checkout root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m pihole_report --help
```

See [offline CI](docs/CI.md) for the exact-commit test matrix and local guarded
runner.

Tests use temporary synthetic fixtures and injected transports. Add regression
tests for changed behavior. Record the Python version, commands, and results in
your pull request. Review Markdown headings, relative links, and issue-template
frontmatter for documentation changes. Do not claim unrun checks passed.

Never run production jobs as a contribution check. Do not reload launchd, enable
a production manifest, send email, fetch live feeds, or upload backups as part of
routine validation. Source publication does not authorize deployment. Production
scheduling and OneDrive integration are macOS-specific; portability changes need
explicit evidence rather than assumptions based on a Linux test pass.

## Preserve safety and data integrity

- Commit code, synthetic fixtures, and placeholder examples only. Never commit
  real DNS history, client identifiers, reports, databases, secrets, logs,
  deployment manifests, or operational receipts.
- Use example domains and documentation IP addresses. Redact screenshots and
  error output before sharing. Check the full staged diff, not only `.gitignore`.
- Preserve TLS verification, destination declarations, manifest checks, and
  conservative recovery of uncertain delivery outcomes.
- Never overwrite an edited research CSV or populate its manual `Block` decision
  from an automated recommendation. Matching a hostname must not silently imply
  blocking its base domain. The reporter must not change Pi-hole rules.
- Keep frozen reports/retries reproducible. Introduce schema changes deliberately
  and test compatibility and collisions.

## Pull requests

Keep each change focused, describe its purpose, link related issues, and complete
the PR checklist. Update documentation when behavior, commands, formats, or
limitations change. Follow [accessibility guidance](ACCESSIBILITY.md) for output
and documentation changes. Include test evidence and disclose remaining gaps.

When completing an upgrade listed in `future-upgrades.md`, follow `AGENTS.md`:
record completion evidence, add a useful replacement if possible, and rerank the
roadmap. Do not invent filler. This community-documentation change itself does
not complete any of the roadmap's implementation upgrades.

Maintainer review is required before merging contributions. Respect the existing
[MIT license](LICENSE), retain third-party notices (including the vendored Public
Suffix List's MPL-2.0 notice), and submit only material you have the right to share.

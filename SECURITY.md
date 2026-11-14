# Security Policy

## Reporting a vulnerability

Do not put vulnerabilities, exploit details, credentials, DNS history, or real reports in public issues or pull requests.

Use the repository's [Security tab](https://github.com/mickpletcher/Pi-hole-Daily-Reporter/security) and choose **Report a vulnerability** if GitHub private vulnerability reporting is available. If that option is absent, open a public issue containing only a request for a private reporting channel. Wait for a maintainer to establish that channel before sharing details. Do not assume a public issue or GitHub profile is private.

Include the affected commit/version, a description of the impact, and minimal reproduction steps using synthetic data. Share sensitive evidence only through the agreed private channel. There is no guaranteed response time, bounty program, or supported backport schedule stated by this project.

## Versions and updates

Report problems against any version, and identify whether they reproduce on current `main`. Fix availability and affected versions must be confirmed for each report; this policy does not promise maintenance of older releases. Updating source does not update a live installation or authorize changing its deployment manifest.

## Scope and security expectations

The reporter collects Pi-hole data into local SQLite history and optionally uses configured HTTPS feeds, SMTP delivery, and a local OneDrive destination. DNS history, client identifiers, credentials, backups, and reports can contain private information.

Security-relevant boundaries include untrusted API/feed data and hostnames, local filesystem paths, generated reports/CSV cells, configured destinations, and production authorization. Reviewers should investigate failures in TLS verification, credential handling, output escaping/formula protection, bounded input processing, path confinement, manifest checks, and recovery/delivery integrity. These are intended properties, not a claim that vulnerabilities cannot exist.

A source-comparison recommendation must not change Pi-hole rules or override a manual `Block` decision. Uncertain delivery must not silently trigger duplicate email. Source publication must not include private runtime data.

No vulnerability class is categorically excluded by this policy. Explain realistic prerequisites, reachability, and impact without testing against someone else's systems or real data.

## Safe development and deployment

Use temporary synthetic fixtures and injected transports for tests. Do not upload live databases, logs, configuration, credentials, or reports as evidence. Keep secrets outside the checkout, preserve certificate verification, and review staged changes for private data.

See [privacy and operational safety](docs/PRIVACY.md), [configuration](docs/CONFIGURATION.md), and [contributing](CONTRIBUTING.md). Production deployment, scheduling, external delivery, and changes to security settings require separate review and authorization.

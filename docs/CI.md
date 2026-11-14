# Offline continuous integration

The `Offline safety checks` workflow runs on main pushes, all pull requests, and
manual dispatch. It checks out the exact PR head SHA, not the synthetic merge
commit, and prints that revision in each safety job. Both Linux and macOS run
Python 3.11, 3.12, 3.13 and 3.14. Python 3.11 is the declared minimum; future
Python releases are not claimed tested until added to this matrix.

Every change, including documentation-only changes, receives the lightweight
Markdown/local-link check and the safety suite. Keeping stable job names and no
path filters avoids missing checks. Repository administrators can separately
choose required checks; this workflow does not change branch protection.

Run locally from the repository root:

```sh
python3 scripts/check_docs.py
python3 scripts/run_offline_tests.py
```

The documentation check validates local inline Markdown file/heading links,
heading spacing and closed code fences without fetching URLs. It is deliberately
not a full Markdown renderer or an external-link availability checker.

The test launcher uses a temporary HOME and temporary output directory, strips
inherited account/configuration environment variables and installs an audit hook
that denies real socket connections, listeners, sends and DNS resolution. Python
child workers inherit the guard. Tests may patch transports with synthetic mocks.
The launcher checks that the guard is active before running the suite. This is a
regression guard, not a sandbox against intentionally malicious code. GitHub's
checkout and Python setup require network access before the offline suite starts.

No credentials, live feeds, real Pi-hole, email service, OneDrive directory or
production manifests are supplied. CI does not call production commands, deploy,
cache reports or upload artifacts. Thus no user reports or databases can enter CI
artifacts; only synthetic test output appears in job logs. Actions are pinned by
commit and the workflow token has only read access to repository contents.

## Safety evidence

- `tests/test_ci.py`: all CSV schema 1–3 column layouts, deterministic bytes,
  idempotent publication and preservation of edited-file collisions.
- `tests/test_domains.py` and `tests/test_source_check.py`: legacy schema fixtures.
- `tests/test_research_csv.py`: real-format manual Block edits are never overwritten.
- `tests/test_production.py`: frozen report reuse after known email failure,
  changed-frozen-report refusal, and uncertain email suppression without retry.
- `tests/test_delivery.py`: uncertain submission sanitization and bounded workers.
- `tests/test_deployment.py` and `tests/test_upgrade.py`: manifest and upgrade safety.

A local pass is not evidence of a hosted macOS or matrix pass. Review the Actions
run for the specific commit before recording that upgrade as completed.

# Local configuration

This repository deliberately does not include a runnable personal deployment.
Examples contain documentation-only addresses and disabled production settings.
Do not replace placeholders with real details in a tracked example.

## 1. Create a private declaration

From the checkout, create an owner-only configuration without starting a job:

```sh
umask 077
mkdir -p config
python3 - <<'PY'
import json
from pathlib import Path
from pihole_report.deployment import example_deployment
path = Path('config/deployment.json')
with path.open('x') as out:
    out.write(json.dumps(example_deployment(), indent=2) + '\n')
path.chmod(0o600)
PY
```

This uses the current checkout's absolute path and stays disabled. It will not
overwrite an existing file. `examples/deployment.example.json` illustrates the
same schema with an artificial installation path. The entire local `config/`
and `runtime/` directories are ignored by Git.

Edit the local declaration, not the tracked example:

- `scope.root`, `database`, `report`: an existing compatible data tree. Keep the
  active database outside cloud-sync folders. Back up and validate a private copy
  before any installation change.
- `scope.site`: a local label, consistent with the history being reused.
- `pihole_base`, `pihole_ip`, `pihole_tls_name`, `pihole_ca`: verified HTTPS origin,
  explicit TCP address, matching TLS hostname and the approved CA file.
- `pihole_password_file`, `smtp_password_file`: owner-only secret files. Store
  their paths here, never their contents. Keep secrets outside shared files.
- `smtp_host`, `smtp_port`, `smtp_sender`, `smtp_recipient`: the approved sender
  and recipient using verified STARTTLS. No test message is sent during setup.
- `backup_account`, `backup_root`, `backup_destination`, `backup_preferences`:
  the intended OneDrive account, actual synced root, destination inside that root,
  and account preferences file. This adapter uses macOS File Provider checks;
  placeholder paths are not functional cloud configuration.
- `backup_retention`: the authorized number of recognized application snapshots.
- `legacy_stdout`: the existing prior report log used for duplicate suppression.
- `state_directory`: exactly `<checkout>/state/production`.
- `research_mode` and `unifi_mode`: currently fixed to `cache-only` and
  `cached-only`. Current device mappings do not prove historical identity.
- `scheduler`: exact existing project, manifest, database, wrapper, plist and
  executable Python paths. Interpreter symlinks are fingerprinted by migration;
  other configured paths must be canonical and must not use symbolic links.

`enabled: true` declares the reviewed local scope. This alone does not enable
production: a separate manifest gate is still required. Missing, disabled,
world-readable, linked, inconsistent or unknown-field declarations are refused.
No environment variable can silently replace a declared recipient or endpoint.

## 2. Validate privately, then create a disabled manifest

Run the offline tests and compare outputs against a copied history. Read-only
rendering, live read-only shadow collection and real delivery are different
checks. Do not treat one as proof of the others. The public CLI provides explicit
`--root`, endpoint and credential-file options for shadow collection; it never
sends email or exports cloud backups.

After reviewing an enabled local declaration, this command creates a *disabled*
manifest, without making any network request:

```sh
umask 077
python3 - <<'PY'
import json
from pathlib import Path
from pihole_report.production import manifest_template
path = Path('config/production.json')
with path.open('x') as out:
    out.write(json.dumps(manifest_template(), indent=2) + '\n')
path.chmod(0o600)
PY
```

Review every destination and the final source before enabling this manifest.
Its scope must exactly equal the local declaration and its module hashes must
match. Any later source edit invalidates that binding. Do not enable or run it
merely because the configuration parses. Real sends/uploads and transitions need
the relevant owner's authorization.

No installer automatically creates or reloads a scheduler. Migration/upgrade
helpers require a separately reviewed specification/plan, a loaded idle job,
application locks and a safe schedule margin. An initial installation may need
platform-specific setup beyond these existing-installation transition helpers.

## Optional curated lists

By default the manifest does not refresh remote lists. For an explicitly selected
public GitHub source, copy `examples/list-source.example.json` to the *data root's*
`config/list-source.json`, use owner-only mode, and edit its repository/ref. The
source must publish these files under `Lists/` at a complete commit:

- `curated-blocklist-policy.txt`
- `curated-blocklist-device.txt`
- `curated-whitelist.txt`

Only then enable `refresh_lists` in the private manifest. The application checks
GitHub/raw-content HTTPS origins, commit identity, file formats and sudden count
drops; an incomplete refresh retains the previous validated selection. This does
not install Pi-hole rules or perform AI research. With refresh disabled, supply
and review local list inputs under the data root's `config/lists/`.

## Private policy and evidence

New databases do not inherit another installation's historical protection audit
or telemetry decisions. Supply local protected-domain/list inputs and import only
valid, authorized history/evidence. Unknown current rule state remains unknown.
Do not convert a public domain-family guess into verified exact-hostname research.


## CSV destination and retention

The daily research-needed CSV uses the same explicitly declared OneDrive account
and backup destination. Review this readable-data export together with database
backup authorization before enabling production. No extra destination or automatic
research service is used. A CSV stage result records its filename, row count and
checksum; it does not place hostname contents in process arguments.

Only the frozen current report list is exported. Previously delivered mail and
completed history backups are not repeated to recover a failed CSV. All CSVs are
retained; choosing a future deletion policy requires an explicit decision separate
from the existing JSON-log and SQLite-snapshot retention settings.

Version 0.5.1 appends an empty `Block` column to every new CSV. This is a manual
review field: `1` means block, `0` means do not block, and blank means undecided.
The reporter does not infer or apply these decisions, import edited CSVs, or
overwrite existing files. Manual edits remain untouched.

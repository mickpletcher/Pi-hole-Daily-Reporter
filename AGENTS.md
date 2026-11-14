# Contributor and agent guidance

## Maintain the upgrade roadmap

Whenever an upgrade listed in `future-upgrades.md` is implemented, review the
roadmap in the same change. Move the completed item out of future work and record
its implementation and validation evidence in release notes or a completed-work
section.

If possible, add a new, useful upgrade recommendation grounded in the current
package to replace the completed item. Include its rationale, completion criteria
and relevant code references, place it in the appropriate importance tier, and
rerank the remaining items. Do not invent filler or relist an already implemented
feature just to maintain a fixed number of recommendations. If no worthwhile
replacement is identified, record that briefly in the change summary instead.

This maintenance rule does not authorize implementing additional recommendations,
changing a live deployment or modifying user data.

## Update the change log for every change

Every change to this package must update the root `change.log` in the same commit
or pull request. This includes code, documentation, tests, dependencies,
configuration, build and release tooling, and repository automation or guidance.
Record relevant GitHub repository-setting changes there as well when applied.

Add a dated entry, newest first, describing what changed and why, the checks
actually performed and their results, and any compatibility or operational
impact. Distinguish source changes from deployment changes: never imply that a
live installation was updated or a check passed unless verified. Keep entries
concise, preserve previous history, and do not include secrets or private user
data. Updating an existing entry for the same change is sufficient; a change-log
edit does not require a second, recursive entry about itself.

Before committing or submitting a change, verify that `change.log` describes the
complete change. This requirement complements the roadmap-maintenance rule above
and does not authorize deployment, account-setting changes, or other actions.

## Archive completed upgrades

When a listed upgrade is completed and its completion criteria are verified, move
its description and validation evidence from `future-upgrades.md` into the root
`completed-upgrades.md`. Do not label pending or unverified work completed. Retain
the roadmap replenishment and reranking requirements above, and update `change.log`
in the same change.

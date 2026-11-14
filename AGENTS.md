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

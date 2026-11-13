# Local source comparison

Create `config/blocklist-sources.txt` under the report's working root, with one direct public HTTPS blocklist URL per line. Blank lines and `#` comments are allowed; duplicate URLs are checked once. Use current raw feed addresses, not project homepages. Do not include allowlist feeds or private/token-bearing URLs. The personal source inventory is configuration, not published with this application.

Each newly generated daily report downloads these sources afresh and matches the research-needed hostnames locally. No observed hostnames are sent to the providers. No external AI is used and no Pi-hole setting is changed. Frozen retries reuse their original comparison, rather than changing an already emailed report.

New CSVs retain `domain,hostname` first and a blank manual `Block` column last. `RecommendedBlock=1` means a supported blocking rule matched. `MatchedSources` identifies the feed URLs; `SourceCheckStatus` and `SourcesCheckedAt` show coverage and time. Blank recommendations are unresolved, not an allow decision. Existing edited CSVs are never overwritten. The emailed report summarizes counts; per-feed errors, hashes and unsupported-line counts are retained in its frozen context/run log.

Plain domains and hosts entries match exactly. `||domain^` matches that hostname and descendants; supported `@@||domain^` exceptions suppress matches within that feed. Arbitrary regexes, URL paths, modifiers and unsupported formats are not guessed. Unsupported rules make a source partial; unsupported exceptions suppress that source's positive matches. Lists may overlap, contain false positives or block useful services. Matches are recommendations, not malware verdicts or independent votes.

Limits: 128 unique sources, 64 MiB per source, four concurrent requests, verified TLS, redirects refused, 15-second socket timeout and a 240-second overall worker deadline. Failed, too-large, HTML, empty or unsupported feeds are explicit incomplete checks, never clean results. A worker timeout makes the comparison incomplete but does not prevent report/email delivery. No last-good cache is represented as current. Use direct final HTTPS endpoints if a feed redirects.

CSV schema 3 adds recommendations. Schemas 1 and 2 remain supported for byte-identical rendering of earlier frozen exports.

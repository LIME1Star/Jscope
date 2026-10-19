# Workspaces, rescans and diffs (Phase 3)

```bash
jscope ws-init                                   # creates ./.jscope-ws
jscope ws-add acme ./acme-js ./acme-admin-js     # a target = name + one or more paths
jscope ws-scan acme                              # first run records a baseline
jscope ws-scan acme                              # "unchanged ... nothing re-analyzed"
jscope ws-scan --all --fail-on-regression        # cron/CI: exit 3 on regressions
jscope ws-diff acme [--from 0001 --to latest]
jscope ws-history acme | ws-summary | ws-list | ws-remove acme
jscope ai ws:acme --dry-run                      # see exactly what AI would receive
```

## What "incremental" means here
A scan is skipped only when its fingerprint is identical to the previous one: every input file's content hash,
analysis-relevant config (analyzers, thresholds, excludes, source-map expansion, plugin trust list), plugin
*source* hashes, and the JScope version. If anything differs, the **whole target is re-analyzed**. This is
deliberate: route -> component -> API correlation is cross-file, so re-running only changed files would yield a
wrong graph. Output format, verbosity and concurrency do not affect the fingerprint.

## What a diff contains
- **files**: added / removed / modified (by content hash)
- **findings**: new, resolved, confidence up/down. Matched by stable key `category|subject`;
  `JS-####` ids are order-based and are *not* stable across scans.
- **routes** (from the knowledge graph): added, removed, **protection weakened / strengthened**, endpoints
  gained/lost per route.

## Priority boosts from change
Deterministic and shown in each finding's reasons. Never applied to a first scan (a baseline is not "new").

| Rule | Points |
|---|---|
| finding is new since previous scan | +12 |
| finding's confidence rose | +8 |
| endpoint reachable from a route that lost client-side protection | +14 |

## `--fail-on-regression`
Exit code 3 if there is a new finding at/above `--fail-level` (default HIGH), a finding rising to it, or any route
that lost protection. Resolved findings and confidence drops never fail the run.

## Caveats
- A route "losing protection" means the *client-side* guard disappeared from the JS. It is a prompt to re-test the
  server, not proof of a vulnerability.
- Paths are stored as absolute paths of the machine that scanned; diffs across machines will show every file as
  added/removed.
- Scan records contain evidence snippets (including any secrets found). Treat `.jscope-ws/` as sensitive.


<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img alt="JScope" src="assets/logo-light.svg" width="360">
  </picture>
</p>

<p align="center">
  <b>Evidence-based JavaScript intelligence for bug bounty hunters and web app pentesters.</b><br>
  Reconstructs how a web app behaves from its JS, and refuses to show a finding it can't justify.
</p>

<p align="center">
  <a href="https://github.com/LIME1Star/JScope/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/LIME1Star/JScope/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
</p>

---

Most JS recon tools hand you a long list of strings. JScope hands you a **map** (routes, components, API calls, guards, roles)
and a **ranked list of where to start testing**, where every point in the ranking has a stated reason and every finding
carries the evidence behind it.

```text
$ jscope analyze tests/sample_react

[where to start testing]  (deterministic ranking; reasons shown)
   68  [CONFIRMED] JS-0004  endpoint: /api/admin/reports/export
       test: Request as an unauthenticated / low-privilege user and check for missing access control.
   58  [CONFIRMED] JS-0001  endpoint: /api/admin/users
       test: Request as an unauthenticated / low-privilege user and check for missing access control.
   54  [CONFIRMED] JS-0003  endpoint: /api/users/{id}/profile
       test: Vary the ID parameter across accounts/sessions and diff authorization results.
   ...

[route map]  6 route(s)   (R=route G=guard role=declared role E=endpoint)
  R /                            UNPROTECTED
      E /api/v1/feed
  R /admin/reports               UNPROTECTED
      E /api/admin/reports/export
  R /login                       UNPROTECTED
      E /api/auth/login
  R /admin/users                 guards=RequireAuth roles=admin
      E /api/admin/users
  R /billing                     guards=RequireAuth
      E /api/payments/invoices
  R /profile                     guards=RequireAuth
      E /api/users/{id}/profile
```

An unguarded `/admin/reports` route calling an admin export endpoint is exactly the kind of lead you want surfaced in seconds.
Try it yourself on the bundled fixture (`tests/sample_react`).

## Install

```bash
pip install jscope
jscope doctor        # checks your install
```

Python 3.10+. For YAML OpenAPI specs: `pip install "jscope[yaml] @ git+https://github.com/LIME1Star/JScope.git"`
## Quick start

```bash
jscope analyze ./path/to/js-project --verbose      # ranking, route map, evidence appendix
jscope explain JS-0004 --findings-file f.json      # full evidence chain for one finding
jscope graph ./project                             # route -> component -> API -> guard map
jscope https://app.example.com                     # crawl + download + analyze (authorized targets only)
jscope report f.json --format html -o report.html  # re-render: human | json | markdown | html | sarif
```

Remote commands (`go`, `scan`, `crawl`, `download`) are bound to the target host, rate-limited, and **refuse loopback/private
addresses by default**. For controlled local testing pass `--allow-private`.

## What makes it different

| | Typical JS recon | JScope |
|---|---|---|
| Method | regex over bundles | tree-sitter AST, constant propagation, dead-branch detection |
| Output | flat list of URLs / strings | route, guard and role graph with route-to-API attribution |
| Findings | everything that matches | only evidence-backed candidates, scored deterministically |
| Triage | you sort it out | ranked "where to start testing", each point explained |
| Honesty | silent on limits | every finding states what it could *not* resolve |

Tools like LinkFinder, jsluice and SecretFinder are excellent at fast extraction, and JScope is built to sit alongside them,
adding structure and prioritization on top.

## How it stays honest

```text
analyzers propose  --->  EvidenceEngine scores + dedups  --->  you see Findings
   (Candidate)             (deterministic, explainable)           (Finding)
```

Analyzers can never emit a finding directly, only `Candidate`s backed by typed `Evidence`. That boundary keeps a noisy analyzer
(including community plugins) from polluting your output. Confidence means "this pattern exists and means what it looks like",
**not** "this is exploitable"; only the opt-in `confirm` / `verify` steps add runtime evidence. Details:
[docs/EVIDENCE_SCHEMA.md](docs/EVIDENCE_SCHEMA.md).

## What it analyzes

14 built-in analyzers: routes (React Router, Vue Router, Angular, Next.js), authentication and authorization patterns, storage and
token handling, GraphQL operations and schemas, OpenAPI specs (correlated both ways with client calls), service workers,
source maps, HTML forms/CSP/SRI, WASM modules, secrets, endpoints and framework detection.

Also included: workspaces with baseline diffing (`ws-scan`), optional AI explanations that never invent findings
([docs/AI.md](docs/AI.md)), a plugin system with trust tiers ([docs/PLUGINS.md](docs/PLUGINS.md)), SARIF output for CI, and
opt-in runtime confirmation and browser observation.

## Status and limitations

JScope is a **beta development tool, not a production scanner.** Be aware of these before relying on it:

- Symbol resolution is a per-file heuristic. There is no cross-file data flow yet, and import resolution handles relative
  paths only (no `@/` or tsconfig aliases).
- Client-side authorization findings are observations, not vulnerabilities. A missing guard may live in a layout or on the server.
- Runtime confirmation is opt-in and narrow: GET/OPTIONS only, allow-listed hosts. It shows a route *responds*, not that it is *vulnerable*.
- The accuracy benchmark uses 12 synthetic fixtures; a real-world corpus is on the [roadmap](docs/ROADMAP.md).
- Network scope enforcement is not unified across every component and DNS pinning is not guaranteed on all paths. Read
  [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md). Plugins execute arbitrary Python.

**Only test systems you own or are explicitly authorized to assess.**

## Development

```bash
git clone https://github.com/LIME1Star/JScope && cd JScope
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
python -m jscope benchmark --strict
```

See [CHANGELOG.md](CHANGELOG.md) for release history and [docs/](docs/) for each subsystem. Issues and pull requests are welcome.

## License

MIT, see [LICENSE](LICENSE).

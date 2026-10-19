# Changelog

## 0.4.2 -- release hardening

**Fixed**
- `jscope go <url>` (and `jscope <url>`) failed on every remote target: the downloader refused to run without a transport policy and
  `go` never supplied one. `go` now binds one target-scoped policy to discovery and download, like `scan` does.
- Findings depended on where the project lived on disk: the test-path heuristic matched `/tests/`, `/test/`, `/fixtures/` anywhere in
  the *absolute* path, so a project under e.g. `~/tests/app/` had findings silently demoted. Heuristics now run on the path relative
  to the analysis root (a `tests/` directory *inside* the project is still detected).
- The local-server tests had drifted from the hardened transport (loopback is blocked by default); they now opt in explicitly.

**Added**
- `--allow-private` on `go`, `scan`, `crawl` and `download`: explicit opt-in to loopback/private destinations for controlled local
  testing. Blocked by default.
- Packaging: single `pyproject.toml` (version read from `jscope.__version__`), MIT `LICENSE`, `.gitignore`, optional extras
  (`yaml`, `browser`, `dev`), CI on Python 3.10-3.13 with a build/`twine check` job.
- Regression tests for the safe default, path-independent findings, and the version single-source.

**Removed**
- `setup.py`, `requirements.txt` (superseded by `pyproject.toml`) and the internal release checklist.

## 0.4.1 -- CLI simplification

New: `jscope <target>` / `jscope go <target>` (one command: analyze a local path, or crawl+download+analyze a URL,
with predictable output under `jscope-out/`, a one-keystroke target-confirmation banner for live targets, and a
`--confirm` flag chaining into runtime confirmation). New: `jscope doctor` (diagnoses stale installs -- multiple
`jscope` launchers on PATH, missing dependencies, which file is actually running). New: `python -m jscope` works
directly from source, no install required. No behavior change to any existing subcommand.

## 0.4.0 -- Phase 4 (final roadmap phase)

**Confidence-affecting changes (reviewable):**
- New evidence type `RUNTIME_NOT_FOUND` (-3). Only the opt-in prober can produce it; analyzers/plugins are blocked (like `RUNTIME_CONTEXT`, +6, unchanged).
- Endpoints corroborated by a second independent source gain `ARTIFACT_RESOLVED` (+3) from `openapi_analyzer` / `graphql_schema_analyzer`
  and the engine's `CROSS_ANALYZER_AGREEMENT` (+4). A client call that a spec also documents can therefore reach CONFIRMED.
- No existing weight or threshold changed. Priority gains: +10 documented-but-never-called (+5 if unresolved client calls exist),
  +/-10 runtime confirm / not-found, and base points for new surfaces (`undocumented_api` 36, `unauthenticated_write` 30,
  `deprecated_api` 20, `csrf_candidate` 18, `supply_chain` 16, `wasm` 14, `csp_weak` 12).

**New analyzers:** `html_analyzer` (forms, upload/password fields, cleartext credentials, missing-CSRF hint, SRI, meta CSP, comments),
`openapi_analyzer` (spec <-> client correlation both ways), `graphql_schema_analyzer` (SDL + introspection JSON), `wasm_analyzer`.
**New inputs:** HTML pages and Vue SFCs (inline `<script>` bodies become real JS files with original line numbers), OpenAPI/Swagger
(JSON, YAML with PyYAML), GraphQL schemas, WASM. Content-sniffed; `artifacts.enabled: false` turns it off.
**New commands:** `jscope report` (Report Mode), `jscope confirm` (opt-in runtime confirmation). `analyze` gains `--format markdown|html|sarif` and `-o`.
**New graph nodes/edges:** page, form, spec_operation; loads, contains_form, submits_to, documents.
**Changed:** JSON schema 0.4 (additive). `Analyzer.run_after` (soft ordering). Workspace fingerprints include artifact files and `artifacts.enabled`.
**Crawl/download/scan now cover every artifact kind** (found by testing on a real phone): `crawl` also collects the page HTML, `*.wasm` references and
well-known spec paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/schema.graphql`, ... GET only; kept only if the response really is a spec/schema,
so SPAs that answer 200/HTML for everything add no junk; `--no-probe` disables). `download` names files by content (.html/.json/.wasm/...).
`scan` is one command with `--out`, `--format`, `-o`, `--save-findings`, `--min-confidence`, `--no-probe`.
**Fixed:** HTTP errors/unreachable hosts/missing URL files are clean `error:` messages (were tracebacks); short retry on 502/503/504; `crawl --out` creates parent
directories; `-o` now works for json/human output too.
**Fixed along the way:** explicit non-JS files passed to `analyze` are no longer fed to the JS parser.

## 0.3.0 -- Phase 3

**Confidence-affecting changes (reviewable):** none. No evidence weight or threshold changed. Only the
*priority ranking* gains three diff-driven boosts (+12 new, +8 confidence raised, +14 route lost protection),
applied only when a previous scan exists.

**New:** workspaces (`ws-init/add/list/remove/scan/history/diff/summary`), multi-target `--all` scans, fingerprint-based
incremental rescans, scan diffs (files, findings by stable key, graph route protection/endpoints),
`--fail-on-regression` (exit 3), `jscope ai` (opt-in, redacted, validated, dry-runnable).
**Changed:** JSON schema 0.3 (adds nothing breaking; `priority` may include change reasons). `run_analysis()` returns `file_hashes`.
**Docs:** `docs/WORKSPACES.md`, `docs/AI.md`.

## 0.2.0 -- Phase 2

**Confidence-affecting changes (reviewable, per the changelog discipline):**
- NEW evidence type `ARTIFACT_RESOLVED` (+3). No existing weight or threshold changed.
- `idor_candidate` attack-surface regex tightened: `/identity`, `/video/play` etc. no longer match
  (only real ID-parameter segments such as `{id}`, `:id`, `[userId]`). This removes a Phase 1 false positive.
- Findings supported only by community-tier plugins are capped at `plugins.community_confidence_cap` (MEDIUM).

**New analyzers:** router, auth, authorization, storage, graphql, service_worker, source_map.
**New core:** Application Knowledge Graph (`core/graph.py`), shared AST queries (`parsing/queries.py`).
**Plugin system:** loader (directories + `jscope.analyzers` entry points), trust tiers, `jscope plugin-new` scaffolder.
**Hardening:** runtime enforcement of propose/promote; evidence re-attribution; per-analyzer crash isolation;
duplicate analyzer names rejected.
**Reporting:** deterministic "where to start testing" ranking with reasons; route map; diagnostics; graph persisted
in `--save-findings` output (JSON schema 0.2).
**CLI:** `graph`, `plugins`, `plugin-new`; `analyze --expand-source-maps --plugin-path`.
**Pipeline:** also collects `.mjs/.cjs/.jsx`; `run_analysis()` returns graph/diagnostics (`analyze_paths()` kept).

## Phase 2 foundation (scope transport and passive inventory)
- Added `jscope.security_transport` with URL/host normalization, exact-host transport authorization, redirect revalidation, DNS address policy, central timeout/budget/rate/response limits, and redacted JSONL journal events.
- Routed crawler requests through the guarded transport; the default crawl scope is the exact explicitly supplied target host.
- Added passive candidate inventory and assessment-specific explicit approval commands: `scope-discover`, `scope-review`, and `scope-approve`.
- Added focused security tests and `docs/PHASE2_SECURITY.md` documenting guarantees and remaining gaps.
- This is not yet universal network-boundary enforcement: see the Phase 2 security document for downloader/plugin and DNS pinning limitations.


## 0.4.2-dev — Phases 3–5 work

- Added streamed response byte caps, per-host pacing, concurrency control, and cross-origin credential stripping in guarded Requests transport.
- Added assessment-bound orchestration primitives, stable endpoint/finding identities, module capability metadata, provenance-aware correlations, and sanitized evidence storage.
- Added JSON/Markdown assessment reports and regression tests.
- Documented incomplete transport consolidation, DNS pinning limitations, module-budget limitations, and the blocked full test suite.

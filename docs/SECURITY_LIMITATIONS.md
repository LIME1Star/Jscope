# Security limitations and release readiness

## Fixed or materially improved
- Guarded Requests transport streams decoded body chunks and blocks over-limit responses while reading; responses close on limit failure.
- Redirect destinations are validated before the next send; each hop consumes the global request budget and repeats DNS checks.
- Host matching in `GuardedSession` is exact; URL parsing rejects userinfo, unsupported schemes, malformed authorities, and invalid ports.
- TLS verification is forced on the guarded adapter; cross-origin redirect handling strips caller/session credentials and cookies.
- Request pacing, per-host pacing, concurrency bounds, response-size limits, and structured journal events are present.
- Downloader refuses to run without an explicit policy; CLI download requires `--allow-host`.
- Assessment engine rejects manifest/schema/assessment-ID/approval mismatches, verifies approved hosts exactly match transport hosts, and detects manifest mutation.
- Evidence sanitization, stable endpoint/finding IDs, and correlation provenance have focused regression coverage.

## Partially fixed / limited
- **Central transport:** crawler and downloader use `GuardedSession`; runtime probing uses a separate `ScopePolicy`/`ScopedClient`. Optional AI-provider traffic is a separate external service call, not target assessment traffic. There is no single shared adapter for every possible network-capable component.
- **DNS:** `GuardedSession` checks DNS before calling Requests but does not pin the socket to the validated address. DNS rebinding/TOCTOU is not guaranteed safe in this adapter. `runtime/scope.py` has a separate connection-pinning hook, but global coverage was not proven.
- **Response limits:** the guarded Requests adapter caps decompressed `iter_content` bytes. Other transport implementations require separate verification.
- **Module budgets:** request budgets are temporarily constrained through the shared policy, but time budgets are checked after a runner returns and cannot preempt a hung module. Do not load untrusted plugins in-process.
- **Audit journal:** line hashes do not provide authenticated tamper-proof storage.
- **Assessment coverage:** module registry and orchestration primitives exist, but full staged pipeline integration/resume persistence is incomplete. Correlation is static and deliberately not proof of reachability/authorization.
- **Reports:** new JSON/Markdown exports exist for engine results; end-to-end CLI integration and comprehensive schema compatibility tests remain incomplete.

## Unresolved / release blockers
1. Install `tree-sitter-javascript` in a network-enabled clean environment, then run all tests and CLI/package tests.
2. Consolidate target network access onto one connection-pinned transport and prove every crawler, downloader, runtime, API, and extension path uses it or is disabled.
3. Bind all active modules to a persisted assessment manifest and approval history, with revalidation at each request boundary.
4. Implement/test robust DNS pinning for every supported HTTP path, including IPv4/IPv6 and mixed DNS answers.
5. Implement bounded safe retries/backoff or explicitly remove misleading unused retry configuration.
6. Add full active authorization test modules only with synthetic role-separated accounts and non-destructive test objects; validate expected/observed policy instead of status-code heuristics.
7. Add durable resumability, cancellation propagation, module preemption/isolation, and report/evidence persistence tests.
8. Complete clean-install and packaging tests; CLI help could not be run due missing import dependency.

## Release status

This archive should be treated as a development build, not a production-ready scanner. Focused security tests are not a substitute for a successful full-suite run and verified end-to-end scope enforcement.

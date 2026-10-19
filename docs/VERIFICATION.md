# Verification (FR-04)

`jscope verify` attempts to REPRODUCE a candidate finding, not just re-score it. It is opt-in, active and requires
`--authorize-active-tests` plus `--allow-host`. Every request goes through the same `ScopePolicy` as `jscope confirm`
and `jscope observe` (docs/RUNTIME.md): scheme/host/port allow-list, DNS validated and pinned, loopback/private/
metadata addresses blocked unless `--allow-private`, rate-limited, and stoppable mid-run (a `.jscope-stop` file or
`EmergencyStop.trip()`).

## Supported classes and procedures

| vuln_class | procedure | what it does |
|---|---|---|
| `dom_xss_candidate` / `reflected_xss` | `xss-browser-marker` (needs `playwright install chromium`), else `xss-http-reflection` | injects a harmless, unique marker through the documented source and checks whether it parses as a DOM element (browser) or is reflected unescaped (HTTP fallback) |
| `open_redirect_candidate` | `redirect-marker` | injects a URL to `jscope-verify.invalid` and checks for a redirect there |
| CORS (`metadata.verify_as: cors`) | `cors-probe` | sends a test `Origin` header, checks `Access-Control-Allow-Origin`/`-Credentials` |
| `idor` / `broken_access_control` | `authz-diff` | requests the SAME endpoint with >=2 **configured** test identities (`--identity NAME=Header:value`) and compares status/response shape. Never attempts privilege escalation or invents credentials. |

Anything else returns `unverified` with `procedure: no-procedure` rather than guessing.

## Status meanings

`confirmed` (reproduced under a documented procedure) | `probable` (strong but not fully conclusive, e.g. HTTP-level
reflection without a browser) | `inconclusive` (could not establish either way -- missing identities, out of scope,
ambiguous response) | `rejected` (the procedure ran and did NOT reproduce the issue -- the original static finding is
**kept**, not deleted) | `unverified` (no procedure exists, or verification was never run).

A finding only becomes `confirmed_vulnerability` in `classification.evidence_class` when `status == "confirmed"` AND a
`procedure` is recorded (see `jscope/core/classification.py`). A bare status claim with no procedure can never read as
confirmed.

## Safety

- Nothing here performs a destructive request. XSS/redirect tests inject inert markers; CORS/authz tests are GETs.
- Request/response evidence in `actions` is redacted (`jscope/core/redact.py`): no Authorization/Cookie headers, no
  cookie values, sensitive query parameters masked.

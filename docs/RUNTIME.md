# Runtime confirmation (`jscope confirm`)

The only part of JScope that sends traffic. It is opt-in, narrow, and a separate step from analysis.

```bash
jscope analyze ./dump --save-findings f.json
jscope confirm f.json --base-url https://app.example.com --allow-host app.example.com --dry-run     # review the plan; sends nothing
jscope confirm f.json --base-url https://app.example.com --allow-host app.example.com --i-have-permission --out confirmed.json
```

## What it will and will not do

* Sends **GET** (only for endpoints the client itself calls with GET) and **OPTIONS** (everything else). Never POST/PUT/PATCH/DELETE, never a body.
* Only hosts you named with `--allow-host`; the host is re-checked at the moment of sending. Redirects are not followed.
* `--i-have-permission` is required to send. You are asserting you are authorized to test that host.
* Skips, and tells you why: paths with unresolved parameters/queries, absolute URLs on other hosts, and side-effect-sounding paths (logout, delete, reset, checkout, ...).
* Rate-limited (default 2/s) with a hard cap (default 100). `--header 'Cookie: ...'` lets you supply a session you own.

## How a response becomes evidence

A random non-existent path is fetched first (the *baseline*). A response indistinguishable from it (same status, content type, ~size) is
**inconclusive**: an SPA answering 200/HTML for everything, or a gateway answering 401 for everything, cannot confirm an endpoint.

| Response | Verdict | Effect |
|---|---|---|
| 200-299 non-HTML, differs from baseline | exists | `RUNTIME_CONTEXT` +6 |
| 401 / 403 | exists, protected | `RUNTIME_CONTEXT` +6 |
| 405, or OPTIONS with an `Allow` header | exists | `RUNTIME_CONTEXT` +6 |
| 3xx differing from baseline | exists | `RUNTIME_CONTEXT` +6 |
| 404 / 410 | not found | `RUNTIME_NOT_FOUND` -3 (a wrong base URL looks identical) |
| 5xx, errors, catch-all matches | inconclusive | no change |

Evidence reaches findings only through `apply_runtime_evidence`, which accepts nothing but prober-attributed `RUNTIME_*` evidence; the analyzer
manager strips those types from every analyzer and plugin. A not-found **downgrades** a finding (floor INFORMATIONAL); it never deletes one.
"Exists" means "responds", not "vulnerable".

# Runtime observation (FR-03)

`jscope observe <base-url> --allow-host ... [--scenario file.json] [--driver auto|playwright|http]` drives a target
through a scenario and records a `RuntimeTrace`: navigations, requests/responses, redirects, console errors and (with
the Playwright driver) storage/cookies snapshots.

- **`playwright` driver**: a real, isolated Chromium (service workers blocked, no extra permissions, CSP not
  bypassed). Install with `pip install playwright && playwright install chromium`.
- **`http` driver**: no JavaScript execution. Fetches the page and its `<script src>`/`<link rel=stylesheet>`
  references through the scoped client. Always says so in `trace.limitations`.
- **`auto`** picks Playwright if available, else falls back to `http`.

A trace is `status: "incomplete"` whenever anything was blocked, timed out, or needed a capability the driver doesn't
have (e.g. a `click` step on the HTTP driver). An incomplete trace's absence is never evidence of safety --
`jscope.runtime.observe.correlate()` only reports a static finding as `not_observed` (vs. `inconclusive`) when the
trace is complete AND came from the browser driver.

`--findings-file` correlates the trace against a saved findings JSON: `confirmed_by_runtime` (template-matched path,
`exactness: endpoint-match` or the stronger `initiator-file` when the initiating script also contains the static call
site -- correlation is always file-level, never a fabricated line number), `runtime_only` (requests static analysis
missed) and `not_observed`.

Credentials are never retained: cookie values and sensitive storage keys are masked, Authorization/Cookie headers are
dropped, URLs are redacted (`jscope/core/redact.py`).

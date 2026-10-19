# Phase 2: scope-enforced transport and passive discovery

## Guarded transport

`jscope.security_transport` provides `TransportPolicy` and `GuardedSession`. It validates URL syntax, schemes, ports, normalized IDNA hostnames, exact host scope at the transport boundary, URL user-info, redirects, DNS answers, request methods, timeout, request count, response size, and a per-request rate limit. The standalone `validate_url` helper can check root-domain boundary semantics, but transport authorization requires exact membership in the approved host set; subdomains are not implicitly approved. Redirects are disabled in Requests and followed manually only after validating the next URL. TLS verification remains enabled.

Use an explicit assessment identifier and approved host set. Private, loopback, and link-local destinations are denied by default; internal authorized testing can opt in via `allow_private`, `allow_loopback`, and `allow_link_local` in a policy created from a validated current assessment manifest. Do not pass a discovered candidate as approved merely because it was discovered.

Example:

```python
from jscope.security_transport import TransportPolicy, GuardedSession
policy = TransportPolicy(
    hosts={"example.com", "api.example.com"},
    assessment_id="the-current-assessment-id",
    journal_path=".jscope-ws/assessments/network-events.jsonl",
    total_budget=100, requests_per_second=2,
)
with_session = GuardedSession(policy)
response = with_session.get("https://example.com/")
```

## Passive inventory and approvals

- `jscope scope-discover <manifest.json> --host-file candidates.txt` records candidate provenance and timestamp without network activity or approval.
- `jscope scope-review <manifest.json>` shows hosts and approval history.
- `jscope scope-approve <manifest.json> api.example.com` requires interactive confirmation; `--yes` is the explicit non-interactive approval mechanism. Only hosts already recorded as known and inside the root-domain boundary can be approved.

Approval is tied to the assessment ID in the manifest. New or changed scope requires a new explicit decision. Discovery never triggers active testing.

## Limits and remaining integration gaps

The guarded adapter is integrated into the crawler. DNS addresses are checked before Requests connects, but the standard Requests resolver/connection pool does not pin the validated address to the socket; DNS rebinding and TOCTOU are therefore reduced but not eliminated. The response-size check occurs after Requests has materialized the body, so it is not a hard streaming-memory cap. The adapter's retry field is descriptive only; callers currently control retries and should avoid retrying non-idempotent methods. The downloader and any third-party plugin that creates its own HTTP client are not universally forced through this adapter yet; treat them as remaining network-boundary integration gaps and do not claim universal enforcement. The existing `scan` workflow also needs end-to-end assessment-manifest binding before it can be described as fully scope-enforced.

Journal JSONL records redact URL query values and user-info, include assessment IDs/reason codes, and add a record hash. Hashes detect accidental changes only when the expected chain/head is independently retained; they do not prove authenticity or prevent tampering.

"""Runtime confirmation (Phase 4): the ONLY part of JScope that talks to a target. Opt-in, narrow by construction.

Hard rules (enforced in code, each covered by a test):
  * nothing is sent unless the caller passes an explicit allow-list of hosts AND the base URL's host is in it
  * only GET (for endpoints the client itself calls with GET) and OPTIONS (for everything else). Never POST/PUT/PATCH/DELETE,
    never a request body
  * redirects are NOT followed (a 3xx is evidence in itself and following could leave the allow-list)
  * endpoints with unresolved parameters, absolute URLs on other hosts, and side-effect-sounding paths are skipped, with the reason
  * rate-limited, hard request cap, identifying User-Agent
  * a catch-all baseline (random non-existent path) is fetched first, so an SPA that answers 200/HTML for everything cannot
    "confirm" an endpoint; a response indistinguishable from the baseline is inconclusive, not positive

Results become RUNTIME_CONTEXT / RUNTIME_NOT_FOUND evidence applied through `apply_runtime_evidence` -- the engine's own door.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from jscope.core.evidence import (RUNTIME_ANALYZER, Evidence, EvidenceType, Finding, apply_runtime_evidence)
from jscope.runtime.scope import (EmergencyStopped, ScopePolicy, ScopeViolation, pinned_dns, system_resolver)

USER_AGENT = "jscope-confirm/0.4 (authorized security testing; safe methods only)"
_UNRESOLVED = re.compile(r"(\{|\}|\$\{|/:[A-Za-z_]|\[[^\]]+\]|<[^>]+>|\?)")
_SIDE_EFFECT = re.compile(r"(logout|signout|sign-out|delete|remove|destroy|unsubscribe|revoke|reset|cancel|activate|confirm|"
                          r"checkout|purchase|\bpay\b|payment|send|invite|webhook|callback|verify|approve|reject|purge|truncate|"
                          r"disable|enable|import|sync|trigger|run|execute)", re.I)


@dataclass
class HttpResponse:
    status: int
    content_type: str = ""
    length: int = 0
    headers: dict = field(default_factory=dict)


Fetcher = Callable[[str, str, dict, float], HttpResponse]       # (method, url, headers, timeout) -> response


def default_fetch(method: str, url: str, headers: dict, timeout: float) -> HttpResponse:
    import requests
    r = requests.request(method, url, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
    try:
        body = r.raw.read(65536, decode_content=True) if method == "GET" else b""
    finally:
        r.close()
    return HttpResponse(r.status_code, r.headers.get("Content-Type", ""), int(r.headers.get("Content-Length") or len(body)),
                        {k.lower(): v for k, v in r.headers.items()})


@dataclass
class PlanItem:
    finding_id: str
    subject: str
    method: str                 # GET | OPTIONS
    url: str | None
    skip_reason: str | None = None


@dataclass
class ProbeResult:
    finding_id: str
    subject: str
    method: str
    url: str
    status: int | None
    verdict: str                # exists | exists_protected | not_found | inconclusive | error
    reason: str


class ScopeError(ScopeViolation):
    pass


class Prober:
    def __init__(self, base_url: str, allow_hosts: list[str], rate_per_second: float = 2.0, max_requests: int = 100,
                 timeout: float = 8.0, headers: dict | None = None, fetch: Fetcher | None = None,
                 sleep: Callable[[float], None] = time.sleep, policy: ScopePolicy | None = None,
                 allow_private: bool = False):
        u = urlparse(base_url)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ScopeError("base URL must be an absolute http(s) URL")
        self.allow = {h.lower() for h in allow_hosts if h}
        if not self.allow:
            raise ScopeError("at least one --allow-host is required: JScope never probes a host you have not named")
        if u.netloc.lower() not in self.allow:
            raise ScopeError(f"base URL host {u.netloc.lower()!r} is not in the allow-list {sorted(self.allow)}")
        self.base = f"{u.scheme}://{u.netloc}{u.path.rstrip('/')}"
        self.host = u.netloc.lower()
        self.min_gap = 1.0 / rate_per_second if rate_per_second > 0 else 1.0
        self.max_requests, self.timeout = max_requests, timeout
        self.headers = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
        self._fetch, self._sleep = fetch or default_fetch, sleep
        self._real_network = fetch is None
        self.sent = 0
        self._last = 0.0
        # FR-10: every request is validated by a ScopePolicy (scheme/host/port/DNS/address class) before it is sent. With an
        # injected `fetch` (tests) nothing touches the network, so DNS and address-class checks are skipped for that seam only.
        self.policy = policy or ScopePolicy(
            allow_hosts=set(self.allow), allow_private=allow_private or not self._real_network,
            resolver=system_resolver if self._real_network else (lambda h, p: []),
            rate_per_second=rate_per_second, max_requests=max_requests, timeout=timeout, redirects="none")
        if policy is None and any(":" in h for h in self.allow):
            self.policy.ports = None

    # ------------------------------------------------------------ planning (sends nothing)
    def plan(self, findings: list[Finding]) -> list[PlanItem]:
        items: list[PlanItem] = []
        for f in findings:
            if f.category != "endpoint":
                continue
            subject = f.subject
            if "://" in subject:
                host = urlparse(subject).netloc.lower()
                if host not in self.allow:
                    items.append(PlanItem(f.id, subject, "GET", None, f"host {host!r} is not in the allow-list"))
                    continue
                path = urlparse(subject).path
            else:
                path = subject
            if _UNRESOLVED.search(path):
                items.append(PlanItem(f.id, subject, "GET", None, "path has unresolved parameters / a query string; a real value is needed"))
                continue
            if _SIDE_EFFECT.search(path):
                items.append(PlanItem(f.id, subject, "GET", None, "path sounds state-changing; not probed even with a safe method"))
                continue
            method = str(f.metadata.get("method") or "").upper()
            probe_method = "GET" if method in ("", "GET") and f.metadata.get("callee") != "form" else "OPTIONS"
            if not path.startswith("/"):
                items.append(PlanItem(f.id, subject, probe_method, None, "not a path"))
                continue
            url = (f"{urlparse(subject).scheme}://{urlparse(subject).netloc}{path}" if "://" in subject else self.base + path)
            items.append(PlanItem(f.id, subject, probe_method, url))
        return items

    # ------------------------------------------------------------ execution
    def _send(self, method: str, url: str) -> HttpResponse:
        host = urlparse(url).netloc.lower()
        if host not in self.allow:                                   # defence in depth: re-check at the point of sending
            raise ScopeError(f"refusing to send to {host!r}")
        if method not in ("GET", "OPTIONS"):
            raise ScopeError(f"method {method} is never sent by JScope")
        try:
            self.policy.stop.check()
            addrs = self.policy.check_url(url, resolve=self._real_network)      # scheme, port, DNS, private/loopback/metadata ranges
        except EmergencyStopped:
            raise
        except ScopeViolation as exc:
            raise ScopeError(str(exc)) from exc
        if self.sent >= self.max_requests:
            raise ScopeError("request cap reached")
        wait = self.min_gap - (time.monotonic() - self._last)
        if wait > 0:
            self._sleep(wait)
        self.policy.stop.check()
        self._last = time.monotonic()
        self.sent += 1
        if self._real_network and addrs:
            with pinned_dns(urlparse(url).hostname or "", addrs[0]):     # connect to the address we validated, never re-resolve
                return self._fetch(method, url, self.headers, self.timeout)
        return self._fetch(method, url, self.headers, self.timeout)

    def baseline(self) -> HttpResponse | None:
        try:
            return self._send("GET", f"{self.base}/jscope-nonexistent-{secrets.token_hex(6)}")
        except ScopeError:
            raise
        except Exception:        # noqa: BLE001
            return None

    @staticmethod
    def _same_as_baseline(r: HttpResponse, b: HttpResponse | None) -> bool:
        if b is None or r.status != b.status:
            return False
        ct = lambda x: x.content_type.split(";")[0].strip().lower()
        if ct(r) != ct(b):
            return False
        return abs(r.length - b.length) <= max(32, int(0.05 * max(b.length, 1)))

    def judge(self, item: PlanItem, r: HttpResponse, base: HttpResponse | None) -> tuple[str, str]:
        st, ct = r.status, r.content_type.split(";")[0].strip().lower()
        if st in (404, 410) and item.method == "GET":
            return "not_found", f"{st}: no such route at this base URL (a wrong base URL also looks like this)"
        if self._same_as_baseline(r, base):
            return "inconclusive", f"{st} is indistinguishable from the server's answer for a random non-existent path (catch-all)"
        if item.method == "OPTIONS":
            allow = r.headers.get("allow", "") + r.headers.get("access-control-allow-methods", "")
            if st in (200, 204) and allow:
                return "exists", f"OPTIONS {st} advertises methods: {allow[:60]}"
            return "inconclusive", f"OPTIONS {st} without an Allow header proves nothing"
        if st in (401, 403):
            return "exists_protected", f"{st}: the route exists and demands authorization"
        if st == 405:
            return "exists", "405 Method Not Allowed: the route exists"
        if 200 <= st < 300:
            if ct in ("text/html", "application/xhtml+xml") and (base is None or ct == base.content_type.split(";")[0].strip().lower()):
                return "inconclusive", f"{st} text/html for an API-style path looks like an app-shell fallback"
            return "exists", f"{st} {ct or 'no content-type'}, {r.length} bytes"
        if 300 <= st < 400:
            return "exists", f"{st} redirect to {r.headers.get('location', '?')[:60]} (differs from the catch-all baseline)"
        if st in (404, 410):
            return "not_found", f"{st}: no such route at this base URL (a wrong base URL also looks like this)"
        return "inconclusive", f"{st} is not decisive"

    def run(self, findings: list[Finding]) -> tuple[list[PlanItem], list[ProbeResult]]:
        plan = self.plan(findings)
        todo = [p for p in plan if p.url]
        results: list[ProbeResult] = []
        if not todo:
            return plan, results
        try:
            base = self.baseline()
        except EmergencyStopped:
            return plan, results
        for item in todo:
            try:
                r = self._send(item.method, item.url)
            except EmergencyStopped as exc:
                results.append(ProbeResult(item.finding_id, item.subject, item.method, item.url, None, "error", f"stopped: {exc}"))
                break
            except ScopeError as exc:
                results.append(ProbeResult(item.finding_id, item.subject, item.method, item.url, None, "error", str(exc)))
                if "cap" in str(exc):
                    break
                continue
            except Exception as exc:       # noqa: BLE001  network errors are not evidence either way
                results.append(ProbeResult(item.finding_id, item.subject, item.method, item.url, None, "error", f"{type(exc).__name__}: {exc}"[:120]))
                continue
            verdict, reason = self.judge(item, r, base)
            results.append(ProbeResult(item.finding_id, item.subject, item.method, item.url, r.status, verdict, reason))
        return plan, results


def evidence_for(res: ProbeResult) -> list[Evidence]:
    if res.verdict in ("exists", "exists_protected"):
        t = EvidenceType.RUNTIME_CONTEXT
    elif res.verdict == "not_found":
        t = EvidenceType.RUNTIME_NOT_FOUND
    else:
        return []                                           # inconclusive / error never move a score
    return [Evidence(t, f"{res.method} {res.url} -> {res.reason}", RUNTIME_ANALYZER, None, None,
                     f"{res.method} {res.status}", {"verdict": res.verdict, "status": res.status})]


def apply_results(findings: list[Finding], results: list[ProbeResult]) -> list[Finding]:
    by_id: dict[str, list[Evidence]] = {}
    for r in results:
        by_id.setdefault(r.finding_id, []).extend(evidence_for(r))
    out = []
    for f in findings:
        extra = by_id.get(f.id)
        out.append(apply_runtime_evidence(f, extra) if extra else f)
    return out

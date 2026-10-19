"""Verification engine (FR-04): attempts to establish whether a candidate finding is genuinely reproducible.

Every procedure returns a VerificationResult with one of five statuses (confirmed, probable, unverified, inconclusive,
rejected) and NEVER upgrades a finding on its own authority: `jscope.core.classification.classify` is the only place a
status becomes `confirmed_vulnerability`, and only when `procedure` is also set (so a bare status without a recorded,
reproducible procedure can never read as confirmed). A rejected verification does NOT delete or silently clean a finding
-- the original static evidence stays, with the verification attached (FR-04 acceptance criteria).

Supported classes in this version: dom_xss / reflected_xss, open_redirect, cors_misconfiguration, security_headers,
idor / broken_access_control (requires configured test identities). Each `generate_test` call derives a SAFE test
(read-only / harmless marker) from the finding; nothing here ever performs a destructive request.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from jscope.core.redact import redact_obj, redact_url
from jscope.runtime.observe import PlaywrightDriver, Scenario, Recorder, RuntimeTrace
from jscope.runtime.scope import EmergencyStopped, ScopePolicy, ScopeViolation, ScopedClient, ScopedResponse

STATUSES = ("confirmed", "probable", "unverified", "inconclusive", "rejected")
SUPPORTED_CLASSES = ("dom_xss_candidate", "reflected_xss", "open_redirect_candidate", "cors_misconfiguration",
                     "security_headers", "idor", "broken_access_control", "session_handling")


@dataclass
class TestIdentity:
    __test__ = False      # not a pytest test class: a verification-engine data type that happens to start with "Test"
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    role: str = ""


@dataclass
class TestCase:
    vuln_class: str
    finding_id: str
    description: str
    preconditions: list[str] = field(default_factory=list)
    requests_planned: int = 0


@dataclass
class VerificationResult:
    finding_id: str
    vuln_class: str
    status: str
    procedure: str
    preconditions: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)       # redacted request/response evidence
    observations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    behavior_reproduced: bool = False
    at: float = field(default_factory=time.time)
    error: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        return {"status": self.status, "procedure": self.procedure, "preconditions": self.preconditions,
                "actions": self.actions, "observations": self.observations, "limitations": self.limitations,
                "behavior_reproduced": self.behavior_reproduced, "at": self.at, "error": self.error, "class": self.vuln_class}


def _rejected(fid: str, cls: str, procedure: str, reason: str) -> VerificationResult:
    return VerificationResult(fid, cls, "rejected", procedure, observations=[reason], limitations=[reason])


def _inconclusive(fid: str, cls: str, procedure: str, reason: str, actions: list | None = None) -> VerificationResult:
    return VerificationResult(fid, cls, "inconclusive", procedure, observations=[reason], limitations=[reason], actions=actions or [])


class VerificationEngine:
    def __init__(self, policy: ScopePolicy, base_url: str, identities: list[TestIdentity] | None = None,
                 playwright_driver: PlaywrightDriver | None = None, authorized: bool = False):
        self.policy = policy
        self.base = base_url.rstrip("/")
        self.identities = identities or []
        self.client = ScopedClient(policy)
        self.pw = playwright_driver
        self.authorized = authorized                       # FR-10: active verification requires explicit authorization

    # ------------------------------------------------------------------------------------------ dispatch
    def verify(self, finding: dict) -> VerificationResult:
        cls = finding.get("metadata", {}).get("sink_class") or _infer_class(finding)
        proc = {"html": self.verify_xss, "navigation": self.verify_open_redirect}.get(cls)
        category = finding.get("category")
        if category == "endpoint" and finding.get("metadata", {}).get("verify_as") == "cors":
            proc = self.verify_cors
        if category in ("authorization", "idor") or finding.get("attack_surface") == "idor_candidate":
            proc = self.verify_authorization
        if proc is None:
            return VerificationResult(finding["id"], cls or category or "unknown", "unverified", "no-procedure",
                                      observations=["no verification procedure is defined for this finding's class"])
        if not self.authorized:
            return _rejected(finding["id"], cls or category, "authorization-check",
                             "active verification requires explicit authorization (--authorize-active-tests)")
        try:
            self.policy.stop.check()
            return proc(finding)
        except EmergencyStopped as exc:
            return _inconclusive(finding["id"], cls or category, "stopped", f"emergency stop: {exc}")
        except ScopeViolation as exc:
            return _rejected(finding["id"], cls or category, "scope-check", f"target is out of scope: {exc}")

    # ------------------------------------------------------------------------------------------ XSS (reflected / DOM)
    def verify_xss(self, finding: dict) -> VerificationResult:
        flow = finding.get("metadata", {}).get("flow", {})
        src_kind = flow.get("source", {}).get("kind", "")
        url = self._url_for_source(finding, flow)
        if url is None:
            return _inconclusive(finding["id"], "dom_xss_candidate", "xss-marker",
                                 "could not derive a concrete, safe test URL from this static source")
        marker = f"jscopex{uuid.uuid4().hex[:8]}"
        probe = f'<i data-jscope="{marker}">{marker}</i>'
        test_url = self._inject(url, src_kind, probe)
        if test_url is None:
            return _inconclusive(finding["id"], "dom_xss_candidate", "xss-marker",
                                 f"do not know how to safely inject a marker into source kind {src_kind!r}")
        if self.pw is None or not PlaywrightDriver.available():
            return self._xss_http_fallback(finding, test_url, marker, probe)
        return self._xss_browser(finding, test_url, marker)

    def _xss_browser(self, finding: dict, test_url: str, marker: str) -> VerificationResult:
        trace = RuntimeTrace(test_url, "playwright")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return self._xss_http_fallback(finding, test_url, marker, marker)
        actions = [{"request": {"method": "GET", "url": redact_url(test_url)}}]
        try:
            self.policy.check_url(test_url)
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
                ctx = browser.new_context(service_workers="block", permissions=[])
                page = ctx.new_page()
                rec = Recorder(self.policy, trace)
                ctx.route("**/*", rec.route_handler)
                page.goto(test_url, wait_until="load", timeout=15000)
                self.policy.stop.check()
                found = page.evaluate(f"() => !!document.querySelector('[data-jscope=\"{marker}\"]')")
                browser.close()
        except EmergencyStopped:
            raise
        except ScopeViolation as exc:
            return _rejected(finding["id"], "dom_xss_candidate", "xss-browser-marker", f"target out of scope: {exc}")
        except Exception as exc:     # noqa: BLE001
            return _inconclusive(finding["id"], "dom_xss_candidate", "xss-browser-marker",
                                 f"browser verification did not complete: {type(exc).__name__}", actions)
        actions.append({"observation": "marker element present in the DOM" if found else "marker element not found"})
        if found:
            return VerificationResult(finding["id"], "dom_xss_candidate", "confirmed", "xss-browser-marker",
                                      actions=actions, observations=[f"a harmless marker element ({marker}) injected via the "
                                      "documented source was parsed into the live DOM, confirming the sink renders it as markup"],
                                      behavior_reproduced=True)
        return VerificationResult(finding["id"], "dom_xss_candidate", "rejected", "xss-browser-marker", actions=actions,
                                  observations=["the injected marker was NOT found as a DOM element; the sink likely encodes or strips it"])

    def _xss_http_fallback(self, finding: dict, test_url: str, marker: str, probe: str) -> VerificationResult:
        try:
            r = self.client.request("GET", test_url, follow=True)
        except ScopeViolation as exc:
            return _rejected(finding["id"], "dom_xss_candidate", "xss-http-reflection", f"target out of scope: {exc}")
        body = r.body.decode("utf-8", "replace")
        actions = [{"request": {"method": "GET", "url": redact_url(test_url)}, "response": {"status": r.status}}]
        if probe in body:
            return VerificationResult(finding["id"], "reflected_xss", "probable", "xss-http-reflection", actions=actions,
                                      observations=[f"marker reflected unescaped in the response body (static check only; "
                                      "DOM parsing / script execution was not observed -- install playwright to confirm)"],
                                      limitations=["no browser available: this is reflection evidence, not confirmed DOM execution"])
        if marker in body:
            return VerificationResult(finding["id"], "reflected_xss", "unverified", "xss-http-reflection", actions=actions,
                                      observations=["marker reflected but appears escaped/encoded"], behavior_reproduced=False)
        return VerificationResult(finding["id"], "reflected_xss", "rejected", "xss-http-reflection", actions=actions,
                                  observations=["marker not found in the response; could not reproduce"])

    def _url_for_source(self, finding: dict, flow: dict) -> str | None:
        meta = finding.get("metadata", {})
        if meta.get("test_url"):
            return urljoin(self.base + "/", meta["test_url"])
        return self.base + "/"

    @staticmethod
    def _inject(url: str, src_kind: str, probe: str) -> str | None:
        u = urlparse(url)
        if src_kind == "url_hash":
            return url.split("#")[0] + "#" + probe
        if src_kind in ("url_query", "url"):
            return url.split("?")[0] + "?" + urlencode({"q": probe})
        if src_kind == "referrer":
            return None                                                 # cannot forge the Referer header from the target URL alone
        return None

    # ------------------------------------------------------------------------------------------ open redirect
    def verify_open_redirect(self, finding: dict) -> VerificationResult:
        flow = finding.get("metadata", {}).get("flow", {})
        url = self._url_for_source(finding, flow)
        marker_host = "jscope-verify.invalid"
        test_url = self._inject(url, flow.get("source", {}).get("kind", ""), f"https://{marker_host}/")
        if test_url is None:
            return _inconclusive(finding["id"], "open_redirect_candidate", "redirect-marker",
                                 "could not derive a concrete test URL for this source kind")
        try:
            r = self.client.request("GET", test_url, follow=False)
        except ScopeViolation as exc:
            return _rejected(finding["id"], "open_redirect_candidate", "redirect-marker", f"target out of scope: {exc}")
        loc = r.headers.get("location", "")
        actions = [{"request": {"method": "GET", "url": redact_url(test_url)}, "response": {"status": r.status, "location": redact_url(loc)}}]
        if 300 <= r.status < 400 and marker_host in loc:
            return VerificationResult(finding["id"], "open_redirect_candidate", "confirmed", "redirect-marker", actions=actions,
                                      observations=[f"server issued a {r.status} redirect to the attacker-controlled host from the test URL"],
                                      behavior_reproduced=True)
        return VerificationResult(finding["id"], "open_redirect_candidate", "rejected", "redirect-marker", actions=actions,
                                  observations=["no redirect to the attacker-controlled host was observed"])

    # ------------------------------------------------------------------------------------------ CORS / headers
    def verify_cors(self, finding: dict) -> VerificationResult:
        path = finding.get("subject", "/")
        url = self.base + (path if path.startswith("/") else "/" + path)
        origin = "https://jscope-verify.invalid"
        try:
            r = self.client.request("GET", url, headers={"Origin": origin})
        except ScopeViolation as exc:
            return _rejected(finding["id"], "cors_misconfiguration", "cors-probe", f"target out of scope: {exc}")
        aco, acc = r.headers.get("access-control-allow-origin", ""), r.headers.get("access-control-allow-credentials", "")
        actions = [{"request": {"method": "GET", "url": redact_url(url), "headers": {"Origin": origin}},
                    "response": {"status": r.status, "headers": {"access-control-allow-origin": aco, "access-control-allow-credentials": acc}}}]
        if aco == origin and acc.lower() == "true":
            return VerificationResult(finding["id"], "cors_misconfiguration", "confirmed", "cors-probe", actions=actions,
                                      observations=["server reflected an arbitrary Origin in Access-Control-Allow-Origin "
                                      "together with Access-Control-Allow-Credentials: true -- any site can read authenticated responses"],
                                      behavior_reproduced=True)
        if aco == "*":
            return VerificationResult(finding["id"], "cors_misconfiguration", "probable", "cors-probe", actions=actions,
                                      observations=["Access-Control-Allow-Origin: * (credentials are not allowed with a wildcard, "
                                      "so impact depends on whether the endpoint needs authentication)"])
        return VerificationResult(finding["id"], "cors_misconfiguration", "rejected", "cors-probe", actions=actions,
                                  observations=["server did not reflect the test Origin"])

    # ------------------------------------------------------------------------------------------ authorization / IDOR
    def verify_authorization(self, finding: dict) -> VerificationResult:
        if len(self.identities) < 2:
            return _inconclusive(finding["id"], "broken_access_control", "authz-diff",
                                 "needs at least two configured test identities (--identity NAME=... at least twice); "
                                 "none/too few configured")
        path = finding.get("subject", "")
        if not path.startswith("/") or re.search(r"[:{<*]", path):
            return _inconclusive(finding["id"], "broken_access_control", "authz-diff",
                                 "endpoint path still has an unresolved parameter; supply a concrete --test-url")
        url = self.base + path
        responses: dict[str, ScopedResponse] = {}
        actions = []
        try:
            for ident in self.identities:
                r = self.client.request("GET", url, headers=ident.headers, follow=True)
                responses[ident.name] = r
                actions.append({"identity": ident.name, "role": ident.role,
                                "request": {"method": "GET", "url": redact_url(url)}, "response": {"status": r.status, "length": r.length}})
        except ScopeViolation as exc:
            return _rejected(finding["id"], "broken_access_control", "authz-diff", f"target out of scope: {exc}")
        low_priv = [i for i in self.identities if not i.role or i.role in ("user", "low", "unauth", "guest")]
        high_priv = [i for i in self.identities if i not in low_priv] or self.identities[1:]
        if not low_priv:
            low_priv = [self.identities[0]]
        lo, hi = responses[low_priv[0].name], responses[high_priv[0].name]
        if lo.status == 200 and hi.status == 200 and lo.length and hi.length and abs(lo.length - hi.length) / max(lo.length, hi.length) < 0.05:
            return VerificationResult(finding["id"], "broken_access_control", "confirmed", "authz-diff", actions=actions,
                                      observations=[f"identity '{low_priv[0].name}' (role={low_priv[0].role or 'unspecified'}) received "
                                      f"a 200 response of similar size/shape to '{high_priv[0].name}' -- access does not appear to be "
                                      "differentiated by role for this endpoint"], behavior_reproduced=True,
                                      limitations=["response-shape comparison is a strong signal, not proof the SAME record/data was returned; "
                                                   "manually diff the response bodies"])
        if lo.status in (401, 403) and hi.status == 200:
            return VerificationResult(finding["id"], "broken_access_control", "rejected", "authz-diff", actions=actions,
                                      observations=[f"low-privilege identity got {lo.status}; access control appears to be enforced"])
        return VerificationResult(finding["id"], "broken_access_control", "inconclusive", "authz-diff", actions=actions,
                                  observations=[f"responses differ in a way JScope cannot interpret automatically "
                                  f"({low_priv[0].name}={lo.status}/{lo.length}b, {high_priv[0].name}={hi.status}/{hi.length}b)"])


def _infer_class(finding: dict) -> str | None:
    cat = finding.get("category")
    if cat == "secret":
        return None
    return cat

"""Runtime observation (FR-03): collect evidence about what the application ACTUALLY does, inside an explicit scope.

Two drivers share one trace model:
  * PlaywrightDriver  -- a real browser (JavaScript executes, XHR/fetch are seen). Needs `pip install playwright` + a browser.
  * HttpPassiveDriver -- no JavaScript: fetches the page and its script/stylesheet references through the scoped client.
                         Honest about its blind spot: requests initiated BY script are not observed.
Both route every outbound request through ScopePolicy (scheme/host/port/DNS/address class/redirects/rate/stop switch).

Evidence discipline (PRD FR-03):
  * a trace separates what was OBSERVED from what static analysis INFERRED; correlation never claims an exact source line
    (exactness is `endpoint-match` or `initiator-file`, never a line number)
  * a blocked request, browser failure or timeout makes the trace `incomplete` and every conclusion that depends on the
    missing part `inconclusive` -- absence of an observation is never reported as safety
  * credentials are not retained: Authorization/Cookie headers are never recorded, cookie VALUES are never stored,
    storage values for sensitive-looking keys are masked, URLs are redacted (jscope.core.redact)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from jscope.core.redact import redact_storage_value, redact_url
from jscope.runtime.scope import (EmergencyStopped, ScopePolicy, ScopeViolation, ScopedClient, pinned_dns)

DRIVERS = ("auto", "playwright", "http")


@dataclass
class TraceEvent:
    kind: str                 # navigation | redirect | request | response | blocked | storage | console_error | step
    url: str = ""
    method: str = ""
    status: int | None = None
    resource_type: str = ""   # document | script | xhr | fetch | stylesheet | image | other
    from_url: str = ""
    initiator: str = ""       # script URL that issued the request when the driver can tell (file-level only)
    detail: str = ""
    step: int = 0
    seq: int = 0

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", None) or k in ("kind", "seq")}


@dataclass
class RuntimeTrace:
    target: str
    driver: str
    scenario: str = "default"
    events: list[TraceEvent] = field(default_factory=list)
    status: str = "complete"                       # complete | incomplete
    incomplete_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    storage: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)

    def add(self, **kw) -> TraceEvent:
        ev = TraceEvent(seq=len(self.events), **kw)
        self.events.append(ev)
        return ev

    def incomplete(self, reason: str) -> None:
        self.status = "incomplete"
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def requests(self, *types: str) -> list[TraceEvent]:
        return [e for e in self.events if e.kind == "request" and (not types or e.resource_type in types)]

    def to_dict(self) -> dict:
        return {"schema": "jscope-runtime-trace/1", "target": redact_url(self.target), "driver": self.driver, "scenario": self.scenario,
                "status": self.status, "incomplete_reasons": self.incomplete_reasons, "limitations": self.limitations,
                "events": [e.to_dict() for e in self.events], "storage": self.storage, "scope": self.scope}


# ------------------------------------------------------------------------------------------------ scenarios
@dataclass
class Scenario:
    name: str = "default"
    steps: list[dict] = field(default_factory=list)       # {"goto": path} {"click": sel} {"fill": [sel, text]} {"wait_ms": n}

    @staticmethod
    def load(path: str) -> "Scenario":
        data = json.loads(open(path, encoding="utf-8").read())
        steps = data.get("steps", [])
        if not isinstance(steps, list) or not all(isinstance(s, dict) and len(s) == 1 for s in steps):
            raise ValueError("scenario steps must be a list of single-key objects, e.g. {\"goto\": \"/\"}")
        for s in steps:
            if next(iter(s)) not in ("goto", "click", "fill", "wait_ms"):
                raise ValueError(f"unsupported scenario step {next(iter(s))!r}")
        return Scenario(str(data.get("name", "scenario")), steps)

    @staticmethod
    def default(path: str = "/") -> "Scenario":
        return Scenario("default", [{"goto": path}])


# ------------------------------------------------------------------------------------------------ passive HTTP driver
class HttpPassiveDriver:
    name = "http-passive"

    def __init__(self, policy: ScopePolicy, client: ScopedClient | None = None):
        self.policy = policy
        self.client = client or ScopedClient(policy)

    def run(self, base_url: str, scenario: Scenario, trace: RuntimeTrace) -> None:
        trace.limitations.append("passive HTTP driver: JavaScript is NOT executed, so requests issued by scripts (XHR/fetch), "
                                 "client-side routing and DOM state are not observed")
        for i, step in enumerate(scenario.steps):
            (kind, arg), = step.items()
            trace.add(kind="step", detail=f"{kind} {redact_url(str(arg)) if kind == 'goto' else '...'}", step=i)
            if kind != "goto":
                trace.incomplete(f"step {kind!r} needs a real browser (use --driver playwright)")
                continue
            try:
                self._goto(urljoin(base_url, str(arg)), trace, i)
            except EmergencyStopped as exc:
                trace.incomplete(f"emergency stop: {exc}")
                return
            except ScopeViolation as exc:
                trace.add(kind="blocked", url=redact_url(urljoin(base_url, str(arg))), detail=str(exc), step=i)
                trace.incomplete(f"request blocked by scope policy: {exc}")
            except Exception as exc:     # noqa: BLE001 - network errors are inconclusive, never "safe"
                trace.incomplete(f"request failed: {type(exc).__name__}")

    def _goto(self, url: str, trace: RuntimeTrace, step: int) -> None:
        r = self.client.request("GET", url, follow=True, body_limit=512 * 1024)
        for frm, st, to in r.redirects:
            trace.add(kind="redirect", url=redact_url(to), from_url=redact_url(frm), status=st, step=step)
        trace.add(kind="request", url=redact_url(r.url), method="GET", resource_type="document", step=step)
        trace.add(kind="response", url=redact_url(r.url), status=r.status, resource_type="document", step=step)
        trace.add(kind="navigation", url=redact_url(r.url), status=r.status, step=step)
        if "html" not in (r.content_type or "").lower():
            return
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.body.decode("utf-8", "replace"), "html.parser")
        subs: list[tuple[str, str]] = []
        for el in soup.find_all("script", src=True):
            subs.append((urljoin(r.url, el["src"]), "script"))
        for el in soup.find_all("link", href=True):
            if {"stylesheet", "modulepreload"} & set(el.get("rel", [])):
                subs.append((urljoin(r.url, el["href"]), "stylesheet"))
        for u, rtype in subs[:40]:
            try:
                sr = self.client.request("GET", u, follow=True, body_limit=1024)
                trace.add(kind="request", url=redact_url(sr.url), method="GET", resource_type=rtype, initiator=redact_url(r.url), step=step)
                trace.add(kind="response", url=redact_url(sr.url), status=sr.status, resource_type=rtype, step=step)
            except ScopeViolation as exc:
                trace.add(kind="blocked", url=redact_url(u), detail=str(exc), step=step)
                trace.incomplete(f"subresource blocked by scope policy: {urlparse(u).netloc}")
            except EmergencyStopped:
                raise
            except Exception as exc:     # noqa: BLE001
                trace.incomplete(f"subresource failed: {type(exc).__name__}")


# ------------------------------------------------------------------------------------------------ browser driver
class PlaywrightDriver:
    """Real browser driver. The trace recording is separated from Playwright (`on_request`, `on_response`, ...), so the
    event handling is unit-tested with stand-in objects; the launch/route code needs an installed browser."""
    name = "playwright"

    def __init__(self, policy: ScopePolicy, headless: bool = True, step_timeout_ms: int = 15000,
                 sync_playwright: Callable | None = None):
        self.policy, self.headless, self.step_timeout_ms = policy, headless, step_timeout_ms
        self._sync_playwright = sync_playwright

    @staticmethod
    def available() -> bool:
        try:
            import playwright.sync_api  # noqa: F401
            return True
        except ImportError:
            return False

    # -- event recording (browser independent) ----------------------------------------------------
    def attach(self, trace: RuntimeTrace) -> "Recorder":
        return Recorder(self.policy, trace)

    def run(self, base_url: str, scenario: Scenario, trace: RuntimeTrace) -> None:
        sp = self._sync_playwright
        if sp is None:
            try:
                from playwright.sync_api import sync_playwright as sp
            except ImportError:
                trace.incomplete("playwright is not installed (pip install playwright && playwright install chromium)")
                return
        rec = self.attach(trace)
        try:
            host = urlparse(base_url).hostname or ""
            port = urlparse(base_url).port or (443 if base_url.startswith("https") else 80)
            addrs = self.policy.check_url(base_url)               # validated BEFORE the browser starts
            args = ["--disable-dev-shm-usage", "--disable-extensions", "--no-first-run", "--disable-background-networking",
                    f"--host-resolver-rules=MAP {host} {addrs[0] if addrs else host}, MAP * ~NOTFOUND"]   # pins DNS in the browser
            with sp() as p:
                browser = p.chromium.launch(headless=self.headless, args=args)
                ctx = browser.new_context(accept_downloads=False, service_workers="block", permissions=[], ignore_https_errors=False,
                                          java_script_enabled=True, bypass_csp=False)
                ctx.route("**/*", rec.route_handler)
                page = ctx.new_page()
                page.set_default_timeout(self.step_timeout_ms)
                page.on("request", rec.on_request)
                page.on("response", rec.on_response)
                page.on("framenavigated", lambda fr: rec.on_navigated(fr.url) if fr == page.main_frame else None)
                page.on("console", lambda m: rec.on_console(m.type, m.text))
                page.on("requestfailed", lambda r: rec.on_failed(r.url, getattr(r, "failure", "")))
                for i, step in enumerate(scenario.steps):
                    self.policy.stop.check()
                    (kind, arg), = step.items()
                    rec.step = i
                    trace.add(kind="step", detail=f"{kind} {redact_url(str(arg)) if kind == 'goto' else (arg[0] if kind == 'fill' else arg)}", step=i)
                    try:
                        if kind == "goto":
                            page.goto(urljoin(base_url, str(arg)), wait_until="load")
                        elif kind == "click":
                            page.click(str(arg))
                        elif kind == "fill":
                            page.fill(str(arg[0]), str(arg[1]))
                        elif kind == "wait_ms":
                            page.wait_for_timeout(int(arg))
                    except EmergencyStopped:
                        raise
                    except Exception as exc:     # noqa: BLE001 - timeouts etc.
                        trace.incomplete(f"step {i} ({kind}) did not complete: {type(exc).__name__}")
                self.snapshot_storage(page, ctx, trace)
                browser.close()
        except EmergencyStopped as exc:
            trace.incomplete(f"emergency stop: {exc}")
        except ScopeViolation as exc:
            trace.incomplete(f"target blocked by scope policy: {exc}")
        except Exception as exc:     # noqa: BLE001 - browser crash / missing browser binary
            trace.incomplete(f"browser failure: {type(exc).__name__}: {str(exc)[:160]}")

    def snapshot_storage(self, page, ctx, trace: RuntimeTrace) -> None:
        try:
            raw = page.evaluate("() => ({local: Object.entries(localStorage), session: Object.entries(sessionStorage)})")
            trace.storage = store_snapshot(raw.get("local", []), raw.get("session", []), ctx.cookies())
        except Exception as exc:     # noqa: BLE001
            trace.incomplete(f"storage snapshot failed: {type(exc).__name__}")


def store_snapshot(local: list, session: list, cookies: list) -> dict:
    """Keys always; values only for non-sensitive keys, truncated; cookie VALUES never."""
    return {
        "localStorage": [{"key": k, "value": redact_storage_value(k, str(v)), "length": len(str(v))} for k, v in local][:100],
        "sessionStorage": [{"key": k, "value": redact_storage_value(k, str(v)), "length": len(str(v))} for k, v in session][:100],
        "cookies": [{"name": c.get("name"), "domain": c.get("domain"), "httpOnly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")),
                     "sameSite": c.get("sameSite")} for c in cookies][:100],
    }


class Recorder:
    """Turns browser callbacks into trace events, enforcing scope in the route handler."""
    TYPES = {"document": "document", "script": "script", "xhr": "xhr", "fetch": "fetch", "stylesheet": "stylesheet", "image": "image"}

    def __init__(self, policy: ScopePolicy, trace: RuntimeTrace):
        self.policy, self.trace, self.step = policy, trace, 0

    def route_handler(self, route, request=None) -> None:
        request = request or route.request
        try:
            self.policy.stop.check()
            self.policy.check_url(request.url)
            self.policy.before_send()
            route.continue_()
        except (ScopeViolation, EmergencyStopped) as exc:
            self.trace.add(kind="blocked", url=redact_url(request.url), method=request.method, detail=str(exc), step=self.step)
            self.trace.incomplete(f"request to {urlparse(request.url).netloc} blocked by scope policy")
            route.abort("blockedbyclient")

    def on_request(self, req) -> None:
        rt = self.TYPES.get(getattr(req, "resource_type", ""), "other")
        init = ""
        frame_url = getattr(getattr(req, "frame", None), "url", "")
        if rt in ("xhr", "fetch"):
            init = redact_url(frame_url) if frame_url else ""            # page-level only: NOT a source location
        self.trace.add(kind="request", url=redact_url(req.url), method=req.method, resource_type=rt, initiator=init, step=self.step)
        red = getattr(req, "redirected_from", None)
        if red is not None:
            self.trace.add(kind="redirect", url=redact_url(req.url), from_url=redact_url(red.url), step=self.step)

    def on_response(self, resp) -> None:
        self.trace.add(kind="response", url=redact_url(resp.url), status=resp.status,
                       resource_type=self.TYPES.get(getattr(resp.request, "resource_type", ""), "other"), step=self.step)

    def on_navigated(self, url: str) -> None:
        self.trace.add(kind="navigation", url=redact_url(url), step=self.step)

    def on_console(self, kind: str, text: str) -> None:
        if kind == "error":
            from jscope.core.redact import redact_text
            self.trace.add(kind="console_error", detail=(redact_text(text) or "")[:200], step=self.step)

    def on_failed(self, url: str, failure: str) -> None:
        self.trace.incomplete(f"request failed: {redact_url(url)} ({failure})")


# ------------------------------------------------------------------------------------------------ orchestration
def observe(base_url: str, policy: ScopePolicy, scenario: Scenario | None = None, driver: str = "auto",
            drivers: dict[str, Any] | None = None) -> RuntimeTrace:
    scenario = scenario or Scenario.default()
    drivers = drivers or {}
    if driver == "auto":
        driver = "playwright" if PlaywrightDriver.available() else "http"
    d = drivers.get(driver) or (PlaywrightDriver(policy) if driver == "playwright" else HttpPassiveDriver(policy))
    trace = RuntimeTrace(target=base_url, driver=d.name, scenario=scenario.name, scope=policy.describe())
    d.run(base_url, scenario, trace)
    trace.scope = policy.describe()
    if policy.blocked:
        trace.incomplete(f"{len(policy.blocked)} request(s) blocked by scope policy")
    trace.limitations.append("an incomplete trace is inconclusive: missing observations are NOT evidence that behaviour is absent or safe")
    return trace


# ------------------------------------------------------------------------------------------------ correlation
_PARAM = re.compile(r"(:[A-Za-z_]\w*|\{[^}/]*\}|\$\{[^}]*\}|\[[^\]/]+\]|<[^>/]+>|\*)")


def _template_regex(path: str) -> re.Pattern:
    out, last = [], 0
    for m in _PARAM.finditer(path):
        out.append(re.escape(path[last:m.start()]))
        out.append(r"[^/?#]+")
        last = m.end()
    out.append(re.escape(path[last:]))
    return re.compile("^" + "".join(out) + r"/?$")


def correlate(trace: RuntimeTrace, payload: dict) -> dict:
    """Link observed requests to static endpoint findings. Output sections:
       confirmed_by_runtime   static endpoint also seen at runtime        (exactness: endpoint-match | initiator-file)
       runtime_only           observed requests no static finding explains (static analysis missed them)
       not_observed           static endpoints that were NOT seen         (inconclusive unless the trace is complete AND driver ran JS)
    Never claims a source line: runtime evidence carries at most the initiating page/script URL."""
    endpoints = [f for f in payload.get("findings", []) if f.get("category") == "endpoint"]
    templ = []
    for f in endpoints:
        subj = f["subject"]
        path = urlparse(subj).path if "://" in subj else subj.split("?")[0]
        if path.startswith("/"):
            templ.append((f, _template_regex(path), path))
    static_files = {}
    for f in payload.get("findings", []):
        for e in f.get("evidence", []):
            if e.get("file"):
                static_files.setdefault(e["file"].rsplit("/", 1)[-1], set()).add(f["id"])
    seen: dict[str, dict] = {}
    runtime_only: list[dict] = []
    for ev in trace.requests("xhr", "fetch", "document", "other"):
        path = urlparse(ev.url).path or "/"
        hit = next(((f, p) for f, rx, p in templ if rx.match(path)), None)
        if hit:
            f, p = hit
            ent = seen.setdefault(f["id"], {"finding_id": f["id"], "subject": f["subject"], "observed": [], "exactness": "endpoint-match",
                                            "basis": "request path matches the static endpoint (template-aware)"})
            ent["observed"].append({"method": ev.method, "url": ev.url, "status": _status_for(trace, ev.url)})
            init_file = (urlparse(ev.initiator).path.rsplit("/", 1)[-1] if ev.initiator else "")
            if init_file in static_files and f["id"] in static_files[init_file]:
                ent["exactness"] = "initiator-file"
                ent["basis"] += f"; initiated from a page/script ({init_file}) that also contains the static call site (file-level only)"
        elif ev.resource_type in ("xhr", "fetch"):
            runtime_only.append({"method": ev.method, "url": ev.url, "status": _status_for(trace, ev.url),
                                 "note": "observed at runtime but not predicted by static analysis"})
    can_conclude = trace.status == "complete" and trace.driver == "playwright"
    not_obs = [{"finding_id": f["id"], "subject": f["subject"],
                "verdict": "not_observed" if can_conclude else "inconclusive",
                "reason": ("no matching request in a complete browser trace (the scenario may simply not have exercised it)" if can_conclude
                           else "trace is incomplete or JavaScript was not executed; absence proves nothing")}
               for f, _, _ in templ if f["id"] not in seen]
    return {"confirmed_by_runtime": list(seen.values()), "runtime_only": runtime_only, "not_observed": not_obs,
            "trace_status": trace.status, "driver": trace.driver, "incomplete_reasons": trace.incomplete_reasons,
            "note": "runtime observations do not prove exploitability; static/runtime links are endpoint-level, not source-line-level"}


def _status_for(trace: RuntimeTrace, url: str) -> int | None:
    for e in trace.events:
        if e.kind == "response" and e.url == url:
            return e.status
    return None


def novel_routes(trace: RuntimeTrace, payload: dict) -> list[str]:
    """Navigation paths seen at runtime that the static route map did not contain."""
    known = {r["route"] for r in payload.get("route_map", []) or []}
    templ = [_template_regex(r) for r in known if r.startswith("/")]
    out = []
    for e in trace.events:
        if e.kind == "navigation":
            p = urlparse(e.url).path or "/"
            if not any(t.match(p) for t in templ) and p not in out:
                out.append(p)
    return out

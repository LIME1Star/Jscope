"""FR-03: runtime observation, scope enforcement during observation, static/runtime correlation."""
import http.server
import json
import threading
from types import SimpleNamespace

import pytest

from jscope.runtime.observe import (HttpPassiveDriver, PlaywrightDriver, Recorder, RuntimeTrace, Scenario, correlate, novel_routes,
                                    observe, store_snapshot)
from jscope.runtime.scope import ScopePolicy


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        routes = {
            "/": ("text/html", b'<html><script src="/static/app.js"></script><script src="http://evil.invalid/x.js"></script>'
                               b'<link rel="stylesheet" href="/static/a.css"></html>'),
            "/static/app.js": ("application/javascript", b"fetch('/api/users')"),
            "/static/a.css": ("text/css", b"body{}"),
            "/api/users/7": ("application/json", b"{}"),
        }
        if self.path == "/old":
            self.send_response(302); self.send_header("Location", "/new"); self.end_headers(); return
        if self.path == "/new":
            routes["/new"] = ("text/html", b"<html>new</html>")
        if self.path == "/leave":
            self.send_response(302); self.send_header("Location", "http://evil.invalid/"); self.end_headers(); return
        ct, body = routes.get(self.path, ("text/plain", b"nf"))
        self.send_response(200 if self.path in routes else 404)
        self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


def policy(port, **kw):
    return ScopePolicy(allow_hosts={f"127.0.0.1:{port}", "127.0.0.1"}, allow_private=True, rate_per_second=1000, **kw)


def test_passive_trace_contains_expected_requests_and_navigation(server):
    base, port = server
    t = observe(base, policy(port), Scenario.default("/"), driver="http")
    assert t.driver == "http-passive"
    assert [e.url for e in t.events if e.kind == "navigation"] == [base + "/"]
    reqs = {e.url.replace(base, "") for e in t.requests()}
    assert {"/", "/static/app.js", "/static/a.css"} <= reqs
    assert any("JavaScript is NOT executed" in l for l in t.limitations)


def test_out_of_scope_subresource_is_blocked_and_trace_is_inconclusive(server):
    base, port = server
    p = policy(port)
    t = observe(base, p, Scenario.default("/"), driver="http")
    assert any(e.kind == "blocked" and "evil.invalid" in e.url for e in t.events)
    assert t.status == "incomplete" and any("blocked" in r for r in t.incomplete_reasons)
    assert p.blocked


def test_redirect_inside_scope_recorded_and_outside_blocked(server):
    base, port = server
    t = observe(base, policy(port), Scenario("r", [{"goto": "/old"}]), driver="http")
    assert [(e.from_url.replace(base, ""), e.url.replace(base, ""), e.status) for e in t.events if e.kind == "redirect"] == [("/old", "/new", 302)]
    t2 = observe(base, policy(port), Scenario("r", [{"goto": "/leave"}]), driver="http")
    assert t2.status == "incomplete" and any(e.kind == "blocked" for e in t2.events)
    assert not any("evil.invalid" in e.url for e in t2.events if e.kind in ("request", "response"))


def test_unsupported_step_makes_trace_incomplete_not_complete(server):
    base, port = server
    t = observe(base, policy(port), Scenario("s", [{"goto": "/"}, {"click": "#buy"}]), driver="http")
    assert t.status == "incomplete" and any("real browser" in r for r in t.incomplete_reasons)


def test_unreachable_target_is_inconclusive():
    p = ScopePolicy(allow_hosts={"127.0.0.1:9", "127.0.0.1"}, allow_private=True, rate_per_second=1000, timeout=1)
    t = observe("http://127.0.0.1:9", p, Scenario.default("/"), driver="http")
    assert t.status == "incomplete" and any("failed" in r for r in t.incomplete_reasons)


def test_scenario_loading_validation(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"name": "x", "steps": [{"goto": "/"}, {"wait_ms": 10}]}))
    assert Scenario.load(str(f)).steps[0] == {"goto": "/"}
    f.write_text(json.dumps({"steps": [{"exec": "rm -rf /"}]}))
    with pytest.raises(ValueError):
        Scenario.load(str(f))
    f.write_text(json.dumps({"steps": [{"goto": "/", "click": "#x"}]}))
    with pytest.raises(ValueError):
        Scenario.load(str(f))


def test_urls_are_redacted_in_trace(server):
    base, port = server
    t = observe(base, policy(port), Scenario("r", [{"goto": "/?access_token=abc123456&q=ok"}]), driver="http")
    dumped = json.dumps(t.to_dict())
    assert "abc123456" not in dumped and "q=ok" in dumped and "[REDACTED]" in dumped


# ---------------------------------------------------------------------------------------- browser recorder (stand-in objects)
class Route:
    def __init__(self, url, method="GET"):
        self.request = SimpleNamespace(url=url, method=method)
        self.done = None

    def continue_(self):
        self.done = "continue"

    def abort(self, why):
        self.done = f"abort:{why}"


def test_recorder_enforces_scope_in_route_handler():
    trace = RuntimeTrace("https://app.test", "playwright")
    pol = ScopePolicy(allow_hosts={"app.test"}, resolver=lambda h, p: ["93.184.216.34"], rate_per_second=1000)
    rec = Recorder(pol, trace)
    ok, bad, priv = Route("https://app.test/api/x"), Route("https://tracker.example/p.gif"), Route("https://app.test/")
    rec.route_handler(ok)
    rec.route_handler(bad)
    pol.resolver = lambda h, p: ["127.0.0.1"]                         # DNS flips to loopback mid-run
    rec.route_handler(priv)
    assert ok.done == "continue" and bad.done.startswith("abort") and priv.done.startswith("abort")
    assert [e.kind for e in trace.events] == ["blocked", "blocked"] and trace.status == "incomplete"


def test_recorder_records_requests_responses_redirects_without_credentials():
    trace = RuntimeTrace("https://app.test", "playwright")
    rec = Recorder(ScopePolicy(allow_hosts={"app.test"}), trace)
    frame = SimpleNamespace(url="https://app.test/app")
    prev = SimpleNamespace(url="https://app.test/a")
    req = SimpleNamespace(url="https://app.test/api/u/5?token=SECRETVALUE", method="POST", resource_type="fetch", frame=frame,
                          redirected_from=prev, headers={"authorization": "Bearer xyz"})
    rec.on_request(req)
    rec.on_response(SimpleNamespace(url=req.url, status=200, request=req))
    rec.on_navigated("https://app.test/dash")
    rec.on_console("error", "failed with token=abcdef123456")
    dump = json.dumps(trace.to_dict())
    assert "SECRETVALUE" not in dump and "xyz" not in dump and "abcdef123456" not in dump
    kinds = [e.kind for e in trace.events]
    assert kinds == ["request", "redirect", "response", "navigation", "console_error"]
    assert trace.requests("fetch")[0].initiator == "https://app.test/app"          # page-level only


def test_storage_snapshot_never_keeps_cookie_values_or_sensitive_storage():
    snap = store_snapshot([("theme", "dark"), ("auth_token", "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbb")], [("cart", "3")],
                          [{"name": "sid", "value": "SECRETCOOKIE", "domain": "app.test", "httpOnly": True, "secure": True, "sameSite": "Lax"}])
    dump = json.dumps(snap)
    assert "SECRETCOOKIE" not in dump and "eyJhbGci" not in dump and "dark" in dump
    assert snap["cookies"][0]["httpOnly"] is True


def test_playwright_missing_is_reported_as_incomplete(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("playwright"):
            raise ImportError
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    t = RuntimeTrace("https://app.test", "playwright")
    PlaywrightDriver(ScopePolicy(allow_hosts={"app.test"})).run("https://app.test", Scenario.default(), t)
    assert t.status == "incomplete" and "not installed" in t.incomplete_reasons[0]


# ---------------------------------------------------------------------------------------- correlation
PAYLOAD = {"findings": [
    {"id": "JS-1", "category": "endpoint", "subject": "/api/users/:id", "evidence": [{"file": "/p/src/app.js", "line": 3}]},
    {"id": "JS-2", "category": "endpoint", "subject": "/api/admin/export", "evidence": [{"file": "/p/src/admin.js", "line": 9}]},
    {"id": "JS-3", "category": "endpoint", "subject": "/api/orders/${id}/items", "evidence": []}],
    "route_map": [{"route": "/", "guards": [], "roles": [], "unguarded": True, "endpoints": []}]}


def _trace(driver="playwright", complete=True):
    t = RuntimeTrace("https://app.test", driver)
    t.add(kind="request", url="https://app.test/api/users/7", method="GET", resource_type="fetch", initiator="https://app.test/static/app.js")
    t.add(kind="response", url="https://app.test/api/users/7", status=200, resource_type="fetch")
    t.add(kind="request", url="https://app.test/api/hidden/flags", method="GET", resource_type="xhr")
    t.add(kind="navigation", url="https://app.test/settings")
    if not complete:
        t.incomplete("browser failure")
    return t


def test_correlation_links_without_claiming_line_numbers_and_finds_unknowns():
    c = correlate(_trace(), PAYLOAD)
    hit = c["confirmed_by_runtime"][0]
    assert hit["finding_id"] == "JS-1" and hit["exactness"] == "initiator-file" and "line" not in json.dumps(hit).replace("file-level", "")
    assert [r["url"] for r in c["runtime_only"]] == ["https://app.test/api/hidden/flags"]
    assert novel_routes(_trace(), PAYLOAD) == ["/settings"]


def test_not_observed_is_only_a_verdict_after_a_complete_browser_trace():
    done = {n["finding_id"]: n["verdict"] for n in correlate(_trace(), PAYLOAD)["not_observed"]}
    assert done == {"JS-2": "not_observed", "JS-3": "not_observed"}
    broken = {n["finding_id"]: n["verdict"] for n in correlate(_trace(complete=False), PAYLOAD)["not_observed"]}
    passive = {n["finding_id"]: n["verdict"] for n in correlate(_trace("http-passive"), PAYLOAD)["not_observed"]}
    assert set(broken.values()) == {"inconclusive"} and set(passive.values()) == {"inconclusive"}

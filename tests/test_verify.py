"""FR-04: evidence-based vulnerability verification against vulnerable and patched fixtures."""
import http.server
import threading

import pytest

from jscope.runtime.scope import ScopePolicy
from jscope.verify.engine import TestIdentity, VerificationEngine

VULN_HTML = (b'<html><body><div id="out"></div><script>'
            b'document.getElementById("out").innerHTML = new URLSearchParams(location.search).get("q") || "";'
            b'</script></body></html>')
PATCHED_HTML = (b'<html><body><div id="out"></div><script>'
                b'document.getElementById("out").textContent = new URLSearchParams(location.search).get("q") || "";'
                b'</script></body></html>')


def make_server(routes):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            handler = routes.get(self.path.split("?")[0])
            if handler is None:
                self.send_response(404); self.end_headers(); return
            self._qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            handler(self)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def simple_html(body):
    def h(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    return h


def reflecting_html(escape=False):
    """Simulates a server that reflects ?q= directly (or HTML-escaped) into the page -- classic reflected XSS fixture."""
    import html as _html
    from urllib.parse import parse_qs

    def h(self):
        q = parse_qs(self._qs).get("q", [""])[0]
        shown = _html.escape(q) if escape else q
        body = f"<html><body><div>{shown}</div></body></html>".encode()
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    return h


def pol(port, **kw):
    return ScopePolicy(allow_hosts={f"127.0.0.1:{port}", "127.0.0.1"}, allow_private=True, rate_per_second=1000, **kw)


def xss_finding():
    return {"id": "JS-1", "category": "dataflow", "subject": "x", "attack_surface": "dom_xss_candidate",
            "metadata": {"sink_class": "html", "flow": {"source": {"kind": "url_query"}}}}


# ----------------------------------------------------------------------------------------- XSS: vulnerable vs patched
def test_reflected_xss_http_fallback_vulnerable_fixture():
    srv = make_server({"/": reflecting_html(escape=False)})
    port = srv.server_address[1]
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True)
    r = eng.verify(xss_finding())
    assert r.status == "probable" and r.vuln_class == "reflected_xss"
    assert any("reflected" in o for o in r.observations)
    srv.shutdown()


def test_reflected_xss_http_fallback_patched_fixture_does_not_confirm():
    srv = make_server({"/": reflecting_html(escape=True)})
    port = srv.server_address[1]
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True)
    r = eng.verify(xss_finding())
    assert r.status in ("rejected", "unverified")
    srv.shutdown()


def test_xss_browser_confirms_dom_execution_vulnerable_fixture():
    pytest.importorskip("playwright")
    from jscope.runtime.observe import PlaywrightDriver
    if not PlaywrightDriver.available():
        pytest.skip("playwright package present but no browser binary installed")
    srv = make_server({"/": simple_html(VULN_HTML)})
    port = srv.server_address[1]
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", playwright_driver=PlaywrightDriver(pol(port)), authorized=True)
    r = eng.verify(xss_finding())
    assert r.status == "confirmed" and r.behavior_reproduced and r.procedure == "xss-browser-marker"
    srv.shutdown()


def test_xss_browser_rejects_on_patched_fixture():
    pytest.importorskip("playwright")
    from jscope.runtime.observe import PlaywrightDriver
    if not PlaywrightDriver.available():
        pytest.skip("no browser binary installed")
    srv = make_server({"/": simple_html(PATCHED_HTML)})
    port = srv.server_address[1]
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", playwright_driver=PlaywrightDriver(pol(port)), authorized=True)
    r = eng.verify(xss_finding())
    assert r.status == "rejected" and not r.behavior_reproduced
    srv.shutdown()


# ----------------------------------------------------------------------------------------- redirect
def test_open_redirect_confirmed_and_rejected():
    def redir(self):
        loc = dict(p.split("=") for p in self.path.split("?", 1)[1].split("&")).get("q", "/")
        self.send_response(302); self.send_header("Location", loc); self.end_headers()

    def safe_redir(self):
        self.send_response(302); self.send_header("Location", "/home"); self.end_headers()

    srv = make_server({"/go": redir})
    port = srv.server_address[1]
    f = {"id": "JS-2", "category": "dataflow", "subject": "x", "metadata": {"sink_class": "navigation", "flow": {"source": {"kind": "url_query"}},
                                                                            "test_url": "/go"}}
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True)
    r = eng.verify(f)
    assert r.status == "confirmed" and r.behavior_reproduced
    srv.shutdown()

    srv2 = make_server({"/go": safe_redir})
    port2 = srv2.server_address[1]
    eng2 = VerificationEngine(pol(port2), f"http://127.0.0.1:{port2}", authorized=True)
    r2 = eng2.verify({**f, "metadata": {**f["metadata"]}})
    assert r2.status == "rejected"
    srv2.shutdown()


# ----------------------------------------------------------------------------------------- CORS
def test_cors_misconfiguration_confirmed():
    def h(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    srv = make_server({"/api/me": h})
    port = srv.server_address[1]
    f = {"id": "JS-3", "category": "endpoint", "subject": "/api/me", "metadata": {"verify_as": "cors"}}
    eng = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True)
    r = eng.verify(f)
    assert r.status == "confirmed" and "Credentials" in r.observations[0]
    srv.shutdown()


def test_security_headers_not_misreported_when_absent():
    def h(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
    srv = make_server({"/api/me": h})
    port = srv.server_address[1]
    f = {"id": "JS-4", "category": "endpoint", "subject": "/api/me", "metadata": {"verify_as": "cors"}}
    r = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True).verify(f)
    assert r.status == "rejected"
    srv.shutdown()


# ----------------------------------------------------------------------------------------- authorization / IDOR
def test_authorization_confirmed_when_responses_match():
    def h(self):
        body = b'{"id":7,"ssn":"secret"}'
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    srv = make_server({"/api/users/7": h})
    port = srv.server_address[1]
    f = {"id": "JS-5", "category": "idor", "subject": "/api/users/7", "attack_surface": "idor_candidate", "metadata": {}}
    ids = [TestIdentity("user_a", role="user"), TestIdentity("user_b", role="user")]
    r = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", identities=ids, authorized=True).verify(f)
    assert r.status == "confirmed" and r.vuln_class == "broken_access_control"
    assert "SAME record" not in r.observations[0]
    srv.shutdown()


def test_authorization_rejected_when_enforced():
    def h(self):
        auth = self.headers.get("X-Role", "")
        if auth != "admin":
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers(); return
        body = b"{}"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    srv = make_server({"/api/admin/x": h})
    port = srv.server_address[1]
    f = {"id": "JS-6", "category": "idor", "subject": "/api/admin/x", "metadata": {}}
    ids = [TestIdentity("guest", role="user", headers={"X-Role": "guest"}), TestIdentity("admin", role="admin", headers={"X-Role": "admin"})]
    r = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", identities=ids, authorized=True).verify(f)
    assert r.status == "rejected" and "enforced" in r.observations[0]
    srv.shutdown()


def test_authorization_inconclusive_without_identities():
    f = {"id": "JS-7", "category": "idor", "subject": "/api/x", "metadata": {}}
    r = VerificationEngine(ScopePolicy(allow_hosts={"a"}), "http://a", authorized=True).verify(f)
    assert r.status == "inconclusive" and "two configured test identities" in r.observations[0]


def test_authorization_never_attempts_privilege_escalation_only_compares_configured_identities():
    calls = []

    def h(self):
        calls.append(self.headers.get("X-Role"))
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
    srv = make_server({"/api/x": h})
    port = srv.server_address[1]
    ids = [TestIdentity("u", role="user", headers={"X-Role": "user"}), TestIdentity("a", role="admin", headers={"X-Role": "admin"})]
    VerificationEngine(pol(port), f"http://127.0.0.1:{port}", identities=ids, authorized=True).verify(
        {"id": "JS-8", "category": "idor", "subject": "/api/x", "metadata": {}})
    assert calls == ["user", "admin"]                                      # exactly the configured identities, nothing invented
    srv.shutdown()


# ----------------------------------------------------------------------------------------- authorization requirement / scope
def test_verification_rejected_without_authorization():
    r = VerificationEngine(ScopePolicy(allow_hosts={"a"}), "http://a", authorized=False).verify(xss_finding())
    assert r.status == "rejected" and "authorization" in r.observations[0]


def test_verification_out_of_scope_target_is_rejected_not_crashed():
    f = {**xss_finding(), "metadata": {"sink_class": "html", "flow": {"source": {"kind": "url_query"}}}}
    eng = VerificationEngine(ScopePolicy(allow_hosts={"nope.test"}), "http://other.test", authorized=True)
    r = eng.verify(f)
    assert r.status == "rejected" and "scope" in r.observations[0]


def test_unsupported_class_is_unverified_not_crashed():
    r = VerificationEngine(ScopePolicy(allow_hosts={"a"}), "http://a", authorized=True).verify(
        {"id": "JS-9", "category": "secret", "subject": "x", "metadata": {}})
    assert r.status == "unverified" and r.procedure == "no-procedure"


def test_verification_result_redacts_urls_in_actions():
    srv = make_server({"/": reflecting_html(escape=False)})
    port = srv.server_address[1]
    f = {"id": "JS-10", "category": "dataflow", "subject": "x", "metadata": {"sink_class": "html", "flow": {"source": {"kind": "url_query"}}}}
    r = VerificationEngine(pol(port), f"http://127.0.0.1:{port}", authorized=True).verify(f)
    import json
    assert "jscopex" not in json.dumps(r.actions).split("q=")[0]
    srv.shutdown()

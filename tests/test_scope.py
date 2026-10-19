"""FR-10: scope policy, DNS validation, redirects, emergency stop."""
import pytest

from jscope.runtime.prober import Prober, ScopeError, HttpResponse
from jscope.runtime.scope import (EmergencyStop, EmergencyStopped, ScopeViolation, ScopePolicy, ScopedClient, ScopedResponse)


def pol(resolver=None, **kw):
    kw.setdefault("allow_hosts", {"app.test"})
    return ScopePolicy(resolver=resolver or (lambda h, p: ["93.184.216.34"]), **kw)


def test_allowed_public_host_passes_and_returns_addresses():
    assert pol().check_url("https://app.test/x") == ["93.184.216.34"]


@pytest.mark.parametrize("url,why", [
    ("ftp://app.test/x", "scheme"),
    ("https://other.test/x", "allow-list"),
    ("https://app.test:8443/x", "port"),
    ("https://user:pw@app.test/x", "credentials"),
])
def test_scheme_host_port_credentials_blocked_and_logged(url, why):
    p = pol()
    with pytest.raises(ScopeViolation) as e:
        p.check_url(url)
    assert why in str(e.value)
    assert p.blocked and p.blocked[0].url == url


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.9", "::1", "fe80::1",
                                "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1", "224.0.0.1"])
def test_prohibited_resolution_blocked_even_for_allowed_name(ip):
    p = pol(resolver=lambda h, port: [ip])
    with pytest.raises(ScopeViolation) as e:
        p.check_url("https://app.test/")
    assert "allow-private" in str(e.value)


def test_one_bad_answer_among_many_blocks():
    p = pol(resolver=lambda h, port: ["93.184.216.34", "10.1.1.1"])          # classic rebinding trick: mixed answers
    with pytest.raises(ScopeViolation):
        p.check_url("https://app.test/")


def test_private_allowed_only_with_explicit_opt_in():
    p = pol(resolver=lambda h, port: ["127.0.0.1"], allow_private=True)
    assert p.check_url("https://app.test/") == ["127.0.0.1"]


def test_literal_ip_checked_without_dns():
    p = ScopePolicy(allow_hosts={"127.0.0.1"})
    with pytest.raises(ScopeViolation):
        p.check_url("http://127.0.0.1/")
    assert ScopePolicy(allow_hosts={"127.0.0.1"}, allow_private=True).check_url("http://127.0.0.1/") == ["127.0.0.1"]


def test_explicit_port_in_allow_list():
    p = pol(allow_hosts={"app.test:8443"})
    assert p.check_url("https://app.test:8443/")
    with pytest.raises(ScopeViolation):
        p.check_url("https://app.test:9999/")


def test_unresolvable_name_is_blocked():
    with pytest.raises(ScopeViolation):
        pol(resolver=lambda h, p: []).check_url("https://app.test/")


# ------------------------------------------------------------------------------------------ redirects
def client(responses, **kw):
    calls = []

    def transport(method, url, headers, timeout, limit):
        calls.append(url)
        return responses[url]
    policy = pol(**kw)
    return ScopedClient(policy, transport=transport, sleep=lambda s: None), calls, policy


def test_redirect_inside_scope_followed():
    c, calls, _ = client({"https://app.test/a": ScopedResponse(302, headers={"location": "/b"}),
                          "https://app.test/b": ScopedResponse(200)}, rate_per_second=1000)
    r = c.request("GET", "https://app.test/a", follow=True)
    assert r.status == 200 and calls == ["https://app.test/a", "https://app.test/b"] and r.redirects


def test_redirect_out_of_scope_blocked_before_connecting():
    c, calls, p = client({"https://app.test/a": ScopedResponse(302, headers={"location": "https://evil.test/x"})}, rate_per_second=1000)
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://app.test/a", follow=True)
    assert calls == ["https://app.test/a"] and any("evil.test" in b.url for b in p.blocked)


def test_redirect_to_metadata_ip_blocked():
    c, calls, _ = client({"https://app.test/a": ScopedResponse(302, headers={"location": "http://169.254.169.254/latest"})},
                         allow_hosts={"app.test", "169.254.169.254"}, rate_per_second=1000)
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://app.test/a", follow=True)
    assert len(calls) == 1


def test_redirects_disabled_and_hop_limit():
    c, _, _ = client({"https://app.test/a": ScopedResponse(302, headers={"location": "/b"})}, redirects="none", rate_per_second=1000)
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://app.test/a", follow=True)
    loop = {"https://app.test/a": ScopedResponse(302, headers={"location": "/a"})}
    c2, _, _ = client(loop, max_redirects=2, rate_per_second=1000)
    with pytest.raises(ScopeViolation):
        c2.request("GET", "https://app.test/a", follow=True)


def test_redirect_without_follow_is_returned_not_followed():
    c, calls, _ = client({"https://app.test/a": ScopedResponse(302, headers={"location": "https://evil.test/"})}, rate_per_second=1000)
    assert c.request("GET", "https://app.test/a").status == 302 and len(calls) == 1


# ------------------------------------------------------------------------------------------ pacing / stop
def test_request_cap_and_rate_limit():
    sleeps = []
    c = ScopedClient(pol(rate_per_second=2, max_requests=2), transport=lambda *a: ScopedResponse(200), sleep=sleeps.append)
    c.request("GET", "https://app.test/1"); c.request("GET", "https://app.test/2")
    with pytest.raises(ScopeViolation):
        c.request("GET", "https://app.test/3")
    assert sleeps and sleeps[0] > 0


def test_emergency_stop_blocks_before_send(tmp_path):
    stop = EmergencyStop(str(tmp_path / "stop"))
    calls = []
    c = ScopedClient(pol(stop=stop, rate_per_second=1000), transport=lambda *a: calls.append(1) or ScopedResponse(200), sleep=lambda s: None)
    c.request("GET", "https://app.test/ok")
    (tmp_path / "stop").write_text("")
    with pytest.raises(EmergencyStopped):
        c.request("GET", "https://app.test/no")
    assert len(calls) == 1


def test_prober_honours_stop_and_blocks_private(tmp_path):
    stop = EmergencyStop(str(tmp_path / "s"))
    policy = ScopePolicy(allow_hosts={"t.test"}, stop=stop, resolver=lambda h, p: ["10.0.0.1"])
    # real-network mode would resolve to a private address; injected fetch skips DNS, so exercise the policy directly
    with pytest.raises(ScopeViolation):
        policy.check_url("https://t.test/x")
    sent = []
    p = Prober("https://t.test", ["t.test"], rate_per_second=1000, fetch=lambda m, u, h, t: sent.append(u) or HttpResponse(200, "application/json", 5),
               sleep=lambda s: None)
    p.policy.stop = stop
    stop.trip("test")
    from jscope.core.evidence import Confidence, Finding
    f = Finding("JS-1", "endpoint", "/api/x", Confidence.MEDIUM, 4, [], [], None, None, [], metadata={"method": "GET"})
    _, results = p.run([f])
    assert sent == [] and all(r.verdict == "error" for r in results)


def test_static_analysis_never_opens_a_socket(tmp_path, monkeypatch):
    import socket
    from jscope.config import Config
    from jscope.pipeline import run_analysis
    (tmp_path / "a.js").write_text("el.innerHTML = location.hash;\nfetch('/api/x');\n")

    def boom(*a, **k):
        raise AssertionError("static analysis attempted network access")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert run_analysis([str(tmp_path)], Config()).findings


def test_prober_still_requires_allow_list():
    with pytest.raises(ScopeError):
        Prober("https://t.test", [])

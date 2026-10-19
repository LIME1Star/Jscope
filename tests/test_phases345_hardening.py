import json
from pathlib import Path

import pytest

from jscope.assessment_engine import (
    AssessmentError, AssessmentOrchestrator, CorrelationEngine, Endpoint,
    EvidenceStore, FindingRecord, ModuleMetadata, ModuleRegistry,
)
from jscope.security_transport import GuardedSession, PolicyError, TransportPolicy


def test_streamed_response_limit_is_enforced(monkeypatch):
    class Response:
        status_code = 200
        headers = {}
        is_redirect = False
        is_permanent_redirect = False
        def __init__(self): self.closed = False
        def iter_content(self, chunk_size): yield b"1234"; yield b"5678"
        def close(self): self.closed = True
    class Session:
        verify = True
        def __init__(self): self.response = Response()
        def request(self, *a, **kw):
            assert kw["stream"] is True and kw["verify"] is True
            return self.response
    p = TransportPolicy({"example.com"}, "A", allow_private=True, max_response_bytes=5)
    monkeypatch.setattr(p, "check_dns", lambda url: None)
    session = Session()
    with pytest.raises(PolicyError, match="response-size-limit"):
        GuardedSession(p, session).get("https://example.com/")
    assert session.response.closed


def test_evidence_redacts_secrets():
    store = EvidenceStore()
    eid = store.add("response", "Authorization: Bearer secret token=abc&x=1")
    content = store.records[eid]["content"]
    assert "secret" not in content and "token=abc" not in content


def test_correlation_records_provenance_not_authorization():
    items = [
        {"id": "html", "url": "https://example.com/", "content": '<script src="/app.js"></script>'},
        {"id": "js", "url": "https://example.com/app.js", "content": "fetch('/api/me')"},
    ]
    links = CorrelationEngine().correlate(items)
    assert links and links[0].provenance["method"] == "static-string-reference"
    assert links[0].observed is False


def _manifest(path, hosts=("example.com",)):
    data = {
        "schema": "jscope-assessment/1", "assessment_id": "A-1", "status": "approved",
        "authorization": {"fresh_for_this_run": True, "approved_hosts": list(hosts)},
        "hosts": {h: {"state": "approved"} for h in hosts},
    }
    path.write_text(json.dumps(data))
    return data


def test_orchestrator_requires_matching_fresh_manifest_and_scope(tmp_path):
    p = tmp_path / "assessment.json"
    _manifest(p)
    policy = TransportPolicy({"example.com"}, "A-1", allow_private=True)
    engine = AssessmentOrchestrator("A-1", p, policy)
    engine.add_endpoint(Endpoint("https://example.com/api"))
    with pytest.raises(AssessmentError):
        engine.add_endpoint(Endpoint("https://other.test/api"))


def test_manifest_change_invalidates_existing_orchestrator(tmp_path):
    p = tmp_path / "assessment.json"
    _manifest(p)
    engine = AssessmentOrchestrator("A-1", p, TransportPolicy({"example.com"}, "A-1", allow_private=True))
    p.write_text(p.read_text().replace('"approved"', '"planned"'))
    with pytest.raises(AssessmentError, match="changed"):
        engine.revalidate()


def test_finding_dedup_keeps_different_endpoints(tmp_path):
    p = tmp_path / "assessment.json"
    _manifest(p)
    engine = AssessmentOrchestrator("A-1", p, TransportPolicy({"example.com"}, "A-1", allow_private=True))
    engine.add_finding(FindingRecord("Authorization gap", "BOLA", "high", "medium", "/api/a", "GET", "a"))
    engine.add_finding(FindingRecord("Authorization gap", "BOLA", "high", "medium", "/api/b", "GET", "b"))
    assert len(engine.findings) == 2


def test_module_registry_rejects_duplicate_and_invalid_capability():
    registry = ModuleRegistry()
    registry.register(ModuleMetadata("safe"), lambda c, e: "ok")
    with pytest.raises(AssessmentError):
        registry.register(ModuleMetadata("safe"), lambda c, e: "duplicate")
    with pytest.raises(AssessmentError):
        registry.register(ModuleMetadata("bad", traffic="network-anything"), lambda c, e: None)


def test_assessment_reports_are_versioned_and_non_overclaiming(tmp_path):
    from jscope.assessment_reporting import render_json, render_markdown, write_report
    result = {"assessment_id": "A-1", "status": "completed", "endpoints": [],
              "findings": [], "coverage": {"untested": ["api.example.com"]}}
    payload = json.loads(render_json(result))
    assert payload["schema_version"] == "jscope-assessment-result/1"
    assert payload["summary"]["finding_count"] == 0
    assert "not a statement that the application is secure" in render_markdown(result)
    out = write_report(result, tmp_path / "report.json")
    assert json.loads(out.read_text())["assessment_id"] == "A-1"


def test_assessment_rejects_policy_scope_mismatch(tmp_path):
    p = tmp_path / "assessment.json"
    _manifest(p)
    with pytest.raises(AssessmentError, match="scope does not match"):
        AssessmentOrchestrator("A-1", p, TransportPolicy({"other.example"}, "A-1", allow_private=True))


def test_downloader_refuses_unguarded_url_lists(tmp_path):
    from jscope.downloader.downloader import DownloadError, download_urls
    url_file = tmp_path / "urls.txt"
    url_file.write_text("https://example.com/app.js\n")
    with pytest.raises(DownloadError, match="explicit assessment TransportPolicy"):
        download_urls(str(url_file), str(tmp_path / "out"))


def test_guarded_transport_against_local_mock_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"controlled-local-fixture"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = None
    try:
        policy = TransportPolicy({"127.0.0.1"}, "LOCAL-TEST", allow_private=True,
                                 allow_loopback=True, ports={server.server_port},
                                 max_response_bytes=1024, total_budget=2)
        session = GuardedSession(policy)
        response = session.get(f"http://127.0.0.1:{server.server_port}/fixture")
        assert response.status_code == 200
        assert response.content == b"controlled-local-fixture"
    finally:
        if session:
            session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

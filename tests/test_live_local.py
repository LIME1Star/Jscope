"""Real HTTP, no internet: crawl -> download -> analyze against a local server that behaves like a real site."""

import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from jscope.cli import main
from jscope.crawler import crawler as crawler_mod
from jscope.crawler.crawler import CrawlError, discover
from jscope.downloader.downloader import extension_for
from jscope.security_transport import TransportPolicy

INDEX = b"""<!doctype html><html><head><title>t</title><script src="/static/app.js"></script></head><body>
<form method="post" action="/v1/account/avatar" enctype="multipart/form-data"><input type="file" name="a"></form>
<script>axios.post('/v1/reports/internal-metrics', {})</script></body></html>"""
APP_JS = b"axios.get('/v1/users/me'); WebAssembly.instantiateStreaming(fetch('/static/license.wasm'));"
SPEC = json.dumps({"openapi": "3.0.1", "servers": [{"url": "/v1"}], "paths": {
    "/users/me": {"get": {}}, "/admin/purge": {"post": {}}}}).encode()


def _leb(n):
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


WASM = (b"\x00asm" + struct.pack("<I", 1) + bytes([11]) + _leb(1 + 4 + 1 + 1 + 24) + _leb(1) + b"\x00\x41\x00\x0b" + _leb(24) + b"/api/internal/license-ck\x00")


def local_policy():
    """Fresh loopback-permitting policy for the local test server (loopback stays blocked by default)."""
    return TransportPolicy(hosts={"127.0.0.1"}, assessment_id="test-local", allow_loopback=True, allow_private=True, total_budget=100)


def make_server(routes, fallback=None, status_override=None):
    class H(BaseHTTPRequestHandler):
        hits = []

        def do_GET(self):
            H.hits.append(self.path)
            if status_override:
                self.send_response(status_override); self.end_headers(); return
            r = routes.get(self.path.split("?")[0]) or fallback
            if not r:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", r[0])
            self.send_header("Content-Length", str(len(r[1])))
            self.end_headers()
            self.wfile.write(r[1])

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, H


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda s: None)


ROUTES = {"/": ("text/html", INDEX), "/static/app.js": ("application/javascript", APP_JS),
          "/openapi.json": ("application/json", SPEC), "/static/license.wasm": ("application/wasm", WASM)}


def test_crawl_finds_every_artifact_kind():
    srv, _ = make_server(ROUTES)
    try:
        assets = discover(f"http://127.0.0.1:{srv.server_port}/", policy=local_policy())
        kinds = {(a.kind, a.url.rsplit("/", 1)[-1] or "/") for a in assets}
        assert {("html", "/"), ("js", "app.js"), ("wasm", "license.wasm"), ("openapi", "openapi.json")} <= kinds
    finally:
        srv.shutdown()


def test_spa_fallback_does_not_create_junk_spec_probes():
    srv, _ = make_server({"/static/app.js": ("application/javascript", APP_JS)}, fallback=("text/html", INDEX))
    try:
        assets = discover(f"http://127.0.0.1:{srv.server_port}/", policy=local_policy())
        assert not [a for a in assets if a.source == "well_known_path"]        # 200/HTML for every path is not a spec
    finally:
        srv.shutdown()


def test_no_probe_sends_no_spec_requests():
    srv, H = make_server(ROUTES)
    try:
        discover(f"http://127.0.0.1:{srv.server_port}/", probe=False, policy=local_policy())
        assert "/openapi.json" not in H.hits
    finally:
        srv.shutdown()


def test_scan_one_command_end_to_end(tmp_path, capsys):
    srv, _ = make_server(ROUTES)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/"
        rc = main(["scan", url, "--allow-private", "--out", str(tmp_path / "site"), "--save-findings", str(tmp_path / "f.json"),
                   "--format", "json", "-o", str(tmp_path / "r.json")])
        assert rc == 0
        data = json.loads((tmp_path / "r.json").read_text())
        cats = {f["category"] for f in data["findings"]}
        assert {"form", "api_operation", "wasm_module", "undocumented_api"} <= cats
        subj = {f["subject"] for f in data["findings"]}
        assert "/v1/reports/internal-metrics" in subj and "/api/internal/license-ck" in subj
        saved = {p.suffix for p in (tmp_path / "site").iterdir()}
        assert {".html", ".js", ".json", ".wasm"} <= saved
        assert (tmp_path / "f.json").exists()
    finally:
        srv.shutdown()


@pytest.mark.parametrize("status", [503, 403, 404])
def test_http_errors_are_clean_messages_not_tracebacks(status, capsys):
    srv, _ = make_server({}, status_override=status)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/"
        for cmd in (["crawl", url, "--allow-private"], ["scan", url, "--allow-private"]):
            assert main(cmd) == 1
            err = capsys.readouterr().err
            assert f"HTTP {status}" in err and "Traceback" not in err
    finally:
        srv.shutdown()


def test_unreachable_host_is_clean(capsys):
    assert main(["crawl", "http://127.0.0.1:9/", "--allow-private"]) == 1
    assert "could not reach" in capsys.readouterr().err


def test_download_missing_url_file_is_clean(tmp_path, capsys):
    assert main(["download", str(tmp_path / "nope.txt"), "--allow-host", "127.0.0.1", "--out", str(tmp_path / "o")]) == 1
    err = capsys.readouterr().err
    assert "cannot read URL list" in err and "jscope crawl" in err


def test_crawl_creates_parent_dirs_for_out(tmp_path):
    srv, _ = make_server(ROUTES)
    try:
        out = tmp_path / "does" / "not" / "exist" / "urls.txt"
        assert main(["crawl", f"http://127.0.0.1:{srv.server_port}/", "--out", str(out), "--allow-private"]) == 0
        assert out.read_text().strip()
    finally:
        srv.shutdown()


def test_extension_sniffing():
    assert extension_for("http://x/a", b"\x00asm\x01\x00\x00\x00") == ".wasm"
    assert extension_for("http://x/", b"<!doctype html><p>", "text/html") == ".html"
    assert extension_for("http://x/api-docs", b'{"openapi":"3"}', "application/json") == ".json"
    assert extension_for("http://x/a.js", b"var a", "application/javascript") == ".js"
    assert extension_for("http://x/openapi.yaml", b"openapi: 3.0.0", "text/plain") == ".yaml"

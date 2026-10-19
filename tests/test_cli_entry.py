"""`jscope <target>` / `go` / `doctor` -- the simplified entry point from the Oct 2026 CLI-UX pass."""

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from jscope.cli import KNOWN_COMMANDS, _rewrite_bare_target, build_parser, main

INDEX = b'<html><script src="/app.js"></script><body><form method="post" action="/v1/save"></form></body></html>'
APP_JS = b"axios.get('/v1/users/me');"


def make_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = INDEX if self.path == "/" else APP_JS if self.path == "/app.js" else None
            if body is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "text/html" if self.path == "/" else "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------ argv rewriting
def test_known_commands_matches_real_subparsers():
    sub_actions = [a for a in build_parser()._subparsers._group_actions if hasattr(a, "choices")]
    registered = set(sub_actions[0].choices.keys())
    assert registered == KNOWN_COMMANDS


@pytest.mark.parametrize("argv,expected", [
    (["tests/sample_site"], ["go", "tests/sample_site"]),
    (["https://x.com"], ["go", "https://x.com"]),
    (["x.com"], ["go", "x.com"]),
    (["analyze", "tests/sample_site"], ["analyze", "tests/sample_site"]),
    (["-h"], ["-h"]),
    (["--version"], ["--version"]),
    ([], []),
    (["doctor"], ["doctor"]),
    (["go", "x.com"], ["go", "x.com"]),
])
def test_rewrite_bare_target(argv, expected):
    assert _rewrite_bare_target(argv) == expected


# ------------------------------------------------------------------ doctor
def test_doctor_runs_offline_without_crashing(capsys):
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "jscope" in out and "launcher" in out and "dependencies" in out


def test_doctor_version_flag_matches(capsys):
    from jscope import __version__
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


# ------------------------------------------------------------------ go: local path
def test_go_local_path_no_prompt_needed(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    site = Path(__file__).parent / "sample_site"
    rc = main(["go", str(site), "--yes"])
    assert rc == 0
    out = tmp_path / "jscope-out"
    dirs = list(out.iterdir())
    assert len(dirs) == 1
    assert (dirs[0] / "report.md").exists() and (dirs[0] / "findings.json").exists()
    synopsis = capsys.readouterr().out
    assert "finding(s):" in synopsis and "report    :" in synopsis


def test_bare_jscope_call_equals_go(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    site = Path(__file__).parent / "sample_site"
    assert main([str(site), "--yes"]) == 0
    assert (tmp_path / "jscope-out").exists()


# ------------------------------------------------------------------ go: remote target
def test_go_remote_requires_yes_when_noninteractive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["go", "http://127.0.0.1:1/"]) == 1       # no --yes, non-tty -> refuses, no traffic sent
    assert not (tmp_path / "jscope-out").exists()


def test_go_remote_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/"
        rc = main(["go", url, "--yes", "--no-probe", "--allow-private"])
        assert rc == 0
        out_dirs = list((tmp_path / "jscope-out").iterdir())
        assert len(out_dirs) == 1
        d = out_dirs[0]
        assert (d / "report.md").exists() and (d / "findings.json").exists() and (d / "site").is_dir()
        data = json.loads((d / "findings.json").read_text())
        subs = {f["subject"] for f in data["findings"]}
        assert "/v1/users/me" in subs
    finally:
        srv.shutdown()


def test_go_respects_out_and_format_overrides(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    site = Path(__file__).parent / "sample_site"
    custom = tmp_path / "mydir"
    rc = main(["go", str(site), "--yes", "--out", str(custom), "--format", "sarif"])
    assert rc == 0
    assert (custom / "report.sarif").exists()
    json.loads((custom / "report.sarif").read_text())


# ------------------------------------------------------------------ go --confirm chains into the prober (dry-run only)
def test_go_confirm_without_permission_only_plans(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/"
        rc = main(["go", url, "--yes", "--no-probe", "--confirm", "--allow-private"])
        assert rc == 1                                       # confirm runs, but refuses to send without permission
        assert "i-have-permission" in capsys.readouterr().err
    finally:
        srv.shutdown()


def test_go_confirm_on_local_path_is_skipped_not_crashed(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    site = Path(__file__).parent / "sample_site"
    rc = main(["go", str(site), "--yes", "--confirm"])
    assert rc == 0
    assert "needs a URL/host" in capsys.readouterr().err


# ------------------------------------------------------------------ banner content / DNS resolution shown
def test_target_banner_shows_resolved_ip(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "")
    from jscope.cli import _confirm_target
    assert _confirm_target("http://127.0.0.1:1/", yes=False) is True
    assert "resolves to 127.0.0.1" in capsys.readouterr().err


def test_target_banner_handles_dns_failure_gracefully(capsys):
    from jscope.cli import _confirm_target
    assert _confirm_target("http://jscope-definitely-not-a-real-host.invalid/", yes=True) is True
    assert "could NOT be resolved" in capsys.readouterr().err


# ------------------------------------------------------------------ `jscope verify` and `jscope observe` (0.5)
def test_verify_cli_requires_authorization(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    findings = {"findings": [{"id": "JS-1", "category": "dataflow", "subject": "x", "confidence": "MEDIUM", "score": 10,
                              "evidence": [], "contributing_analyzers": [], "attack_surface": None, "suggested_test": None,
                              "reasoning": [], "related": [], "metadata": {"sink_class": "html", "flow": {"source": {"kind": "url_query"}}}}]}
    f = tmp_path / "findings.json"
    f.write_text(json.dumps(findings))
    rc = main(["verify", str(f), "--base-url", "https://app.test", "--allow-host", "app.test", "--out", str(tmp_path / "out.json")])
    assert rc == 0
    out = json.loads((tmp_path / "out.json").read_text())
    assert out["findings"][0]["metadata"]["verification"]["status"] == "rejected"
    assert "requires explicit authorization" in out["findings"][0]["metadata"]["verification"]["observations"][0]
    assert "without --authorize-active-tests" in capsys.readouterr().err


def test_verify_cli_identity_parsing_and_scope(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        port = srv.server_port
        findings = {"findings": [{"id": "JS-2", "category": "idor", "subject": "/app.js", "confidence": "MEDIUM", "score": 10,
                                  "evidence": [], "contributing_analyzers": [], "attack_surface": "idor_candidate",
                                  "suggested_test": None, "reasoning": [], "related": [], "metadata": {}}]}
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        rc = main(["verify", str(f), "--base-url", f"http://127.0.0.1:{port}", "--allow-host", f"127.0.0.1:{port}",
                  "--authorize-active-tests", "--allow-private",
                  "--identity", "guest=X-Role:guest", "--identity", "admin=X-Role:admin", "--identity-role", "admin=admin",
                  "--out", str(tmp_path / "o.json")])
        assert rc == 0
        out = json.loads((tmp_path / "o.json").read_text())
        v = out["findings"][0]["metadata"]["verification"]
        assert v["status"] == "confirmed" and v["procedure"] == "authz-diff"       # same static response for both identities
    finally:
        srv.shutdown()


def test_verify_cli_bad_identity_format(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"findings": []}))
    rc = main(["verify", str(f), "--base-url", "https://app.test", "--allow-host", "app.test", "--identity", "bad"])
    assert rc == 1 and "NAME=header:value" in capsys.readouterr().err


def test_observe_cli_against_local_server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        url = f"http://127.0.0.1:{srv.server_port}"
        rc = main(["observe", url, "--allow-host", f"127.0.0.1:{srv.server_port}", "--allow-private",
                  "--driver", "http", "--out", str(tmp_path / "trace.json")])
        assert rc == 0
        trace = json.loads((tmp_path / "trace.json").read_text())
        assert trace["driver"] == "http-passive"
        assert any(e["kind"] == "navigation" for e in trace["events"])
    finally:
        srv.shutdown()


def test_observe_cli_with_correlation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        url = f"http://127.0.0.1:{srv.server_port}"
        findings = {"findings": [{"id": "JS-1", "category": "endpoint", "subject": "/v1/users/me", "evidence": []}], "route_map": []}
        ff = tmp_path / "findings.json"
        ff.write_text(json.dumps(findings))
        rc = main(["observe", url, "--allow-host", f"127.0.0.1:{srv.server_port}", "--allow-private", "--driver", "http",
                  "--findings-file", str(ff), "--out", str(tmp_path / "trace.json")])
        assert rc == 0
        trace = json.loads((tmp_path / "trace.json").read_text())
        assert "correlation" in trace and "novel_routes" in trace
    finally:
        srv.shutdown()


def test_verify_and_observe_in_known_commands():
    assert {"verify", "observe"} <= KNOWN_COMMANDS


def test_go_remote_loopback_blocked_by_default(tmp_path, monkeypatch, capsys):
    """Safe default: without --allow-private, loopback targets are refused by the transport policy."""
    monkeypatch.chdir(tmp_path)
    srv = make_server()
    try:
        rc = main(["go", f"http://127.0.0.1:{srv.server_port}/", "--yes", "--no-probe"])
        assert rc == 1
        assert "blocked by scope policy" in capsys.readouterr().err
    finally:
        srv.shutdown()

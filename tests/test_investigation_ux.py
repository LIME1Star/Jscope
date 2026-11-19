"""0.6 investigation UX: session context, findings/show/status, context-defaulted runtime commands, shell.

These tests stub the analysis engine (`jscope.pipeline`) with a tiny fake so they exercise ONLY the interaction
layer, and therefore run without tree-sitter. Engine behaviour stays covered by the existing suites.
"""
import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

try:                                    # the interaction layer is tested without a parser; engines are stubbed
    import tree_sitter_javascript  # noqa: F401
except ImportError:
    from unittest.mock import MagicMock
    for _m in ("tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript"):
        sys.modules.setdefault(_m, MagicMock())

from jscope import investigate, session as session_mod
from jscope.cli import KNOWN_COMMANDS, build_parser, main
from jscope.core.evidence import Confidence, Evidence, EvidenceType, Finding
from jscope.core.graph import EdgeKind, KnowledgeGraph, NodeKind
from jscope.shell import handle_line


def _finding(i, cat, subject, conf, related=None, snippet="axios.get(x)"):
    return Finding(id=f"JS-{i:04d}", category=cat, subject=subject, confidence=Confidence(conf), score=10 - i,
                   evidence=[Evidence(type=EvidenceType.AST_PATTERN_MATCH, description="call", analyzer="endpoint_analyzer",
                                      file="/nonexistent/app.js", line=3, snippet=snippet, metadata={})],
                   contributing_analyzers=["endpoint_analyzer"], attack_surface="endpoint", suggested_test="test it",
                   reasoning=["found call"], related=related or [])


def _graph():
    g = KnowledgeGraph()
    g.add_node("r1", NodeKind.ROUTE, "/admin")
    g.add_node("e1", NodeKind.ENDPOINT, "/api/admin/users")
    g.add_edge("r1", "e1", EdgeKind.CALLS, "t", "static")
    return g


@pytest.fixture
def fake_engine(monkeypatch):
    """Replace jscope.pipeline.run_analysis with a deterministic stub."""
    calls = []

    def run_analysis(paths, config):
        calls.append(list(paths))
        fs = [_finding(1, "endpoint", "/api/admin/users", "HIGH", related=["JS-0002"]),
              _finding(2, "endpoint", "/api/users/{id}", "MEDIUM", related=["JS-0001"]),
              _finding(3, "secret", "AWS key", "LOW")]
        return types.SimpleNamespace(findings=fs, frameworks=["react"], file_count=2, graph=_graph(), diagnostics=[],
                                     dataflow={}, file_diagnostics={}, artifact_counts={}, expanded_sources=0)

    mod = types.ModuleType("jscope.pipeline")
    mod.run_analysis = run_analysis
    monkeypatch.setitem(sys.modules, "jscope.pipeline", mod)
    return calls


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "app"
    src.mkdir()
    (src / "a.js").write_text("axios.get('/api/admin/users')\n")
    return src


# ------------------------------------------------------------------ registry / compat
def test_known_commands_in_sync():
    acts = [a for a in build_parser()._subparsers._group_actions if hasattr(a, "choices")]
    assert set(acts[0].choices) == KNOWN_COMMANDS
    assert {"use", "status", "findings", "show"} <= KNOWN_COMMANDS


def test_all_30_commands_still_registered():
    old = {"analyze", "explain", "report", "confirm", "verify", "observe", "benchmark", "graph", "plugins", "plugin-new",
           "download", "crawl", "scan", "go", "doctor", "new", "scope-check", "assessment-plan", "scope-discover",
           "scope-review", "scope-approve", "ws-init", "ws-add", "ws-remove", "ws-list", "ws-scan", "ws-history",
           "ws-diff", "ws-summary", "ai"}
    assert old <= KNOWN_COMMANDS


def test_cli_import_does_not_load_the_analysis_engine():
    import subprocess
    code = "import sys, jscope.cli; sys.exit(1 if 'jscope.pipeline' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


# ------------------------------------------------------------------ context persistence
def test_go_records_context_and_followups_need_no_arguments(proj, fake_engine, capsys):
    assert main(["go", str(proj), "--yes"]) == 0
    s = session_mod.Session.load()
    assert s.target == str(proj) and s.kind == "path" and Path(s.findings_file).is_file()
    capsys.readouterr()

    assert main(["findings"]) == 0
    out = capsys.readouterr().out
    assert "/api/admin/users" in out and "AWS key" in out

    assert main(["status"]) == 0
    assert "3 finding(s)" in capsys.readouterr().out


def test_analyze_also_records_context(proj, fake_engine, capsys):
    assert main(["analyze", str(proj)]) == 0
    capsys.readouterr()
    assert main(["show", "1"]) == 0
    assert "JS-0001" in capsys.readouterr().out


def test_context_is_found_from_a_subdirectory(proj, fake_engine, monkeypatch, capsys):
    main(["go", str(proj), "--yes"])
    capsys.readouterr()
    monkeypatch.chdir(proj)
    assert main(["findings", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 3


def test_new_target_resets_stale_findings(proj):
    s = session_mod.Session.load()
    s.set_target("https://a.example.com")
    s.record_analysis(proj / "f.json")
    s.set_target("https://b.example.com")
    assert s.findings_file is None and s.host == "b.example.com"


def test_corrupt_session_does_not_block(proj, capsys):
    (proj.parent / ".jscope").mkdir()
    (proj.parent / ".jscope" / "session.json").write_text("{nope")
    assert main(["status"]) == 0
    assert "no active investigation" in capsys.readouterr().out


def test_followup_without_analysis_gives_actionable_error(proj, capsys):
    assert main(["findings"]) == 1
    assert "run `jscope <target>` first" in capsys.readouterr().err


# ------------------------------------------------------------------ findings / show
def test_findings_filters_and_json(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    assert main(["findings", "--category", "secret"]) == 0
    out = capsys.readouterr().out
    assert "AWS key" in out and "/api/admin" not in out
    assert main(["findings", "--min-confidence", "HIGH", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in rows] == ["JS-0001"] and "finding" not in rows[0]


@pytest.mark.parametrize("ref", ["1", "#1", "JS-0001", "0001", "admin/users"])
def test_show_resolves_rank_id_and_text(proj, fake_engine, capsys, ref):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    assert main(["show", ref]) == 0
    assert "JS-0001" in capsys.readouterr().out


def test_show_ambiguous_and_missing(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    assert main(["show", "/api/"]) == 2
    assert "matches 2 findings" in capsys.readouterr().err
    assert main(["show", "99"]) == 2
    assert "no finding #99" in capsys.readouterr().err


def test_show_connects_evidence_routes_related_and_next_actions(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    main(["show", "1"])
    out = capsys.readouterr().out
    assert "reached from" in out and "route /admin" in out and "UNPROTECTED" in out
    assert "evidence (1)" in out and "app.js:3" in out
    assert "related" in out and "JS-0001" not in out.split("related")[1].split("next")[0] or "axios" in out
    assert "static_inference" in out or "observed_fact" in out or "security_hypothesis" in out
    assert "show 1 --full" in out


def test_show_full_and_explain_alias_match(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    main(["show", "1", "--full"]); a = capsys.readouterr().out
    main(["explain", "JS-0001"]); b = capsys.readouterr().out
    assert a == b and "raw evidence:" in a


def test_show_inference_is_never_labelled_confirmed(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    main(["show", "1", "--json"])
    row = json.loads(capsys.readouterr().out)
    assert row["verification"] == "unverified" and row["evidence_class"] != "confirmed_vulnerability"


def test_graph_uses_context_and_filters(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    assert main(["graph", "--unprotected"]) == 0
    assert "/admin" in capsys.readouterr().out
    assert main(["graph", "--filter", "nomatch"]) == 0
    assert "/admin" not in capsys.readouterr().out


def test_report_uses_context(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()
    assert main(["report", "--format", "markdown"]) == 0
    assert "/api/admin/users" in capsys.readouterr().out


# ------------------------------------------------------------------ remote target + scope-safe runtime defaults
class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b'<html><script src="/app.js"></script></html>' if self.path == "/" else b"axios.get('/v1/users/me');"
                if self.path == "/app.js" else None)
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else "application/javascript")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def test_remote_go_no_enter_prompt_and_scope_is_remembered(proj, fake_engine, server, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)           # interactive: must NOT block on input()
    monkeypatch.setattr("builtins.input", lambda *_: (_ for _ in ()).throw(AssertionError("prompted")))
    url = f"http://127.0.0.1:{server.server_port}/"
    assert main(["go", url, "--no-probe", "--allow-private"]) == 0
    s = session_mod.Session.load()
    assert s.kind == "url" and s.host == f"127.0.0.1:{server.server_port}" and s.allow_private


def test_noninteractive_remote_still_requires_yes(proj, fake_engine):
    assert main(["go", "http://127.0.0.1:1/"]) == 1


def test_confirm_defaults_to_context_but_still_needs_authorization(proj, fake_engine, server, capsys):
    url = f"http://127.0.0.1:{server.server_port}/"
    main(["go", url, "--yes", "--no-probe", "--allow-private"]); capsys.readouterr()
    assert main(["confirm", "--dry-run"]) == 0
    cap = capsys.readouterr()
    assert "nothing was sent" in cap.err
    assert main(["confirm"]) == 1                                   # no --authorize-active-tests -> refuses
    assert "--authorize-active-tests" in capsys.readouterr().err


def test_confirm_without_any_target_explains_itself(proj, fake_engine, capsys):
    main(["go", str(proj), "--yes"]); capsys.readouterr()          # local path: no runtime host
    assert main(["confirm", "--dry-run"]) == 1
    assert "no runtime target" in capsys.readouterr().err


def test_explicit_base_url_does_not_inherit_context_scope(proj, fake_engine, server, capsys):
    url = f"http://127.0.0.1:{server.server_port}/"
    main(["go", url, "--yes", "--no-probe", "--allow-private"]); capsys.readouterr()
    rc = main(["confirm", "--base-url", "https://other.example.com", "--dry-run"])
    assert rc == 1                                                  # other host + no --allow-host -> scope error, not silent
    assert "error" in capsys.readouterr().err


def test_verify_accepts_rank_and_writes_back_with_static_backup(proj, fake_engine, server, capsys):
    url = f"http://127.0.0.1:{server.server_port}/"
    main(["go", url, "--yes", "--no-probe", "--allow-private"]); capsys.readouterr()
    ff = Path(session_mod.Session.load().findings_file)
    assert main(["verify", "--finding-id", "1", "--authorize-active-tests"]) == 0
    assert ff.with_name(ff.stem + ".static.json").exists()
    data = json.loads(ff.read_text())
    assert "verification" in next(f for f in data["findings"] if f["id"] == "JS-0001")["metadata"]
    assert "verification" not in next(f for f in data["findings"] if f["id"] == "JS-0002")["metadata"]


# ------------------------------------------------------------------ shell
def _run(lines, answers=()):
    asked = iter(answers)
    for line in lines:
        handle_line(line, main, lambda q: next(asked))


def test_shell_path_then_number_then_findings(proj, fake_engine, capsys):
    _run([str(proj), "1", "findings --category secret", "status"])
    out = capsys.readouterr().out
    assert "JS-0001" in out and "AWS key" in out and "target" in out
    assert len(fake_engine) == 1                                    # analysis ran once; nothing re-parsed


def test_shell_exit_and_blank(proj):
    assert handle_line("", main, input) == 0
    assert handle_line("exit", main, input) is None


def test_shell_survives_bad_input(proj, fake_engine, capsys):
    assert handle_line("findings --nope", main, input) == 2          # argparse error, shell stays alive
    assert handle_line("show 'unterminated", main, input) == 1


def test_shell_confirm_asks_once_and_declining_sends_nothing(proj, fake_engine, server, capsys):
    url = f"http://127.0.0.1:{server.server_port}/"
    main(["go", url, "--yes", "--no-probe", "--allow-private"]); capsys.readouterr()
    questions = []
    handle_line("confirm", main, lambda q: (questions.append(q), "n")[1])
    out = capsys.readouterr()
    assert len(questions) == 1 and "read-only request" in questions[0]
    assert "not sent" in out.out


def test_shell_help(capsys):
    handle_line("help", main, input)
    assert "findings" in capsys.readouterr().out
    assert handle_line("help show", main, input) == 0

from pathlib import Path

import pytest

from jscope.analyzers.base import Analyzer
from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.manager import AnalyzerManager
from jscope.cli import main
from jscope.config import Config
from jscope.core.evidence import (Candidate, Confidence, Evidence, EvidenceEngine, EvidenceType as ET)
from jscope.pipeline import core_analyzers, run_analysis
from jscope.plugin.loader import load_plugins, scaffold
from tests.helpers import by_subject, ctx_for, run

PLUGINS = Path(__file__).parent / "sample_plugins"


def _strong(analyzer):
    return [Evidence(ET.AST_PATTERN_MATCH, "a", analyzer), Evidence(ET.SYMBOL_RESOLVED, "b", analyzer),
            Evidence(ET.DATA_FLOW, "c", analyzer), Evidence(ET.CALL_GRAPH_REACHABLE, "d", analyzer)]   # 2+3+3+3 = 11


def test_engine_rejects_non_candidates():
    with pytest.raises(TypeError):
        EvidenceEngine().propose("not a candidate")          # type: ignore[arg-type]


def test_community_only_findings_are_capped():
    eng = EvidenceEngine(analyzer_tiers={"plug": "community"})
    eng.propose(Candidate("x", "s", "plug", _strong("plug")))
    f = eng.promote()[0]
    assert f.confidence == Confidence.MEDIUM and any("CAPPED" in r for r in f.reasoning)


def test_community_plus_core_agreement_is_not_capped():
    eng = EvidenceEngine(analyzer_tiers={"plug": "community", "core1": "core"})
    eng.propose(Candidate("x", "s", "plug", _strong("plug")))
    eng.propose(Candidate("x", "s", "core1", [Evidence(ET.AST_PATTERN_MATCH, "e", "core1")]))
    assert eng.promote()[0].confidence == Confidence.CONFIRMED


def test_manager_enforces_propose_promote_boundary():
    res = load_plugins([str(PLUGINS / "evil.py")], {"framework_detector", "endpoint_analyzer"}, use_entry_points=False)
    assert [a.name for a in res.analyzers] == ["evil"]
    ctx = ctx_for({"a.js": 'fetch("/api/admin/users");'})
    eng = EvidenceEngine(analyzer_tiers={"evil": "community"})
    mgr = AnalyzerManager([FrameworkDetector(), EndpointAnalyzer()] + res.analyzers)
    mgr.run(ctx, eng)
    findings = eng.promote()
    d = " | ".join(mgr.diagnostics)
    assert "only Candidates are accepted" in d                       # forged Finding dropped
    assert "engine-controlled" in d                                   # forged CROSS_ANALYZER_AGREEMENT / RUNTIME dropped
    assert "re-attributed" in d                                       # spoofed analyzer name rewritten
    assert all(f.id != "JS-9999" for f in findings)
    ep = by_subject(findings, "endpoint")["/api/admin/users"]
    types = [e.type.value for e in ep.evidence]
    assert types.count("CROSS_ANALYZER_AGREEMENT") == 1               # only the engine's own, real one
    assert "RUNTIME_CONTEXT" not in types


def test_analyzer_crash_is_isolated():
    res = load_plugins([str(PLUGINS / "boom.py")], set(), use_entry_points=False)
    ctx = ctx_for({"a.js": 'window.__NEXT_DATA__ = {};'})
    eng = EvidenceEngine(min_display_confidence=Confidence.INFORMATIONAL)
    mgr = AnalyzerManager([FrameworkDetector()] + res.analyzers)
    mgr.run(ctx, eng)
    assert any("boom" in d and "crashed" in d for d in mgr.diagnostics)
    assert by_subject(eng.promote(), "framework")                    # the healthy analyzer still reported


def test_duplicate_analyzer_names_rejected():
    with pytest.raises(ValueError):
        AnalyzerManager([FrameworkDetector(), FrameworkDetector()])


def test_loader_tiers_collisions_and_errors(tmp_path):
    (tmp_path / "dup.py").write_text(
        "from jscope.analyzers.base import Analyzer\n"
        "class D(Analyzer):\n    name='endpoint_analyzer'\n"
        "ANALYZERS=[D]\n")
    (tmp_path / "broken.py").write_text("raise SyntaxError('nope')\n")
    (tmp_path / "empty.py").write_text("X = 1\n")
    core = {a.name for a in core_analyzers()}
    res = load_plugins([str(tmp_path), str(PLUGINS / "todo_finder.py"), "/does/not/exist"], core,
                       verified={"todo_finder"}, use_entry_points=False)
    assert [a.name for a in res.analyzers] == ["todo_finder"] and res.analyzers[0].tier == "verified"
    msg = " | ".join(res.errors)
    assert "already registered" in msg and "import failed" in msg and "neither ANALYZERS" in msg and "not found" in msg


def test_plugin_flows_through_pipeline_with_cap(tmp_path):
    (tmp_path / "x.js").write_text("dangerousThing();")
    cfg = Config()
    cfg.data["plugins"]["paths"] = [str(PLUGINS / "todo_finder.py")]
    r = run_analysis([str(tmp_path)], cfg)
    f = next(f for f in r.findings if f.category == "todo")
    assert f.confidence == Confidence.MEDIUM                          # 4 strong evidence, but community-only => capped
    assert f.metadata["analyzer_tiers"] == {"todo_finder": "community"}
    cfg.data["plugins"]["verified"] = ["todo_finder"]
    f2 = next(f for f in run_analysis([str(tmp_path)], cfg).findings if f.category == "todo")
    assert f2.confidence in (Confidence.HIGH, Confidence.CONFIRMED)


def test_scaffolded_plugin_loads_and_runs(tmp_path):
    target = scaffold("My Cool Check", str(tmp_path / "plugins"))
    assert target.name == "my_cool_check.py"
    (tmp_path / "app.js").write_text("dangerousThing(1);")
    cfg = Config()
    cfg.data["plugins"]["paths"] = [str(target.parent)]
    r = run_analysis([str(tmp_path / "app.js")], cfg)
    assert any(f.category == "my_cool_check" for f in r.findings)
    with pytest.raises(FileExistsError):
        scaffold("My Cool Check", str(tmp_path / "plugins"))
    with pytest.raises(ValueError):
        scaffold("123bad", str(tmp_path))


def test_cli_graph_and_plugins_commands(tmp_path, capsys):
    saved = tmp_path / "f.json"
    app = Path(__file__).parent / "sample_react"
    assert main(["analyze", str(app), "--save-findings", str(saved), "--format", "json"]) == 0
    capsys.readouterr()
    assert main(["graph", str(saved)]) == 0
    out = capsys.readouterr().out
    assert "R /admin/reports" in out and "UNPROTECTED" in out and "-> E /api/admin/users" in out
    assert main(["explain", "JS-0001", "--findings-file", str(saved)]) == 0
    assert "[core]" in capsys.readouterr().out
    assert main(["plugins", "--plugin-path", str(PLUGINS / "todo_finder.py")]) == 0
    out = capsys.readouterr().out
    assert "router_analyzer" in out and "todo_finder" in out and "community" in out

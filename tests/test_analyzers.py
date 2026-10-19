from jscope.analyzers.base import ProjectContext
from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.secret_analyzer import SecretAnalyzer
from jscope.parsing.ast_engine import ASTEngine


def _ctx(src: str, path: str = "a.js"):
    engine = ASTEngine()
    pf = engine.parse_bytes(src.encode(), path=path)
    return pf, ProjectContext(files=[pf], ast=engine)


def test_framework_detector_finds_nextjs_marker():
    pf, ctx = _ctx('window.__NEXT_DATA__ = {};')
    candidates = FrameworkDetector().analyze_file(pf, ctx)
    assert any(c.subject == "Next.js" for c in candidates)


def test_endpoint_analyzer_classifies_admin_path():
    pf, ctx = _ctx('fetch("/api/admin/users");')
    candidates = EndpointAnalyzer().analyze_file(pf, ctx)
    assert len(candidates) == 1
    assert candidates[0].attack_surface == "admin"
    assert candidates[0].subject == "/api/admin/users"


def test_endpoint_analyzer_ignores_non_path_strings():
    pf, ctx = _ctx('fetch("hello world not a path");')
    candidates = EndpointAnalyzer().analyze_file(pf, ctx)
    assert candidates == []


def test_secret_analyzer_flags_aws_key():
    pf, ctx = _ctx('const k = "AKIAABCDEFGHIJKLMNOP";')
    candidates = SecretAnalyzer().analyze_file(pf, ctx)
    assert len(candidates) == 1
    assert candidates[0].metadata["service"] == "AWS"


def test_secret_analyzer_penalizes_test_paths():
    pf, ctx = _ctx('const k = "AKIAABCDEFGHIJKLMNOP";', path="__tests__/mock.test.js")
    candidates = SecretAnalyzer().analyze_file(pf, ctx)
    types = [e.type.value for e in candidates[0].evidence]
    assert "TEST_FIXTURE_CONTEXT" in types


def test_secret_analyzer_ignores_clean_code():
    pf, ctx = _ctx('const greeting = "hello there";')
    candidates = SecretAnalyzer().analyze_file(pf, ctx)
    assert candidates == []

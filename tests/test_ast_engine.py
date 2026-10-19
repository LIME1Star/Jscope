from jscope.parsing.ast_engine import ASTEngine


def _pf(src: str):
    return ASTEngine().parse_bytes(src.encode(), path="<test>")


def test_parse_caches_by_content_hash():
    engine = ASTEngine()
    pf1 = engine.parse_bytes(b"const x = 1;", path="a.js")
    pf2 = engine.parse_bytes(b"const x = 1;", path="b.js")
    assert pf1.content_hash == pf2.content_hash
    assert pf1.tree is pf2.tree


def test_size_limit_skips_file():
    engine = ASTEngine(max_bytes=10)
    pf = engine.parse_bytes(b"x" * 100, path="huge.js")
    assert pf.skipped_reason is not None
    assert pf.tree is None


def test_find_calls_detects_fetch():
    engine = ASTEngine()
    pf = engine.parse_bytes(b'fetch("/api/users");', path="a.js")
    sites = engine.find_calls(pf)
    assert len(sites) == 1
    assert sites[0].callee == "fetch"
    assert sites[0].args_resolved[0].value == "/api/users"
    assert sites[0].args_resolved[0].is_literal


def test_symbol_resolution_through_const():
    engine = ASTEngine()
    pf = engine.parse_bytes(b'const URL = "/api/admin"; fetch(URL);', path="a.js")
    sites = engine.find_calls(pf)
    resolved = sites[0].args_resolved[0]
    assert resolved.value == "/api/admin"
    assert resolved.resolved_via_symbol


def test_process_env_flagged_as_placeholder():
    engine = ASTEngine()
    pf = engine.parse_bytes(b'fetch(process.env.API_URL);', path="a.js")
    sites = engine.find_calls(pf)
    resolved = sites[0].args_resolved[0]
    assert resolved.is_placeholder


def test_dead_branch_detection():
    engine = ASTEngine()
    pf = engine.parse_bytes(b'if (false) { fetch("/internal/debug"); }', path="a.js")
    sites = engine.find_calls(pf)
    assert engine.is_in_dead_branch(pf, sites[0].node)


def test_live_branch_not_flagged_dead():
    engine = ASTEngine()
    pf = engine.parse_bytes(b'if (userIsAdmin) { fetch("/internal/debug"); }', path="a.js")
    sites = engine.find_calls(pf)
    assert not engine.is_in_dead_branch(pf, sites[0].node)

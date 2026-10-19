"""Phase 4: artifacts (HTML, Vue, OpenAPI, GraphQL schema, WASM), runtime confirmation, report formats."""

import json
import struct
from pathlib import Path

import pytest

from jscope.analyzers.base import Analyzer
from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.graphql_analyzer import GraphQLAnalyzer
from jscope.analyzers.graphql_schema_analyzer import GraphQLSchemaAnalyzer
from jscope.analyzers.html_analyzer import HtmlAnalyzer
from jscope.analyzers.manager import AnalyzerManager
from jscope.analyzers.openapi_analyzer import OpenApiAnalyzer
from jscope.analyzers.wasm_analyzer import WasmAnalyzer
from jscope.cli import main
from jscope.config import Config
from jscope.core.artifacts import Artifact, classify_artifact, collect_artifacts
from jscope.core.evidence import (Candidate, Confidence, Evidence, EvidenceEngine, EvidenceType as ET, Finding,
                                  apply_runtime_evidence)
from jscope.parsing.wasm import parse_wasm
from jscope.pipeline import collect_manifest, run_analysis
from jscope.reporting import formats
from jscope.runtime.prober import HttpResponse, Prober, ScopeError, apply_results
from tests.helpers import ctx_for

SITE = Path(__file__).parent / "sample_site"


@pytest.fixture
def site(tmp_path):
    """Copy of the fixture outside any tests/ directory (paths under tests/ get the test-fixture penalty by design)."""
    import shutil
    dst = tmp_path / "webapp"
    shutil.copytree(SITE, dst)
    return dst


def art(kind, path, data):
    return Artifact(kind, path, data if isinstance(data, bytes) else data.encode(), "h")


def go(analyzers, sources=None, artifacts=()):
    ctx = ctx_for(sources or {})
    ctx.artifacts.extend(artifacts)
    engine = EvidenceEngine()
    AnalyzerManager([FrameworkDetector(), *analyzers]).run(ctx, engine)
    return engine.promote(), ctx


def leb(n):
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def wstr(x):
    x = x.encode()
    return leb(len(x)) + x


def wsec(i, p):
    return bytes([i]) + leb(len(p)) + p


def wasm_bytes(strings=b"", imports=()):
    imp = leb(len(imports)) + b"".join(wstr("wbg") + wstr(n) + b"\x00" + leb(0) for n in imports)
    data = leb(1) + b"\x00\x41\x00\x0b" + leb(len(strings)) + strings
    return b"\x00asm" + struct.pack("<I", 1) + wsec(2, imp) + wsec(7, leb(1) + wstr("memory") + b"\x02" + leb(0)) + wsec(11, data)


# ------------------------------------------------------------------ artifact detection
def test_classify_content_sniffing():
    assert classify_artifact("a.html", b"<html>") == "html"
    assert classify_artifact("x.json", b'{"openapi":"3.0.0","paths":{}}') == "openapi"
    assert classify_artifact("pkg.json", b'{"name":"x","version":"1"}') is None
    assert classify_artifact("m.wasm", b"\x00asm\x01\x00\x00\x00") == "wasm"
    assert classify_artifact("fake.wasm", b"not wasm") is None
    assert classify_artifact("s.graphql", b"type Query { a: Int }") == "graphql_schema"
    intro = json.dumps({"data": {"__schema": {"types": []}}}).encode()
    assert classify_artifact("i.json", intro) == "graphql_schema"


def test_collect_respects_exclude(tmp_path):
    (tmp_path / "a.html").write_text("<p>")
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "b.html").write_text("<p>")
    got = collect_artifacts([str(tmp_path)], exclude=["*/skip/*"])
    assert [Path(a.path).name for a in got] == ["a.html"]


# ------------------------------------------------------------------ HTML
def test_forms_and_surfaces():
    html = ('<form method="post" action="/avatar" enctype="multipart/form-data"><input type="file" name="f"></form>'
            '<form method="post" action="/session"><input type="password" name="p"><input type="hidden" name="csrf_token"></form>')
    f, _ = go([HtmlAnalyzer()], artifacts=[art("html", "p.html", html)])
    forms = {x.subject: x for x in f if x.category == "form"}
    assert forms["POST /avatar [p.html]"].attack_surface == "upload"
    assert forms["POST /session [p.html]"].attack_surface == "auth"
    csrf = [x for x in f if x.category == "form_csrf"]
    assert [x.subject for x in csrf] == ["POST /avatar [p.html]"]          # token present on /session
    assert csrf[0].metadata["absence_based"] is True and csrf[0].confidence == Confidence.LOW


def test_sri_only_when_origin_known():
    tag = '<script src="https://cdn.x.io/a.js"></script>'
    f, _ = go([HtmlAnalyzer()], artifacts=[art("html", "a.html", tag)])
    assert not [x for x in f if x.category == "html_resource"]            # origin unknowable offline -> silence
    f, _ = go([HtmlAnalyzer()], artifacts=[art("html", "a.html", '<base href="https://me.com/">' + tag)])
    assert [x.subject for x in f if x.category == "html_resource"] == ["https://cdn.x.io/a.js"]
    ok = '<base href="https://me.com/"><script src="https://cdn.x.io/a.js" integrity="sha384-x"></script>'
    f, _ = go([HtmlAnalyzer()], artifacts=[art("html", "a.html", ok)])
    assert not [x for x in f if x.category == "html_resource"]


def test_form_and_js_agree_on_endpoint():
    f, _ = go([EndpointAnalyzer(), HtmlAnalyzer()], {"a.js": "axios.post('/v1/save', d)"},
              [art("html", "p.html", '<form method="post" action="/v1/save"></form>')])
    e = [x for x in f if x.category == "endpoint" and x.subject == "/v1/save"][0]
    assert {"endpoint_analyzer", "html_analyzer"} <= set(e.contributing_analyzers)
    assert any(ev.type == ET.CROSS_ANALYZER_AGREEMENT for ev in e.evidence)


def test_inline_script_lines_preserved_and_analyzed(tmp_path):
    (tmp_path / "p.html").write_text("<html>\n<body>\n\n<script>\naxios.get('/api/inline-thing');\n</script>\n</body></html>")
    res = run_analysis([str(tmp_path)], Config.load(None))
    ep = [f for f in res.findings if f.category == "endpoint" and f.subject == "/api/inline-thing"][0]
    line = next(e.line for e in ep.evidence if e.file)
    assert line == 5                                                       # real line in the .html, not in the snippet
    assert res.artifact_counts == {"html": 1}


def test_vue_sfc_script_analyzed(tmp_path):
    (tmp_path / "C.vue").write_text("<template><p/></template>\n<script>\nexport default { m() { axios.get('/api/vue-call') } }\n</script>")
    res = run_analysis([str(tmp_path)], Config.load(None))
    assert any(f.subject == "/api/vue-call" for f in res.findings)


# ------------------------------------------------------------------ OpenAPI
SPEC = {"openapi": "3.0.1", "servers": [{"url": "https://api.acme.com/v1"}, {"url": "https://staging.acme.com/v1"}],
        "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}, "security": [{"b": []}],
        "paths": {"/users/me": {"get": {}}, "/users/{userId}": {"get": {}, "delete": {}},
                  "/admin/purge": {"post": {}}, "/promo": {"post": {"security": []}}, "/old": {"get": {"deprecated": True}},
                  "/files": {"post": {"requestBody": {"content": {"multipart/form-data": {}}}}}}}


def spec_art(spec=SPEC):
    return art("openapi", "openapi.json", json.dumps(spec))


def test_openapi_correlation_both_directions():
    js = {"a.js": "axios.get('/v1/users/me'); axios.post('/v1/files', d); axios.get('/v1/reports/x'); fetch('https://api.stripe.com/v1/c'); fetch('/static/a.css'); axios.get('/other/y')"}
    f, ctx = go([EndpointAnalyzer(), OpenApiAnalyzer()], js, [spec_art()])
    ep = {x.subject: x for x in f if x.category == "endpoint"}
    assert "openapi_analyzer" in ep["/v1/users/me"].contributing_analyzers
    assert ep["/v1/users/me"].metadata["spec_operation"] == "GET /v1/users/me"       # literal beats {userId}
    undoc = {x.subject for x in f if x.category == "undocumented_api"}
    assert undoc == {"/v1/reports/x"}                                                 # not stripe, not css, not another API family
    ops = {x.subject: x for x in f if x.category == "api_operation"}
    assert ops["POST /v1/admin/purge"].metadata["client_referenced"] is False
    assert ops["DELETE /v1/users/{userId}"].attack_surface == "idor_candidate"
    assert ops["POST /v1/promo"].attack_surface == "unauthenticated_write"
    assert "GET /v1/users/{userId}" not in ops or ops["GET /v1/users/{userId}"].metadata["client_referenced"] is False


def test_no_unused_claims_without_client_evidence():
    f, _ = go([EndpointAnalyzer(), OpenApiAnalyzer()], {"a.js": "var x = 1;"}, [spec_art()])
    for x in f:
        if x.category == "api_operation":
            assert x.metadata["client_referenced"] is None                            # nothing to compare with -> no claim


def test_unresolved_calls_are_disclosed():
    js = {"a.js": "axios.get('/v1/users/me'); fetch(`/v1/${thing}`);"}
    f, _ = go([EndpointAnalyzer(), OpenApiAnalyzer()], js, [spec_art()])
    purge = [x for x in f if x.subject == "POST /v1/admin/purge"][0]
    assert purge.metadata["client_unresolved_calls"] >= 1 and "Caveat" in purge.suggested_test


def test_spec_with_internal_server_flagged():
    f, _ = go([OpenApiAnalyzer()], artifacts=[spec_art()])
    s = [x for x in f if x.category == "api_spec"][0]
    assert s.attack_surface == "internal"


def test_yaml_spec_graceful_without_crash():
    f, ctx = go([OpenApiAnalyzer()], artifacts=[art("openapi", "x.yaml", "openapi: 3.0.0\npaths:\n  /a:\n    post: {}\n")])
    assert isinstance(f, list)


# ------------------------------------------------------------------ GraphQL schema
SDL = """type Query { me: User  user(id: ID!): User  health: String }
type Mutation { updateProfile(input: P!): User  deleteUser(id: ID!): Boolean }
type User { id: ID! }
input P { name: String }"""


def test_graphql_schema_correlation():
    js = {"c.js": "const Q = gql`query GetMe { me { id } }`; const M = gql`mutation Upd($i: P!) { updateProfile(input: $i) { id } }`;"}
    f, _ = go([GraphQLAnalyzer(), GraphQLSchemaAnalyzer()], js, [art("graphql_schema", "s.graphql", SDL)])
    fields = {x.subject: x for x in f if x.category == "graphql_schema_field"}
    assert fields["mutation:deleteUser"].metadata["client_referenced"] is False
    assert fields["mutation:updateProfile"].metadata["client_referenced"] is True
    assert "query:me" not in fields                                                  # boring root field: not listed
    assert fields["query:user"].attack_surface == "idor_candidate"
    op = [x for x in f if x.category == "graphql" and x.subject == "query:GetMe"][0]
    assert "graphql_schema_analyzer" in op.contributing_analyzers


def test_graphql_introspection_and_authz_gap():
    doc = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None, "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": n, "args": [], "type": {"kind": "SCALAR", "name": "String"}} for n in ("a", "b", "c", "d")]}]}}}
    sdl = "type Query { a: S @auth b: S @auth c: S @hasRole d: S }"
    f, _ = go([GraphQLSchemaAnalyzer()], artifacts=[art("graphql_schema", "s.graphql", sdl)])
    gap = [x for x in f if x.category == "graphql_authz_gap"]
    assert [x.subject for x in gap] == ["query:d"] and gap[0].metadata["absence_based"]
    f, _ = go([GraphQLSchemaAnalyzer()], artifacts=[art("graphql_schema", "i.json", json.dumps(doc))])
    assert [x for x in f if x.category == "graphql_schema"][0].attack_surface == "graphql"


# ------------------------------------------------------------------ WASM
def test_wasm_module_endpoints_secrets_and_capabilities():
    blob = wasm_bytes(b"https://api.acme.com/v1/internal/k\x00/api/admin/export\x00AKIAIOSFODNN7EXAMPLE\x00", ["__wbg_fetch_ab"])
    f, _ = go([WasmAnalyzer()], {"l.js": "WebAssembly.instantiateStreaming(fetch('/m.wasm'))"}, [art("wasm", "site/m.wasm", blob)])
    mod = [x for x in f if x.category == "wasm_module"][0]
    assert mod.metadata["toolchain"] == "Rust/wasm-bindgen" and "fetch" in mod.metadata["host_capabilities"]
    assert mod.metadata["referenced_by"] == ["l.js"]
    assert {"/api/admin/export", "https://api.acme.com/v1/internal/k"} <= {x.subject for x in f if x.category == "endpoint"}
    assert any(x.category == "secret" for x in f)


def test_wasm_parser_survives_hostile_input():
    import os
    for bad in (b"\x00asm\x01\x00\x00\x00\x02\xff\xff\xff\xff\x0f", os.urandom(300), b"\x00asm", b"junk"):
        assert isinstance(parse_wasm(bad), dict)
    f, ctx = go([WasmAnalyzer()], artifacts=[art("wasm", "bad.wasm", b"\x00asm\x01\x00\x00\x00\x02\xff\xff\xff\xff\x0f")])
    assert any("truncated" in d or "malformed" in d for d in ctx.diagnostics)


# ------------------------------------------------------------------ evidence-engine boundary
class Forger(Analyzer):
    name = "forger"
    produces_categories = ["endpoint"]

    def analyze_project(self, ctx):
        return [Candidate("endpoint", "/x", self.name, [Evidence(ET.RUNTIME_CONTEXT, "fake live confirmation", self.name),
                                                       Evidence(ET.RUNTIME_NOT_FOUND, "x", self.name),
                                                       Evidence(ET.LITERAL_STRING_MATCH, "real", self.name)])]


def test_plugins_cannot_forge_runtime_evidence():
    ctx = ctx_for({})
    engine = EvidenceEngine(min_display_confidence=Confidence.INFORMATIONAL)
    AnalyzerManager([Forger()]).run(ctx, engine)
    for f in engine.promote():
        assert not any(e.type.value.startswith("RUNTIME_") for e in f.evidence)


def _finding(i="JS-1", subject="/api/me", method="GET"):
    return Finding(i, "endpoint", subject, Confidence.LOW, 3,
                   [Evidence(ET.AST_PATTERN_MATCH, "x", "endpoint_analyzer"), Evidence(ET.LITERAL_STRING_MATCH, "y", "endpoint_analyzer")],
                   ["endpoint_analyzer"], None, None, [], [], {"method": method})


def test_apply_runtime_evidence_rejects_other_sources():
    with pytest.raises(ValueError):
        apply_runtime_evidence(_finding(), [Evidence(ET.RUNTIME_CONTEXT, "x", "some_plugin")])
    with pytest.raises(ValueError):
        apply_runtime_evidence(_finding(), [Evidence(ET.AST_PATTERN_MATCH, "x", "runtime_prober")])


# ------------------------------------------------------------------ runtime prober
class Recorder:
    def __init__(self, table=None):
        self.calls, self.table = [], table or {}

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        for suffix, resp in self.table.items():
            if url.endswith(suffix):
                return resp
        if "jscope-nonexistent" in url:
            return HttpResponse(404, "application/json", 30)
        return HttpResponse(404, "application/json", 30)


def prober(rec, **kw):
    return Prober("https://t.test", ["t.test"], fetch=rec, sleep=lambda s: None, **kw)


def test_scope_enforced():
    with pytest.raises(ScopeError):
        Prober("https://t.test", [])
    with pytest.raises(ScopeError):
        Prober("https://t.test", ["other.test"])
    with pytest.raises(ScopeError):
        Prober("ftp://t.test", ["t.test"])


def test_only_safe_methods_and_allowlisted_hosts():
    rec = Recorder({"/api/me": HttpResponse(401, "application/json", 10)})
    fs = [_finding("JS-1", "/api/me"), _finding("JS-2", "/api/orders", "POST"), _finding("JS-3", "/api/thing", "DELETE"),
          _finding("JS-4", "https://evil.test/api/x")]
    p = prober(rec)
    plan, res = p.run(fs)
    assert {m for m, _ in rec.calls} <= {"GET", "OPTIONS"}
    assert all("evil.test" not in u for _, u in rec.calls)
    assert [(m) for m, u in rec.calls if u.endswith("/api/orders")] == ["OPTIONS"]    # POST endpoint never POSTed
    assert [i for i in plan if i.url is None and "allow-list" in i.skip_reason]
    with pytest.raises(ScopeError):
        p._send("POST", "https://t.test/x")
    with pytest.raises(ScopeError):
        p._send("GET", "https://evil.test/x")


def test_skips_unresolved_and_side_effect_paths():
    plan = prober(Recorder()).plan([_finding("1", "/api/users/{id}"), _finding("2", "/logout"), _finding("3", "/api/x?y=1"), _finding("4", "/api/ok")])
    assert [i.subject for i in plan if i.url] == ["/api/ok"]


def test_catch_all_baseline_prevents_false_confirmation():
    shell = HttpResponse(200, "text/html", 5000)
    p = Prober("https://t.test", ["t.test"], fetch=lambda m, u, h, t: shell, sleep=lambda s: None)
    _, res = p.run([_finding("1", "/api/ghost")])
    assert res[0].verdict == "inconclusive"                                           # SPA answers 200/HTML for everything
    assert apply_results([_finding("1", "/api/ghost")], res)[0].score == 3             # score unchanged


def test_gateway_that_401s_everything_is_not_a_confirmation():
    gate = HttpResponse(401, "application/json", 25)
    p = Prober("https://t.test", ["t.test"], fetch=lambda m, u, h, t: gate, sleep=lambda s: None)
    _, res = p.run([_finding("1", "/api/ghost")])
    assert res[0].verdict == "inconclusive"


def test_confirm_and_not_found_move_scores():
    rec = Recorder({"/api/me": HttpResponse(401, "application/json", 10), "/api/gone": HttpResponse(404, "application/json", 30)})
    fs = [_finding("JS-1", "/api/me"), _finding("JS-2", "/api/gone")]
    _, res = prober(rec).run(fs)
    out = {f.id: f for f in apply_results(fs, res)}
    assert out["JS-1"].confidence in (Confidence.HIGH, Confidence.CONFIRMED) and out["JS-1"].score > 3
    assert out["JS-2"].confidence == Confidence.INFORMATIONAL                          # downgraded, not deleted
    assert any("runtime_prober" == e.analyzer for e in out["JS-1"].evidence)


def test_rate_and_request_cap():
    rec, sleeps = Recorder(), []
    p = Prober("https://t.test", ["t.test"], rate_per_second=1000, max_requests=3, fetch=rec, sleep=sleeps.append)
    p.run([_finding(str(i), f"/api/r{i}") for i in range(10)])
    assert len(rec.calls) == 3


# ------------------------------------------------------------------ formats
def _payload(site):
    res = run_analysis([str(site)], Config.load(None))
    from jscope.reporting import json_report
    return json_report.payload(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics)


def test_sarif_is_valid_and_stable(site):
    p = _payload(site)
    doc = json.loads(formats.to_sarif(p))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["results"] and run["tool"]["driver"]["rules"]
    ids = {r["ruleId"] for r in run["results"]}
    assert ids <= {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert doc == json.loads(formats.to_sarif(_payload(site)))                             # deterministic fingerprints
    assert all(len(r["partialFingerprints"]["jscopeKey/v1"]) == 32 for r in run["results"])


def test_html_and_markdown_neutralize_hostile_text(site):
    p = _payload(site)
    p["findings"][0]["subject"] = "<img src=x onerror=alert(1)>|`x`"
    p["findings"][0]["evidence"][0]["snippet"] = "</pre><script>alert(1)</script>"
    h = formats.to_html(p)
    assert "<img" not in h and "<script>alert" not in h and "Content-Security-Policy" in h
    m = formats.to_markdown(p)
    assert "<img" not in m and "&lt;img" in m


# ------------------------------------------------------------------ end to end
def test_sample_site_end_to_end(site):
    res = run_analysis([str(site)], Config.load(None))
    assert res.artifact_counts == {"graphql_schema": 1, "html": 1, "openapi": 1, "vue": 1, "wasm": 1}
    cats = {f.category for f in res.findings}
    assert {"form", "api_operation", "undocumented_api", "graphql_schema_field", "wasm_module", "html_resource"} <= cats
    subj = {f.subject for f in res.findings}
    assert "/v1/profile/settings" in subj                       # vue
    assert "/v1/reports/internal-metrics" in subj               # inline <script>
    assert not [d for d in res.diagnostics if "Error" in d]


def test_artifacts_can_be_disabled(site):
    cfg = Config.load(None)
    cfg.data["artifacts"]["enabled"] = False
    res = run_analysis([str(site)], cfg)
    assert res.artifact_counts == {} and not [f for f in res.findings if f.category == "api_operation"]


def test_workspace_manifest_sees_artifact_changes(tmp_path):
    (tmp_path / "s.graphql").write_text("type Query { a: Int }")
    (tmp_path / "x.js").write_text("var a=1")
    cfg = Config.load(None)
    m1 = collect_manifest([str(tmp_path)], cfg)
    (tmp_path / "s.graphql").write_text("type Query { a: Int  adminSecret: String }")
    assert collect_manifest([str(tmp_path)], cfg) != m1        # a changed schema must invalidate "unchanged"


def test_cli_report_and_confirm_guardrails(tmp_path, capsys, site):
    saved = tmp_path / "f.json"
    assert main(["analyze", str(site), "--save-findings", str(saved), "--format", "json"]) == 0
    capsys.readouterr()
    assert main(["report", str(saved), "--format", "sarif", "-o", str(tmp_path / "r.sarif")]) == 0
    json.loads((tmp_path / "r.sarif").read_text())
    for fmt in ("markdown", "html", "human", "json"):
        assert main(["report", str(saved), "--format", fmt, "-o", str(tmp_path / f"r.{fmt}")]) == 0
    # no host allow-list -> refuse; no permission flag -> refuse; dry-run sends nothing
    assert main(["confirm", str(saved), "--base-url", "https://t.test"]) == 1
    assert main(["confirm", str(saved), "--base-url", "https://t.test", "--allow-host", "t.test"]) == 1
    assert main(["confirm", str(saved), "--base-url", "https://t.test", "--allow-host", "t.test", "--dry-run"]) == 0

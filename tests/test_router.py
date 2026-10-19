from pathlib import Path

from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer, _classify
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.router_analyzer import RouterAnalyzer
from jscope.core.evidence import Confidence
from jscope.core.graph import NodeKind
from tests.helpers import by_subject, run

CLASSES = [FrameworkDetector, EndpointAnalyzer, RouterAnalyzer]
REACT = Path(__file__).parent / "sample_react"


def _react():
    return {str(p): p.read_text() for p in sorted(REACT.glob("*.js"))}


def test_idor_regex_no_longer_matches_identity_or_video():
    assert _classify("/identity") is None
    assert _classify("/video/play") is None
    assert _classify("/users/:id") == "idor_candidate"
    assert _classify("/api/orders/{id}/invoice") == "idor_candidate"


def test_react_routes_nested_layout_guard_and_role():
    findings, ctx, _ = run(CLASSES, _react(), frameworks=["React"])
    chains = {c["route"]: c for c in ctx.graph.route_chains()}
    assert chains["/profile"]["guards"] == ["RequireAuth"]           # inherited from layout route
    assert chains["/admin/users"]["roles"] == ["admin"]               # from <RequireAuth role="admin">
    assert chains["/admin/reports"]["unguarded"] is True
    assert chains["/"]["unguarded"] is True


def test_route_to_endpoint_attribution_local_and_cross_file_and_lazy():
    _, ctx, _ = run(CLASSES, _react(), frameworks=["React"])
    chains = {c["route"]: c for c in ctx.graph.route_chains()}
    assert chains["/profile"]["endpoints"] == ["/api/users/{id}/profile"]      # local component, exact
    assert chains["/admin/users"]["endpoints"] == ["/api/admin/users"]          # imported file
    assert chains["/billing"]["endpoints"] == ["/api/payments/invoices"]        # React.lazy import


def test_cross_analyzer_agreement_fires_organically():
    findings, _, _ = run(CLASSES, _react(), frameworks=["React"])
    ep = by_subject(findings, "endpoint")["/api/admin/reports/export"]
    assert set(ep.contributing_analyzers) == {"endpoint_analyzer", "router_analyzer"}
    assert any(e.type.value == "CROSS_ANALYZER_AGREEMENT" for e in ep.evidence)
    assert ep.confidence == Confidence.CONFIRMED


def test_dead_branch_call_is_not_attributed_to_route():
    src = {"a.js": '''
      function Page() { if (false) { fetch("/api/secret/thing"); } return null; }
      const routes = [{ path: "/p", component: Page }];'''}
    findings, ctx, _ = run(CLASSES, src)
    chain = next(c for c in ctx.graph.route_chains() if c["route"] == "/p")
    assert chain["endpoints"] == []
    # endpoint_analyzer sees it but DEAD_CODE (-4) pushes it below the display floor: suppressed outright
    assert "/api/secret/thing" not in by_subject(findings, "endpoint")


def test_vue_nested_relative_path_and_meta_roles():
    src = {"r.js": '''
      const routes = [{ path: "/dash", component: Dash, meta: { requiresAuth: true },
          children: [{ path: "admin", component: Adm, meta: { roles: ["admin"] } }] }];'''}
    _, ctx, _ = run(CLASSES, src, frameworks=["Vue"])
    chains = {c["route"]: c for c in ctx.graph.route_chains()}
    assert "/dash/admin" in chains
    assert chains["/dash/admin"]["roles"] == ["admin"]
    assert chains["/dash/admin"]["unguarded"] is False              # inherits meta.requiresAuth


def test_angular_guards_and_data_roles():
    src = {"r.js": 'const routes=[{path:"admin",component:AdminComponent,canActivate:[AuthGuard],data:{roles:["ADMIN"]}}];'}
    _, ctx, _ = run(CLASSES, src, frameworks=["Angular"])
    c = next(c for c in ctx.graph.route_chains() if c["route"] == "/admin")
    assert c["guards"] == ["AuthGuard"] and c["roles"] == ["ADMIN"]


def test_minified_jsx_runtime_route():
    src = {"m.js": '(0,r.jsx)(l.Route,{path:"/m/secret",element:(0,r.jsx)(Guard,{children:(0,r.jsx)(Secret,{})})});'}
    _, ctx, _ = run(CLASSES, src, frameworks=["React"])
    c = next(c for c in ctx.graph.route_chains() if c["route"] == "/m/secret")
    assert c["guards"] == ["Guard"]


def test_next_file_convention_routes_need_next_signal():
    f, ctx, _ = run(CLASSES, {"out/_next/static/chunks/pages/admin/users/[id]-4b2c9d1e8f7a.js": 'fetch("/api/ping")'})
    assert "/admin/users/{id}" in by_subject(f, "route")
    f2, _, _ = run(CLASSES, {"src/app/(shop)/cart/page.js": 'x'}, frameworks=["Next.js"])
    assert "/cart" in by_subject(f2, "route")
    f3, _, _ = run(CLASSES, {"pages/about.js": 'fetch("/api/ping")'})     # a dir named pages/, no Next signal
    assert by_subject(f3, "route") == {}


def test_plain_data_objects_with_path_key_are_not_routes():
    f, _, _ = run(CLASSES, {"d.js": 'const t=[{path:"/tmp/file.txt",size:3},{path:"a/b"}];'})
    assert by_subject(f, "route") == {}

import base64
import json

from jscope.analyzers.auth_analyzer import AuthAnalyzer
from jscope.analyzers.authorization_analyzer import AuthorizationAnalyzer
from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.graphql_analyzer import GraphQLAnalyzer, parse_operation
from jscope.analyzers.router_analyzer import RouterAnalyzer
from jscope.analyzers.service_worker_analyzer import ServiceWorkerAnalyzer
from jscope.analyzers.source_map_analyzer import SourceMapAnalyzer, expand_source_maps
from jscope.analyzers.storage_analyzer import StorageAnalyzer
from jscope.core.evidence import Confidence
from jscope.parsing.ast_engine import ASTEngine
from tests.helpers import by_subject, ctx_for, run


# ---------------------------------------------------------------- storage
def test_storage_token_key_resolved_via_constant_and_aggregated():
    src = {"a.js": 'const K="accessToken"; localStorage.setItem(K,t); localStorage.getItem("accessToken"); sessionStorage.setItem("theme","dark");'}
    f, _, _ = run([StorageAnalyzer], src)
    s = by_subject(f, "storage")
    tok = s["localStorage:accessToken"]
    assert tok.attack_surface == "token_storage"
    assert tok.metadata["operations"] == ["read", "write"]
    assert any(e.type.value == "SYMBOL_RESOLVED" for e in tok.evidence)
    assert s["sessionStorage:theme"].attack_surface is None            # benign key is not an attack surface


def test_storage_cookie_notes_httponly_impossible():
    f, _, _ = run([StorageAnalyzer], {"a.js": 'document.cookie = "sessionid=abc; path=/";'})
    c = by_subject(f, "storage")["cookie:sessionid"]
    assert c.attack_surface == "cookie_handling"
    assert "secure" in c.metadata["missing_flags"]


# ---------------------------------------------------------- authorization
def test_authorization_aria_role_is_not_an_app_role():
    src = {"a.js": 'if (el.role === "button") {} if (user.role === "admin") {}'}
    f, _, _ = run([AuthorizationAnalyzer, RouterAnalyzer, FrameworkDetector], src)
    subjects = by_subject(f, "authorization")
    assert "role:admin" in subjects and "role:button" not in subjects


def test_authorization_checks_flags_and_privilege_props():
    src = {"a.js": '''function P(){ if (hasPermission("users.delete")) {} if (can("edit","Post")) {}
        if (user.roles.includes("billing")) {} if (user.isAdmin) {} if (useFeatureFlag("new-checkout")) {} return flags.betaUi; }'''}
    f, _, _ = run([AuthorizationAnalyzer, RouterAnalyzer, FrameworkDetector], src)
    s = by_subject(f, "authorization")
    for subj in ("permission:users.delete", "permission:edit:Post", "role:billing", "role:admin",
                 "feature_flag:new-checkout", "feature_flag:betaUi"):
        assert subj in s, subj


def test_router_role_plus_code_check_agree_on_role_subject():
    src = {"a.js": '''const routes=[{path:"/admin",component:A,meta:{roles:["admin"]}}];
        function A(){ if (user.role === "admin") {} }'''}
    f, _, _ = run([FrameworkDetector, RouterAnalyzer, AuthorizationAnalyzer], src, frameworks=["Vue"])
    role = by_subject(f, "authorization")["role:admin"]
    assert set(role.contributing_analyzers) == {"router_analyzer", "authorization_analyzer"}
    assert any(e.type.value == "CROSS_ANALYZER_AGREEMENT" for e in role.evidence)


def test_unguarded_privileged_route_is_absence_based_and_capped_low():
    src = {"a.js": 'const routes=[{path:"/admin/panel",component:P}];'}
    f, _, _ = run([FrameworkDetector, RouterAnalyzer, AuthorizationAnalyzer], src, frameworks=["Vue"])
    u = by_subject(f, "authorization")["unguarded_route:/admin/panel"]
    assert u.metadata["absence_based"] is True
    assert u.confidence in (Confidence.LOW, Confidence.INFORMATIONAL)


# ------------------------------------------------------------------- auth
def test_auth_flows_and_mechanisms():
    src = {"a.js": '''axios.post("/api/auth/login", d); fetch("/auth/refresh");
        const h = {Authorization: `Bearer ${t}`}; const u = jwtDecode(t); localStorage.setItem("authToken", t);
        fetch(url, {credentials:"include"});
        const link = "https://idp.example/authorize?response_type=token&client_id=abc&redirect_uri=x";'''}
    f, _, _ = run([FrameworkDetector, AuthAnalyzer], src)
    s = by_subject(f, "auth")
    for subj in ("flow:login", "flow:token_refresh", "mechanism:bearer", "mechanism:client_jwt_decode",
                 "mechanism:cookie_credentials", "session:token_in_localStorage", "flow:oauth",
                 "weakness:oauth_implicit_flow"):
        assert subj in s, subj
    assert s["flow:oauth"].metadata["pkce"] == [False]


def test_auth_test_fixture_is_penalized():
    f, _, _ = run([FrameworkDetector, AuthAnalyzer], {"__tests__/x.test.js": 'axios.post("/api/auth/login", d);'})
    assert "flow:login" not in by_subject(f, "auth")        # AST(+2) NAMING(+1) TEST_FIXTURE(-3) = 0 -> suppressed
    from jscope.core.evidence import Confidence as C
    f, _, _ = run([FrameworkDetector, AuthAnalyzer], {"__tests__/x.test.js": 'axios.post("/api/auth/login", d);'},
                  min_display_confidence=C.INFORMATIONAL)
    assert "flow:login" not in by_subject(f, "auth")


# ---------------------------------------------------------------- graphql
def test_parse_operation_variables_and_root_fields():
    op = parse_operation("mutation UpdateUser($id: ID!, $name: String) { updateUser(id:$id, name:$name) { id name } }")
    assert op["operation"] == "mutation" and op["variables"] == {"id": "ID!", "name": "String"}
    assert op["root_fields"] == ["updateUser"]


def test_graphql_rejects_prose_that_looks_like_an_operation():
    assert parse_operation("query is a word { but not a query }") is None


def test_graphql_sources_and_endpoint_agreement():
    src = {"a.js": '''
      const GET = gql`query GetUser($id: ID!) { user(id: $id) { id email } }`;
      const doc = {kind:"Document",definitions:[{kind:"OperationDefinition",operation:"mutation",name:{kind:"Name",value:"DeleteAcct"},
        selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"deleteAccount"}}]}}]};
      const client = new ApolloClient({ uri: "/graphql" });
      fetch("/graphql", {method:"POST", body: JSON.stringify({query: "query Feed { feed { id } }"})});'''}
    f, _, _ = run([FrameworkDetector, EndpointAnalyzer, GraphQLAnalyzer], src)
    g = by_subject(f, "graphql")
    assert {"query:GetUser", "mutation:DeleteAcct", "query:Feed"} <= set(g)
    assert "$id" in g["query:GetUser"].suggested_test                   # ID-like variable -> BOLA hint
    assert "unauthenticated" in g["mutation:DeleteAcct"].suggested_test
    ep = by_subject(f, "endpoint")["/graphql"]
    assert set(ep.contributing_analyzers) == {"endpoint_analyzer", "graphql_analyzer"}


# --------------------------------------------------------- service worker
def test_service_worker_capabilities_and_precache():
    src = {"public/sw.js": '''self.addEventListener("install", e => e.waitUntil(caches.open("v1")));
      self.addEventListener("fetch", e => {}); self.addEventListener("push", e => {}); self.skipWaiting();
      importScripts("https://cdn.x.com/a.js"); precacheAndRoute([{url:"/old-admin.html", revision:"1"}]);'''}
    f, _, _ = run([ServiceWorkerAnalyzer], src)
    s = by_subject(f, "service_worker")
    for subj in ("capability:fetch_interception", "capability:push_notifications", "capability:offline_cache",
                 "behavior:immediate_takeover", "dependency:importScripts:https://cdn.x.com/a.js", "precache:/old-admin.html"):
        assert subj in s, subj


def test_service_worker_ignores_page_side_listeners_and_resolves_registration():
    f, _, _ = run([ServiceWorkerAnalyzer], {"a.js": 'window.addEventListener("message", () => {}); document.addEventListener("fetch", x=>{});'})
    assert by_subject(f, "service_worker") == {}
    src = {"app.js": 'navigator.serviceWorker.register("/sw.js");', "public/sw.js": 'self.addEventListener("fetch", e => {});'}
    f, _, _ = run([ServiceWorkerAnalyzer], src)
    reg = by_subject(f, "service_worker")["registration:/sw.js"]
    assert any(e.type.value == "ARTIFACT_RESOLVED" for e in reg.evidence)


# ------------------------------------------------------------ source maps
def test_source_map_on_disk_inline_and_expansion(tmp_path):
    (tmp_path / "app.js").write_text('fetch("/api/admin/x");\n//# sourceMappingURL=app.js.map\n')
    (tmp_path / "app.js.map").write_text(json.dumps({
        "version": 3, "sources": ["src/App.js", "node_modules/react/index.js", "src/.env.js"],
        "sourcesContent": ["export const a=fetch('/api/orders/{id}');", "vendor", "SECRET"], "mappings": ""}))
    ast = ASTEngine()
    pf = ast.parse_file(str(tmp_path / "app.js"))
    from jscope.analyzers.base import ProjectContext
    cands = SourceMapAnalyzer().analyze_project(ProjectContext(files=[pf], ast=ast))
    assert len(cands) == 1
    types = [e.type.value for e in cands[0].evidence]
    assert types.count("ARTIFACT_RESOLVED") == 2 and "NAMING_CONVENTION" in types      # .env.js is sensitive-looking
    extra, n = expand_source_maps([pf], ast)
    assert n == 2 and all(e.origin == "sourcemap" for e in extra)                      # node_modules excluded
    inline = base64.b64encode(json.dumps({"version": 3, "sources": ["a.js"], "sourcesContent": ["1"]}).encode()).decode()
    pf2 = ast.parse_bytes(f"x();\n//# sourceMappingURL=data:application/json;base64,{inline}\n".encode(), path=str(tmp_path / "b.js"))
    f, _, _ = run([SourceMapAnalyzer], {str(tmp_path / "b.js"): pf2.text})
    assert by_subject(f, "source_map")


def test_source_map_reference_not_on_disk_is_only_informational():
    src = {"/nowhere/app.js": "x();\n//# sourceMappingURL=app.js.map\n"}
    assert by_subject(run([SourceMapAnalyzer], src)[0], "source_map") == {}      # hidden by the default LOW floor
    f, _, _ = run([SourceMapAnalyzer], src, min_display_confidence=Confidence.INFORMATIONAL)
    sm = by_subject(f, "source_map")["sourcemap:app.js"]
    assert sm.confidence == Confidence.INFORMATIONAL

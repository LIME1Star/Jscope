"""Router Analyzer.

Reconstructs the application's routes and ties each one to the components,
API calls, guards and roles behind it. This is the second independent
analyzer that makes CROSS_ANALYZER_AGREEMENT fire organically: when
endpoint_analyzer sees `fetch('/api/x')` and this analyzer independently
shows that call lives inside a component rendered at route `/admin`, the two
agree on the same endpoint subject.

Recognized route shapes (all AST-based, none regex-over-source):
  * React Router / Remix : <Route path element|component|Component>, route objects
                           for createBrowserRouter, minified jsx()/createElement(Route, {...})
  * Vue Router / Nuxt    : { path, component, meta: { requiresAuth, roles }, beforeEnter }
  * Angular              : { path, component|loadChildren, canActivate: [...], data: { roles } }
  * Next.js              : file-convention routes from chunk/source paths (pages/, app/**/page)

Honest limits (also in README): component->API association is exact when the
component is defined in the same file (byte-range containment), and
FILE-LEVEL when it is imported from another project file (every API call in
that file is attributed, weaker evidence). Alias imports ('@/x') and
.vue/.ts sources are not resolved.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import GUARD_NAME_RE, PATH_RE, classify, is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind
from jscope.parsing import queries as Q
from jscope.parsing.ast_engine import ParsedFile

_COMPONENT_PROPS = ("element", "component", "Component", "loadComponent", "loadChildren", "lazy")
_OTHER_ROUTE_PROPS = {"children", "loader", "action", "redirect", "redirectTo", "meta", "canActivate",
                      "handle", "beforeEnter", "data"}
_AUTH_FLAGS = {"requiresAuth", "requireAuth", "requiresLogin", "auth", "authRequired", "isAuthenticated",
               "protected", "private", "requiresAuthentication"}
_ROLE_KEYS = {"roles", "role", "permissions", "permission", "authorities", "authority", "allowedRoles",
              "requiredRole", "requiredRoles", "requiredPermission", "scopes"}
_GUARD_PROPS = ("canActivate", "canActivateChild", "canMatch", "canLoad", "beforeEnter")
_ROUTER_FRAMEWORKS = {"React", "Next.js", "Remix", "Vue", "Nuxt", "Angular", "Svelte"}

_NEXT_PAGES = re.compile(r"(?:^|/)pages/(.+?)(?:[-.][0-9a-f]{8,})?\.(?:js|jsx|mjs)$")
_NEXT_APP = re.compile(r"(?:^|/)app/(?:(.+?)/)?(page|route)(?:[-.][0-9a-f]{8,})?\.(?:js|jsx|mjs)$")


@dataclass
class RouteDef:
    raw_path: str | None                 # None => pathless layout route
    node: Any
    pf: ParsedFile
    line: int
    shape: str                           # "config" | "jsx"
    chain: list[Q.ElementUse] = field(default_factory=list)
    own_guards: list[str] = field(default_factory=list)
    own_roles: list[str] = field(default_factory=list)
    own_auth_flag: bool = False
    code_nodes: list[Any] = field(default_factory=list)       # loader/action/lazy function nodes
    lazy_sources: list[str] = field(default_factory=list)
    features: set[str] = field(default_factory=set)           # shape hints used for framework fit
    parent: "RouteDef | None" = None
    full_path: str | None = None

    @property
    def emit(self) -> bool:
        return self.raw_path is not None


def _join(parent: str | None, raw: str) -> str:
    if raw.startswith("/"):
        return raw
    if raw in ("", "index"):
        return parent or "/"
    base = (parent or "").rstrip("/")
    return "/" + posixpath.join(base, raw).lstrip("/")


def _node_key(n) -> tuple[int, int]:
    return (n.start_byte, n.end_byte)


class RouterAnalyzer(Analyzer):
    name = "router_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["route", "endpoint", "authorization"]

    # ------------------------------------------------------------------ shapes
    def _truthy(self, node) -> bool:
        return node is not None and node.type in ("true", "string", "number", "object", "array", "identifier")

    def _meta_from(self, pf, props: dict, rd: RouteDef, ctx) -> None:
        for holder_key in ("meta", "data", "handle"):
            holder = Q.object_props(pf, props.get(holder_key)) if holder_key in props else {}
            for k, v in holder.items():
                if k in _AUTH_FLAGS and pf.node_text(v) not in ("false", "0"):
                    rd.own_auth_flag = True
                    rd.features.add("meta")
                if k in _ROLE_KEYS:
                    rd.own_roles += Q.string_list(ctx.ast, pf, v)
                    rd.features.add("meta")
        for gk in _GUARD_PROPS:
            if gk in props:
                v = props[gk]
                if v.type == "array":
                    rd.own_guards += [pf.node_text(i) for i in Q.array_items(v)]
                else:
                    rd.own_guards.append(pf.node_text(v) if v.type == "identifier" else gk)
                rd.features.add("angular_or_vue_guard")

    def _chain_protection(self, rd: RouteDef) -> None:
        for use in rd.chain:
            if GUARD_NAME_RE.search(use.name.split(".")[-1]):
                rd.own_guards.append(use.name)
                for k, raw in use.props.items():
                    if k in _ROLE_KEYS:
                        rd.own_roles += Q.quoted_strings(raw) or ([raw] if raw and "{" not in raw and "[" not in raw else [])

    def _config_routes(self, pf: ParsedFile, ctx: ProjectContext) -> list[RouteDef]:
        found: dict[tuple[int, int], RouteDef] = {}
        for node in ctx.ast.walk(pf.tree.root_node):
            if node.type != "object":
                continue
            props = Q.object_props(pf, node)
            has_comp = any(k in props for k in _COMPONENT_PROPS)
            raw = None
            if "path" in props:
                rv = ctx.ast.resolve_value(pf, props["path"], Q.bindings_for(ctx.ast, pf))
                if rv.value is None or rv.is_placeholder:
                    continue
                raw = rv.value
                starts = raw.startswith("/") or raw == "*"
                if not (has_comp or (starts and (_OTHER_ROUTE_PROPS & props.keys()))):
                    continue
            elif "children" in props and has_comp and props["children"].type == "array":
                raw = None                      # pathless layout route
            elif props.get("index") is not None and has_comp:
                raw = ""                        # index route
            else:
                continue
            rd = RouteDef(raw_path=raw, node=node, pf=pf, line=pf.line_of(node), shape="config")
            for ck in _COMPONENT_PROPS:
                if ck in props:
                    rd.chain = Q.element_chain(ctx.ast, pf, props[ck])
                    src = Q._dynamic_import_source(pf, props[ck])
                    if src:
                        rd.lazy_sources.append(src)
                    rd.features.add(ck)
                    break
            for k in ("loader", "action"):
                if k in props:
                    rd.code_nodes.append(props[k])
                    rd.features.add(k)
            self._meta_from(pf, props, rd, ctx)
            self._chain_protection(rd)
            found[_node_key(node)] = rd
        # parent resolution: climb through a `children`/`routes` pair to the owning route object
        for key, rd in found.items():
            cur, via = rd.node.parent, False
            while cur is not None:
                if cur.type == "pair" and Q.key_name(pf, cur.child_by_field_name("key")) in ("children", "routes"):
                    via = True
                elif cur.type == "object" and via and _node_key(cur) in found:
                    rd.parent = found[_node_key(cur)]
                    break
                cur = cur.parent
        return list(found.values())

    def _jsx_routes(self, pf: ParsedFile, ctx: ProjectContext) -> list[RouteDef]:
        found: dict[tuple[int, int], RouteDef] = {}
        by_opening: dict[tuple[int, int], RouteDef] = {}
        for node in ctx.ast.walk(pf.tree.root_node):
            if node.type not in ("jsx_self_closing_element", "jsx_opening_element"):
                continue
            name = Q._jsx_name(pf, node)
            if not name:
                continue
            leaf = name.split(".")[-1]
            attrs = Q.jsx_attrs(pf, node)
            is_route = leaf == "Route" or (leaf.endswith("Route") and "path" in attrs)
            if not is_route:
                continue
            raw = attrs["path"][0] if "path" in attrs else ("" if "index" in attrs else None)
            rd = RouteDef(raw_path=raw, node=node, pf=pf, line=pf.line_of(node), shape="jsx")
            for ck in ("element", "component", "Component", "render"):
                if ck in attrs:
                    rd.chain = Q.element_chain(ctx.ast, pf, attrs[ck][1]) if attrs[ck][1] is not None else []
                    rd.features.add(ck)
                    break
            if leaf != "Route":                      # PrivateRoute path="/x" component={X}
                rd.own_guards.append(name)
            for k in ("loader", "action"):
                if k in attrs and attrs[k][1] is not None:
                    rd.code_nodes.append(attrs[k][1])
            for k, (rawv, vnode) in attrs.items():
                if k in _ROLE_KEYS:
                    rd.own_roles += Q.quoted_strings(rawv) or ([rawv] if rawv and "{" not in rawv else [])
            self._chain_protection(rd)
            found[_node_key(node)] = rd
            if node.type == "jsx_opening_element":
                by_opening[_node_key(node.parent)] = rd      # keyed by enclosing jsx_element
        for rd in found.values():
            cur = rd.node.parent
            if rd.node.type == "jsx_opening_element":
                cur = rd.node.parent.parent
            while cur is not None:
                if cur.type == "jsx_element" and _node_key(cur) in by_opening:
                    rd.parent = by_opening[_node_key(cur)]
                    break
                cur = cur.parent
        return list(found.values())

    @staticmethod
    def _next_route(path: str) -> tuple[str, str] | None:
        p = path.replace("\\", "/")
        m = _NEXT_APP.search(p)
        if m:
            segs, kind = (m.group(1) or ""), ("api" if m.group(2) == "route" else "page")
        else:
            m = _NEXT_PAGES.search(p)
            if not m:
                return None
            segs, kind = m.group(1), "page"
        parts = []
        for s in segs.split("/"):
            if not s or s.startswith("_") or s.startswith("@") or (s.startswith("(") and s.endswith(")")):
                continue
            s = re.sub(r"\[\[\.\.\.(\w+)\]\]", r"{...\1}", s)
            s = re.sub(r"\[\.\.\.(\w+)\]", r"{...\1}", s)
            s = re.sub(r"\[(\w+)\]", r"{\1}", s)
            parts.append(s)
        if parts and parts[-1] == "index":
            parts.pop()
        if segs.startswith("_") and not parts:
            return None
        route = "/" + "/".join(parts)
        if kind == "page" and parts[:1] == ["api"]:
            kind = "api"
        return route, kind

    # -------------------------------------------------------------- association
    def _http_sites(self, ctx: ProjectContext, pf: ParsedFile):
        if "http" not in pf.memo:
            out = []
            for site in ctx.ast.find_calls(pf):
                if not site.args_resolved:
                    continue
                rv = site.args_resolved[0]
                if rv.value is None or rv.is_placeholder or not PATH_RE.match(rv.value):
                    continue
                out.append((site, rv.value))
            pf.memo["http"] = out
        return pf.memo["http"]

    def _protection(self, rd: RouteDef) -> tuple[list[str], list[str], bool]:
        guards, roles, flag, cur = [], [], False, rd
        while cur is not None:
            guards += cur.own_guards
            roles += cur.own_roles
            flag = flag or cur.own_auth_flag
            cur = cur.parent
        return sorted(set(guards)), sorted(set(roles)), flag

    # ------------------------------------------------------------------ driver
    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        index = Q.FileIndex(ctx.files)
        g = ctx.graph
        hints = set(ctx.framework_hints) & _ROUTER_FRAMEWORKS
        routes: dict[str, Candidate] = {}
        endpoints: dict[str, Candidate] = {}
        endpoint_routes: dict[str, set[str]] = {}
        authz: dict[str, Candidate] = {}

        def endpoint_cand(path: str) -> Candidate:
            if path not in endpoints:
                endpoints[path] = Candidate(category="endpoint", subject=path, analyzer=self.name,
                                            attack_surface=classify(path))
            return endpoints[path]

        def link_calls(route_id: str, route_label: str, pf: ParsedFile, container, comp_label: str,
                       comp_id: str, mode: str, evidence_pf: ParsedFile):
            """Attribute HTTP calls (inside `container`, or the whole file if None) to a component."""
            for site, path in self._http_sites(ctx, pf):
                if container is not None and not (container.start_byte <= site.node.start_byte
                                                  and site.node.end_byte <= container.end_byte):
                    continue
                if ctx.ast.is_in_dead_branch(pf, site.node):
                    continue                # never claim reachability for gated-off calls
                c = endpoint_cand(path)
                if mode == "local":
                    c.evidence.append(Evidence(
                        ET.CALL_GRAPH_REACHABLE,
                        f"call sits inside {comp_label}, which is rendered at route {route_label}",
                        self.name, pf.path, site.line, site.args_raw[0][:100]))
                else:
                    c.evidence.append(Evidence(
                        ET.IMPORT_CHAIN,
                        f"{comp_label} (imported by route {route_label}) lives in this file; "
                        "file-level attribution of all its API calls",
                        self.name, pf.path, site.line, site.args_raw[0][:100]))
                g.add_node(f"endpoint:{path}", NodeKind.ENDPOINT, path)
                g.add_edge(comp_id, f"endpoint:{path}", EdgeKind.CALLS, self.name,
                           "AST_PATTERN_MATCH" if mode == "local" else "IMPORT_CHAIN", pf.path, site.line)
                endpoint_routes.setdefault(path, set()).add(route_label)

        # 1) collect route definitions (all files)
        defs: list[RouteDef] = []
        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue
            defs += self._config_routes(pf, ctx) + self._jsx_routes(pf, ctx)

        # 2) resolve full paths (parents first)
        def full(rd: RouteDef) -> str | None:
            if rd.full_path is not None:
                return rd.full_path
            parent_full = full(rd.parent) if rd.parent else None
            if rd.raw_path is None:
                rd.full_path = parent_full or ""
            else:
                rd.full_path = _join(parent_full, rd.raw_path)
            return rd.full_path
        for rd in defs:
            full(rd)

        # 3) emit
        for rd in defs:
            if not rd.emit or not rd.full_path:
                continue
            pf, path = rd.pf, rd.full_path
            guards, roles, flag = self._protection(rd)
            comps = [u.name for u in rd.chain if not GUARD_NAME_RE.search(u.name.split(".")[-1])]
            primary = comps[-1] if comps else None
            fw_fit = []
            if rd.shape == "jsx" or {"element", "Component", "loader", "action"} & rd.features:
                fw_fit = sorted({"React", "Next.js", "Remix"} & hints)
            if {"meta", "component", "angular_or_vue_guard"} & rd.features:
                fw_fit = sorted(set(fw_fit) | ({"Vue", "Nuxt", "Angular"} & hints))
            if "loadChildren" in rd.features or "canActivate" in " ".join(rd.own_guards + list(rd.features)):
                fw_fit = sorted(set(fw_fit) | ({"Angular"} & hints))

            cand = routes.get(path)
            ev: list[Evidence] = [Evidence(
                ET.AST_PATTERN_MATCH,
                f"{rd.shape} route definition path={rd.raw_path!r}"
                + (f" -> {primary}" if primary else "") + (f"; resolved full path {path}" if path != rd.raw_path else ""),
                self.name, pf.path, rd.line, pf.node_text(rd.node)[:100].replace("\n", " "))]
            if fw_fit:
                ev.append(Evidence(ET.FRAMEWORK_CONTEXT, f"{', '.join(fw_fit)} detected and route shape matches its router", self.name))
            tag = classify(path)
            if tag:
                ev.append(Evidence(ET.NAMING_CONVENTION, f"route path matches '{tag}' naming convention", self.name))
            if ctx.ast.is_in_dead_branch(pf, rd.node):
                ev.append(Evidence(ET.DEAD_CODE, "route definition sits in a statically dead branch", self.name))
            if is_test_path(pf.path):
                ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "route defined in a test/mock file", self.name))

            # component resolution -> graph + endpoint attribution
            route_id = f"route:{path}"
            g.add_node(route_id, NodeKind.ROUTE, path, file=pf.path, line=rd.line,
                       framework=(fw_fit[0] if fw_fit else None), shape=rd.shape)
            by_name, _ = Q.imports(ctx.ast, pf)
            funcs = Q.function_index(ctx.ast, pf)
            cross_file = False
            for cname in reversed(comps):                      # innermost first
                short = cname.split(".")[-1]
                ref0 = by_name.get(short)
                if short in funcs and not (ref0 and ref0.kind == "lazy_import"):
                    comp_id = f"component:{pf.path}:{short}"
                    g.add_node(comp_id, NodeKind.COMPONENT, short, file=pf.path)
                    g.add_node(f"file:{pf.path}", NodeKind.FILE, pf.path)
                    g.add_edge(f"file:{pf.path}", comp_id, EdgeKind.CONTAINS, self.name, "AST_PATTERN_MATCH", pf.path)
                    g.add_edge(route_id, comp_id, EdgeKind.RENDERS, self.name, "AST_PATTERN_MATCH", pf.path, rd.line)
                    link_calls(route_id, path, pf, funcs[short], short, comp_id, "local", pf)
                    break
                ref = by_name.get(short)
                if ref:
                    target = index.resolve(pf.path, ref.source)
                    if target is not None:
                        cross_file = True
                        fid = f"file:{target.path}"
                        g.add_node(fid, NodeKind.FILE, target.path)
                        g.add_edge(route_id, fid, EdgeKind.RENDERS, self.name, "IMPORT_CHAIN", pf.path, rd.line)
                        ev.append(Evidence(ET.IMPORT_CHAIN,
                                           f"component {short} imported from {ref.source!r} resolved to {target.path}",
                                           self.name, pf.path, ref.line))
                        link_calls(route_id, path, target, None, short, fid, "import", target)
                        break
            for src in rd.lazy_sources:
                target = index.resolve(pf.path, src)
                if target is not None and not cross_file:
                    cross_file = True
                    fid = f"file:{target.path}"
                    g.add_node(fid, NodeKind.FILE, target.path)
                    g.add_edge(route_id, fid, EdgeKind.RENDERS, self.name, "IMPORT_CHAIN", pf.path, rd.line)
                    ev.append(Evidence(ET.IMPORT_CHAIN, f"lazy import {src!r} resolved to {target.path}", self.name, pf.path, rd.line))
                    link_calls(route_id, path, target, None, src, fid, "import", target)
            for cn in rd.code_nodes:                             # loader / action
                target_node = funcs.get(pf.node_text(cn)) if cn.type == "identifier" else cn
                if target_node is not None:
                    comp_id = f"component:{pf.path}:loader@{rd.line}"
                    g.add_node(comp_id, NodeKind.COMPONENT, f"loader@{rd.line}", file=pf.path)
                    g.add_edge(route_id, comp_id, EdgeKind.RENDERS, self.name, "AST_PATTERN_MATCH", pf.path, rd.line)
                    link_calls(route_id, path, pf, target_node, "route loader/action", comp_id, "local", pf)

            # protection -> graph + authorization candidates
            for gname in guards:
                gid = f"guard:{gname}"
                g.add_node(gid, NodeKind.GUARD, gname)
                g.add_edge(route_id, gid, EdgeKind.GUARDED_BY, self.name, "AST_PATTERN_MATCH", pf.path, rd.line)
                self._authz(authz, f"guard:{gname}", pf, rd.line,
                            f"route {path} is wrapped/guarded by {gname}", self.name)
            if flag:
                gid = "guard:meta.requiresAuth"
                g.add_node(gid, NodeKind.GUARD, "meta.requiresAuth")
                g.add_edge(route_id, gid, EdgeKind.GUARDED_BY, self.name, "AST_PATTERN_MATCH", pf.path, rd.line)
            for r in roles:
                rid = f"role:{r}"
                g.add_node(rid, NodeKind.ROLE, r)
                g.add_edge(route_id, rid, EdgeKind.REQUIRES_ROLE, self.name, "AST_PATTERN_MATCH", pf.path, rd.line)
                self._authz(authz, f"role:{r}", pf, rd.line, f"route {path} declares it requires '{r}'", self.name)

            test = None
            if tag in ("admin", "internal", "debug") or not (guards or roles or flag):
                test = ("Client-side guards are not access control: replay this route's API calls "
                        "(see related endpoints) without credentials and as a low-privilege user.")
            if cand is None:
                routes[path] = Candidate(
                    category="route", subject=path, analyzer=self.name, evidence=ev, attack_surface=tag,
                    suggested_test=test,
                    metadata={"file": pf.path, "line": rd.line, "guards": guards, "roles": roles,
                              "client_auth_flag": flag, "component": primary, "shape": rd.shape,
                              "unguarded": not (guards or roles or flag)})
            else:
                cand.evidence += ev

        # 4) Next.js file-convention routes
        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None or pf.origin != "disk":
                continue
            nr = self._next_route(pf.path)
            if nr is None:
                continue
            if "Next.js" not in ctx.framework_hints and "_next" not in pf.path.replace("\\", "/") \
                    and ".next" not in pf.path:
                continue
            path, kind = nr
            tag = classify(path)
            ev = [Evidence(ET.FRAMEWORK_CONTEXT,
                           f"file path follows the Next.js {'API route' if kind == 'api' else 'page'} convention -> {path}",
                           self.name, pf.path)]
            if tag:
                ev.append(Evidence(ET.NAMING_CONVENTION, f"route path matches '{tag}' naming convention", self.name))
            if is_test_path(pf.path):
                ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file lives in a test/mock location", self.name))
            route_id = f"route:{path}"
            fid = f"file:{pf.path}"
            g.add_node(route_id, NodeKind.ROUTE, path, file=pf.path, framework="Next.js", shape="file", route_kind=kind)
            g.add_node(fid, NodeKind.FILE, pf.path)
            g.add_edge(route_id, fid, EdgeKind.RENDERS, self.name, "FRAMEWORK_CONTEXT", pf.path)
            for site, epath in self._http_sites(ctx, pf):
                if ctx.ast.is_in_dead_branch(pf, site.node):
                    continue
                c = endpoint_cand(epath)
                c.evidence.append(Evidence(ET.FRAMEWORK_CONTEXT,
                                           f"issued from the Next.js {'handler' if kind == 'api' else 'page chunk'} for {path}",
                                           self.name, pf.path, site.line, site.args_raw[0][:100]))
                g.add_node(f"endpoint:{epath}", NodeKind.ENDPOINT, epath)
                g.add_edge(fid, f"endpoint:{epath}", EdgeKind.CALLS, self.name, "FRAMEWORK_CONTEXT", pf.path, site.line)
                endpoint_routes.setdefault(epath, set()).add(path)
            if path not in routes:
                routes[path] = Candidate(
                    category="route", subject=path, analyzer=self.name, evidence=ev, attack_surface=tag,
                    suggested_test=("Next.js API route: test auth/authorization on each HTTP method directly."
                                    if kind == "api" else None),
                    metadata={"file": pf.path, "shape": "file", "kind": kind, "guards": [], "roles": [],
                              "unguarded": True, "client_auth_flag": False})
            else:
                routes[path].evidence += ev

        # 5) finalize endpoint candidates (aggregate route list once, here)
        for path, c in endpoints.items():
            c.metadata["routes"] = sorted(endpoint_routes.get(path, []))
            c.related = [f"route:{r}" for r in c.metadata["routes"]]
        for path, c in routes.items():
            c.related = [e for e, rs in endpoint_routes.items() if path in rs]

        return list(routes.values()) + list(endpoints.values()) + list(authz.values())

    def _authz(self, store: dict, subject: str, pf: ParsedFile, line: int, desc: str, who: str) -> None:
        ev = Evidence(ET.AST_PATTERN_MATCH, desc, who, pf.path, line)
        if subject in store:
            store[subject].evidence.append(ev)
        else:
            store[subject] = Candidate(
                category="authorization", subject=subject, analyzer=who, evidence=[ev],
                attack_surface="authorization",
                suggested_test="Route guards run in the browser. Strip/alter the client check and call the protected API directly.")

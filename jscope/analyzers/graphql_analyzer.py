"""GraphQL Analyzer.

Extracts operations (queries, mutations, subscriptions), their variables and
root fields from three sources, strongest first:
  1. precompiled documents   {kind:"OperationDefinition", ...}     (Apollo/codegen bundles)
  2. gql`...` / graphql(`...`) tagged templates, and strings passed to client calls
  3. bare string literals that parse as an operation (weakest, LITERAL only)
plus client/endpoint configuration, introspection use and persisted queries.
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import PATH_RE, is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing import queries as Q

# header may contain ONLY: name, (variables), @directives -- arbitrary prose before '{' is rejected
_OP_RE = re.compile(r"^\s*(query|mutation|subscription)\b\s*([A-Za-z_]\w*)?\s*(\([^)]*\))?\s*(?:@\w+(?:\([^)]*\))?\s*)*\{", re.S)
_VAR_RE = re.compile(r"\$(\w+)\s*:\s*([\w!\[\]]+)")
_TOKEN_RE = re.compile(r"\{|\}|\([^)]*\)|\.\.\.\s*\w*|[A-Za-z_]\w*(?:\s*:\s*[A-Za-z_]\w*)?")
_CLIENT_CALLS = {"request", "query", "mutate", "usequery", "usemutation", "uselazyquery", "usesubscription",
                 "graphql", "gql", "execute", "subscribe"}
_CLIENT_CTORS = {"apolloclient", "httplink", "createhttplink", "graphqlclient", "createclient", "urqlclient"}
_ENDPOINT_KEYS = ("uri", "url", "endpoint", "httpurl")


def parse_operation(text: str) -> dict | None:
    text = re.sub(r"\$\{[^}]*\}", "", text)       # drop JS interpolations
    m = _OP_RE.match(text)
    if not m:
        return None
    op, name, vars_raw = m.group(1), m.group(2), m.group(3) or ""
    variables = dict(_VAR_RE.findall(vars_raw))
    depth, fields, i = 0, [], m.end() - 1
    for tok in _TOKEN_RE.findall(text[i:]):
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1 and not tok.startswith(("(", "...")):
            fields.append(tok.split(":")[-1].strip())
    if not fields:
        return None
    return {"operation": op, "name": name, "variables": variables, "root_fields": fields[:15]}


class GraphQLAnalyzer(Analyzer):
    name = "graphql_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["graphql", "endpoint"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        cands: dict[tuple[str, str], Candidate] = {}
        ctx.shared.setdefault("graphql_ops", {})        # presence == "graphql_analyzer ran"

        def add(cat: str, subject: str, ev: list[Evidence], surface: str | None, test: str | None, meta: dict):
            c = cands.get((cat, subject))
            if c is None:
                c = cands[(cat, subject)] = Candidate(category=cat, subject=subject, analyzer=self.name, evidence=[],
                                                      attack_surface=surface, suggested_test=test, metadata=dict(meta))
            c.evidence += ev
            if cat == "graphql" and meta.get("root_fields") is not None:
                # shared fact for api_correlation: which schema root fields the client actually uses
                dead = any(e.type == ET.DEAD_CODE for e in ev)
                if not dead:
                    first = next((e for e in ev if e.file), None)
                    ctx.shared.setdefault("graphql_ops", {})[subject] = {
                        "operation": meta.get("operation"), "root_fields": list(meta.get("root_fields", [])),
                        "site": (first.file, first.line) if first else (None, None)}

        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue
            bind = Q.bindings_for(ctx.ast, pf)
            ops_in_file = 0

            def base_ev(node, typ, desc):
                ev = [Evidence(typ, desc, self.name, pf.path, pf.line_of(node), pf.node_text(node)[:100].replace("\n", " "))]
                if ctx.ast.is_in_dead_branch(pf, node):
                    ev.append(Evidence(ET.DEAD_CODE, "sits in a statically dead branch", self.name))
                if is_test_path(pf.path):
                    ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock", self.name))
                return ev

            def emit(info: dict, ev: list[Evidence]):
                nonlocal ops_in_file
                ops_in_file += 1
                label = info["name"] or f"anonymous({','.join(info['root_fields'][:3])})"
                subject = f"{info['operation']}:{label}"
                id_vars = [v for v, t in info["variables"].items() if t.rstrip("!").startswith("ID") or re.search(r"id$", v, re.I)]
                if info["operation"] == "mutation":
                    test = ("Call this mutation as an unauthenticated and a low-privilege user; check field-level authorization, "
                            "mass assignment through the input type, and rate limits.")
                elif info["operation"] == "subscription":
                    test = "Subscribe as another tenant/user and check for cross-account event leakage."
                else:
                    test = "Run as another account and without auth; check object-level authorization on every root field."
                if id_vars:
                    test += f" Variable(s) {', '.join('$' + v for v in id_vars)} look like object IDs: swap in another account's IDs (BOLA/IDOR)."
                add("graphql", subject, ev, "graphql", test,
                    {**info, "id_like_variables": id_vars})

            for node in ctx.ast.walk(pf.tree.root_node):
                # 1) precompiled document objects
                if node.type == "object":
                    props = Q.object_props(pf, node)
                    if "kind" in props and pf.node_text(props["kind"]).strip("'\"") == "OperationDefinition" and "operation" in props:
                        op = pf.node_text(props["operation"]).strip("'\"")
                        nm = None
                        if "name" in props:
                            nm = pf.node_text(Q.object_props(pf, props["name"]).get("value") or props["name"]).strip("'\"")
                            nm = nm if re.fullmatch(r"\w+", nm or "") else None
                        fields = []
                        sel = Q.object_props(pf, props.get("selectionSet")).get("selections")
                        for item in Q.array_items(sel):
                            fp = Q.object_props(pf, item)
                            if "name" in fp:
                                v = Q.object_props(pf, fp["name"]).get("value")
                                if v is not None:
                                    fields.append(pf.node_text(v).strip("'\""))
                        vs = {}
                        for item in Q.array_items(props.get("variableDefinitions")):
                            vp = Q.object_props(pf, item)
                            try:
                                vname = pf.node_text(Q.object_props(pf, Q.object_props(pf, vp["variable"])["name"])["value"]).strip("'\"")
                                vs[vname] = "?"
                            except KeyError:
                                pass
                        if op in ("query", "mutation", "subscription") and (nm or fields):
                            emit({"operation": op, "name": nm, "variables": vs, "root_fields": fields[:15]},
                                 base_ev(node, ET.AST_PATTERN_MATCH, "precompiled GraphQL OperationDefinition document"))
                    continue
                # 2) gql`...`
                if node.type == "call_expression":
                    fn = node.child_by_field_name("function")
                    args = Q.call_args(node)
                    name = Q._callee_node_name(ctx.ast, pf, fn) if fn is not None else None
                    if name and Q.last_segment(name).lower() in ("gql", "graphql") and args and args[0].type == "template_string":
                        info = parse_operation(pf.node_text(args[0]).strip("`"))
                        if info:
                            emit(info, base_ev(node, ET.AST_PATTERN_MATCH, f"{name}`...` tagged template contains a {info['operation']}"))
                    # client configuration
                    if name and Q.last_segment(name).lower() in _CLIENT_CTORS and args and args[0].type == "object":
                        self._client_cfg(ctx, pf, node, args[0], add, base_ev)
                elif node.type == "new_expression":
                    ctor = node.child_by_field_name("constructor")
                    args = Q.call_args(node)
                    if ctor is not None and pf.node_text(ctor).split(".")[-1].lower() in _CLIENT_CTORS and args and args[0].type == "object":
                        self._client_cfg(ctx, pf, node, args[0], add, base_ev)
                # 3) bare strings
                elif node.type in ("string", "template_string"):
                    raw = pf.node_text(node).strip("'\"`")
                    if "__schema" in raw or "IntrospectionQuery" in raw:
                        add("graphql", "introspection_query", base_ev(node, ET.LITERAL_STRING_MATCH, "introspection query text present"),
                            "graphql", "Check whether introspection is enabled in production; if so dump the schema and diff against what the UI uses.", {})
                    if "persistedQuery" in raw or "sha256Hash" in raw:
                        add("graphql", "persisted_queries", base_ev(node, ET.LITERAL_STRING_MATCH, "persisted-query / sha256Hash reference"),
                            "graphql", "Test whether the server accepts arbitrary query text or unregistered hashes (allow-list bypass).", {})
                    info = parse_operation(raw)
                    if info and node.parent is not None and not (node.parent.type == "arguments" and node.parent.parent is not None
                                                                  and node.parent.parent.type == "call_expression"
                                                                  and Q.last_segment(Q._callee_node_name(ctx.ast, pf, node.parent.parent.child_by_field_name("function")) or "").lower() in ("gql", "graphql")):
                        ev = base_ev(node, ET.LITERAL_STRING_MATCH, "string literal parses as a GraphQL operation")
                        par, ctxual = node.parent, False
                        if par.type == "pair" and Q.key_name(pf, par.child_by_field_name("key")) in ("query", "mutation", "subscription", "document"):
                            ctxual = True
                        elif par.type == "arguments" and par.parent is not None and par.parent.type == "call_expression":
                            nm = Q._callee_node_name(ctx.ast, pf, par.parent.child_by_field_name("function")) or ""
                            ctxual = Q.last_segment(nm).lower() in _CLIENT_CALLS
                        if ctxual:
                            ev.append(Evidence(ET.AST_PATTERN_MATCH, "operation text is passed to a GraphQL client / sent as the `query` field", self.name, pf.path, pf.line_of(node)))
                        emit(info, ev)

            # GraphQL transport calls in a file that actually contains operations
            if ops_in_file:
                for site in ctx.ast.find_calls(pf):
                    if site.args_resolved and site.args_resolved[0].value and PATH_RE.match(site.args_resolved[0].value) \
                            and "graphql" in site.args_resolved[0].value.lower():
                        p = site.args_resolved[0].value
                        add("endpoint", p, [Evidence(ET.AST_PATTERN_MATCH,
                                                      f"{site.callee}() to a GraphQL endpoint in a file defining {ops_in_file} operation(s)",
                                                      self.name, pf.path, site.line, site.args_raw[0][:100])],
                            "graphql", "Send introspection and batched/aliased queries; test per-field authorization.", {})
        return list(cands.values())

    def _client_cfg(self, ctx, pf, node, obj, add, base_ev) -> None:
        props = Q.object_props(pf, obj)
        for key in props:
            if key.lower() in _ENDPOINT_KEYS:
                rv = ctx.ast.resolve_value(pf, props[key], Q.bindings_for(ctx.ast, pf))
                if rv.value and not rv.is_placeholder and PATH_RE.match(rv.value):
                    add("endpoint", rv.value, base_ev(node, ET.AST_PATTERN_MATCH, f"GraphQL client configured with {key}={rv.value}"),
                        "graphql", "Send introspection and batched/aliased queries; test per-field authorization.", {})

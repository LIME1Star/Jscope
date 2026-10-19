"""Authorization Analyzer: roles, permissions, feature flags, privilege
flags, and unguarded privileged routes.

Everything found here is a CLIENT-SIDE check. That is exactly why it is
interesting: client-side authorization is never enforcement, so each
observed check names an access-control rule the server must also implement
-- and a place to test whether it does.

False-positive controls (the point of the project):
  * `x.role === 'button'` (ARIA/DOM roles) is NOT reported; a role
    comparison only counts when the receiver looks like a user/session
    object or the value looks like an application role.
  * the unguarded-route finding is absence-based, so it is capped LOW by
    construction (it can never reach MEDIUM on its own).
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind
from jscope.parsing import queries as Q

_USERISH = re.compile(r"(user|session|auth|profile|account|member|me|identity|principal|claims|token)", re.I)
_ARIA = {"button", "tab", "tablist", "tabpanel", "dialog", "alert", "alertdialog", "menu", "menuitem", "listbox",
         "option", "presentation", "none", "img", "link", "checkbox", "radio", "textbox", "navigation", "banner",
         "main", "region", "form", "search", "tooltip", "status", "progressbar", "switch", "grid", "row", "cell",
         "list", "listitem", "heading", "article", "group", "separator", "complementary", "contentinfo"}
_APP_ROLES = {"admin", "administrator", "superadmin", "super_admin", "owner", "moderator", "editor", "manager",
              "staff", "root", "superuser", "user", "viewer", "member", "guest", "support", "billing", "operator"}
_ROLE_PROPS = {"role", "roles", "userrole", "usertype", "accounttype", "rolename", "role_name", "user_role",
               "permissionlevel", "accesslevel", "access_level", "userlevel", "level"}
_CHECK_FUNCS = {"hasrole", "hasanyrole", "hasallroles", "haspermission", "haspermissions", "hasanypermission",
                "can", "cannot", "checkpermission", "isallowed", "hasscope", "hasaccess", "isauthorized",
                "usepermission", "usecan", "requirerole", "requirepermission", "withrole", "withpermission",
                "authorize", "ability"}
_FLAG_FUNCS = {"usefeatureflag", "isfeatureenabled", "isenabled", "variation", "boolvariation", "getfeatureflag",
               "useflag", "featureflag", "isfeatureon", "usegate", "checkgate", "getbooleanvalue", "isfeatureactive"}
_LIST_RECEIVERS = {"roles", "permissions", "scopes", "authorities", "groups", "claims", "entitlements"}
_FLAG_OBJECTS = {"flags", "featureflags", "features", "featuretoggles", "toggles", "experiments"}
_PRIV_PROPS = {"isadmin": "admin", "is_admin": "admin", "issuperadmin": "superadmin", "is_super_admin": "superadmin",
               "isstaff": "staff", "is_staff": "staff", "issuperuser": "superuser", "is_superuser": "superuser",
               "ismoderator": "moderator"}

_TEST_CLIENT = ("Client-side check only: it proves the UI hides this, not that the server refuses it. "
                "Replay the underlying API calls with a lower-privilege (or no) token.")


class AuthorizationAnalyzer(Analyzer):
    name = "authorization_analyzer"
    depends_on = ["router_analyzer"]
    produces_categories = ["authorization"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        cands: dict[str, Candidate] = {}

        def add(subject: str, ev: list[Evidence], test: str | None = _TEST_CLIENT, meta: dict | None = None):
            c = cands.get(subject)
            if c is None:
                c = cands[subject] = Candidate(category="authorization", subject=subject, analyzer=self.name,
                                               evidence=[], attack_surface="authorization",
                                               suggested_test=test, metadata=dict(meta or {}))
            c.evidence += ev

        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue
            bind = Q.bindings_for(ctx.ast, pf)

            def evid(node, desc: str, via_symbol: bool = False) -> list[Evidence]:
                ev = [Evidence(ET.AST_PATTERN_MATCH, desc, self.name, pf.path, pf.line_of(node),
                               pf.node_text(node)[:100].replace("\n", " "))]
                if via_symbol:
                    ev.append(Evidence(ET.SYMBOL_RESOLVED, "value resolved through a constant", self.name))
                if ctx.ast.is_in_dead_branch(pf, node):
                    ev.append(Evidence(ET.DEAD_CODE, "check sits in a statically dead branch", self.name))
                if is_test_path(pf.path):
                    ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock", self.name))
                return ev

            def graph_role(node, subject_role: str):
                owner = Q.enclosing_function_name(pf, node)
                rid = f"role:{subject_role}"
                ctx.graph.add_node(rid, NodeKind.ROLE, subject_role)
                fid = f"file:{pf.path}"
                ctx.graph.add_node(fid, NodeKind.FILE, pf.path)
                if owner:
                    cid = f"component:{pf.path}:{owner}"
                    ctx.graph.add_node(cid, NodeKind.COMPONENT, owner, file=pf.path)
                    ctx.graph.add_edge(fid, cid, EdgeKind.CONTAINS, self.name, "AST_PATTERN_MATCH", pf.path)
                    ctx.graph.add_edge(cid, rid, EdgeKind.CHECKS_ROLE, self.name, "AST_PATTERN_MATCH", pf.path, pf.line_of(node))
                else:
                    ctx.graph.add_edge(fid, rid, EdgeKind.CHECKS_ROLE, self.name, "AST_PATTERN_MATCH", pf.path, pf.line_of(node))

            for node in ctx.ast.walk(pf.tree.root_node):
                t = node.type
                # 1) user.role === 'admin'
                if t == "binary_expression":
                    op = node.child_by_field_name("operator")
                    if op is None or pf.node_text(op) not in ("===", "==", "!==", "!="):
                        continue
                    for side, other in (("left", "right"), ("right", "left")):
                        sn, on = node.child_by_field_name(side), node.child_by_field_name(other)
                        if sn is None or on is None or sn.type != "member_expression":
                            continue
                        prop = sn.child_by_field_name("property")
                        pname = pf.node_text(prop).lower() if prop is not None else ""
                        if pname not in _ROLE_PROPS:
                            continue
                        rv = ctx.ast.resolve_value(pf, on, bind)
                        if rv.value is None or rv.is_placeholder:
                            continue
                        val = rv.value.strip()
                        recv = pf.node_text(sn.child_by_field_name("object")) if sn.child_by_field_name("object") else ""
                        looks_user = bool(_USERISH.search(recv))
                        if val.lower() in _ARIA and not looks_user:
                            continue                        # DOM/ARIA role, not an app role
                        if not (looks_user or val.lower() in _APP_ROLES):
                            continue
                        add(f"role:{val}", evid(node, f"{recv}.{pf.node_text(prop)} compared to '{val}'", rv.resolved_via_symbol))
                        graph_role(node, val)
                # 2) hasRole('x') / can('edit','Post') / useFeatureFlag('x')
                elif t == "call_expression":
                    fn = node.child_by_field_name("function")
                    if fn is None:
                        continue
                    name = Q._callee_node_name(ctx.ast, pf, fn) or ""
                    leaf = Q.last_segment(name).lower()
                    args = Q.call_args(node)
                    rvs = [ctx.ast.resolve_value(pf, a, bind) for a in args[:2]]
                    if leaf in _CHECK_FUNCS and rvs and rvs[0].value and not rvs[0].is_placeholder:
                        val = rvs[0].value
                        if len(rvs) > 1 and rvs[1].value and leaf in ("can", "cannot", "ability"):
                            val = f"{val}:{rvs[1].value}"
                        kind = "role" if "role" in leaf else "permission"
                        add(f"{kind}:{val}", evid(node, f"{name}('{val}') authorization check", rvs[0].resolved_via_symbol))
                        graph_role(node, f"{val}") if kind == "role" else None
                    elif leaf in _FLAG_FUNCS and rvs and rvs[0].value and not rvs[0].is_placeholder:
                        add(f"feature_flag:{rvs[0].value}",
                            evid(node, f"{name}('{rvs[0].value}') feature-flag check", rvs[0].resolved_via_symbol),
                            test="Feature flags gate UI, often not the API. Call the flagged feature's endpoints directly "
                                 "while the flag is off for your account.")
                    elif leaf == "includes" and fn.type == "member_expression" and rvs and rvs[0].value:
                        recv_node = fn.child_by_field_name("object")
                        recv = pf.node_text(recv_node) if recv_node is not None else ""
                        rleaf = recv.split(".")[-1].lower()
                        if rleaf in _LIST_RECEIVERS:
                            kind = "role" if rleaf in ("roles", "groups") else "permission"
                            add(f"{kind}:{rvs[0].value}", evid(node, f"{recv}.includes('{rvs[0].value}')"))
                            if kind == "role":
                                graph_role(node, rvs[0].value)
                # 3) user.isAdmin / flags.newBilling
                elif t == "member_expression":
                    prop = node.child_by_field_name("property")
                    obj = node.child_by_field_name("object")
                    if prop is None or obj is None:
                        continue
                    pname = pf.node_text(prop)
                    if pname.lower() in _PRIV_PROPS and not (node.parent is not None and node.parent.type == "assignment_expression"
                                                              and node.parent.child_by_field_name("left") == node):
                        role = _PRIV_PROPS[pname.lower()]
                        add(f"role:{role}", evid(node, f"reads privilege flag {pf.node_text(node)}"),
                            test=_TEST_CLIENT + " Also test whether the server accepts a client-supplied "
                                 f"'{pname}' (mass assignment) or trusts a tampered token/response claim.")
                        graph_role(node, role)
                    elif pf.node_text(obj).split(".")[-1].lower() in _FLAG_OBJECTS and prop.type == "property_identifier":
                        add(f"feature_flag:{pname}", evid(node, f"reads feature flag {pf.node_text(node)}"),
                            test="Feature flags gate UI, often not the API. Call the flagged feature's endpoints directly.")

        # 4) privileged routes with no guard found (absence-based => LOW by construction)
        for r in ctx.graph.by_kind(NodeKind.ROUTE):
            prot = ctx.graph.route_protection(r.id)
            if not prot["unguarded"] or r.attrs.get("route_kind") == "api":
                continue
            from jscope.analyzers.common import classify
            tag = classify(r.label)
            if tag not in ("admin", "internal", "debug"):
                continue
            cands[f"unguarded_route:{r.label}"] = Candidate(
                category="authorization", subject=f"unguarded_route:{r.label}", analyzer=self.name,
                evidence=[
                    Evidence(ET.NAMING_CONVENTION, f"route path matches '{tag}' naming convention", self.name,
                             r.attrs.get("file"), r.attrs.get("line")),
                    Evidence(ET.AST_PATTERN_MATCH,
                             "route definition found with no guard wrapper, guard prop, meta flag or role declaration "
                             "(absence-based: a guard could live in a layout, the component, or the server)",
                             self.name, r.attrs.get("file"), r.attrs.get("line")),
                ],
                attack_surface="authorization",
                suggested_test="No client-side guard seen around a privileged route. Load it unauthenticated, "
                               "and replay its API calls as a low-privilege user.",
                metadata={"absence_based": True, "route": r.label})
        return list(cands.values())

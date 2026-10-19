"""Storage Analyzer: localStorage / sessionStorage / IndexedDB / cookies.

Findings are per (store, key), aggregated across read/write sites. Keys
that look credential-bearing in script-readable storage are flagged as
token-storage attack surface (any XSS can exfiltrate them) -- that is a
risk *observation*, not a vulnerability claim, and is scored accordingly.
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import SENSITIVE_KEY_RE, is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind
from jscope.parsing import queries as Q
from jscope.parsing.ast_engine import ParsedFile

_STORES = {"localStorage", "sessionStorage"}
_OPS = {"setItem": "write", "getItem": "read", "removeItem": "delete"}
_COOKIE_NAME_RE = re.compile(r"^\s*([^=;\s]+)\s*=")


class StorageAnalyzer(Analyzer):
    name = "storage_analyzer"
    depends_on: list[str] = []
    produces_categories = ["storage"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        cands: dict[str, Candidate] = {}
        ops: dict[str, set[str]] = {}

        def add(subject: str, ev: list[Evidence], op: str, surface: str | None, test: str | None, meta: dict):
            c = cands.get(subject)
            if c is None:
                c = cands[subject] = Candidate(category="storage", subject=subject, analyzer=self.name,
                                               evidence=[], attack_surface=surface, suggested_test=test,
                                               metadata=dict(meta))
            c.evidence += ev
            ops.setdefault(subject, set()).add(op)

        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue
            g = ctx.graph
            for site in Q.iter_calls(ctx.ast, pf):
                parts = site.callee.split(".")
                kind = key = store = None
                if len(parts) >= 2 and parts[-1] in _OPS and parts[-2] in _STORES:
                    store, kind = parts[-2], _OPS[parts[-1]]
                    key = site.args_resolved[0] if site.args_resolved else None
                elif site.callee.endswith("indexedDB.open"):
                    store, kind = "indexedDB", "open"
                    key = site.args_resolved[0] if site.args_resolved else None
                elif parts[0] in ("Cookies", "cookies", "Cookie") and parts[-1] in ("set", "get", "remove"):
                    store, kind = "cookie", {"set": "write", "get": "read", "remove": "delete"}[parts[-1]]
                    key = site.args_resolved[0] if site.args_resolved else None
                if store is None or key is None or key.value is None or key.is_placeholder:
                    continue
                self._record(ctx, pf, site.node, site.line, store, key.value, kind, key, add, g)

            # document.cookie = "name=value; Secure; SameSite=Lax"
            for node in ctx.ast.walk(pf.tree.root_node):
                if node.type != "assignment_expression":
                    continue
                left = node.child_by_field_name("left")
                if left is None or pf.node_text(left).replace("window.", "") != "document.cookie":
                    continue
                rv = ctx.ast.resolve_value(pf, node.child_by_field_name("right"), Q.bindings_for(ctx.ast, pf))
                if rv.value is None:
                    continue
                m = _COOKIE_NAME_RE.match(rv.value)
                if m:
                    self._record(ctx, pf, node, pf.line_of(node), "cookie", m.group(1), "write", rv, add,
                                 g, cookie_attrs=rv.value.lower())

        out = []
        for subject, c in cands.items():
            c.metadata["operations"] = sorted(ops[subject])
            out.append(c)
        return out

    def _record(self, ctx, pf: ParsedFile, node, line: int, store: str, key: str, op: str, rv, add, g,
                cookie_attrs: str | None = None) -> None:
        subject = f"{store}:{key}"
        ev = [Evidence(ET.AST_PATTERN_MATCH, f"{store} {op} with key '{key}'", self.name, pf.path, line,
                       pf.node_text(node)[:100].replace("\n", " "))]
        if rv.resolved_via_symbol:
            ev.append(Evidence(ET.SYMBOL_RESOLVED, "storage key resolved through a constant", self.name))
        sensitive = bool(SENSITIVE_KEY_RE.search(key))
        if sensitive:
            ev.append(Evidence(ET.NAMING_CONVENTION, f"key '{key}' looks credential-bearing", self.name))
        if ctx.ast.is_in_dead_branch(pf, node):
            ev.append(Evidence(ET.DEAD_CODE, "access sits in a statically dead branch", self.name))
        if is_test_path(pf.path):
            ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock", self.name))

        surface = test = None
        meta = {"store": store, "key": key, "sensitive": sensitive}
        if sensitive and store in _STORES:
            surface = "token_storage"
            test = ("Script-readable storage: any XSS (or malicious third-party script) can read this. "
                    "Look for XSS sinks, and check whether the token is long-lived and unscoped.")
        elif store == "cookie" and cookie_attrs is not None:
            missing = [f for f in ("secure", "samesite") if f not in cookie_attrs]
            meta["missing_flags"] = missing
            meta["note"] = "document.cookie cannot set HttpOnly, so this cookie is script-readable by construction"
            if sensitive:
                surface = "cookie_handling"
                test = "Cookie is set from JS (so never HttpOnly). Check scope/expiry and whether the server trusts it for auth."
        add(subject, ev, op, surface, test, meta)

        owner = Q.enclosing_function_name(pf, node)
        sid = f"storage:{subject}"
        g.add_node(sid, NodeKind.STORAGE, subject, sensitive=sensitive)
        if owner:
            cid = f"component:{pf.path}:{owner}"
            g.add_node(cid, NodeKind.COMPONENT, owner, file=pf.path)
            g.add_node(f"file:{pf.path}", NodeKind.FILE, pf.path)
            g.add_edge(f"file:{pf.path}", cid, EdgeKind.CONTAINS, self.name, "AST_PATTERN_MATCH", pf.path)
            g.add_edge(cid, sid, EdgeKind.USES_STORAGE, self.name, "AST_PATTERN_MATCH", pf.path, line)
        else:
            g.add_node(f"file:{pf.path}", NodeKind.FILE, pf.path)
            g.add_edge(f"file:{pf.path}", sid, EdgeKind.USES_STORAGE, self.name, "AST_PATTERN_MATCH", pf.path, line)

"""Higher-level AST queries shared by the Phase 2 analyzers.

Sits on top of ASTEngine so analyzers never touch raw tree-sitter grammar
quirks. Results are memoized per ParsedFile (`pf.memo`) because several
analyzers ask the same questions of the same file.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any

from jscope.parsing.ast_engine import ASTEngine, CallSite, ParsedFile, ResolvedValue

_PUNCT = {"(", ")", ",", "[", "]", "{", "}"}
_FUNC_TYPES = {"function_declaration", "function_expression", "function", "arrow_function",
               "generator_function_declaration", "method_definition"}


def norm_path(p: str) -> str:
    return posixpath.normpath(p.replace("\\", "/"))


def bindings_for(engine: ASTEngine, pf: ParsedFile) -> dict[str, Any]:
    if "bindings" not in pf.memo:
        pf.memo["bindings"] = engine._local_bindings(pf, pf.tree.root_node) if pf.tree else {}
    return pf.memo["bindings"]


def _callee_node_name(engine: ASTEngine, pf: ParsedFile, fn) -> str | None:
    # minified JSX runtime calls look like (0,r.jsx)(...): unwrap to the last member
    if fn.type == "parenthesized_expression":
        inner = [c for c in fn.children if c.type not in ("(", ")")]
        if inner and inner[0].type == "sequence_expression":
            inner = [c for c in inner[0].children if c.type != ","]
        return _callee_node_name(engine, pf, inner[-1]) if inner else None
    return engine._callee_dotted_name(pf, fn)


def iter_calls(engine: ASTEngine, pf: ParsedFile) -> list[CallSite]:
    """EVERY call_expression and new_expression, with dotted callee when resolvable."""
    if "calls" in pf.memo:
        return pf.memo["calls"]
    sites: list[CallSite] = []
    if pf.tree is not None:
        bindings = bindings_for(engine, pf)
        for node in engine.walk(pf.tree.root_node):
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
            elif node.type == "new_expression":
                fn = node.child_by_field_name("constructor")
            else:
                continue
            if fn is None:
                continue
            name = _callee_node_name(engine, pf, fn)
            if name is None:
                continue
            args = call_args(node)
            sites.append(CallSite(
                callee=name, args_raw=[pf.node_text(a) for a in args],
                args_resolved=[engine.resolve_value(pf, a, bindings) for a in args],
                line=pf.line_of(node), node=node))
    pf.memo["calls"] = sites
    return sites


def call_args(call_node) -> list[Any]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    if args.type == "template_string":      # gql`...` tagged template
        return [args]
    return [c for c in args.children if c.type not in _PUNCT]


def last_segment(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def key_name(pf: ParsedFile, key_node) -> str | None:
    if key_node is None:
        return None
    if key_node.type in ("property_identifier", "identifier", "shorthand_property_identifier"):
        return pf.node_text(key_node)
    if key_node.type == "string":
        return pf.node_text(key_node).strip("'\"")
    return None


def object_props(pf: ParsedFile, obj) -> dict[str, Any]:
    """name -> value node for a JS object literal (pairs and shorthand)."""
    out: dict[str, Any] = {}
    if obj is None or obj.type != "object":
        return out
    for ch in obj.children:
        if ch.type == "pair":
            k = key_name(pf, ch.child_by_field_name("key"))
            v = ch.child_by_field_name("value")
            if k is not None and v is not None:
                out[k] = v
        elif ch.type == "shorthand_property_identifier":
            out[pf.node_text(ch)] = ch
    return out


def array_items(node) -> list[Any]:
    if node is None or node.type != "array":
        return []
    return [c for c in node.children if c.type not in _PUNCT]


def string_list(engine: ASTEngine, pf: ParsedFile, node) -> list[str]:
    """['a','b'] or 'a' -> list of resolved strings (unresolvable items skipped)."""
    if node is None:
        return []
    b = bindings_for(engine, pf)
    items = array_items(node) if node.type == "array" else [node]
    out = []
    for it in items:
        rv = engine.resolve_value(pf, it, b)
        if rv.value is not None and not rv.is_placeholder:
            out.append(rv.value)
    return out


def enclosing_function_name(pf: ParsedFile, node) -> str | None:
    cur = node.parent
    while cur is not None:
        if cur.type in ("function_declaration", "class_declaration", "generator_function_declaration"):
            n = cur.child_by_field_name("name")
            if n is not None:
                return pf.node_text(n)
        if cur.type in ("arrow_function", "function_expression", "function"):
            par = cur.parent
            # unwrap HOCs like memo(forwardRef(() => ...))
            while par is not None and par.type in ("arguments", "call_expression", "parenthesized_expression"):
                par = par.parent
            if par is not None and par.type == "variable_declarator":
                n = par.child_by_field_name("name")
                if n is not None and n.type == "identifier":
                    return pf.node_text(n)
        cur = cur.parent
    return None


def function_index(engine: ASTEngine, pf: ParsedFile) -> dict[str, Any]:
    """name -> node whose byte range contains the function/component body."""
    if "funcs" in pf.memo:
        return pf.memo["funcs"]
    idx: dict[str, Any] = {}
    if pf.tree is not None:
        for node in engine.walk(pf.tree.root_node):
            if node.type in ("function_declaration", "class_declaration", "generator_function_declaration"):
                n = node.child_by_field_name("name")
                if n is not None:
                    idx[pf.node_text(n)] = node
            elif node.type == "variable_declarator":
                n = node.child_by_field_name("name")
                v = node.child_by_field_name("value")
                if n is None or v is None or n.type != "identifier":
                    continue
                if v.type in _FUNC_TYPES or (v.type == "call_expression" and any(
                        d.type in _FUNC_TYPES for d in engine.walk(v))):
                    idx[pf.node_text(n)] = v
    pf.memo["funcs"] = idx
    return idx


@dataclass
class ImportRef:
    source: str
    kind: str            # "import" | "require" | "lazy_import"
    imported: str | None = None
    line: int = 0


def _str_of(pf: ParsedFile, node) -> str | None:
    return pf.node_text(node).strip("'\"`") if node is not None and node.type == "string" else None


def _dynamic_import_source(pf: ParsedFile, node) -> str | None:
    for d in _walk(node):
        if d.type == "call_expression":
            fn = d.child_by_field_name("function")
            if fn is not None and fn.type == "import":
                a = call_args(d)
                return _str_of(pf, a[0]) if a else None
    return None


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def imports(engine: ASTEngine, pf: ParsedFile) -> tuple[dict[str, ImportRef], list[ImportRef]]:
    """(local_name -> ImportRef, every module edge incl. side-effect/dynamic imports)."""
    if "imports" in pf.memo:
        return pf.memo["imports"]
    by_name: dict[str, ImportRef] = {}
    edges: list[ImportRef] = []
    if pf.tree is not None:
        for node in engine.walk(pf.tree.root_node):
            if node.type == "import_statement":
                src = next((_str_of(pf, c) for c in node.children if c.type == "string"), None)
                if src is None:
                    continue
                edges.append(ImportRef(src, "import", None, pf.line_of(node)))
                clause = next((c for c in node.children if c.type == "import_clause"), None)
                if clause is None:
                    continue
                for c in clause.children:
                    if c.type == "identifier":
                        by_name[pf.node_text(c)] = ImportRef(src, "import", "default", pf.line_of(node))
                    elif c.type == "named_imports":
                        for spec in c.children:
                            if spec.type == "import_specifier":
                                ids = [x for x in spec.children if x.type == "identifier"]
                                if ids:
                                    local = pf.node_text(ids[-1])
                                    by_name[local] = ImportRef(src, "import", pf.node_text(ids[0]), pf.line_of(node))
                    elif c.type == "namespace_import":
                        ids = [x for x in c.children if x.type == "identifier"]
                        if ids:
                            by_name[pf.node_text(ids[-1])] = ImportRef(src, "import", "*", pf.line_of(node))
            elif node.type == "variable_declarator":
                n = node.child_by_field_name("name")
                v = node.child_by_field_name("value")
                if n is None or v is None or n.type != "identifier":
                    continue
                if v.type == "call_expression":
                    fn = v.child_by_field_name("function")
                    if fn is not None and fn.type == "identifier" and pf.node_text(fn) == "require":
                        a = call_args(v)
                        src = _str_of(pf, a[0]) if a else None
                        if src:
                            by_name[pf.node_text(n)] = ImportRef(src, "require", None, pf.line_of(node))
                            edges.append(ImportRef(src, "require", None, pf.line_of(node)))
                            continue
                    src = _dynamic_import_source(pf, v)     # lazy(() => import('./X')), dynamic(...), loadable(...)
                    if src:
                        by_name[pf.node_text(n)] = ImportRef(src, "lazy_import", None, pf.line_of(node))
            elif node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "import":
                    a = call_args(node)
                    src = _str_of(pf, a[0]) if a else None
                    if src:
                        edges.append(ImportRef(src, "dynamic_import", None, pf.line_of(node)))
    pf.memo["imports"] = (by_name, edges)
    return pf.memo["imports"]


class FileIndex:
    """Resolve relative module specifiers to project files. Alias paths
    ('@/x', bare package names) are intentionally NOT resolved -- Phase 2
    does not read tsconfig/webpack alias config."""

    def __init__(self, files: list[ParsedFile]):
        self.by_path = {norm_path(f.path): f for f in files if not f.skipped_reason}

    def resolve(self, from_path: str, source: str) -> ParsedFile | None:
        if not source.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(norm_path(from_path)), source))
        for cand in (base, base + ".js", base + ".jsx", base + ".mjs", base + ".cjs",
                     base + "/index.js", base + "/index.jsx"):
            if cand in self.by_path:
                return self.by_path[cand]
        return None

    def by_basename(self, name: str) -> ParsedFile | None:
        name = name.split("?")[0].lstrip("/")
        for p, f in self.by_path.items():
            if p == name or p.endswith("/" + name):
                return f
        return None


def calls_within(sites: list[CallSite], container) -> list[CallSite]:
    return [s for s in sites if container.start_byte <= s.node.start_byte and s.node.end_byte <= container.end_byte]


# ---- JSX / element helpers -------------------------------------------------

@dataclass
class ElementUse:
    name: str
    props: dict[str, str]     # prop name -> raw value text (quotes/braces stripped)


def _jsx_name(pf: ParsedFile, el) -> str | None:
    for c in el.children:
        if c.type in ("identifier", "member_expression", "nested_identifier", "jsx_namespace_name"):
            return pf.node_text(c)
    return None


def jsx_attrs(pf: ParsedFile, el) -> dict[str, tuple[str, Any]]:
    """attr name -> (raw text, value node)."""
    out = {}
    for c in el.children:
        if c.type != "jsx_attribute":
            continue
        kids = [k for k in c.children if k.type != "="]
        if not kids:
            continue
        name = pf.node_text(kids[0])
        val = kids[1] if len(kids) > 1 else None
        if val is not None and val.type == "jsx_expression":
            inner = [k for k in val.children if k.type not in ("{", "}")]
            val = inner[0] if inner else None
        raw = pf.node_text(val).strip("'\"") if val is not None else "true"
        out[name] = (raw, val)
    return out


def element_chain(engine: ASTEngine, pf: ParsedFile, node, _depth: int = 0) -> list[ElementUse]:
    """Component names from outermost wrapper to innermost for an element
    expression: <Guard role="x"><Page/></Guard>, jsx(Guard,{children:jsx(Page,{})}),
    createElement(Guard, props, createElement(Page))."""
    if node is None or _depth > 6:
        return []
    t = node.type
    if t == "jsx_expression":
        inner = [k for k in node.children if k.type not in ("{", "}")]
        return element_chain(engine, pf, inner[0], _depth + 1) if inner else []
    if t == "jsx_self_closing_element":
        n = _jsx_name(pf, node)
        return [ElementUse(n, {k: v[0] for k, v in jsx_attrs(pf, node).items()})] if n else []
    if t == "jsx_element":
        opening = next((c for c in node.children if c.type == "jsx_opening_element"), None)
        if opening is None:
            return []
        n = _jsx_name(pf, opening)
        if not n:
            return []
        me = [ElementUse(n, {k: v[0] for k, v in jsx_attrs(pf, opening).items()})]
        for c in node.children:
            if c.type in ("jsx_element", "jsx_self_closing_element", "jsx_expression"):
                sub = element_chain(engine, pf, c, _depth + 1)
                if sub:
                    return me + sub
        return me
    if t == "call_expression":
        fn = node.child_by_field_name("function")
        name = _callee_node_name(engine, pf, fn) if fn is not None else None
        if name and last_segment(name) in ("jsx", "jsxs", "jsxDEV", "createElement", "h"):
            args = call_args(node)
            if not args:
                return []
            first = pf.node_text(args[0]).strip("'\"")
            if args[0].type not in ("identifier", "member_expression"):
                return []
            props_node = args[1] if len(args) > 1 and args[1].type == "object" else None
            props = {k: pf.node_text(v).strip("'\"") for k, v in object_props(pf, props_node).items()}
            me = [ElementUse(first, props)]
            child = object_props(pf, props_node).get("children") if props_node else None
            if child is None and len(args) > 2:
                child = args[2]
            if child is not None:
                if child.type == "array":
                    for it in array_items(child):
                        sub = element_chain(engine, pf, it, _depth + 1)
                        if sub:
                            return me + sub
                else:
                    sub = element_chain(engine, pf, child, _depth + 1)
                    if sub:
                        return me + sub
            return me
    if t == "identifier":   # component: Admin  /  Component: Admin
        return [ElementUse(pf.node_text(node), {})]
    if t in ("arrow_function", "function_expression"):   # () => import('./x') or () => <X/>
        body = node.child_by_field_name("body")
        return element_chain(engine, pf, body, _depth + 1) if body is not None else []
    return []


def quoted_strings(raw: str) -> list[str]:
    return re.findall(r"['\"]([^'\"]+)['\"]", raw)

"""Interprocedural, inter-file taint engine (FR-01).

Design in one paragraph: every file is *executed abstractly* once (module scope), then every top-level function and every
closure created along the way is executed with clean parameters so sources found inside them are seen. Whenever execution
reaches a call whose callee resolves to project code (local function, import/require, dynamic import, callback passed
along) the callee is executed with the actual argument values -- context-sensitively, memoised by (function, argument
taint identities), with depth and recursion limits. Values carry taint (source + the steps taken), applied mitigations and
explicit *assumptions* (e.g. "passed through unresolved call foo()"). Nothing unresolved is silently guessed: it either
becomes an assumption on the flow or a recorded limitation.

A flow is only ever a *potential* flow. The engine never claims exploitability; verification (jscope.verify) does that.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from jscope.dataflow import rules as R
from jscope.dataflow.modules import ModuleResolver
from jscope.dataflow.rules import Mitigation
from jscope.parsing.ast_engine import ParsedFile

MAX_DEPTH = 14
MAX_STEPS_PER_FILE = 400_000
MAX_PATH_STEPS = 40
_FN_TYPES = {"function_declaration", "function_expression", "function", "arrow_function", "generator_function",
             "generator_function_declaration", "method_definition"}
_WRAPPERS = {"parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression",
             "type_assertion", "instantiation_expression", "await_expression", "yield_expression"}
_TERMINATORS = {"return_statement", "throw_statement", "break_statement", "continue_statement"}


# ======================================================================================== model
@dataclass(frozen=True)
class Taint:
    kind: str
    file: str
    line: int
    snippet: str
    steps: tuple = ()                  # ((file, line, text), ...)
    mitigations: tuple = ()            # tuple[Mitigation]
    assumptions: tuple = ()            # tuple[str]

    @property
    def ident(self) -> tuple:
        return (self.kind, self.file, self.line, tuple(m.name for m in self.mitigations), self.assumptions)

    def step(self, file: str, line: int, text: str) -> "Taint":
        if self.steps and self.steps[-1][2] == text and self.steps[-1][0] == file and self.steps[-1][1] == line:
            return self
        if len(self.steps) >= MAX_PATH_STEPS:
            return self
        return Taint(self.kind, self.file, self.line, self.snippet, self.steps + ((file, line, text),),
                     self.mitigations, self.assumptions)

    def mitigate(self, m: Mitigation) -> "Taint":
        if any(x.name == m.name for x in self.mitigations):
            return self
        return Taint(self.kind, self.file, self.line, self.snippet, self.steps, self.mitigations + (m,), self.assumptions)

    def assume(self, text: str) -> "Taint":
        if text in self.assumptions:
            return self
        return Taint(self.kind, self.file, self.line, self.snippet, self.steps, self.mitigations,
                     self.assumptions + (text,))


class Val:
    """Abstract value: taint set plus optional structure (object fields, callable, module namespace, external ref)."""
    __slots__ = ("t", "props", "fn", "ns", "ext", "imp", "lits", "pyfn")

    def __init__(self, t=frozenset(), props=None, fn=None, ns=None, ext=None, imp=None, lits=None, pyfn=None):
        self.t: frozenset = t if isinstance(t, frozenset) else frozenset(t)
        self.props: dict[str, Val] | None = props
        self.fn: FnVal | None = fn
        self.ns: str | None = ns
        self.ext: tuple | None = ext
        self.imp: tuple | None = imp
        self.lits: tuple | None = lits                 # literal string array contents (allow-list detection)
        self.pyfn: Callable | None = pyfn

    @property
    def tainted(self) -> bool:
        return bool(self.t)

    def all_taints(self) -> frozenset:
        out = set(self.t)
        for v in (self.props or {}).values():
            out |= v.all_taints()
        return frozenset(out)

    def map_taints(self, f: Callable[[Taint], Taint]) -> "Val":
        return Val(frozenset(f(x) for x in self.t),
                   {k: v.map_taints(f) for k, v in self.props.items()} if self.props is not None else None,
                   self.fn, self.ns, self.ext, self.imp, self.lits, self.pyfn)


CLEAN = Val()


def join(a: Val | None, b: Val | None) -> Val:
    if a is None:
        return b if b is not None else CLEAN
    if b is None or a is b:
        return a
    props = None
    if a.props is not None or b.props is not None:
        props = {}
        for k in set(a.props or {}) | set(b.props or {}):
            props[k] = join((a.props or {}).get(k), (b.props or {}).get(k))
    return Val(a.t | b.t, props, a.fn or b.fn, a.ns or b.ns, a.ext or b.ext, a.imp or b.imp,
               a.lits if a.lits == b.lits else None, a.pyfn or b.pyfn)


def union_vals(vals: list[Val]) -> Val:
    t: set = set()
    for v in vals:
        t |= v.all_taints()
    return Val(frozenset(t)) if t else CLEAN


@dataclass
class FnVal:
    node: Any
    file: str
    scope: "Scope"
    name: str = "<anonymous>"
    key: tuple = ()


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent: "Scope | None" = None):
        self.vars: dict[str, Val] = {}
        self.parent = parent

    def lookup(self, name: str) -> Val | None:
        s: Scope | None = self
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def declare(self, name: str, v: Val) -> None:
        self.vars[name] = v

    def assign(self, name: str, v: Val, weak: bool) -> None:
        s: Scope | None = self
        while s is not None:
            if name in s.vars:
                s.vars[name] = join(s.vars[name], v) if weak else v
                return
            s = s.parent
        self.vars[name] = v


@dataclass
class Frame:
    file: str
    fname: str = "<module>"
    returns: list = field(default_factory=list)
    dead: bool = False
    cond: int = 0
    depth: int = 0


@dataclass
class Flow:
    source_kind: str
    source_file: str
    source_line: int
    source_snippet: str
    sink_class: str
    sink_name: str
    sink_file: str
    sink_line: int
    sink_snippet: str
    steps: tuple
    status: str                      # candidate | uncertain | sanitized | unreachable
    mitigations: tuple = ()
    assumptions: tuple = ()
    files: tuple = ()                # every file the path touches (source, steps, sink)
    root: str = ""                   # file whose root analysis discovered this flow (incremental cache attribution)

    @property
    def key(self) -> tuple:
        return (self.source_kind, self.source_file, self.source_line, self.sink_file, self.sink_line, self.sink_name)

    @property
    def cross_file(self) -> bool:
        return len(set(self.files)) > 1


@dataclass
class Limitation:
    file: str
    line: int
    kind: str
    message: str


@dataclass
class ModuleState:
    path: str
    scope: Scope
    exports: dict[str, Val] = field(default_factory=dict)
    stars: list[str] = field(default_factory=list)
    status: str = "new"              # new | running | done
    packages: set = field(default_factory=set)


_STATUS_RANK = {"candidate": 0, "uncertain": 1, "sanitized": 2, "unreachable": 3}


# ======================================================================================== engine
class DataFlowEngine:
    def __init__(self, files: list[ParsedFile], resolver: ModuleResolver | None = None,
                 vue_templates: list[tuple] | None = None):
        self.files: dict[str, ParsedFile] = {pf.path: pf for pf in files if pf.tree is not None and not pf.skipped_reason}
        keys = [(pf.path.split("#")[0] if pf.origin == "vue-sfc" else pf.path) for pf in self.files.values()]
        paths = list(self.files)
        self._alias_to_real = {k: p for k, p in zip(keys, paths)}
        self.resolver = resolver or ModuleResolver(keys)
        self.modules: dict[str, ModuleState] = {}
        self.flows: dict[tuple, Flow] = {}
        self.limitations: list[Limitation] = []
        self._lim_seen: set = set()
        self.pending: list[FnVal] = []
        self._pending_seen: set = set()
        self._memo: dict[tuple, Val] = {}
        self._stack: list[tuple] = []
        self._analyzed_clean: set = set()
        self.steps_used: dict[str, int] = {}
        self.truncated_files: set[str] = set()
        self.import_edges: dict[str, set[str]] = {}          # file -> project files it imports (for incremental)
        self.unresolved_imports: list[tuple] = []             # (file, line, spec, reason)
        self.vue_templates = vue_templates or []
        self.vue_state: dict[tuple, set] = {}
        self.root_files: set[str] = set()
        self.attr: str = ""                                   # file currently being analysed as a root (cache attribution)
        self.isolate_roots = False                            # True => memo cleared per root, so each root's flows are self-contained
        self.suppressed: set[str] = set()                     # roots whose results come from the cache: their flows are not re-reported

    # ------------------------------------------------------------------ helpers
    def lim(self, file: str, line: int, kind: str, msg: str) -> None:
        k = (file, line, kind, msg)
        if k not in self._lim_seen:
            self._lim_seen.add(k)
            self.limitations.append(Limitation(file, line, kind, msg))

    def tick(self, file: str) -> bool:
        n = self.steps_used.get(file, 0) + 1
        self.steps_used[file] = n
        if n > MAX_STEPS_PER_FILE:
            if file not in self.truncated_files:
                self.truncated_files.add(file)
                self.lim(file, 1, "budget", f"analysis budget exceeded ({MAX_STEPS_PER_FILE} steps); results for this file are partial")
            return False
        return True

    @staticmethod
    def named(node) -> list:
        return [c for c in node.children if c.is_named and c.type != "comment"]

    def txt(self, pf: ParsedFile, node) -> str:
        return pf.node_text(node)

    def unwrap(self, node):
        while node is not None and node.type in _WRAPPERS:
            ch = self.named(node)
            if not ch:
                return node
            node = ch[-1] if node.type == "type_assertion" else ch[0]
        return node

    def dotted(self, pf: ParsedFile, node) -> str | None:
        node = self.unwrap(node)
        if node is None:
            return None
        t = node.type
        if t in ("identifier", "property_identifier", "shorthand_property_identifier"):
            return self.txt(pf, node)
        if t == "this":
            return "this"
        if t == "member_expression":
            o = self.dotted(pf, node.child_by_field_name("object"))
            p = node.child_by_field_name("property")
            if o is None or p is None:
                return None
            return f"{o}.{self.txt(pf, p)}"
        if t == "call_expression":                       # `a.b().c` -> "a.b().c" shape used for jQuery receiver detection
            f = self.dotted(pf, node.child_by_field_name("function"))
            return f"{f}()" if f else None
        return None

    def str_value(self, pf: ParsedFile, node) -> str | None:
        node = self.unwrap(node)
        if node is None:
            return None
        if node.type == "string":
            frags = [self.txt(pf, c) for c in node.children if c.type == "string_fragment"]
            if frags or len(node.children) == 2:
                return "".join(frags)
            return self.txt(pf, node)[1:-1]
        if node.type == "template_string" and all(c.type != "template_substitution" for c in node.children):
            return self.txt(pf, node).strip("`")
        return None

    def real_path(self, key: str) -> str | None:
        return self._alias_to_real.get(key) or (key if key in self.files else None)

    # ------------------------------------------------------------------ module execution
    def get_module(self, path: str) -> ModuleState | None:
        path = self.real_path(path)
        if path is None or path not in self.files:
            return None
        m = self.modules.get(path)
        if m is None:
            m = ModuleState(path=path, scope=Scope())
            self.modules[path] = m
        if m.status == "new":
            m.status = "running"
            prev_attr, self.attr = self.attr, path
            try:
                pf = self.files[path]
                frame = Frame(path)
                root = pf.tree.root_node
                self.hoist(pf, root, m.scope, m)
                self.exec_block(pf, root, m.scope, frame, m)
                self.finish_cjs(m)
            finally:
                self.attr = prev_attr
            m.status = "done"
        return m

    def finish_cjs(self, m: ModuleState) -> None:
        d = m.exports.get("default")
        if d is not None and d.props:
            for k, v in d.props.items():
                m.exports.setdefault(k, v)

    def hoist(self, pf: ParsedFile, block, scope: Scope, m: ModuleState | None) -> None:
        for c in self.named(block):
            node = c
            exported = False
            if c.type == "export_statement":
                decl = c.child_by_field_name("declaration")
                if decl is None:
                    continue
                node, exported = decl, True
            if node.type in ("function_declaration", "generator_function_declaration"):
                nm = node.child_by_field_name("name")
                if nm is not None:
                    name = self.txt(pf, nm)
                    fv = self.make_fn(pf, node, scope, name)
                    scope.declare(name, Val(fn=fv))
                    if exported and m is not None:
                        m.exports[name] = scope.vars[name]
                        if "default" in self.txt(pf, c)[:25]:
                            m.exports["default"] = scope.vars[name]

    def make_fn(self, pf: ParsedFile, node, scope: Scope, name: str) -> FnVal:
        return FnVal(node, pf.path, scope, name, (pf.path, node.start_byte))

    # ------------------------------------------------------------------ statements
    def exec_block(self, pf, block, scope, frame, m=None) -> None:
        for c in self.named(block):
            if not self.tick(pf.path):
                return
            self.exec_stmt(pf, c, scope, frame, m)

    def exec_stmt(self, pf, node, scope, frame, m=None) -> None:
        t = node.type
        if t == "expression_statement":
            for c in self.named(node):
                self.eval(pf, c, scope, frame)
        elif t in ("lexical_declaration", "variable_declaration"):
            for d in self.named(node):
                if d.type == "variable_declarator":
                    self.exec_declarator(pf, d, scope, frame, m)
        elif t == "return_statement":
            ch = self.named(node)
            v = self.eval(pf, ch[0], scope, frame) if ch else CLEAN
            frame.returns.append(v)
        elif t == "statement_block":
            inner = Scope(scope)
            self.hoist(pf, node, inner, None)
            self.exec_block(pf, node, inner, frame)
        elif t == "if_statement":
            self.exec_if(pf, node, scope, frame)
        elif t in ("for_statement", "while_statement", "do_statement"):
            self.exec_loop(pf, node, scope, frame)
        elif t == "for_in_statement":
            self.exec_for_in(pf, node, scope, frame)
        elif t == "switch_statement":
            self.eval_opt(pf, node.child_by_field_name("value"), scope, frame)
            body = node.child_by_field_name("body")
            frame.cond += 1
            if body is not None:
                for case in self.named(body):
                    val_node = case.child_by_field_name("value")
                    for st in self.named(case):
                        if val_node is not None and st.id == val_node.id:
                            continue
                        self.exec_stmt(pf, st, scope, frame)
            frame.cond -= 1
        elif t == "try_statement":
            body = node.child_by_field_name("body")
            if body is not None:
                self.exec_stmt(pf, body, scope, frame)
            h = node.child_by_field_name("handler")
            if h is not None:
                hs = Scope(scope)
                p = h.child_by_field_name("parameter")
                if p is not None:
                    self.bind_pattern(pf, p, CLEAN, hs, frame, declare=True)
                hb = h.child_by_field_name("body")
                frame.cond += 1
                if hb is not None:
                    self.exec_stmt(pf, hb, hs, frame)
                frame.cond -= 1
            f = node.child_by_field_name("finalizer")
            if f is not None:
                fb = f.child_by_field_name("body")
                if fb is not None:
                    self.exec_stmt(pf, fb, scope, frame)
        elif t == "throw_statement":
            for c in self.named(node):
                self.eval(pf, c, scope, frame)
        elif t == "labeled_statement":
            b = node.child_by_field_name("body")
            if b is not None:
                self.exec_stmt(pf, b, scope, frame)
        elif t in ("function_declaration", "generator_function_declaration"):
            nm = node.child_by_field_name("name")
            if nm is not None and scope.lookup(self.txt(pf, nm)) is None:
                scope.declare(self.txt(pf, nm), Val(fn=self.make_fn(pf, node, scope, self.txt(pf, nm))))
            nm_s = self.txt(pf, nm) if nm is not None else ""
            v = scope.lookup(nm_s)
            if v is not None and v.fn is not None:
                self.register_pending(v.fn)
        elif t == "class_declaration":
            self.exec_class(pf, node, scope, frame)
        elif t == "export_statement":
            self.exec_export(pf, node, scope, frame, m)
        elif t == "import_statement":
            self.exec_import(pf, node, scope, frame, m)
        # interface / type / enum / ambient declarations carry no runtime flow: ignored on purpose

    def eval_opt(self, pf, node, scope, frame) -> Val:
        return self.eval(pf, node, scope, frame) if node is not None else CLEAN

    def exec_declarator(self, pf, d, scope, frame, m=None) -> None:
        name_node = d.child_by_field_name("name")
        value = d.child_by_field_name("value")
        v = self.eval(pf, value, scope, frame) if value is not None else CLEAN
        if value is not None and name_node is not None and name_node.type == "identifier":
            v = self.add_step(v, pf, d, f"assigned to `{self.txt(pf, name_node)}`")
            if v.fn is not None and v.fn.name == "<anonymous>":
                v.fn.name = self.txt(pf, name_node)
        if name_node is not None:
            self.bind_pattern(pf, name_node, v, scope, frame, declare=True, m=m)

    def add_step(self, v: Val, pf, node, text: str) -> Val:
        if not v.t and not v.props:
            return v
        line = pf.line_of(node)
        return v.map_taints(lambda x: x.step(pf.path, line, text))

    def bind_pattern(self, pf, pat, v: Val, scope, frame, declare=False, m=None) -> None:
        t = pat.type
        if t in ("required_parameter", "optional_parameter"):
            p = pat.child_by_field_name("pattern")
            dflt = pat.child_by_field_name("value")
            if p is not None:
                vv = join(v, self.eval(pf, dflt, scope, frame)) if dflt is not None else v
                self.bind_pattern(pf, p, vv, scope, frame, declare, m)
            return
        if t == "identifier":
            name = self.txt(pf, pat)
            if declare:
                scope.declare(name, v)
            else:
                scope.assign(name, v, frame.cond > 0)
            self.note_vue_state(pf, name, v)
            return
        if t == "assignment_pattern" or t == "object_assignment_pattern":
            left, right = pat.child_by_field_name("left"), pat.child_by_field_name("right")
            vv = join(v, self.eval(pf, right, scope, frame)) if right is not None else v
            if left is not None:
                if left.type == "shorthand_property_identifier_pattern":
                    scope.declare(self.txt(pf, left), vv)
                else:
                    self.bind_pattern(pf, left, vv, scope, frame, declare, m)
            return
        if t == "rest_pattern":
            ch = self.named(pat)
            if ch:
                self.bind_pattern(pf, ch[0], Val(v.all_taints()), scope, frame, declare, m)
            return
        if t == "object_pattern":
            for c in self.named(pat):
                if c.type == "shorthand_property_identifier_pattern":
                    name = self.txt(pf, c)
                    sub = self.member_of(v, name)
                    (scope.declare if declare else (lambda n, x: scope.assign(n, x, frame.cond > 0)))(name, sub)
                    self.note_vue_state(pf, name, sub)
                elif c.type == "pair_pattern":
                    k, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                    key = self.txt(pf, k).strip("'\"") if k is not None else ""
                    if val is not None:
                        self.bind_pattern(pf, val, self.member_of(v, key), scope, frame, declare, m)
                elif c.type in ("object_assignment_pattern", "assignment_pattern"):
                    left, right = c.child_by_field_name("left"), c.child_by_field_name("right")
                    if left is not None:
                        key = self.txt(pf, left)
                        sub = self.member_of(v, key)
                        if right is not None:
                            sub = join(sub, self.eval(pf, right, scope, frame))
                        scope.declare(key, sub)
                elif c.type == "rest_pattern":
                    ch = self.named(c)
                    if ch:
                        self.bind_pattern(pf, ch[0], Val(v.all_taints()), scope, frame, declare, m)
            return
        if t == "array_pattern":
            for c in self.named(pat):
                self.bind_pattern(pf, c, Val(v.all_taints()), scope, frame, declare, m)
            return
        if t == "member_expression" or t == "subscript_expression":
            self.assign_member(pf, pat, v, scope, frame)

    def note_vue_state(self, pf, name: str, v: Val) -> None:
        if pf.origin == "vue-sfc":
            ts = v.all_taints()
            if ts:
                self.vue_state.setdefault((pf.path, name), set()).update(ts)

    def member_of(self, v: Val, name: str) -> Val:
        if v.ns is not None:
            return self.resolve_export_val(v.ns, name)
        if v.imp is not None:
            v = self.force(v)
            if v.ns is not None:
                return self.resolve_export_val(v.ns, name)
        if v.ext is not None:
            return Val(v.t, ext=(v.ext[0], name))
        if v.props is not None:
            if name in v.props:
                return v.props[name]
            if not v.t:
                return CLEAN
        return Val(v.t) if v.t else CLEAN

    # ------------------------------------------------------------------ if / loops / validators
    def exec_if(self, pf, node, scope, frame) -> None:
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt_wrap = node.child_by_field_name("alternative")
        alt = None
        if alt_wrap is not None:
            ch = self.named(alt_wrap)
            alt = ch[0] if alt_wrap.type == "else_clause" and ch else alt_wrap
        cond_expr = self.unwrap(cond) if cond is not None else None
        self.eval_opt(pf, cond_expr, scope, frame)
        const = self.const_truth(pf, cond_expr)
        v_true = self.validations(pf, cond_expr, True, scope)
        v_false = self.validations(pf, cond_expr, False, scope)

        def run(branch, validations, dead):
            if branch is None:
                return
            saved = self.apply_validations(validations, scope, frame)
            old_dead = frame.dead
            frame.dead = frame.dead or dead
            frame.cond += 1
            self.exec_stmt(pf, branch, scope, frame)
            frame.cond -= 1
            frame.dead = old_dead
            self.restore_validations(saved, scope)

        run(cons, v_true, const is False)
        run(alt, v_false, const is True)
        if cons is not None and self.terminates(cons):
            self.apply_validations(v_false, scope, frame)               # `if (!ok(x)) return;` => x validated afterwards
        if alt is not None and self.terminates(alt):
            self.apply_validations(v_true, scope, frame)

    def terminates(self, node) -> bool:
        if node.type in _TERMINATORS:
            return True
        if node.type == "statement_block":
            ch = self.named(node)
            return bool(ch) and ch[-1].type in _TERMINATORS
        return False

    def const_truth(self, pf, node) -> bool | None:
        if node is None:
            return None
        text = self.txt(pf, node).strip()
        if text in ("false", "0", "null", "undefined", "''", '""', "!1"):
            return False
        if text in ("true", "1", "!0"):
            return True
        if "NODE_ENV" in text and ("development" in text or "test" in text) and "!" not in text.replace("!==", "").replace("!=", ""):
            return False                          # dev-only branch: not shipped in production bundles
        return None

    def exec_loop(self, pf, node, scope, frame) -> None:
        ls = Scope(scope)
        for fld in ("initializer",):
            init = node.child_by_field_name(fld)
            if init is not None:
                self.exec_stmt(pf, init, ls, frame) if init.type in ("lexical_declaration", "variable_declaration", "expression_statement") else self.eval(pf, init, ls, frame)
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        frame.cond += 1
        for _ in range(2):                                   # twice: lets loop-carried taint reach the top of the body
            self.eval_opt(pf, cond, ls, frame)
            if body is not None:
                self.exec_stmt(pf, body, ls, frame)
            inc = node.child_by_field_name("increment")
            self.eval_opt(pf, inc, ls, frame)
        frame.cond -= 1

    def exec_for_in(self, pf, node, scope, frame) -> None:
        ls = Scope(scope)
        right = self.eval_opt(pf, node.child_by_field_name("right"), scope, frame)
        left = node.child_by_field_name("left")
        if left is not None:
            if left.type in ("lexical_declaration", "variable_declaration"):
                for d in self.named(left):
                    nm = d.child_by_field_name("name") if d.type == "variable_declarator" else d
                    if nm is not None:
                        self.bind_pattern(pf, nm, Val(right.all_taints()), ls, frame, declare=True)
            else:
                self.bind_pattern(pf, left, Val(right.all_taints()), ls, frame, declare=True)
        body = node.child_by_field_name("body")
        frame.cond += 1
        for _ in range(2):
            if body is not None:
                self.exec_stmt(pf, body, ls, frame)
        frame.cond -= 1

    # validators -----------------------------------------------------------------------------------
    def validations(self, pf, cond, truthy: bool, scope) -> list[tuple[str, Mitigation]]:
        """Variables proven validated when `cond` evaluates to `truthy`, as [(variable, Mitigation)]."""
        cond = self.unwrap(cond) if cond is not None else None
        if cond is None:
            return []
        t = cond.type
        if t == "unary_expression":
            op = cond.child_by_field_name("operator")
            if op is not None and op.type == "!":
                return self.validations(pf, cond.child_by_field_name("argument"), not truthy, scope)
            return []
        if t == "binary_expression":
            op = cond.child_by_field_name("operator").type
            left, right = cond.child_by_field_name("left"), cond.child_by_field_name("right")
            if op == "&&":
                return (self.validations(pf, left, True, scope) + self.validations(pf, right, True, scope)) if truthy else []
            if op == "||":
                return [] if truthy else (self.validations(pf, left, False, scope) + self.validations(pf, right, False, scope))
            if op in ("===", "==", "!==", "!="):
                eq_when_true = op in ("===", "==")
                if eq_when_true != truthy:
                    return []                                   # this leaf being true/false says nothing positive
                return self.equality_validation(pf, left, right)
            return []
        if t == "call_expression" and truthy:
            return self.call_validation(pf, cond, scope)
        return []

    def equality_validation(self, pf, left, right) -> list[tuple[str, Mitigation]]:
        out = []
        for a, b in ((left, right), (right, left)):
            a, b = self.unwrap(a), self.unwrap(b)
            if a is None or b is None:
                continue
            da = self.dotted(pf, a)
            if da and da.endswith(".origin"):
                out.append((da.split(".")[0], Mitigation("origin check", effective=R.ALL, note="postMessage origin compared to a fixed value (trust boundary)")))
            elif a.type == "identifier" and self.str_value(pf, b) is not None:
                out.append((self.txt(pf, a), Mitigation("equals literal", effective=R.ALL, note="value is compared to a constant")))
            elif a.type == "unary_expression" and self.txt(pf, a).startswith("typeof") and self.str_value(pf, b) in ("number", "boolean"):
                arg = a.child_by_field_name("argument")
                if arg is not None and arg.type == "identifier":
                    out.append((self.txt(pf, arg), Mitigation("typeof number", effective=R.ALL, note="type check")))
        return out

    def call_validation(self, pf, call, scope) -> list[tuple[str, Mitigation]]:
        fn = self.unwrap(call.child_by_field_name("function"))
        args = call.child_by_field_name("arguments")
        argn = self.named(args) if args is not None and args.type == "arguments" else []
        if fn is None:
            return []
        name = self.dotted(pf, fn) or ""
        prop_n = fn.child_by_field_name("property") if fn.type == "member_expression" else None
        last = self.txt(pf, prop_n) if prop_n is not None else name.split(".")[-1]
        first = self.unwrap(argn[0]) if argn else None
        if last == "test" and fn.type == "member_expression" and first is not None and first.type == "identifier":
            recv = self.unwrap(fn.child_by_field_name("object"))
            if recv is not None and recv.type == "regex":
                src = self.txt(pf, recv)
                body = src[1:src.rfind("/")]
                if R.regex_is_strict_allowlist(body):
                    return [(self.txt(pf, first), Mitigation("strict regex allow-list", effective=R.ALL, note=f"/{body}/ is anchored and alphanumeric-only"))]
                return [(self.txt(pf, first), Mitigation("regex.test()", uncertain=R.ALL, note="validated by a regex that JScope cannot prove strict"))]
            return [(self.txt(pf, first), Mitigation("validator call", uncertain=R.ALL, note=f"{name}() used as a guard; its strictness is unknown"))]
        if last in ("includes", "has") and fn.type == "member_expression" and first is not None and first.type == "identifier":
            recv_v = self.eval(pf, fn.child_by_field_name("object"), scope, Frame(pf.path))
            if recv_v.lits:
                return [(self.txt(pf, first), Mitigation("allow-list", effective=R.ALL, note="value must equal one of a fixed list of literals"))]
            return [(self.txt(pf, first), Mitigation("membership check", uncertain=R.ALL, note="checked against a list JScope could not resolve"))]
        if last in ("isInteger", "isFinite", "isSafeInteger") and first is not None and first.type == "identifier":
            return [(self.txt(pf, first), Mitigation("numeric check", effective=R.ALL))]
        if last in ("startsWith", "endsWith", "indexOf") and fn.type == "member_expression" and first is not None:
            recv = self.unwrap(fn.child_by_field_name("object"))
            if recv is not None and recv.type == "identifier":
                return [(self.txt(pf, recv), Mitigation(f"{last}() guard", uncertain=frozenset({"navigation"}),
                                                       note="prefix/suffix checks do not stop `//host` or `javascript:` tricks"))]
        if name.endswith("isValid") or re.search(r"^(is|validate|check|assert)[A-Z_]", last or ""):
            for a in argn[:1]:
                a = self.unwrap(a)
                if a is not None and a.type == "identifier":
                    return [(self.txt(pf, a), Mitigation(f"{last}() guard", uncertain=R.ALL, note="named like a validator; behaviour not verified"))]
        return []

    def apply_validations(self, vals: list[tuple[str, Mitigation]], scope: Scope, frame: Frame) -> dict:
        saved = {}
        for var, mit in vals:
            cur = scope.lookup(var)
            if cur is None or not cur.all_taints():
                continue
            cur = self.force(cur)
            new = cur.map_taints(lambda x, mit=mit: x.mitigate(mit))
            saved[var] = (cur, new)
            s: Scope | None = scope
            while s is not None:
                if var in s.vars:
                    s.vars[var] = new
                    break
                s = s.parent
        return saved

    def restore_validations(self, saved: dict, scope: Scope) -> None:
        for var, (old, new) in saved.items():
            s: Scope | None = scope
            while s is not None:
                if var in s.vars:
                    if s.vars[var] is new:
                        s.vars[var] = old
                    break
                s = s.parent

    # ------------------------------------------------------------------ classes / exports / imports
    def exec_class(self, pf, node, scope, frame) -> None:
        body = node.child_by_field_name("body")
        nm = node.child_by_field_name("name")
        cls_name = self.txt(pf, nm) if nm is not None else "<class>"
        props: dict[str, Val] = {}
        if body is not None:
            for c in self.named(body):
                if c.type == "method_definition":
                    mn = c.child_by_field_name("name")
                    name = self.txt(pf, mn) if mn is not None else "<method>"
                    fv = self.make_fn(pf, c, scope, f"{cls_name}.{name}")
                    props[name] = Val(fn=fv)
                    self.register_pending(fv)
                elif c.type in ("field_definition", "public_field_definition"):
                    v = c.child_by_field_name("value")
                    if v is not None:
                        self.eval(pf, v, scope, frame)
        if nm is not None:
            scope.declare(cls_name, Val(props=props))

    def exec_export(self, pf, node, scope, frame, m) -> None:
        if m is None:
            return
        decl = node.child_by_field_name("declaration")
        value = node.child_by_field_name("value")
        source = node.child_by_field_name("source")
        text_head = self.txt(pf, node)[:40]
        is_default = bool(re.match(r"export\s+default\b", text_head))
        if decl is not None:
            self.exec_stmt(pf, decl, scope, frame, m)
            names: list[str] = []
            if decl.type in ("lexical_declaration", "variable_declaration"):
                for d in self.named(decl):
                    nm = d.child_by_field_name("name") if d.type == "variable_declarator" else None
                    if nm is not None and nm.type == "identifier":
                        names.append(self.txt(pf, nm))
                    elif nm is not None:
                        names += [x for x in re.findall(r"[A-Za-z_$][\w$]*", self.txt(pf, nm))]
            else:
                nm = decl.child_by_field_name("name")
                if nm is not None:
                    names.append(self.txt(pf, nm))
            for n in names:
                v = scope.lookup(n)
                if v is not None:
                    m.exports[n] = v
                    if is_default:
                        m.exports["default"] = v
            return
        if value is not None:
            m.exports["default"] = self.eval(pf, value, scope, frame)
            return
        clause = next((c for c in self.named(node) if c.type == "export_clause"), None)
        target = None
        if source is not None:
            spec = self.str_value(pf, source)
            res = self.resolver.resolve(spec or "", pf.path)
            self.note_import(pf, node, spec or "", res)
            target = res.path
        if clause is not None:
            for sp in self.named(clause):
                if sp.type != "export_specifier":
                    continue
                n = sp.child_by_field_name("name")
                a = sp.child_by_field_name("alias")
                local = self.txt(pf, n) if n is not None else ""
                exported = self.txt(pf, a) if a is not None else local
                if target:
                    m.exports[exported] = Val(imp=(target, local))
                else:
                    v = scope.lookup(local)
                    if v is not None:
                        m.exports[exported] = v
        elif target and not clause:
            m.stars.append(target)            # `export * from './x'`

    def note_import(self, pf, node, spec: str, res) -> None:
        if res.status == "resolved" and res.path:
            real = self.real_path(res.path)
            if real:
                self.import_edges.setdefault(pf.path, set()).add(real)
        elif res.status == "unresolved":
            self.unresolved_imports.append((pf.path, pf.line_of(node), spec, res.reason))
            self.lim(pf.path, pf.line_of(node), "unresolved-import", f"import '{spec}' not resolved: {res.reason}")

    def exec_import(self, pf, node, scope, frame, m) -> None:
        src = node.child_by_field_name("source")
        spec = self.str_value(pf, src) if src is not None else None
        if spec is None:
            return
        res = self.resolver.resolve(spec, pf.path)
        self.note_import(pf, node, spec, res)
        if m is not None:
            m.packages.add(spec)
        clause = next((c for c in self.named(node) if c.type == "import_clause"), None)
        if clause is None:
            return

        def binding(imported: str) -> Val:
            if res.status == "resolved" and res.path and self.real_path(res.path):
                return Val(imp=(self.real_path(res.path), imported))
            return Val(ext=(spec, imported))

        for c in self.named(clause):
            if c.type == "identifier":
                scope.declare(self.txt(pf, c), binding("default"))
            elif c.type == "namespace_import":
                ids = [x for x in self.named(c) if x.type == "identifier"]
                if ids:
                    if res.status == "resolved" and res.path and self.real_path(res.path):
                        scope.declare(self.txt(pf, ids[0]), Val(ns=self.real_path(res.path)))
                    else:
                        scope.declare(self.txt(pf, ids[0]), Val(ext=(spec, None)))
            elif c.type == "named_imports":
                for sp in self.named(c):
                    if sp.type != "import_specifier":
                        continue
                    n = sp.child_by_field_name("name")
                    a = sp.child_by_field_name("alias")
                    nm = self.txt(pf, n) if n is not None else ""
                    scope.declare(self.txt(pf, a) if a is not None else nm, binding(nm))

    def force(self, v: Val) -> Val:
        """Resolve a lazy import binding to the exporting module's value (running that module if needed)."""
        guard = 0
        while v.imp is not None and guard < 20:
            guard += 1
            path, name = v.imp
            nv = self.resolve_export_val(path, name)
            v = nv
        return v

    def resolve_export_val(self, path: str, name: str, _seen: set | None = None) -> Val:
        _seen = _seen or set()
        if (path, name) in _seen:
            return CLEAN
        _seen.add((path, name))
        m = self.modules.get(path)
        if m is not None and m.status == "running":
            v = m.exports.get(name) or m.scope.vars.get(name)           # circular import: whatever is already defined
            if v is not None:
                return v
            self.lim(path, 1, "circular-import", f"circular import: '{name}' requested before its module finished executing")
            return CLEAN
        m = self.get_module(path)
        if m is None:
            return CLEAN
        if name in m.exports:
            v = m.exports[name]
            return self.force(v) if v.imp is not None else v
        if name == "default" and "default" not in m.exports:
            return Val(ns=path)                                         # CJS-style `import x from` of a namespace-ish module
        for star in m.stars:
            v = self.resolve_export_val(star, name, _seen)
            if v is not CLEAN:
                return v
        return CLEAN

    # ------------------------------------------------------------------ expressions
    def eval(self, pf, node, scope, frame) -> Val:
        if node is None:
            return CLEAN
        if not self.tick(pf.path):
            return CLEAN
        t = node.type
        if t in _WRAPPERS:
            ch = self.named(node)
            if not ch:
                return CLEAN
            return self.eval(pf, ch[-1] if t == "type_assertion" else ch[0], scope, frame)
        if t == "identifier":
            v = scope.lookup(self.txt(pf, node))
            if v is None:
                return CLEAN
            return self.force(v) if v.imp is not None else v
        if t in ("string", "number", "true", "false", "null", "undefined", "regex", "this", "super", "property_identifier",
                 "shorthand_property_identifier", "template_literal_type"):
            return CLEAN
        if t == "template_string":
            parts = [self.eval(pf, c.child_by_field_name("expression") or (self.named(c)[0] if self.named(c) else None), scope, frame)
                     for c in node.children if c.type == "template_substitution"]
            return union_vals(parts)
        if t == "member_expression":
            return self.eval_member(pf, node, scope, frame)
        if t == "subscript_expression":
            obj = self.eval(pf, node.child_by_field_name("object"), scope, frame)
            idx = node.child_by_field_name("index")
            iv = self.eval_opt(pf, idx, scope, frame)
            key = self.str_value(pf, idx) if idx is not None else None
            od = self.dotted(pf, node.child_by_field_name("object"))
            if od in R.STORAGE_OBJECTS or (od or "").replace("window.", "") in R.STORAGE_OBJECTS:
                return self.make_source(pf, node, "storage")
            if key is not None and obj.props is not None and key in obj.props:
                return obj.props[key]
            return Val(obj.all_taints()) if obj.all_taints() else CLEAN
        if t == "call_expression":
            return self.eval_call(pf, node, scope, frame)
        if t == "new_expression":
            return self.eval_new(pf, node, scope, frame)
        if t == "binary_expression":
            op = node.child_by_field_name("operator").type
            l, r = node.child_by_field_name("left"), node.child_by_field_name("right")
            lv, rv = self.eval(pf, l, scope, frame), self.eval(pf, r, scope, frame)
            if op in ("+", "||", "??", "&&"):
                return union_vals([lv, rv]) if (lv.all_taints() or rv.all_taints()) else (lv if op != "+" else CLEAN)
            return CLEAN
        if t == "unary_expression":
            self.eval_opt(pf, node.child_by_field_name("argument"), scope, frame)
            return CLEAN
        if t == "update_expression":
            return CLEAN
        if t == "ternary_expression":
            self.eval_opt(pf, node.child_by_field_name("condition"), scope, frame)
            frame.cond += 1
            a = self.eval_opt(pf, node.child_by_field_name("consequence"), scope, frame)
            b = self.eval_opt(pf, node.child_by_field_name("alternative"), scope, frame)
            frame.cond -= 1
            return join(a, b)
        if t == "assignment_expression":
            return self.eval_assign(pf, node, scope, frame)
        if t == "augmented_assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            rv = self.eval(pf, right, scope, frame)
            lv = self.eval(pf, left, scope, frame)
            nv = union_vals([lv, rv]) if (lv.all_taints() or rv.all_taints()) else CLEAN
            if left is not None:
                self.assign_target(pf, left, nv, scope, frame, weak=True)
            return nv
        if t == "object":
            return self.eval_object(pf, node, scope, frame)
        if t == "array":
            vals, lits = [], []
            for c in self.named(node):
                if c.type == "spread_element":
                    ch = self.named(c)
                    vals.append(self.eval(pf, ch[0], scope, frame) if ch else CLEAN)
                    lits = None if lits is not None else lits
                    continue
                vals.append(self.eval(pf, c, scope, frame))
                if lits is not None:
                    s = self.str_value(pf, c)
                    if s is None:
                        lits = None
                    else:
                        lits.append(s)
            v = union_vals(vals)
            return Val(v.t, lits=tuple(lits) if lits else None) if (v.t or lits) else CLEAN
        if t in ("arrow_function", "function_expression", "function", "generator_function"):
            fv = self.make_fn(pf, node, scope, "<anonymous>")
            self.register_pending(fv)
            return Val(fn=fv)
        if t == "sequence_expression":
            last = CLEAN
            for c in self.named(node):
                last = self.eval(pf, c, scope, frame)
            return last
        if t == "spread_element":
            ch = self.named(node)
            return self.eval(pf, ch[0], scope, frame) if ch else CLEAN
        if t in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            return self.eval_jsx(pf, node, scope, frame)
        if t == "jsx_expression":
            ch = self.named(node)
            return self.eval(pf, ch[0], scope, frame) if ch else CLEAN
        if t == "class":
            self.exec_class(pf, node, scope, frame)
            return CLEAN
        if t == "pair":
            return self.eval_opt(pf, node.child_by_field_name("value"), scope, frame)
        # unknown expression kind: evaluate children so nested calls/sinks are still seen
        vals = [self.eval(pf, c, scope, frame) for c in self.named(node) if c.type not in ("type_annotation",)]
        return union_vals(vals) if vals else CLEAN

    # sources --------------------------------------------------------------------------------------
    def make_source(self, pf, node, kind: str, snippet: str | None = None) -> Val:
        line = pf.line_of(node)
        snip = (snippet or self.txt(pf, node)).replace("\n", " ")[:90]
        return Val(frozenset({Taint(kind, pf.path, line, snip)}))

    def eval_member(self, pf, node, scope, frame) -> Val:
        d = self.dotted(pf, node)
        obj_node = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        pname = self.txt(pf, prop) if prop is not None else ""
        if d:
            nd = re.sub(r"^(window|self|globalThis|top|parent)\.", "", d) if not d.startswith("window.location") else d
            m = R.URL_MEMBER.match(d)
            if m and scope.lookup("location") is None:
                return self.make_source(pf, node, R.URL_KIND[m.group(1)])
            if d in ("document.URL", "document.documentURI", "window.document.URL"):
                return self.make_source(pf, node, "url")
            if nd in ("document.referrer",):
                return self.make_source(pf, node, "referrer")
            if nd == "document.cookie":
                return self.make_source(pf, node, "cookie")
            if d in ("window.name",):
                return self.make_source(pf, node, "window_name")
            root = d.split(".")[0]
            if root in R.STORAGE_OBJECTS and d.count(".") == 1 and scope.lookup(root) is None and pname not in ("getItem", "setItem", "removeItem", "clear", "key", "length"):
                return self.make_source(pf, node, "storage")
        if pname == "value" and obj_node is not None:
            od = self.dotted(pf, obj_node) or ""
            ot = self.txt(pf, obj_node)
            if od.endswith(".target") or od.endswith(".current") or od == "target" or R.FORM_CALL_RE.search(ot):
                return self.make_source(pf, node, "form_input")
        if pname == "responseText" and obj_node is not None:
            return self.make_source(pf, node, "network_response")
        obj = self.eval(pf, obj_node, scope, frame)
        obj = self.force(obj) if obj.imp is not None else obj
        if pname == "length":
            return CLEAN
        return self.member_of(obj, pname)

    # assignments ----------------------------------------------------------------------------------
    def eval_assign(self, pf, node, scope, frame) -> Val:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        rv = self.eval(pf, right, scope, frame)
        if left is not None and left.type == "identifier":
            rv = self.add_step(rv, pf, node, f"assigned to `{self.txt(pf, left)}`")
            if rv.fn is not None and rv.fn.name == "<anonymous>":
                rv.fn.name = self.txt(pf, left)
        if left is not None:
            self.assign_target(pf, left, rv, scope, frame, weak=False)
        return rv

    def assign_target(self, pf, left, v: Val, scope, frame, weak: bool) -> None:
        left = self.unwrap(left)
        if left is None:
            return
        if left.type == "identifier":
            scope.assign(self.txt(pf, left), v, frame.cond > 0 or weak)
            self.note_vue_state(pf, self.txt(pf, left), v)
        elif left.type in ("member_expression", "subscript_expression"):
            self.assign_member(pf, left, v, scope, frame)
        elif left.type in ("object_pattern", "array_pattern"):
            self.bind_pattern(pf, left, v, scope, frame, declare=False)

    def assign_member(self, pf, left, v: Val, scope, frame) -> None:
        d = self.dotted(pf, left) or ""
        prop = left.child_by_field_name("property")
        pname = self.txt(pf, prop) if prop is not None and left.type == "member_expression" else None
        obj_node = left.child_by_field_name("object")
        # --- CommonJS exports
        m = self.modules.get(pf.path)
        if m is not None and pname is not None:
            if d == "module.exports":
                m.exports["default"] = v
                return
            if d.startswith(("module.exports.", "exports.")) and d.count(".") <= 2:
                m.exports[pname] = v
                return
        # --- sinks on assignment
        if pname in R.HTML_ASSIGN_PROPS:
            self.report(pf, left, "html", f".{pname} = ...", v, frame, scope)
        elif pname == "src" and obj_node is not None and re.search(r"(?i)script", self.txt(pf, obj_node)):
            self.report(pf, left, "code", "script.src = ...", v, frame, scope)
        elif R.NAV_ASSIGN_DOTTED.match(d) and (pname in (None, "href") or d.endswith("location")):
            self.report(pf, left, "navigation", f"{d} = ...", v, frame, scope)
        elif pname == "onmessage" and v.fn is not None:
            self.call_message_handler(pf, left, v, scope, frame)
        if pname == "innerText" or pname == "textContent":
            return                                              # safe sinks: text, not markup
        # --- record property on tracked objects (field-sensitive for locals)
        if obj_node is not None:
            on = self.unwrap(obj_node)
            if on is not None and on.type == "identifier":
                name = self.txt(pf, on)
                cur = scope.lookup(name)
                key = pname if pname is not None else self.str_value(pf, left.child_by_field_name("index"))
                if cur is not None and key is not None and cur.imp is None and cur.ns is None and cur.ext is None:
                    props = dict(cur.props) if cur.props is not None else {}
                    props[key] = join(props.get(key), v) if frame.cond > 0 else v
                    nv = Val(cur.t, props, cur.fn, None, None, None, cur.lits, cur.pyfn)
                    scope.assign(name, nv, False)
                elif cur is None and key is not None:
                    scope.assign(name, Val(props={key: v}), False)
            elif on is not None and on.type == "this" and pname is not None:
                self.note_vue_state(pf, pname, v)
        if pname == "value" and obj_node is not None:
            on = self.unwrap(obj_node)
            if on is not None and on.type == "identifier":
                self.note_vue_state(pf, self.txt(pf, on), v)       # Vue ref: `x.value = ...`

    def eval_object(self, pf, node, scope, frame) -> Val:
        props: dict[str, Val] = {}
        t: set = set()
        for c in self.named(node):
            if c.type == "pair":
                k, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                key = self.str_value(pf, k) if k is not None and k.type in ("string",) else (self.txt(pf, k) if k is not None and k.type in ("property_identifier", "number", "identifier") else None)
                vv = self.eval_opt(pf, val, scope, frame)
                if key is None:
                    t |= vv.all_taints()
                else:
                    props[key] = vv
                    if val is not None and val.type in _FN_TYPES and vv.fn is not None and vv.fn.name == "<anonymous>":
                        vv.fn.name = key
            elif c.type == "shorthand_property_identifier":
                name = self.txt(pf, c)
                sv = scope.lookup(name) or CLEAN
                props[name] = self.force(sv) if sv.imp is not None else sv
            elif c.type == "method_definition":
                mn = c.child_by_field_name("name")
                name = self.txt(pf, mn) if mn is not None else "<method>"
                fv = self.make_fn(pf, c, scope, name)
                props[name] = Val(fn=fv)
                self.register_pending(fv)
            elif c.type == "spread_element":
                ch = self.named(c)
                sv = self.eval(pf, ch[0], scope, frame) if ch else CLEAN
                if sv.props:
                    for k2, v2 in sv.props.items():
                        props[k2] = v2
                t |= set(sv.t)
        v = Val(frozenset(t), props)
        return v

    def eval_jsx(self, pf, node, scope, frame) -> Val:
        for n in self.walk_jsx(node):
            if n.type == "jsx_attribute":
                ch = self.named(n)
                name = self.txt(pf, ch[0]) if ch else ""
                val = ch[1] if len(ch) > 1 else None
                if val is not None and val.type == "jsx_expression":
                    inner = self.named(val)
                    expr = inner[0] if inner else None
                    if name == "dangerouslySetInnerHTML" and expr is not None:
                        obj = self.eval(pf, expr, scope, frame)
                        h = obj.props.get("__html") if obj.props is not None else None
                        h = h if h is not None else Val(obj.all_taints())
                        self.report(pf, n, "html", "dangerouslySetInnerHTML", h, frame, scope)
                    else:
                        self.eval_opt(pf, expr, scope, frame)
            elif n.type == "jsx_expression" and n.parent is not None and n.parent.type != "jsx_attribute":
                ch = self.named(n)
                if ch:
                    self.eval(pf, ch[0], scope, frame)
        return CLEAN

    def walk_jsx(self, node):
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            if n.type == "jsx_expression" and (n.parent is None or n.parent.type != "jsx_attribute"):
                continue                                # evaluated as a whole by the caller; don't walk into JS twice
            stack.extend(reversed(n.children))

    # ------------------------------------------------------------------ calls
    def register_pending(self, fv: FnVal) -> None:
        if fv.key not in self._pending_seen:
            self._pending_seen.add(fv.key)
            self.pending.append(fv)

    def eval_args(self, pf, args_node, scope, frame) -> list[Val]:
        out: list[Val] = []
        if args_node is None:
            return out
        if args_node.type == "template_string":
            return [self.eval(pf, args_node, scope, frame)]
        for c in self.named(args_node):
            out.append(self.eval(pf, c, scope, frame))
        return out

    def arg_nodes(self, args_node) -> list:
        if args_node is None or args_node.type == "template_string":
            return []
        return self.named(args_node)

    def eval_new(self, pf, node, scope, frame) -> Val:
        ctor = node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        args = self.eval_args(pf, args_node, scope, frame)
        name = self.dotted(pf, ctor) or ""
        if name in ("Function", "window.Function"):
            if args:
                self.report(pf, node, "code", "new Function(...)", args[-1], frame, scope)
            return CLEAN
        if name == "Promise" and args and args[0].fn is not None:
            collected: list[Val] = []
            res = Val(pyfn=lambda a: (collected.append(a[0] if a else CLEAN), CLEAN)[1])
            self.call_fn(args[0].fn, [res, Val(pyfn=lambda a: CLEAN)], node, frame, pf)
            return union_vals(collected)
        if name == "XMLHttpRequest":
            return CLEAN
        cv = self.eval(pf, ctor, scope, frame)
        cv = self.force(cv) if cv.imp is not None else cv
        base = name.split(".")[-1]
        if cv.props is not None and ctor is not None and ctor.type == "identifier":
            return Val(props=dict(cv.props))                # user class: instance exposes its methods
        if base in R.PASSTHROUGH_CTORS:
            return union_vals(args)
        ts = union_vals(args)
        if ts.t:
            return Val(frozenset(x.assume(f"passed through unresolved constructor new {base}()") for x in ts.t))
        return CLEAN

    def callee_names(self, pf, fn_node, scope) -> list[str]:
        raw = self.dotted(pf, fn_node) or ""
        names = [raw] if raw else []
        if raw:
            root = raw.split(".")[0]
            rv = scope.lookup(root)
            if rv is not None and rv.ext is not None and rv.ext[0]:
                pkg, member = rv.ext
                rest = raw.split(".", 1)[1] if "." in raw else ""
                parts = [pkg] + ([member] if member and member != "default" else []) + ([rest] if rest else [])
                names.append(".".join(parts))
                if member and member != "default":
                    names.append(".".join([member] + ([rest] if rest else [])))
        return names

    def eval_call(self, pf, node, scope, frame) -> Val:
        fn_node = self.unwrap(node.child_by_field_name("function"))
        args_node = node.child_by_field_name("arguments")
        line = pf.line_of(node)
        # --- dynamic import() ---------------------------------------------------------
        if fn_node is not None and fn_node.type == "import":
            spec_nodes = self.arg_nodes(args_node)
            spec = self.str_value(pf, spec_nodes[0]) if spec_nodes else None
            if spec is None:
                self.lim(pf.path, line, "dynamic-import", "import() with a non-literal specifier cannot be resolved statically")
                return CLEAN
            res = self.resolver.resolve(spec, pf.path)
            self.note_import(pf, node, spec, res)
            if res.status == "resolved" and res.path and self.real_path(res.path):
                return Val(ns=self.real_path(res.path))
            return Val(ext=(spec, None))
        args = self.eval_args(pf, args_node, scope, frame)
        argn = self.arg_nodes(args_node)
        if fn_node is None:
            return CLEAN
        names = self.callee_names(pf, fn_node, scope)
        raw = names[0] if names else ""
        last = raw.split(".")[-1] if raw else (self.txt(pf, fn_node.child_by_field_name("property")) if fn_node.type == "member_expression" and fn_node.child_by_field_name("property") is not None else "")
        recv_node = fn_node.child_by_field_name("object") if fn_node.type == "member_expression" else None
        recv_text = self.txt(pf, recv_node) if recv_node is not None else ""

        # --- require() ----------------------------------------------------------------
        if raw == "require" and scope.lookup("require") is None and argn:
            spec = self.str_value(pf, argn[0])
            if spec is None:
                self.lim(pf.path, line, "dynamic-require", "require() with a non-literal specifier cannot be resolved statically")
                return CLEAN
            m = self.modules.get(pf.path)
            if m is not None:
                m.packages.add(spec)
            res = self.resolver.resolve(spec, pf.path)
            self.note_import(pf, node, spec, res)
            if res.status == "resolved" and res.path and self.real_path(res.path):
                return Val(ns=self.real_path(res.path))
            return Val(ext=(spec, None))

        # --- sinks --------------------------------------------------------------------
        sink = self.match_sink_call(pf, node, raw, last, recv_text, args, argn, scope)
        if sink:
            for cls, label, idx in sink:
                if idx == "all":
                    for a in args:
                        self.report(pf, node, cls, label, a, frame, scope)
                elif idx < len(args):
                    self.report(pf, node, cls, label, args[idx], frame, scope)

        # --- sanitizers ---------------------------------------------------------------
        for nm in names:
            for pat, mit in R.SANITIZERS:
                if pat.search(nm):
                    target = args[0] if args else CLEAN
                    if not target.all_taints() and last != "sanitize":
                        return CLEAN
                    if mit.effective >= R.ALL:
                        return CLEAN
                    return target.map_taints(lambda x, mit=mit: x.mitigate(mit))
            if R.DB_ESCAPERS.search(nm) and args:
                return args[0].map_taints(lambda x: x.mitigate(Mitigation("SQL escaping", effective=frozenset({"sql"}))))
        if last == "replace" and recv_node is not None and len(args) >= 1:
            rv = self.eval(pf, recv_node, scope, frame)
            if rv.all_taints():
                return rv.map_taints(lambda x: x.mitigate(R.PARTIAL_REPLACE))

        # --- sources as calls ---------------------------------------------------------
        if last in ("getItem",) and recv_text.replace("window.", "") in R.STORAGE_OBJECTS:
            return self.make_source(pf, node, "storage")
        if last == "val" and R.JQUERY_RECEIVER.match(recv_text or ""):
            return self.make_source(pf, node, "form_input")
        if raw in R.NETWORK_CALLEES or raw.startswith(R.NETWORK_PREFIX) or (last in ("get", "post", "put", "patch", "request") and recv_text in ("axios", "$", "$http", "http", "api", "client")):
            v = self.make_source(pf, node, "network_response")
            if raw in ("$.get", "$.post", "$.getJSON") and len(args) > 1:
                for a in args[1:]:
                    if a.fn is not None:
                        self.call_fn(a.fn, [v], node, frame, pf)
            if raw == "$.ajax" and args and args[0].props and args[0].props.get("success") is not None and args[0].props["success"].fn is not None:
                self.call_fn(args[0].props["success"].fn, [v], node, frame, pf)
            return v
        if last == "addEventListener" and argn and (self.str_value(pf, argn[0]) == "message") and len(args) > 1 and args[1].fn is not None:
            self.call_message_handler(pf, node, args[1], scope, frame)
            return CLEAN

        # --- promise & collection combinators ----------------------------------------
        if recv_node is not None and last in ("then", "catch", "finally") and args:
            rv = self.eval(pf, recv_node, scope, frame)
            rv = self.force(rv) if rv.imp is not None else rv
            res_vals = [rv] if last != "catch" else [rv]
            for a in args[:2]:
                if a.fn is not None:
                    pass_in = rv if rv.ns is None else rv
                    out = self.call_fn(a.fn, [pass_in], node, frame, pf)
                    res_vals.append(out)
                elif a.pyfn is not None:
                    a.pyfn([rv])
            return union_vals(res_vals) if any(x.all_taints() for x in res_vals) else (rv if rv.ns is not None else CLEAN)
        if recv_node is not None and last in ("map", "forEach", "filter", "find", "some", "every", "flatMap", "reduce") and args and args[0].fn is not None:
            rv = self.eval(pf, recv_node, scope, frame)
            elem = Val(rv.all_taints())
            cb_args = [elem, CLEAN, CLEAN] if last != "reduce" else [CLEAN, elem]
            out = self.call_fn(args[0].fn, cb_args, node, frame, pf)
            if last in ("forEach",):
                return CLEAN
            if last in ("filter", "find", "some", "every"):
                return elem if last in ("filter", "find") else CLEAN
            return union_vals([out, elem]) if last == "reduce" else out
        if raw in ("setTimeout", "setInterval", "queueMicrotask", "requestAnimationFrame", "setImmediate") and args and args[0].fn is not None:
            self.call_fn(args[0].fn, [], node, frame, pf)
            return CLEAN
        if raw in ("useEffect", "useLayoutEffect", "useCallback_", "$", "jQuery") and args and args[0].fn is not None:
            self.call_fn(args[0].fn, [], node, frame, pf)
            return CLEAN
        if raw in R.CLEAN_FUNCS:
            return CLEAN

        # --- project-internal callee --------------------------------------------------
        callee = self.resolve_callee(pf, fn_node, scope, frame, raw)
        if callee is not None:
            if callee.fn is not None:
                return self.call_fn(callee.fn, args, node, frame, pf)
            if callee.pyfn is not None:
                return callee.pyfn(args)
        # --- known pass-through / unresolved -----------------------------------------
        recv_val = self.eval(pf, recv_node, scope, frame) if recv_node is not None else CLEAN
        if recv_node is not None and recv_val.ns is not None:
            ex = self.member_of(recv_val, last)
            ex = self.force(ex) if ex.imp is not None else ex
            if ex.fn is not None:
                return self.call_fn(ex.fn, args, node, frame, pf)
        recv_all = recv_val.all_taints()
        arg_all = union_vals(args).t
        if not recv_all and not arg_all:
            return CLEAN
        if raw in R.PASSTHROUGH_FUNCS or last in R.PASS_METHODS or any(n in R.PASSTHROUGH_FUNCS for n in names):
            return Val(recv_all | arg_all)
        desc = raw or last or "<expr>"
        if fn_node.type == "member_expression" and (self.dotted(pf, fn_node) is None):
            self.lim(pf.path, line, "computed-call", "call on a dynamically computed receiver/property; flow through it is assumed")
        a_txt = f"passed through unresolved call {desc}()"
        out = frozenset(x.assume(a_txt) for x in (recv_all | arg_all))
        self.lim(pf.path, line, "unresolved-call", f"tainted value flows through {desc}(), whose behaviour is unknown")
        return Val(out)

    def resolve_callee(self, pf, fn_node, scope, frame, raw: str) -> Val | None:
        if fn_node.type == "identifier":
            v = scope.lookup(self.txt(pf, fn_node))
            if v is None:
                return None
            v = self.force(v) if v.imp is not None else v
            return v if (v.fn or v.pyfn) else None
        if fn_node.type == "member_expression":
            obj = self.eval(pf, fn_node.child_by_field_name("object"), scope, frame)
            obj = self.force(obj) if obj.imp is not None else obj
            prop = fn_node.child_by_field_name("property")
            pname = self.txt(pf, prop) if prop is not None else ""
            mv = self.member_of(obj, pname)
            mv = self.force(mv) if mv.imp is not None else mv
            return mv if (mv.fn or mv.pyfn) else None
        if fn_node.type in ("arrow_function", "function_expression", "function"):
            fv = self.make_fn(pf, fn_node, scope, "<iife>")
            return Val(fn=fv)
        if fn_node.type == "call_expression":
            inner = self.eval(pf, fn_node, scope, frame)
            return inner if inner.fn else None
        return None

    def match_sink_call(self, pf, node, raw, last, recv_text, args, argn, scope):
        out = []
        recv_clean = recv_text.replace("window.", "")
        if last in ("write", "writeln") and recv_clean in ("document",):
            out.append(("html", f"document.{last}()", "all"))
        elif last == "insertAdjacentHTML":
            out.append(("html", "insertAdjacentHTML()", 1))
        elif last == "createContextualFragment":
            out.append(("html", "createContextualFragment()", 0))
        elif raw in ("eval", "window.eval", "globalThis.eval"):
            out.append(("code", "eval()", 0))
        elif raw in ("setTimeout", "setInterval", "window.setTimeout", "window.setInterval") and args and args[0].fn is None:
            out.append(("code", f"{raw}(<string>)", 0))
        elif raw == "Function":
            out.append(("code", "Function()", len(args) - 1 if args else 0))
        elif last in ("assign", "replace") and recv_clean in ("location", "document.location") and args:
            out.append(("navigation", f"location.{last}()", 0))
        elif raw in ("window.open", "open") and args and scope.lookup("open") is None:
            out.append(("navigation", "window.open()", 0))
        elif last in R.JQUERY_HTML_METHODS and R.JQUERY_RECEIVER.match(recv_text or "") and args:
            out.append(("html", f"jQuery .{last}()", 0))
        elif last == "setAttribute" and len(argn) >= 2:
            an = (self.str_value(pf, argn[0]) or "").lower()
            if an.startswith("on") or an == "srcdoc":
                out.append(("html" if an == "srcdoc" else "code", f"setAttribute('{an}')", 1))
            elif an in ("href", "src", "action", "formaction"):
                out.append(("navigation", f"setAttribute('{an}')", 1))
        m = self.modules.get(pf.path)
        pkgs = m.packages if m is not None else set()
        if last in R.CMD_FUNCS or raw in R.CMD_FUNCS:
            if pkgs & R.CMD_PACKAGES or any(n.split(".")[0] in R.CMD_PACKAGES for n in self.callee_names(pf, self.unwrap(node.child_by_field_name("function")), scope)):
                out.append(("command", f"{raw or last}()", 0))
        if last in R.DB_METHODS and pkgs & R.DB_PACKAGES and args:
            out.append(("sql", f".{last}()", 0))
        return out

    # ------------------------------------------------------------------ function execution
    def call_message_handler(self, pf, node, handler: Val, scope, frame) -> None:
        if handler.fn is None:
            return
        src = self.make_source(pf, node, "postmessage", snippet="message event .data")
        ev = Val(props={"data": src, "origin": CLEAN, "source": CLEAN})
        self.call_fn(handler.fn, [ev], node, frame, pf)

    def call_fn(self, fn: FnVal, args: list[Val], call_node, frame: Frame, call_pf: ParsedFile) -> Val:
        if fn.file not in self.files:
            return CLEAN
        if frame.depth >= MAX_DEPTH:
            self.lim(call_pf.path, call_pf.line_of(call_node), "depth", f"call depth limit ({MAX_DEPTH}) reached at {fn.name}(); flow beyond is not tracked")
            return union_vals(args)
        if fn.key in self._stack:
            self.lim(call_pf.path, call_pf.line_of(call_node), "recursion", f"recursive call to {fn.name}(); summarised by argument taint")
            return union_vals(args)
        ident = tuple(tuple(sorted(x.ident for x in a.all_taints())) for a in args)
        key = (fn.key, ident)
        if key in self._memo:
            return self._memo[key]
        self._memo[key] = CLEAN                         # cycle guard for mutually recursive contexts
        pf = self.files[fn.file]
        node = fn.node
        # wrap args with call-site steps
        line = call_pf.line_of(call_node)
        wrapped = [self.add_step(a, call_pf, call_node, f"passed as argument to {fn.name}()") if a.all_taints() else a for a in args]
        sc = Scope(fn.scope)
        params = node.child_by_field_name("parameters")
        single = node.child_by_field_name("parameter")
        new_frame = Frame(fn.file, fn.name, [], frame.dead, 0, frame.depth + 1)
        if single is not None:
            self.bind_pattern(pf, single, wrapped[0] if wrapped else CLEAN, sc, new_frame, declare=True)
        elif params is not None:
            for i, p in enumerate(self.named(params)):
                self.bind_pattern(pf, p, wrapped[i] if i < len(wrapped) else CLEAN, sc, new_frame, declare=True)
        self._stack.append(fn.key)
        try:
            body = node.child_by_field_name("body")
            if body is not None:
                if body.type == "statement_block":
                    self.hoist(pf, body, sc, None)
                    self.exec_block(pf, body, sc, new_frame)
                else:
                    new_frame.returns.append(self.eval(pf, body, sc, new_frame))
        finally:
            self._stack.pop()
        ret = join_all(new_frame.returns)
        if ret.all_taints():
            ret = self.add_step(ret, pf, node, f"returned from {fn.name}()")
        self._memo[key] = ret
        return ret

    # ------------------------------------------------------------------ reporting
    def report(self, pf, node, sink_class: str, label: str, v: Val, frame: Frame, scope: Scope) -> None:
        taints = v.all_taints()
        if not taints or (self.attr and self.attr in self.suppressed):
            return
        line = pf.line_of(node)
        snippet = self.txt(pf, node).replace("\n", " ")[:110]
        dead = frame.dead or self.is_dead(pf, node)
        for t in taints:
            status, applied = self.judge(t, sink_class)
            if dead:
                status = "unreachable"
            steps = t.steps + ((pf.path, line, f"reaches {R.sink_label(sink_class)} sink {label}"),)
            files = tuple(dict.fromkeys([t.file] + [s[0] for s in steps]))
            fl = Flow(t.kind, t.file, t.line, t.snippet, sink_class, label, pf.path, line, snippet, steps, status,
                      tuple(t.mitigations), t.assumptions, files, self.attr)
            self.keep(fl)

    def keep(self, fl: Flow) -> None:
        """Insert a flow, keeping the worst-case status; ties broken deterministically so results never depend on
        discovery order (required for incremental == clean)."""
        old = self.flows.get(fl.key)
        if old is None or self._order(fl) < self._order(old):
            self.flows[fl.key] = fl

    @staticmethod
    def _order(f: Flow) -> tuple:
        return (_STATUS_RANK[f.status], len(f.steps), repr(f.steps), f.assumptions, tuple(m.name for m in f.mitigations))

    @staticmethod
    def judge(t: Taint, sink_class: str) -> tuple[str, tuple]:
        eff = [m for m in t.mitigations if sink_class in m.effective]
        if eff:
            return "sanitized", tuple(eff)
        unc = [m for m in t.mitigations if sink_class in m.uncertain]
        if unc:
            return "uncertain", tuple(unc)
        return "candidate", ()

    def is_dead(self, pf, node) -> bool:
        cur = node.parent
        while cur is not None:
            if cur.type == "if_statement":
                cond = cur.child_by_field_name("condition")
                cons = cur.child_by_field_name("consequence")
                alt = cur.child_by_field_name("alternative")
                tr = self.const_truth(pf, self.unwrap(cond)) if cond is not None else None
                if tr is False and cons is not None and cons.start_byte <= node.start_byte <= cons.end_byte:
                    return True
                if tr is True and alt is not None and alt.start_byte <= node.start_byte <= alt.end_byte:
                    return True
            cur = cur.parent
        return False

    # ------------------------------------------------------------------ roots
    def run(self, only_files: set[str] | None = None) -> None:
        targets = sorted(p for p in self.files if (only_files is None or p in only_files))
        if only_files is None and not self.isolate_roots:
            for path in sorted(self.files):
                self.get_module(path)                  # module bodies first: exports must exist before callers need them
        for path in targets:
            self.get_module(path)
        for path in targets:
            self.root_files.add(path)
            self.attr = path
            if self.isolate_roots:
                self._memo.clear()
            self.run_roots(path)
            self.attr = ""
        self.drain_pending(targets)
        self.check_vue_templates()

    def run_roots(self, path: str) -> None:
        pf = self.files[path]
        m = self.modules.get(path)
        if m is None:
            return
        for fv in self.top_level_functions(pf, m):
            self.analyze_clean(fv, pf)

    def top_level_functions(self, pf, m) -> list[FnVal]:
        out: list[FnVal] = []
        seen: set = set()

        def visit(node):
            for c in node.children:
                if c.type in ("function_declaration", "generator_function_declaration"):
                    nm = c.child_by_field_name("name")
                    name = self.txt(pf, nm) if nm is not None else "<fn>"
                    v = m.scope.vars.get(name)
                    fv = v.fn if v is not None and v.fn is not None and v.fn.node.id == c.id else self.make_fn(pf, c, m.scope, name)
                    if fv.key not in seen:
                        seen.add(fv.key)
                        out.append(fv)
                elif c.type in ("export_statement", "statement_block", "expression_statement", "program"):
                    visit(c)
        visit(pf.tree.root_node)
        for name, v in list(m.scope.vars.items()):
            if v.fn is not None and v.fn.file == pf.path and v.fn.key not in seen:
                seen.add(v.fn.key)
                out.append(v.fn)
            for pv in (v.props or {}).values():
                if pv.fn is not None and pv.fn.file == pf.path and pv.fn.key not in seen:
                    seen.add(pv.fn.key)
                    out.append(pv.fn)
        return out

    def analyze_clean(self, fv: FnVal, pf=None) -> None:
        k = (fv.key, "clean")
        if k in self._analyzed_clean or fv.file not in self.files:
            return
        self._analyzed_clean.add(k)
        pf = self.files[fv.file]
        n = len(fv.node.child_by_field_name("parameters").named_children) if fv.node.child_by_field_name("parameters") is not None else 1
        self.call_fn(fv, [CLEAN] * n, fv.node, Frame(fv.file), pf)

    def drain_pending(self, targets: list[str]) -> None:
        guard = 0
        tset = set(targets)
        while self.pending and guard < 200_000:
            guard += 1
            fv = self.pending.pop(0)
            if fv.file in tset:
                self.attr = fv.file
                if self.isolate_roots:
                    self._memo.clear()
                self.analyze_clean(fv)
                self.attr = ""

    # ------------------------------------------------------------------ Vue templates
    def check_vue_templates(self) -> None:
        for script_path, art_path, line, expr in self.vue_templates:
            root = re.match(r"[A-Za-z_$][\w$]*", expr.strip())
            if not root:
                continue
            ts = self.vue_state.get((script_path, root.group(0)))
            if not ts:
                continue
            if script_path in self.suppressed:
                continue
            for t in ts:
                status, applied = self.judge(t, "html")
                steps = t.steps + ((art_path, line, f"rendered by v-html=\"{expr.strip()}\" in the template"),)
                self.keep(Flow(t.kind, t.file, t.line, t.snippet, "html", "v-html", art_path, line, f'v-html="{expr.strip()}"',
                               steps, status, tuple(applied), t.assumptions, tuple(dict.fromkeys([t.file] + [s[0] for s in steps])),
                               script_path))


def join_all(vals: list[Val]) -> Val:
    out: Val | None = None
    for v in vals:
        out = join(out, v)
    return out if out is not None else CLEAN

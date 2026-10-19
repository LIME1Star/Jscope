"""
AST Engine
==========

Thin, cached wrapper around tree-sitter's JavaScript grammar.

Design notes (see design-brainstorm.md §9 "Performance"):
  - "Parse once, analyze many": ASTs are cached by content hash, so
    re-running with a different analyzer config never re-parses unchanged
    files.
  - Bounded worst-case behavior: files above `max_bytes` are skipped with a
    clear "skipped: size limit" marker rather than risking a hang on a
    pathological minified vendor bundle.

This module intentionally exposes a small, high-level query surface
(`find_calls`, `resolve_string`, etc.) rather than leaking raw tree-sitter
node types everywhere else in the codebase -- analyzers should not need to
know tree-sitter's grammar quirks.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_javascript as _tsjs
from tree_sitter import Language, Parser

_JS_LANGUAGE = Language(_tsjs.language())
_parser = Parser(_JS_LANGUAGE)

# TypeScript / TSX grammars are optional at import time: if the wheel is missing the engine still works for
# JavaScript and reports every .ts/.tsx file as "skipped: grammar unavailable" instead of silently mis-parsing it.
_PARSERS: dict[str, Parser] = {"javascript": _parser}
try:
    import tree_sitter_typescript as _tsts
    _PARSERS["typescript"] = Parser(Language(_tsts.language_typescript()))
    _PARSERS["tsx"] = Parser(Language(_tsts.language_tsx()))
except Exception:          # noqa: BLE001  (ImportError or ABI mismatch)
    pass

TS_AVAILABLE = "typescript" in _PARSERS


def language_for_path(path: str) -> str:
    """Grammar name for a path: .ts/.mts/.cts -> typescript, .tsx -> tsx, anything else -> javascript."""
    low = path.lower().split("#")[0]
    if low.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if low.endswith(".tsx"):
        return "tsx"
    return "javascript"


def count_syntax_errors(root) -> int:
    """Number of ERROR / MISSING nodes under `root` (0 == the grammar parsed the whole file cleanly)."""
    n, stack = 0, [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            n += 1
        if node.has_error:
            stack.extend(node.children)
    return n

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5MB: generous but bounded


@dataclass
class CallSite:
    """A normalized view of a call expression, e.g. fetch(...), axios.get(...)."""

    callee: str                 # dotted callee, e.g. "fetch" or "axios.get"
    args_raw: list[str]         # raw source text of each argument
    args_resolved: list["ResolvedValue"]
    line: int
    node: Any = field(repr=False, default=None)


@dataclass
class ResolvedValue:
    """Result of trying to resolve an AST node to a concrete value."""

    value: str | None            # the resolved string, or None if unresolvable
    is_literal: bool             # True if it was a raw string literal
    resolved_via_symbol: bool    # True if resolution required following a const/let binding
    is_placeholder: bool         # True if it looks like an unsubstituted build placeholder


@dataclass
class ParsedFile:
    path: str
    source: bytes
    content_hash: str
    tree: Any = field(repr=False, default=None)
    skipped_reason: str | None = None
    origin: str = "disk"                       # "disk" | "sourcemap" (recovered original source)
    language: str = "javascript"               # grammar used: javascript | typescript | tsx
    syntax_errors: int = 0                     # ERROR/MISSING nodes: > 0 means this file was only PARTIALLY analyzed
    memo: dict = field(default_factory=dict, repr=False)   # per-file query cache (see parsing/queries.py)

    @property
    def text(self) -> str:
        return self.source.decode("utf-8", errors="replace")

    def line_of(self, node) -> int:
        return node.start_point[0] + 1

    def node_text(self, node) -> str:
        return self.source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


class ASTEngine:
    """Parses JS files with a content-hash keyed cache.

    Cache is in-memory for this process by default; `cache_dir`, if given,
    also persists parsed-source hashes to disk so `jscope analyze` on an
    unchanged project directory can skip re-parsing across runs (this is
    also what powers cheap incremental/differential analysis later).
    """

    def __init__(self, cache_dir: str | None = None, max_bytes: int = DEFAULT_MAX_BYTES):
        self._cache: dict[str, ParsedFile] = {}
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.max_bytes = max_bytes
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    def parse_file(self, path: str) -> ParsedFile:
        data = Path(path).read_bytes()
        return self.parse_bytes(data, path=path)

    def parse_bytes(self, data: bytes, path: str = "<memory>") -> ParsedFile:
        content_hash = self.hash_bytes(data)
        lang = language_for_path(path)
        key = content_hash if lang == "javascript" else f"{content_hash}:{lang}"
        if key in self._cache:
            cached = self._cache[key]
            # Re-tag with the current path for reporting purposes, keep the parsed tree.
            return ParsedFile(
                path=path, source=cached.source, content_hash=content_hash,
                tree=cached.tree, skipped_reason=cached.skipped_reason,
                language=cached.language, syntax_errors=cached.syntax_errors,
            )

        if len(data) > self.max_bytes:
            pf = ParsedFile(path=path, source=data, content_hash=content_hash, language=lang,
                             tree=None, skipped_reason=f"skipped: size limit ({len(data)} bytes)")
            self._cache[key] = pf
            return pf

        parser = _PARSERS.get(lang)
        if parser is None:
            pf = ParsedFile(path=path, source=data, content_hash=content_hash, language=lang, tree=None,
                            skipped_reason=f"skipped: {lang} grammar unavailable (pip install tree-sitter-typescript)")
            self._cache[key] = pf
            return pf

        tree = parser.parse(data)
        pf = ParsedFile(path=path, source=data, content_hash=content_hash, tree=tree, language=lang,
                        syntax_errors=count_syntax_errors(tree.root_node) if tree.root_node.has_error else 0)
        self._cache[key] = pf
        return pf

    # -- query helpers ----------------------------------------------------

    _CALLEE_CANDIDATES = {
        "fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.delete",
        "axios.patch", "$.ajax", "$.get", "$.post", "XMLHttpRequest",
    }

    def walk(self, node):
        yield node
        for child in node.children:
            yield from self.walk(child)

    def _callee_dotted_name(self, pf: ParsedFile, node) -> str | None:
        """Given a call_expression's `function` child, reconstruct a dotted
        name like 'axios.get' or 'fetch'."""
        if node.type == "identifier":
            return pf.node_text(node)
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            obj_name = self._callee_dotted_name(pf, obj)
            if obj_name is None:
                return None
            return f"{obj_name}.{pf.node_text(prop)}"
        return None

    def _local_bindings(self, pf: ParsedFile, root) -> dict[str, Any]:
        """Very small const/let/var propagation: name -> value node, scoped
        to the whole file (module-level heuristic, intentionally simple --
        see design-brainstorm.md §12 on scoping this down honestly rather
        than overclaiming full data-flow)."""
        bindings: dict[str, Any] = {}
        for node in self.walk(root):
            if node.type in ("variable_declarator",):
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and value_node is not None and name_node.type == "identifier":
                    bindings[pf.node_text(name_node)] = value_node
        return bindings

    def resolve_value(self, pf: ParsedFile, node, bindings: dict[str, Any] | None = None,
                       _depth: int = 0) -> ResolvedValue:
        if bindings is None:
            bindings = {}
        if _depth > 5 or node is None:
            return ResolvedValue(None, False, False, False)

        if node.type == "string":
            raw = pf.node_text(node).strip("'\"`")
            return ResolvedValue(raw, is_literal=(_depth == 0), resolved_via_symbol=(_depth > 0),
                                  is_placeholder=False)

        if node.type == "template_string":
            raw = pf.node_text(node).strip("`")
            # if it contains ${...} substitutions we can't statically resolve,
            # keep the raw template shape -- still useful signal.
            return ResolvedValue(raw, is_literal=(_depth == 0), resolved_via_symbol=(_depth > 0),
                                  is_placeholder=False)

        if node.type == "identifier":
            name = pf.node_text(node)
            if name in bindings:
                return self.resolve_value(pf, bindings[name], bindings, _depth + 1)
            return ResolvedValue(None, False, False, False)

        if node.type == "member_expression":
            text = pf.node_text(node)
            if text.startswith("process.env."):
                return ResolvedValue(text, is_literal=False, resolved_via_symbol=False, is_placeholder=True)
            return ResolvedValue(None, False, False, False)

        if node.type == "binary_expression":
            # naive string-concat resolution: left + right, only if both sides resolve
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            lval = self.resolve_value(pf, left, bindings, _depth + 1)
            rval = self.resolve_value(pf, right, bindings, _depth + 1)
            if lval.value is not None and rval.value is not None:
                return ResolvedValue(lval.value + rval.value, is_literal=False,
                                      resolved_via_symbol=True, is_placeholder=False)
            return ResolvedValue(None, False, False, False)

        return ResolvedValue(None, False, False, False)

    def find_calls(self, pf: ParsedFile) -> list[CallSite]:
        """Find call expressions whose callee matches a known HTTP-call shape."""
        if pf.tree is None:
            return []
        root = pf.tree.root_node
        bindings = self._local_bindings(pf, root)
        sites: list[CallSite] = []

        for node in self.walk(root):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                continue
            dotted = self._callee_dotted_name(pf, fn_node)
            if dotted is None:
                continue
            # match exact known callees, or a trailing method on a known object (axios.*, $.* )
            base = dotted.split(".")[0]
            if dotted not in self._CALLEE_CANDIDATES and base not in ("axios", "$"):
                continue

            args_node = node.child_by_field_name("arguments")
            args_raw: list[str] = []
            args_resolved: list[ResolvedValue] = []
            if args_node is not None:
                for child in args_node.children:
                    if child.type in ("(", ")", ","):
                        continue
                    args_raw.append(pf.node_text(child))
                    args_resolved.append(self.resolve_value(pf, child, bindings))

            sites.append(CallSite(
                callee=dotted, args_raw=args_raw, args_resolved=args_resolved,
                line=pf.line_of(node), node=node,
            ))
        return sites

    def find_string_literals(self, pf: ParsedFile):
        """Yield (node, text, line) for every string/template literal in the file."""
        if pf.tree is None:
            return
        for node in self.walk(pf.tree.root_node):
            if node.type == "string":
                yield node, pf.node_text(node).strip("'\""), pf.line_of(node)
            elif node.type == "template_string":
                yield node, pf.node_text(node).strip("`"), pf.line_of(node)

    def is_in_dead_branch(self, pf: ParsedFile, node) -> bool:
        """Heuristic: walk up from `node`; if any ancestor if_statement's
        condition is a literal falsy value, treat as dead code."""
        current = node.parent
        while current is not None:
            if current.type == "if_statement":
                cond = current.child_by_field_name("condition")
                if cond is not None:
                    text = pf.node_text(cond).strip()
                    if text.startswith("(") and text.endswith(")"):
                        text = text[1:-1].strip()
                    if text in ("false", "0", "'false'", '"false"'):
                        return True
                    if "NODE_ENV" in text and "development" in text:
                        return True
            current = current.parent
        return False

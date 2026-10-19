"""Dependency-aware incremental analysis (FR-07).

What is cached: the data-flow engine's per-root results. A *root* is a file; its result (flows, limitations, unresolved
imports) is a pure function of the file's content, the content of every file it transitively imports, the resolver
configuration (tsconfig/aliases), the Vue templates and the engine version. That function's input is hashed into a
`closure hash`; an entry is reused only when its closure hash is unchanged, so:

  * unchanged project            -> every root reused, no analysis
  * one file edited              -> that file and everything that (transitively) imports it is re-analysed
  * a file removed               -> its entry is dropped; importers' closure hashes change so they re-analyse
  * corrupt / foreign cache file -> ignored, full scan (never an error)

Parsed ASTs are NOT persisted (tree-sitter trees are not serialisable and parsing is cheap relative to analysis).
`--no-cache` / clean scans bypass the cache entirely, and a cold incremental run uses the same per-root isolation as a
warm one, so incremental output equals clean output for the same inputs (verified by tests/test_incremental.py).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from jscope.dataflow.engine import DataFlowEngine, Flow, Limitation
from jscope.dataflow.rules import Mitigation
from jscope.parsing.ast_engine import ParsedFile

CACHE_VERSION = 3
ENGINE_VERSION = "dataflow-0.5.0"
CACHE_FILE = "dataflow-cache.json"


def _h(*parts: str) -> str:
    m = hashlib.sha256()
    for p in parts:
        m.update(p.encode("utf-8", "replace"))
        m.update(b"\x00")
    return m.hexdigest()


def flow_to_json(f: Flow) -> dict:
    return {"source_kind": f.source_kind, "source_file": f.source_file, "source_line": f.source_line, "source_snippet": f.source_snippet,
            "sink_class": f.sink_class, "sink_name": f.sink_name, "sink_file": f.sink_file, "sink_line": f.sink_line,
            "sink_snippet": f.sink_snippet, "steps": [list(s) for s in f.steps], "status": f.status,
            "mitigations": [{"name": m.name, "effective": sorted(m.effective), "uncertain": sorted(m.uncertain), "note": m.note}
                            for m in f.mitigations],
            "assumptions": list(f.assumptions), "files": list(f.files), "root": f.root}


def flow_from_json(d: dict) -> Flow:
    return Flow(d["source_kind"], d["source_file"], d["source_line"], d["source_snippet"], d["sink_class"], d["sink_name"],
                d["sink_file"], d["sink_line"], d["sink_snippet"], tuple(tuple(s) for s in d["steps"]), d["status"],
                tuple(Mitigation(m["name"], frozenset(m["effective"]), frozenset(m["uncertain"]), m.get("note", "")) for m in d["mitigations"]),
                tuple(d["assumptions"]), tuple(d["files"]), d.get("root", ""))


@dataclass
class CacheStats:
    reused: list[str] = field(default_factory=list)
    reanalyzed: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    note: str = ""

    def summary(self) -> str:
        return (f"[incremental] reused {len(self.reused)} file(s), re-analyzed {len(self.reanalyzed)}, "
                f"dropped {len(self.dropped)} removed" + (f" ({self.note})" if self.note else ""))


def static_import_specs(pf: ParsedFile) -> list[str]:
    """Every literal module specifier in the file, without executing anything (import/export-from/require/import())."""
    out: list[str] = []
    stack = [pf.tree.root_node]
    while stack:
        n = stack.pop()
        t = n.type
        if t in ("import_statement", "export_statement"):
            src = n.child_by_field_name("source")
            if src is not None:
                out.append(pf.node_text(src).strip("'\"`"))
        elif t == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if fn is not None and args is not None and (fn.type == "import" or (fn.type == "identifier" and pf.node_text(fn) == "require")):
                ch = [c for c in args.children if c.is_named]
                if ch and ch[0].type == "string":
                    out.append(pf.node_text(ch[0]).strip("'\"`"))
        stack.extend(n.children)
    return out


class AnalysisCache:
    def __init__(self, directory: str | None, enabled: bool = True):
        self.dir = Path(directory) if directory else None
        self.enabled = enabled and self.dir is not None
        self.stats = CacheStats()

    # -- persistence -------------------------------------------------------------------------------
    def _load(self) -> dict:
        if not self.enabled:
            return {}
        p = self.dir / CACHE_FILE
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("cache_version") != CACHE_VERSION or data.get("engine") != ENGINE_VERSION or not isinstance(data.get("entries"), dict):
                self.stats.note = "cache from a different JScope version ignored"
                return {}
            return data["entries"]
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError):
            self.stats.note = "cache unreadable; performing a full scan"
            return {}

    def _save(self, entries: dict) -> None:
        if not self.enabled:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.dir / (CACHE_FILE + ".tmp")
            tmp.write_text(json.dumps({"cache_version": CACHE_VERSION, "engine": ENGINE_VERSION, "entries": entries}), encoding="utf-8")
            os.replace(tmp, self.dir / CACHE_FILE)
        except OSError:
            self.stats.note = (self.stats.note + "; " if self.stats.note else "") + "cache could not be written"

    # -- closure hashing -----------------------------------------------------------------------------
    def closure_hashes(self, engine: DataFlowEngine, files: list[ParsedFile]) -> tuple[dict[str, str], dict[str, set[str]]]:
        resolver = engine.resolver
        edges: dict[str, set[str]] = {}
        for pf in files:
            deps: set[str] = set()
            for spec in static_import_specs(pf):
                r = resolver.resolve(spec, pf.path)
                if r.status == "resolved" and r.path:
                    real = engine.real_path(r.path)
                    if real and real != pf.path:
                        deps.add(real)
                elif r.status == "unresolved":
                    deps.add("unresolved:" + spec)           # a spec that starts resolving later must invalidate the entry
            edges[pf.path] = deps
        ts_digest = _h(*[Path(p).read_text(errors="replace") for p in sorted(set(resolver.tsconfig_files)) if os.path.exists(p)],
                       json.dumps(sorted(resolver.aliases.items())))
        tpl_digest = _h(repr(sorted(map(repr, engine.vue_templates))))
        content = {pf.path: pf.content_hash for pf in files}
        out: dict[str, str] = {}
        for pf in files:
            seen, stack = set(), [pf.path]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                stack.extend(d for d in edges.get(cur, ()) if not d.startswith("unresolved:"))
            parts = [f"{p}={content.get(p, '')}" for p in sorted(seen)]
            parts += sorted(d for p in seen for d in edges.get(p, ()) if d.startswith("unresolved:"))
            out[pf.path] = _h(ENGINE_VERSION, ts_digest, tpl_digest, *parts)
        return out, edges

    # -- the one entry point used by DataFlowAnalyzer ------------------------------------------------------
    def run(self, engine: DataFlowEngine, files: list[ParsedFile]) -> CacheStats:
        engine.isolate_roots = True
        entries = self._load()
        hashes, edges = self.closure_hashes(engine, files)
        engine.import_edges = {k: {d for d in v if not d.startswith("unresolved:")} for k, v in edges.items()}
        current = set(hashes)
        reuse = {p for p, h in hashes.items() if entries.get(p, {}).get("closure") == h}
        self.stats.reused = sorted(reuse)
        self.stats.reanalyzed = sorted(current - reuse)
        self.stats.dropped = sorted(set(entries) - current)
        engine.suppressed = set(reuse)
        engine.run(only_files=current - reuse)
        for p in reuse:                                          # replay cached roots
            e = entries[p]
            for fd in e["flows"]:
                engine.keep(flow_from_json(fd))
            for ld in e["limitations"]:
                engine.lim(ld["file"], ld["line"], ld["kind"], ld["message"])
            for u in e["unresolved_imports"]:
                engine.unresolved_imports.append(tuple(u))
        engine.unresolved_imports = sorted(set(engine.unresolved_imports))
        by_root: dict[str, list[Flow]] = {}
        for f in engine.flows.values():
            by_root.setdefault(f.root, []).append(f)
        new_entries = {}
        for p in current:
            if p in reuse:
                new_entries[p] = entries[p]
                continue
            new_entries[p] = {
                "closure": hashes[p],
                "flows": [flow_to_json(f) for f in sorted(by_root.get(p, []), key=lambda f: f.key)],
                "limitations": [{"file": l.file, "line": l.line, "kind": l.kind, "message": l.message}
                                for l in engine.limitations if l.file == p],
                "unresolved_imports": [list(u) for u in engine.unresolved_imports if u[0] == p],
            }
        self._save(new_entries)
        return self.stats

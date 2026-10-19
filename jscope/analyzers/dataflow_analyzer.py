"""Data-flow analyzer (FR-01/FR-02): proposes Candidates for source -> sink paths found by the interprocedural engine.

Every Candidate states what is known and what is assumed. A static data-flow path is a *security hypothesis*: it never
reaches CONFIRMED on its own (the evidence weights cap it below that) and it carries `verification_status: unverified`
until `jscope verify` reproduces it.
"""

from __future__ import annotations

import os
from typing import Any

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind
from jscope.dataflow import rules as R
from jscope.dataflow.engine import DataFlowEngine, Flow
from jscope.dataflow.modules import ModuleResolver

SURFACE = {"html": "dom_xss_candidate", "code": "code_injection_candidate", "navigation": "open_redirect_candidate",
           "sql": "sql_injection_candidate", "command": "command_injection_candidate"}
TESTS = {
    "html": "Put a unique marker (e.g. `jscope\"><i id=jscx>`) into the source and check, in a browser, whether it is parsed as markup at the sink. "
            "Use `jscope verify` with a scoped, authorised target to do this safely.",
    "code": "Send a harmless unique expression through the source and confirm in the browser console whether it is evaluated.",
    "navigation": "Supply an absolute URL on a domain you control and observe whether the browser navigates there; also try `//host` and `javascript:` forms.",
    "sql": "Review the server code that builds this query; send a single quote and compare errors/timing in an authorised environment.",
    "command": "Review how the command string is built; test only with harmless metacharacter probes in an authorised environment.",
}


def _short(path: str) -> str:
    return os.path.basename(path.split("#")[0]) + ("#" + path.split("#")[1] if "#" in path else "")


def flow_to_dict(f: Flow) -> dict[str, Any]:
    return {
        "source": {"kind": f.source_kind, "description": R.HUMAN_SOURCE.get(f.source_kind, f.source_kind), "file": f.source_file,
                   "line": f.source_line, "snippet": f.source_snippet},
        "sink": {"class": f.sink_class, "name": f.sink_name, "file": f.sink_file, "line": f.sink_line, "snippet": f.sink_snippet},
        "status": f.status, "cross_file": f.cross_file,
        "path": [{"file": s[0], "line": s[1], "step": s[2]} for s in f.steps],
        "mitigations": [{"name": m.name, "effective_for": sorted(m.effective), "uncertain_for": sorted(m.uncertain), "note": m.note}
                        for m in f.mitigations],
        "assumptions": list(f.assumptions),
    }


class DataFlowAnalyzer(Analyzer):
    name = "dataflow_analyzer"
    version = "0.5.0"
    depends_on: list[str] = []
    run_after = ["framework_detector"]
    produces_categories = ["dataflow"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        usable = []
        for pf in ctx.files:
            if pf.skipped_reason:
                ctx.add_file_diagnostic(pf.path, f"not analyzed: {pf.skipped_reason}")
            elif pf.tree is None:
                ctx.add_file_diagnostic(pf.path, "not analyzed: no syntax tree")
            else:
                if pf.syntax_errors:
                    ctx.add_file_diagnostic(pf.path, f"partially analyzed: {pf.syntax_errors} syntax error node(s); "
                                                     "constructs inside them are invisible to JScope")
                usable.append(pf)
        keys = [(pf.path.split("#")[0] if pf.origin == "vue-sfc" else pf.path) for pf in usable]
        resolver = ModuleResolver(keys, aliases=ctx.config.get("module_aliases") or {})
        vue_templates = self._vue_templates(ctx)
        engine = DataFlowEngine(usable, resolver, vue_templates)

        cache = ctx.shared.get("dataflow_cache")                 # jscope.core.cache.AnalysisCache | None (FR-07)
        if cache is not None:
            stats = cache.run(engine, usable)
            ctx.diagnostics.append(stats.summary())
            ctx.shared["incremental"] = {"reused": stats.reused, "reanalyzed": stats.reanalyzed, "dropped": stats.dropped}
        else:
            engine.run()

        for lim in engine.limitations:
            if lim.kind in ("unresolved-import", "dynamic-import", "dynamic-require", "budget", "circular-import"):
                ctx.add_file_diagnostic(lim.file, f"{lim.kind}: {lim.message}")
        for path in engine.truncated_files:
            ctx.add_file_diagnostic(path, "partially analyzed: data-flow budget exceeded")
        if resolver.tsconfig_files:
            ctx.shared["tsconfig_files"] = sorted(set(resolver.tsconfig_files))

        flows = sorted(engine.flows.values(), key=lambda f: (f.sink_file, f.sink_line, f.source_file, f.source_line))
        self._populate_graph(ctx, flows)
        ctx.shared["dataflow"] = {
            "flows": [flow_to_dict(f) for f in flows],
            "limitations": [{"file": l.file, "line": l.line, "kind": l.kind, "message": l.message} for l in engine.limitations],
            "import_edges": {k: sorted(v) for k, v in engine.import_edges.items()},
            "unresolved_imports": [{"file": a, "line": b, "specifier": c, "reason": d} for a, b, c, d in engine.unresolved_imports],
            "counts": {s: sum(1 for f in flows if f.status == s) for s in ("candidate", "uncertain", "sanitized", "unreachable")},
        }
        return [self._candidate(f, ctx, engine) for f in flows if f.status != "sanitized"]

    def _populate_graph(self, ctx: ProjectContext, flows) -> None:
        """FR-05: every flow becomes `data_source -[flows_to]-> data_sink` in the knowledge graph, file-attributed and
        tagged with how certain the path is -- distinct from an unrelated finding simply mentioning the same file."""
        g = ctx.graph
        for f in flows:
            src_id = f"dsrc:{f.source_file}:{f.source_line}:{f.source_kind}"
            sink_id = f"dsink:{f.sink_file}:{f.sink_line}:{f.sink_name}"
            g.add_node(src_id, NodeKind.DATA_SOURCE, R.HUMAN_SOURCE.get(f.source_kind, f.source_kind), kind_detail=f.source_kind)
            g.add_node(sink_id, NodeKind.DATA_SINK, f.sink_name, sink_class=f.sink_class)
            exactness = "exact" if not f.assumptions and f.status != "uncertain" else "heuristic"
            g.add_edge(src_id, sink_id, EdgeKind.FLOWS_TO, self.name,
                      "DATA_FLOW" if f.status != "sanitized" else "DATA_FLOW_SANITIZED", f.sink_file, f.sink_line,
                      note=f"status={f.status} exactness={exactness}" + (f"; assumes {'; '.join(f.assumptions)}" if f.assumptions else ""))
            src_file_node, sink_file_node = f"file:{f.source_file}", f"file:{f.sink_file}"
            g.add_node(src_file_node, NodeKind.FILE, f.source_file.rsplit("/", 1)[-1])
            g.add_node(sink_file_node, NodeKind.FILE, f.sink_file.rsplit("/", 1)[-1])
            g.add_edge(src_file_node, src_id, EdgeKind.CONTAINS, self.name, "AST_PATTERN_MATCH", f.source_file, f.source_line)
            g.add_edge(sink_file_node, sink_id, EdgeKind.CONTAINS, self.name, "AST_PATTERN_MATCH", f.sink_file, f.sink_line)

    # --------------------------------------------------------------------------------------------------
    def _vue_templates(self, ctx: ProjectContext) -> list[tuple]:
        out = []
        try:
            from jscope.parsing.html import soup
        except Exception:      # noqa: BLE001
            return out
        for art in ctx.artifacts_of("vue"):
            try:
                tpl = soup(art).find("template")
                if tpl is None:
                    continue
                for el in tpl.find_all(True):
                    expr = el.attrs.get("v-html")
                    if isinstance(expr, str) and expr.strip():
                        out.append((art.path + "#script", art.path, getattr(el, "sourceline", None) or 1, expr))
            except Exception as exc:     # noqa: BLE001
                ctx.add_file_diagnostic(art.path, f"template analysis failed: {type(exc).__name__}")
        # script paths for lang="ts" blocks carry a suffix; make both spellings match
        extra = []
        pfs = {pf.path for pf in ctx.files}
        for sp, ap, ln, ex in out:
            for alt in (sp + ".ts", sp + ".tsx"):
                if alt in pfs:
                    extra.append((alt, ap, ln, ex))
        return out + extra

    def _candidate(self, f: Flow, ctx: ProjectContext, engine: DataFlowEngine) -> Candidate:
        src_h = R.HUMAN_SOURCE.get(f.source_kind, f.source_kind)
        subject = (f"{f.source_kind} -> {f.sink_name} @ {_short(f.sink_file)}:{f.sink_line}"
                   f" (source {_short(f.source_file)}:{f.source_line})")
        path_txt = " -> ".join(f"{_short(s[0])}:{s[1]} {s[2]}" for s in f.steps)
        partial = bool(f.assumptions) or f.status == "uncertain"
        ev: list[Evidence] = [
            Evidence(ET.AST_PATTERN_MATCH, f"{R.sink_label(f.sink_class)} sink {f.sink_name} receives a value derived from {src_h}",
                     self.name, f.sink_file, f.sink_line, f.sink_snippet, {"sink_class": f.sink_class}),
        ]
        why = [f"source: {src_h} at {_short(f.source_file)}:{f.source_line}"]
        if f.assumptions:
            why.append("assumptions: " + "; ".join(f.assumptions))
        if f.status == "uncertain":
            why.append("uncertain validation: " + "; ".join(f"{m.name} ({m.note})" if m.note else m.name for m in f.mitigations))
        ev.append(Evidence(
            ET.DATA_FLOW_PARTIAL if partial else ET.DATA_FLOW,
            ("PARTIAL data-flow path (" + "; ".join(why[1:]) + "): " if partial else "data-flow path: ") + path_txt,
            self.name, f.source_file, f.source_line, f.source_snippet,
            {"path": [{"file": s[0], "line": s[1], "step": s[2]} for s in f.steps], "partial": partial}))
        if f.cross_file:
            ev.append(Evidence(ET.IMPORT_CHAIN, f"the path crosses {len(set(f.files))} files: " + " -> ".join(_short(x) for x in f.files),
                               self.name, f.sink_file, f.sink_line, None, {"files": list(f.files)}))
        if f.status == "unreachable":
            ev.append(Evidence(ET.DEAD_CODE, "the sink sits in a branch that is statically never taken", self.name, f.sink_file, f.sink_line))
        if is_test_path(f.sink_file):
            ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "sink lives in a test/mock/fixture path", self.name, f.sink_file, f.sink_line))
        low = f.sink_file.lower()
        if ".min." in low or "/vendor/" in low or "node_modules" in low:
            ev.append(Evidence(ET.VENDOR_CODE, "sink is inside vendor/minified code", self.name, f.sink_file, f.sink_line))
        hints = ctx.framework_hints
        if (f.sink_name == "dangerouslySetInnerHTML" and "react" in hints) or (f.sink_name == "v-html" and "vue" in hints):
            ev.append(Evidence(ET.FRAMEWORK_CONTEXT, f"{f.sink_name} is the framework's explicit raw-HTML escape hatch", self.name,
                               f.sink_file, f.sink_line))
        limitations = list(f.assumptions)
        limitations.append("static analysis only: exploitability depends on runtime behaviour and server-side handling that JScope has not observed")
        if f.status == "uncertain":
            limitations.append("a validator on the path may or may not be sufficient; verify manually")
        return Candidate(
            category="dataflow", subject=subject, analyzer=self.name, evidence=ev,
            attack_surface=SURFACE.get(f.sink_class), suggested_test=TESTS.get(f.sink_class),
            metadata={
                "flow": flow_to_dict(f), "sink_class": f.sink_class, "source_kind": f.source_kind, "flow_status": f.status,
                "cross_file": f.cross_file, "limitations": limitations,
                "evidence_class": "security_hypothesis", "verification_status": "unverified",
            })

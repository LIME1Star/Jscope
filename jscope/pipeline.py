from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from jscope.analyzers.auth_analyzer import AuthAnalyzer
from jscope.analyzers.authorization_analyzer import AuthorizationAnalyzer
from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.dataflow_analyzer import DataFlowAnalyzer
from jscope.analyzers.endpoint_analyzer import EndpointAnalyzer
from jscope.analyzers.framework_detector import FrameworkDetector
from jscope.analyzers.graphql_analyzer import GraphQLAnalyzer
from jscope.analyzers.graphql_schema_analyzer import GraphQLSchemaAnalyzer
from jscope.analyzers.html_analyzer import HtmlAnalyzer
from jscope.analyzers.openapi_analyzer import OpenApiAnalyzer
from jscope.analyzers.wasm_analyzer import WasmAnalyzer
from jscope.analyzers.manager import AnalyzerManager
from jscope.analyzers.router_analyzer import RouterAnalyzer
from jscope.analyzers.secret_analyzer import SecretAnalyzer
from jscope.analyzers.service_worker_analyzer import ServiceWorkerAnalyzer
from jscope.analyzers.source_map_analyzer import SourceMapAnalyzer, expand_source_maps
from jscope.analyzers.storage_analyzer import StorageAnalyzer
from jscope.config import Config
from jscope.core.artifacts import collect_artifacts
from jscope.core.evidence import Confidence, EvidenceEngine, Finding
from jscope.core.graph import KnowledgeGraph
from jscope.parsing.ast_engine import ASTEngine
from jscope.parsing.html import extract_inline_scripts
from jscope.core.graph import EdgeKind, NodeKind
from jscope.plugin.loader import load_plugins

CORE_ANALYZERS = [FrameworkDetector, EndpointAnalyzer, SecretAnalyzer, RouterAnalyzer, AuthAnalyzer,
                  AuthorizationAnalyzer, StorageAnalyzer, GraphQLAnalyzer, ServiceWorkerAnalyzer,
                  SourceMapAnalyzer, HtmlAnalyzer, OpenApiAnalyzer, GraphQLSchemaAnalyzer, WasmAnalyzer,
                  DataFlowAnalyzer]
_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
_NOT_JS = (".html", ".htm", ".vue", ".wasm", ".graphql", ".gql", ".graphqls", ".json", ".yaml", ".yml", ".d.ts")


def core_analyzers() -> list[Analyzer]:
    return [cls() for cls in CORE_ANALYZERS]


# kept for backward compatibility with Phase 1 callers
ALL_ANALYZERS = core_analyzers()


@dataclass
class AnalysisResult:
    findings: list[Finding]
    frameworks: list[str]
    file_count: int
    engine: EvidenceEngine
    graph: KnowledgeGraph
    diagnostics: list[str] = field(default_factory=list)
    analyzer_counts: dict[str, int] = field(default_factory=dict)
    tiers: dict[str, str] = field(default_factory=dict)
    expanded_sources: int = 0
    file_hashes: dict[str, str] = field(default_factory=dict)   # path -> content hash (disk files only)
    artifact_counts: dict[str, int] = field(default_factory=dict)   # Phase 4: kind -> files analyzed
    dataflow: dict = field(default_factory=dict)                    # 0.5: every flow incl. sanitized/unreachable + limitations
    file_diagnostics: dict[str, list[str]] = field(default_factory=dict)   # 0.5: per-file "skipped / partially analyzed"
    plugin_runs: list[dict] = field(default_factory=list)           # 0.5: plugin identity/version/isolation/outcome


def _collect_js_files(paths: list[str], exclude: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            if path.suffix.lower() not in _NOT_JS:        # html/vue/wasm/spec files are artifacts, not JS (Phase 4)
                out.append(str(path))
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.suffix not in _EXTS or not f.is_file():
                    continue
                rel = str(f)
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
                    continue
                out.append(str(f))
    return sorted(set(out))


def collect_manifest(paths: list[str], config: Config) -> dict[str, str]:
    """path -> content hash for every file that can influence an analysis. Cheap (no parsing).
    Includes sibling `.map` files when source-map expansion is on, since they change the result."""
    exclude = config.get("exclude", [])
    files = _collect_js_files(paths, exclude)
    if config.get("source_maps.expand", False):
        for p in paths:
            if Path(p).is_dir():
                files += [str(f) for f in Path(p).rglob("*.map") if f.is_file()]
    out = {f: ASTEngine.hash_bytes(Path(f).read_bytes()) for f in sorted(set(files))}
    if config.get("artifacts.enabled", True):
        for a in collect_artifacts(paths, exclude):
            out[a.path] = a.content_hash
    return out


def run_analysis(paths: list[str], config: Config) -> AnalysisResult:
    from jscope.analyzers.common import set_analysis_roots
    set_analysis_roots(paths)
    exclude = config.get("exclude", [])
    files = _collect_js_files(paths, exclude)

    ast_engine = ASTEngine(max_bytes=config.get("max_file_bytes", 5 * 1024 * 1024))
    parsed = [ast_engine.parse_file(f) for f in files]

    diagnostics: list[str] = []
    artifacts = collect_artifacts(paths, exclude) if config.get("artifacts.enabled", True) else []
    for art in artifacts:
        if art.kind in ("html", "vue"):                   # inline <script> / .vue <script> become ordinary JS files
            pfs, d = extract_inline_scripts(art, ast_engine)
            parsed += pfs
            diagnostics += d
    expanded = 0
    if config.get("source_maps.expand", False):
        extra, expanded = expand_source_maps(parsed, ast_engine)
        parsed += extra

    ctx = ProjectContext(files=parsed, ast=ast_engine, config=config.data, artifacts=artifacts)
    if config.get("incremental.cache_dir") and config.get("incremental.enabled", True):
        from jscope.core.cache import AnalysisCache
        ctx.shared["dataflow_cache"] = AnalysisCache(config.get("incremental.cache_dir"))

    analyzers = core_analyzers()
    core_names = {a.name for a in analyzers}
    from jscope.plugin.sandbox import SandboxPolicy
    plugin_res = load_plugins(config.get("plugins.paths", []), core_names,
                              set(config.get("plugins.verified", [])),
                              use_entry_points=config.get("plugins.entry_points", True),
                              isolation=config.get("plugins.isolation", "auto"),
                              sandbox_policy=SandboxPolicy(timeout_seconds=float(config.get("plugins.timeout_seconds", 30)),
                                                           memory_mb=int(config.get("plugins.memory_mb", 1024)),
                                                           grant_read=list(config.get("plugins.grant_read", []))))
    analyzers += plugin_res.analyzers
    diagnostics += [f"[plugin-loader] {e}" for e in plugin_res.errors]
    diagnostics += [f"[plugin-isolation] {w}" for w in plugin_res.warnings]

    enabled = set(config.get("analyzers.enabled", [a.name for a in analyzers]))
    enabled |= {a.name for a in plugin_res.analyzers}        # loaded plugins are opt-in by being configured
    tiers = {a.name: a.tier for a in analyzers}

    min_conf = Confidence[config.get("min_confidence", "LOW")]
    cap = Confidence[config.get("plugins.community_confidence_cap", "MEDIUM")]
    engine = EvidenceEngine(min_display_confidence=min_conf, analyzer_tiers=tiers, community_cap=cap)

    manager = AnalyzerManager(analyzers)
    counts = manager.run(ctx, engine, enabled=enabled)
    findings = engine.promote()
    _attach_findings_to_graph(ctx.graph, findings)
    for pf in parsed:                                      # surface per-file parse problems even if no analyzer needed them
        if pf.skipped_reason:
            ctx.add_file_diagnostic(pf.path, f"not analyzed: {pf.skipped_reason}")
        elif pf.syntax_errors:
            ctx.add_file_diagnostic(pf.path, f"partially analyzed: {pf.syntax_errors} syntax error node(s)")

    return AnalysisResult(
        findings=findings, frameworks=sorted(ctx.framework_hints.keys()),
        file_count=sum(1 for p in parsed if p.origin not in ("html-inline", "vue-sfc")) + len(artifacts),
        engine=engine, graph=ctx.graph, diagnostics=diagnostics + ctx.diagnostics,
        analyzer_counts=counts, tiers=tiers, expanded_sources=expanded,
        file_hashes={**{p.path: p.content_hash for p in parsed if p.origin == "disk"}, **{a.path: a.content_hash for a in artifacts}},
        artifact_counts={k: sum(1 for a in artifacts if a.kind == k) for k in sorted({a.kind for a in artifacts})},
        dataflow=ctx.shared.get("dataflow", {}), file_diagnostics=ctx.file_diagnostics,
        plugin_runs=[r.to_dict() for r in ctx.shared.get("plugin_runs", [])] + [
            {"plugin": plugin_res.sources.get(a.name, "?"), "analyzer": a.name, "version": a.version, "tier": a.tier,
             "isolation": "none", "outcome": "ok" if a.name in enabled else "skipped"}
            for a in plugin_res.analyzers if a.name not in plugin_res.isolated])


def analyze_paths(paths: list[str], config: Config) -> tuple[list[Finding], list[str], int, EvidenceEngine]:
    """Phase 1 signature, preserved."""
    r = run_analysis(paths, config)
    return r.findings, r.frameworks, r.file_count, r.engine


def _attach_findings_to_graph(graph, findings) -> None:
    """FR-05: link each promoted Finding back into the graph as a first-class node, so a UI/CLI consumer can walk
    finding -> evidence files -> related data-flow / route / endpoint context in one structure."""
    for f in findings:
        fid = f"finding:{f.id}"
        graph.add_node(fid, NodeKind.FINDING, f.subject, category=f.category, confidence=f.confidence.value, score=f.score)
        flow = f.metadata.get("flow")
        if flow:
            sink_id = f"dsink:{flow['sink']['file']}:{flow['sink']['line']}:{flow['sink']['name']}"
            if sink_id in graph.nodes:
                graph.add_edge(sink_id, fid, EdgeKind.DESCRIBES, "evidence_engine", "DATA_FLOW")
        seen_files = set()
        for e in f.evidence:
            if e.file and e.file not in seen_files:
                seen_files.add(e.file)
                file_node = f"file:{e.file}"
                graph.add_node(file_node, NodeKind.FILE, e.file.rsplit("/", 1)[-1])
                graph.add_edge(fid, file_node, EdgeKind.SUPPORTED_BY, "evidence_engine", e.type.value, e.file, e.line)

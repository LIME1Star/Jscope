"""Analyzer base class. Every analyzer: independent, declares deps, proposes
Candidates only -- never Findings directly (Evidence Engine owns promotion)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jscope.core.artifacts import Artifact
from jscope.core.evidence import Candidate
from jscope.core.graph import KnowledgeGraph
from jscope.parsing.ast_engine import ASTEngine, ParsedFile


@dataclass
class ProjectContext:
    """Shared read-only context passed to every analyzer run."""
    files: list[ParsedFile]
    ast: ASTEngine
    framework_hints: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)
    diagnostics: list[str] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)      # non-JS inputs (Phase 4)
    shared: dict[str, Any] = field(default_factory=dict)         # analyzer -> analyzer facts (declare depends_on!)
    file_diagnostics: dict[str, list[str]] = field(default_factory=dict)   # path -> what was skipped / partially analyzed (FR-02)

    def add_file_diagnostic(self, path: str, message: str) -> None:
        bucket = self.file_diagnostics.setdefault(path, [])
        if message not in bucket:
            bucket.append(message)

    def artifacts_of(self, kind: str) -> list[Artifact]:
        return [a for a in self.artifacts if a.kind == kind]


class Analyzer:
    name: str = "base"
    version: str = "0.1.0"
    depends_on: list[str] = []          # names of analyzers that must run first (hard: error if missing/disabled)
    run_after: list[str] = []           # soft ordering hint: run after these IF they are enabled; ignored otherwise (Phase 4)
    produces_categories: list[str] = []  # e.g. ["endpoint"]
    tier: str = "core"                  # "core" | "verified" | "community" (set by the plugin loader for plugins)

    def analyze_file(self, pf: ParsedFile, ctx: ProjectContext) -> list[Candidate]:
        """Per-file hook. Override in subclasses that work file-by-file."""
        return []

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        """Project-wide hook (cross-file). Default: run analyze_file over all files."""
        out: list[Candidate] = []
        for pf in ctx.files:
            if pf.skipped_reason:
                continue
            out.extend(self.analyze_file(pf, ctx))
        return out

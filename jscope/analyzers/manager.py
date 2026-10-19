"""AnalyzerManager: topologically sorts analyzers by declared dependencies,
runs each project-wide, feeds proposed Candidates into the EvidenceEngine.

Phase 2 hardening -- the propose/promote boundary is now ENFORCED AT RUNTIME,
not just by convention (Python type hints enforce nothing):
  * anything that is not a Candidate is rejected (analyzers cannot emit Findings)
  * evidence is re-attributed to the analyzer that actually produced it, so a
    plugin cannot spoof another analyzer's name to fake CROSS_ANALYZER_AGREEMENT
  * CROSS_ANALYZER_AGREEMENT (engine-only) and RUNTIME_* (prober-only, see apply_runtime_evidence) evidence is dropped
  * a per-candidate evidence cap blocks "confidence farming"
  * one analyzer crashing is recorded as a diagnostic; the run continues
"""

from __future__ import annotations

import dataclasses
import traceback

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, EvidenceEngine, EvidenceType

MAX_EVIDENCE_PER_CANDIDATE = 60
_FORBIDDEN = {EvidenceType.CROSS_ANALYZER_AGREEMENT, EvidenceType.RUNTIME_CONTEXT, EvidenceType.RUNTIME_NOT_FOUND}


class AnalyzerManager:
    def __init__(self, analyzers: list[Analyzer]):
        names = [a.name for a in analyzers]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate analyzer name(s): {', '.join(sorted(dupes))}")
        self.analyzers = {a.name: a for a in analyzers}
        self.diagnostics: list[str] = []

    def _topo_sort(self) -> list[Analyzer]:
        visited: set[str] = set()
        temp: set[str] = set()
        order: list[Analyzer] = []

        def visit(name: str):
            if name in visited:
                return
            if name in temp:
                raise ValueError(f"circular analyzer dependency detected at '{name}'")
            temp.add(name)
            for dep in self.analyzers[name].depends_on:
                if dep not in self.analyzers:
                    raise ValueError(
                        f"analyzer '{name}' depends on '{dep}', which is not registered/enabled"
                    )
                visit(dep)
            for dep in getattr(self.analyzers[name], "run_after", []):
                if dep in self.analyzers:
                    visit(dep)
            temp.discard(name)
            visited.add(name)
            order.append(self.analyzers[name])

        for name in self.analyzers:
            visit(name)
        return order

    def _sanitize(self, analyzer: Analyzer, produced: object) -> list[Candidate]:
        diag = self.diagnostics
        if not isinstance(produced, list):
            diag.append(f"[{analyzer.name}] returned {type(produced).__name__}, expected list[Candidate]; ignored")
            return []
        clean: list[Candidate] = []
        for c in produced:
            if not isinstance(c, Candidate):
                diag.append(f"[{analyzer.name}] emitted a {type(c).__name__}; only Candidates are accepted "
                            "(analyzers cannot create Findings) -- dropped")
                continue
            c.analyzer = analyzer.name
            kept = []
            for e in c.evidence:
                if e.type in _FORBIDDEN:
                    diag.append(f"[{analyzer.name}] tried to emit {e.type.value} on '{c.subject}'; "
                                "this evidence type is engine-controlled -- dropped")
                    continue
                if e.analyzer != analyzer.name:
                    diag.append(f"[{analyzer.name}] evidence on '{c.subject}' claimed analyzer '{e.analyzer}'; "
                                "re-attributed")
                    e = dataclasses.replace(e, analyzer=analyzer.name)
                kept.append(e)
            if len(kept) > MAX_EVIDENCE_PER_CANDIDATE:
                diag.append(f"[{analyzer.name}] '{c.subject}' had {len(kept)} evidence items; "
                            f"truncated to {MAX_EVIDENCE_PER_CANDIDATE}")
                kept = kept[:MAX_EVIDENCE_PER_CANDIDATE]
            c.evidence = kept
            if kept:
                clean.append(c)
        return clean

    def run(self, ctx: ProjectContext, engine: EvidenceEngine, enabled: set[str] | None = None) -> dict[str, int]:
        """Runs all (or `enabled`-filtered) analyzers in dependency order,
        proposing every candidate to `engine`. Returns per-analyzer candidate counts."""
        counts: dict[str, int] = {}
        for analyzer in self._topo_sort():
            if enabled is not None and analyzer.name not in enabled:
                continue
            try:
                candidates = self._sanitize(analyzer, analyzer.analyze_project(ctx))
            except Exception as exc:                      # isolate analyzer failures
                self.diagnostics.append(
                    f"[{analyzer.name}] crashed: {type(exc).__name__}: {exc} "
                    f"({traceback.extract_tb(exc.__traceback__)[-1].name})")
                counts[analyzer.name] = 0
                continue
            counts[analyzer.name] = len(candidates)
            for c in candidates:
                engine.propose(c)
        ctx.diagnostics.extend(self.diagnostics)
        return counts

"""Human-readable report. Structure per design-brainstorm.md §7:
executive snapshot -> attack-surface dossiers -> full findings appendix.
Greppable, not decorative -- no ASCII art, stable field ordering."""

from __future__ import annotations

from jscope.core.evidence import Confidence, Finding
from jscope.core.graph import KnowledgeGraph, NodeKind
from jscope.reporting.priority import PriorityDelta, prioritize

_CONF_ORDER = [Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM,
               Confidence.LOW, Confidence.INFORMATIONAL]


def render(findings: list[Finding], frameworks: list[str], file_count: int,
           verbose: bool = False, top_n: int = 5, graph: KnowledgeGraph | None = None,
           diagnostics: list[str] | None = None, delta: PriorityDelta | None = None,
           preface: str | None = None, artifacts: dict | None = None) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("JSCOPE ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append("")
    if preface:
        lines.append(preface)
        lines.append("")
    lines.append(f"[executive snapshot]")
    lines.append(f"  files analyzed : {file_count}")
    lines.append(f"  frameworks     : {', '.join(frameworks) if frameworks else 'none detected'}")
    if artifacts:
        lines.append("  artifacts      : " + ", ".join(f"{k}={v}" for k, v in sorted(artifacts.items())))
    lines.append(f"  findings       : {len(findings)}")
    for level in _CONF_ORDER:
        n = sum(1 for f in findings if f.confidence == level)
        if n:
            lines.append(f"    {level.value:<14} {n}")
    lines.append("")

    ranked = prioritize(findings, graph, delta)
    if ranked:
        lines.append("[where to start testing]  (deterministic ranking; reasons shown)")
        for f, pts, why in ranked[:top_n]:
            lines.append(f"  {pts:>3}  [{f.confidence.value}] {f.id}  {f.category}: {f.subject}")
            if f.suggested_test:
                lines.append(f"       test: {f.suggested_test}")
            if verbose:
                lines.append(f"       why : {'; '.join(why)}")
        lines.append("")

    if graph is not None and graph.by_kind(NodeKind.ROUTE):
        chains = graph.route_chains()
        lines.append(f"[route map]  {len(chains)} route(s)   (R=route G=guard role=declared role E=endpoint)")
        shown = chains if verbose else sorted(chains, key=lambda c: (not c["unguarded"], c["route"]))[:top_n * 2]
        for c in shown:
            prot = "UNPROTECTED" if c["unguarded"] else "guards=" + ",".join(c["guards"] or ["meta"]) + (
                " roles=" + ",".join(c["roles"]) if c["roles"] else "")
            lines.append(f"  R {c['route']:<28} {prot}")
            for ep in c["endpoints"]:
                lines.append(f"      E {ep}")
        if not verbose and len(chains) > len(shown):
            lines.append(f"  ... {len(chains) - len(shown)} more (use --verbose)")
        lines.append("")

    surfaces: dict[str, list[Finding]] = {}
    for f in findings:
        if f.attack_surface:
            surfaces.setdefault(f.attack_surface, []).append(f)

    if surfaces:
        lines.append("[priority attack surfaces]")
        ranked = sorted(surfaces.items(), key=lambda kv: -len(kv[1]))
        for surface, items in ranked[:top_n]:
            lines.append(f"  * {surface}  ({len(items)} finding(s))")
            for f in sorted(items, key=lambda x: -x.score)[:3]:
                lines.append(f"      - [{f.confidence.value}] {f.id}  {f.subject}")
                if f.suggested_test:
                    lines.append(f"          test: {f.suggested_test}")
        lines.append("")

    lines.append("[findings appendix]")
    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    for category, items in sorted(by_category.items()):
        lines.append(f"  -- {category} ({len(items)}) --")
        for f in items:
            lines.append(f"  {f.id}  [{f.confidence.value:<13} score={f.score:>2}]  {f.subject}")
            if verbose:
                lines.append(f"       analyzers: {', '.join(f.contributing_analyzers)}")
                for r in f.reasoning:
                    lines.append(f"       - {r}")
        lines.append("")

    if diagnostics:
        lines.append("[diagnostics]")
        for d in diagnostics:
            lines.append(f"  ! {d}")
        lines.append("")
    lines.append(f"(run `jscope explain <finding-id>` for the full evidence chain on any finding)")
    return "\n".join(lines)


def render_explain(finding: Finding) -> str:
    lines = [f"Finding {finding.id}: {finding.subject}", "-" * 60]
    lines.append(f"category        : {finding.category}")
    lines.append(f"confidence      : {finding.confidence.value} (score={finding.score})")
    lines.append(f"attack_surface  : {finding.attack_surface or '-'}")
    tiers = finding.metadata.get("analyzer_tiers", {})
    lines.append("contributed_by  : " + ", ".join(f"{a} [{tiers.get(a, 'core')}]" for a in finding.contributing_analyzers))
    lines.append(f"suggested_test  : {finding.suggested_test or '-'}")
    from jscope.core.classification import classify
    cl = classify(finding.category, finding.metadata, {e.type.value for e in finding.evidence}, finding.confidence.value)
    lines.append(f"evidence_class  : {cl['evidence_class']}")
    lines.append(f"verification    : {cl['verification_status']}  (confidence is not exploitability)")
    for lim in cl.get("limitations", []):
        lines.append(f"limitation      : {lim}")
    flow = finding.metadata.get("flow")
    if flow:
        lines.append("")
        lines.append("data-flow path:")
        for st in flow["path"]:
            lines.append(f"  {st['file'].split('/')[-1]}:{st['line']}  {st['step']}")
        for m in flow.get("mitigations", []):
            lines.append(f"  mitigation: {m['name']} effective_for={m['effective_for']} uncertain_for={m['uncertain_for']}")
    lines.append("")
    lines.append("reasoning chain:")
    for r in finding.reasoning:
        lines.append(f"  - {r}")
    lines.append("")
    lines.append("raw evidence:")
    for e in finding.evidence:
        loc = f"{e.file}:{e.line}" if e.file else "-"
        lines.append(f"  [{e.type.value}] ({loc}) {e.description}")
        if e.snippet:
            lines.append(f"      snippet: {e.snippet}")
    return "\n".join(lines)

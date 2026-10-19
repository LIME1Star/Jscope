from __future__ import annotations

import json

from jscope.core.evidence import Finding
from jscope.core.graph import KnowledgeGraph
from jscope.reporting.priority import PriorityDelta, prioritize


def payload(findings: list[Finding], frameworks: list[str], file_count: int,
            graph: KnowledgeGraph | None = None, diagnostics: list[str] | None = None,
            delta: PriorityDelta | None = None, dataflow: dict | None = None,
            file_diagnostics: dict | None = None) -> dict:
    out = {
        "schema_version": "0.5",
        "summary": {"file_count": file_count, "frameworks": frameworks, "finding_count": len(findings)},
        "findings": [f.to_dict() for f in findings],
        "priority": [{"id": f.id, "priority": pts, "reasons": why} for f, pts, why in prioritize(findings, graph, delta)],
        "diagnostics": diagnostics or [],
    }
    if dataflow:
        out["dataflow"] = dataflow
    if file_diagnostics:
        out["file_diagnostics"] = file_diagnostics
    if graph is not None:
        out["graph"] = graph.to_dict()
        out["route_map"] = graph.route_chains()
    return out


def render(findings: list[Finding], frameworks: list[str], file_count: int,
           graph: KnowledgeGraph | None = None, diagnostics: list[str] | None = None,
           delta: PriorityDelta | None = None, dataflow: dict | None = None,
           file_diagnostics: dict | None = None) -> str:
    return json.dumps(payload(findings, frameworks, file_count, graph, diagnostics, delta, dataflow, file_diagnostics), indent=2)

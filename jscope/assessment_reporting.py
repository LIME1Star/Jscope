"""Versioned JSON and Markdown exports for assessment-engine results."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def assessment_payload(result: dict[str, Any], tool_version: str | None = None) -> dict[str, Any]:
    from jscope import __version__
    out = dict(result)
    out["schema_version"] = out.get("schema_version", "jscope-assessment-result/1")
    out["tool_version"] = tool_version or __version__
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    findings = out.get("findings", [])
    counts = {}
    for finding in findings:
        sev = str(finding.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    out["summary"] = {"finding_count": len(findings), "by_severity": counts,
                      "endpoint_count": len(out.get("endpoints", []))}
    return out


def render_json(result: dict[str, Any]) -> str:
    return json.dumps(assessment_payload(result), indent=2, sort_keys=True)


def render_markdown(result: dict[str, Any]) -> str:
    p = assessment_payload(result)
    lines = ["# JScope Assessment Report", "",
             f"- Assessment: `{p.get('assessment_id', 'unknown')}`",
             f"- Status: **{p.get('status', 'unknown')}**",
             f"- Generated: {p['generated_at']}",
             f"- Endpoints inventoried: {p['summary']['endpoint_count']}",
             f"- Findings: {p['summary']['finding_count']}", "",
             "## Coverage and limitations", "",
             "Static references and inferred relationships are not proof of authorization or vulnerability.",
             "Untested components must not be interpreted as secure.", "", "## Findings", ""]
    findings = p.get("findings", [])
    if not findings:
        lines.append("No findings were recorded. This is not a statement that the application is secure.")
    for f in findings:
        lines += [f"### {f.get('title', 'Untitled finding')}",
                  f"- ID: `{f.get('finding_id', 'unknown')}`",
                  f"- Severity / confidence: **{f.get('severity', 'unknown')}** / {f.get('confidence', 'unknown')}",
                  f"- Status: {f.get('status', 'hypothesis')}",
                  f"- Endpoint: `{f.get('method', 'GET')} {f.get('endpoint', 'unknown')}`",
                  "", f.get("summary", ""), ""]
        if f.get("expected"): lines += [f"**Expected:** {f['expected']}", ""]
        if f.get("observed"): lines += [f"**Observed:** {f['observed']}", ""]
        if f.get("remediation"): lines += [f"**Remediation:** {f['remediation']}", ""]
        if f.get("evidence"):
            lines.append("Evidence references: " + ", ".join(f"`{e}`" for e in f["evidence"]))
            lines.append("")
    lines += ["## Endpoints", ""]
    for ep in p.get("endpoints", []):
        lines.append(f"- `{ep.get('method', 'GET')} {ep.get('url', '')}` ({ep.get('source', 'unknown')})")
    return "\n".join(lines).rstrip() + "\n"


def write_report(result: dict[str, Any], path: str | Path, fmt: str = "json") -> Path:
    fmt = fmt.lower()
    if fmt not in {"json", "md", "markdown"}:
        raise ValueError("format must be json or markdown")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = render_json(result) if fmt == "json" else render_markdown(result)
    out.write_text(content, encoding="utf-8")
    return out

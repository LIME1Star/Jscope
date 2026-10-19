"""Report formats rendered from a saved payload dict (Phase 4: Report Mode, PRD sections 6 and 15).

Because they consume the JSON payload, any past scan (a --save-findings file, a workspace scan, a `confirm` output) can be
re-rendered without re-analysis. Everything that originates in analyzed code (subjects, snippets, file paths) is UNTRUSTED
and is escaped for the target format: HTML is entity-escaped, Markdown is neutralised, SARIF is data not markup.
"""

from __future__ import annotations

import hashlib
import html
import json
from typing import Any

from jscope import __version__

_ORDER = ["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
_SARIF_LEVEL = {"CONFIRMED": "error", "HIGH": "warning", "MEDIUM": "note", "LOW": "note", "INFORMATIONAL": "none"}


def _prio(payload: dict) -> dict[str, dict]:
    return {p["id"]: p for p in payload.get("priority", [])}


def _counts(payload: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in payload["findings"]:
        out[f["confidence"]] = out.get(f["confidence"], 0) + 1
    return out


def _first_loc(f: dict) -> tuple[str | None, int | None]:
    for e in f["evidence"]:
        if e.get("file"):
            return e["file"], e.get("line")
    return None, None


# ----------------------------------------------------------------------------- markdown
def _md(s: Any) -> str:
    """Neutralise untrusted text for inline Markdown: no formatting, links, HTML or table breaks."""
    t = str(s).replace("\\", "\\\\").replace("\n", " ").replace("\r", " ")
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for ch in "`*_[]|#!":
        t = t.replace(ch, "\\" + ch)
    return t


def _fence(s: str) -> str:
    longest = max([len(r) for r in __import__("re").findall(r"`+", s)] + [0])
    bar = "`" * max(3, longest + 1)
    return f"{bar}\n{s}\n{bar}"


def to_markdown(payload: dict, top_n: int = 10) -> str:
    fs, prio = payload["findings"], _prio(payload)
    by_id = {f["id"]: f for f in fs}
    L = ["# JScope report", "", f"_JScope {__version__} · schema {payload.get('schema_version', '?')}_", ""]
    s = payload["summary"]
    L += ["## Snapshot", "", f"- files analyzed: **{s['file_count']}**",
          f"- frameworks: {', '.join(map(_md, s['frameworks'])) or 'none detected'}", f"- findings: **{len(fs)}** (" +
          ", ".join(f"{k} {v}" for k, v in sorted(_counts(payload).items(), key=lambda kv: _ORDER.index(kv[0]))) + ")", ""]
    ranked = sorted((p for p in payload.get("priority", []) if p["id"] in by_id), key=lambda p: -p["priority"])[:top_n]
    if ranked:
        L += ["## Where to start testing", "", "| # | Priority | Confidence | Finding | Why |", "|---|---|---|---|---|"]
        for i, p in enumerate(ranked, 1):
            f = by_id[p["id"]]
            L.append(f"| {i} | {p['priority']} | {f['confidence']} | `{f['id']}` {_md(f['category'])}: {_md(f['subject'])} | {_md('; '.join(p['reasons']))} |")
        L.append("")
        L += ["### Suggested first tests", ""]
        for p in ranked[:5]:
            f = by_id[p["id"]]
            if f.get("suggested_test"):
                L.append(f"- **{f['id']}** {_md(f['subject'])}: {_md(f['suggested_test'])}")
        L.append("")
    routes = payload.get("route_map") or []
    if routes:
        L += ["## Route map", "", "| Route | Protection | Endpoints |", "|---|---|---|"]
        for r in routes[:40]:
            prot = "**UNPROTECTED**" if r["unguarded"] else _md(", ".join(r["guards"] or ["meta"]) + (" / roles: " + ", ".join(r["roles"]) if r["roles"] else ""))
            L.append(f"| `{_md(r['route'])}` | {prot} | {_md(', '.join(r['endpoints'][:6]))} |")
        L.append("")
    L += ["## Findings", ""]
    cats: dict[str, list[dict]] = {}
    for f in fs:
        cats.setdefault(f["category"], []).append(f)
    for cat in sorted(cats):
        L += [f"### {_md(cat)} ({len(cats[cat])})", ""]
        for f in cats[cat]:
            L += [f"#### `{f['id']}` {_md(f['subject'])}", "",
                  f"**{f['confidence']}** (score {f['score']}) · analyzers: {_md(', '.join(f['contributing_analyzers']))}"
                  + (f" · surface: {_md(f['attack_surface'])}" if f["attack_surface"] else ""), ""]
            cl = f.get("classification") or {}
            if cl:
                L += [f"Class: **{_md(cl.get('evidence_class', '?'))}** · verification: **{_md(cl.get('verification_status', '?'))}**"
                      " (confidence is not exploitability)", ""]
                L += [f"- limitation: {_md(x)}" for x in cl.get("limitations", [])] + ([""] if cl.get("limitations") else [])
            if f.get("suggested_test"):
                L += [f"> {_md(f['suggested_test'])}", ""]
            L += ["Reasoning:", ""] + [f"- {_md(r)}" for r in f["reasoning"]] + [""]
            ev = [e for e in f["evidence"] if e.get("snippet")][:3]
            for e in ev:
                loc = f"{e['file']}:{e['line']}" if e.get("file") else "-"
                L += [f"`{_md(e['type'])}` {_md(loc)}", "", _fence(str(e["snippet"])), ""]
    if payload.get("diagnostics"):
        L += ["## Diagnostics", ""] + [f"- {_md(d)}" for d in payload["diagnostics"]] + [""]
    return "\n".join(L)


# ----------------------------------------------------------------------------- html
_CSS = ("body{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}"
        "h1,h2{border-bottom:1px solid #d0d7de;padding-bottom:.3rem}code,pre{background:#f6f8fa;border-radius:4px;font-size:13px}"
        "pre{padding:.6rem;overflow:auto}code{padding:.1rem .3rem}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #d0d7de;padding:.35rem .5rem;text-align:left;vertical-align:top}"
        ".c{display:inline-block;border-radius:10px;padding:0 .55rem;font-size:12px;font-weight:600;color:#fff}"
        ".CONFIRMED{background:#8250df}.HIGH{background:#cf222e}.MEDIUM{background:#bc4c00}.LOW{background:#9a6700}.INFORMATIONAL{background:#57606a}"
        "details{border:1px solid #d0d7de;border-radius:6px;margin:.4rem 0;padding:.3rem .7rem}summary{cursor:pointer}"
        "@media(prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}code,pre{background:#161b22}td,th,details,h1,h2{border-color:#30363d}}")


def to_html(payload: dict, top_n: int = 10) -> str:
    e = html.escape
    fs, prio = payload["findings"], _prio(payload)
    by_id = {f["id"]: f for f in fs}
    s = payload["summary"]
    chip = lambda c: f'<span class="c {e(c)}">{e(c)}</span>'
    h = ["<!doctype html><html lang=en><head><meta charset=utf-8>",
         "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
         f"<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>JScope report</title><style>{_CSS}</style></head><body>",
         f"<h1>JScope report</h1><p><small>JScope {e(__version__)} · schema {e(str(payload.get('schema_version', '?')))}</small></p>",
         "<h2>Snapshot</h2><ul>"
         f"<li>files analyzed: <b>{s['file_count']}</b></li><li>frameworks: {e(', '.join(s['frameworks']) or 'none detected')}</li>"
         f"<li>findings: <b>{len(fs)}</b> " + " ".join(f"{chip(k)} {v}" for k, v in sorted(_counts(payload).items(), key=lambda kv: _ORDER.index(kv[0]))) + "</li></ul>"]
    ranked = sorted((p for p in payload.get("priority", []) if p["id"] in by_id), key=lambda p: -p["priority"])[:top_n]
    if ranked:
        h.append("<h2>Where to start testing</h2><table><tr><th>#<th>Priority<th>Finding<th>Why / first test</tr>")
        for i, p in enumerate(ranked, 1):
            f = by_id[p["id"]]
            h.append(f"<tr><td>{i}<td>{p['priority']}<td>{chip(f['confidence'])} <code>{e(f['id'])}</code> {e(f['category'])}: {e(f['subject'])}"
                     f"<td>{e('; '.join(p['reasons']))}" + (f"<br><b>Test:</b> {e(f['suggested_test'])}" if f.get("suggested_test") else "") + "</tr>")
        h.append("</table>")
    routes = payload.get("route_map") or []
    if routes:
        h.append("<h2>Route map</h2><table><tr><th>Route<th>Protection<th>Endpoints</tr>")
        for r in routes[:60]:
            prot = "<b>UNPROTECTED</b>" if r["unguarded"] else e(", ".join(r["guards"] or ["meta"]) + (" / roles: " + ", ".join(r["roles"]) if r["roles"] else ""))
            h.append(f"<tr><td><code>{e(r['route'])}</code><td>{prot}<td>{e(', '.join(r['endpoints'][:8]))}</tr>")
        h.append("</table>")
    h.append("<h2>Findings</h2>")
    for f in fs:
        h.append(f"<details><summary>{chip(f['confidence'])} <code>{e(f['id'])}</code> {e(f['category'])}: {e(f['subject'])}</summary>"
                 f"<p>score {f['score']} · analyzers: {e(', '.join(f['contributing_analyzers']))}"
                 + (f" · surface: {e(f['attack_surface'])}" if f["attack_surface"] else "") + "</p>"
                 + (f"<p><b>Class:</b> {e((f.get('classification') or {}).get('evidence_class', '?'))} · <b>verification:</b> "
                    f"{e((f.get('classification') or {}).get('verification_status', '?'))} <small>(confidence is not exploitability)</small></p>"
                    + "".join(f"<p><small>limitation: {e(x)}</small></p>" for x in (f.get('classification') or {}).get('limitations', [])))
                 + (f"<p><b>Suggested test:</b> {e(f['suggested_test'])}</p>" if f.get("suggested_test") else "")
                 + "<p><b>Reasoning</b></p><ul>" + "".join(f"<li>{e(r)}</li>" for r in f["reasoning"]) + "</ul>")
        for ev in [x for x in f["evidence"] if x.get("snippet")][:4]:
            loc = f"{ev['file']}:{ev['line']}" if ev.get("file") else "-"
            h.append(f"<p><small>{e(ev['type'])} · {e(loc)}</small></p><pre>{e(str(ev['snippet']))}</pre>")
        h.append("</details>")
    if payload.get("diagnostics"):
        h.append("<h2>Diagnostics</h2><ul>" + "".join(f"<li>{e(d)}</li>" for d in payload["diagnostics"]) + "</ul>")
    h.append("</body></html>")
    return "".join(h)


# ----------------------------------------------------------------------------- SARIF 2.1.0
def to_sarif(payload: dict) -> str:
    prio = _prio(payload)
    rules: dict[str, dict] = {}
    results = []
    for f in payload["findings"]:
        rid = f"jscope/{f['category']}" + (f"/{f['attack_surface']}" if f["attack_surface"] else "")
        rules.setdefault(rid, {"id": rid, "name": rid.replace("/", "."),
                               "shortDescription": {"text": f"JScope {f['category']} finding" + (f" ({f['attack_surface']})" if f["attack_surface"] else "")},
                               "helpUri": "https://github.com/jscope/jscope/blob/main/docs/EVIDENCE_SCHEMA.md"})
        file, line = _first_loc(f)
        key = hashlib.sha256(f"{f['category']}|{f['subject']}".encode()).hexdigest()[:32]       # stable across scans (JS-#### ids are not)
        msg = f"{f['subject']} [{f['confidence']}, score {f['score']}]" + (f". Suggested test: {f['suggested_test']}" if f.get("suggested_test") else "")
        res: dict[str, Any] = {
            "ruleId": rid, "level": _SARIF_LEVEL.get(f["confidence"], "note"), "message": {"text": msg},
            "partialFingerprints": {"jscopeKey/v1": key},
            "properties": {"jscopeId": f["id"], "evidenceClass": (f.get("classification") or {}).get("evidence_class"),
                           "verificationStatus": (f.get("classification") or {}).get("verification_status"), "confidence": f["confidence"], "score": f["score"], "attackSurface": f["attack_surface"],
                           "analyzers": f["contributing_analyzers"], "reasoning": f["reasoning"],
                           **({"priority": prio[f["id"]]["priority"]} if f["id"] in prio else {})}}
        if file:
            loc: dict[str, Any] = {"artifactLocation": {"uri": str(file).replace("\\", "/")}}
            if line:
                loc["region"] = {"startLine": int(line)}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "JScope", "version": __version__, "informationUri": "https://github.com/jscope/jscope",
                                         "rules": sorted(rules.values(), key=lambda r: r["id"])}},
                     "results": results,
                     "invocations": [{"executionSuccessful": True, "toolExecutionNotifications":
                                      [{"level": "note", "message": {"text": d}} for d in payload.get("diagnostics", [])]}]}]}
    return json.dumps(doc, indent=2)


FORMATS = {"markdown": to_markdown, "md": to_markdown, "html": to_html, "sarif": to_sarif}


def render_payload(payload: dict, fmt: str) -> str:
    return FORMATS[fmt](payload)

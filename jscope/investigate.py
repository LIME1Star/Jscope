"""Investigation services: ranked findings, finding lookup, evidence context and next actions.

Pure functions over a saved findings payload (the same JSON every other command reads and writes). The direct CLI
and the interactive shell both call these; neither contains its own copy of the logic. Nothing here touches the
network or re-runs analysis.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jscope.core.classification import classify

CONF_ORDER = ["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class LookupError_(Exception):
    """A finding reference that matched nothing, or too much."""

    def __init__(self, message: str, candidates: list[dict] | None = None):
        super().__init__(message)
        self.candidates = candidates or []


def load_payload(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise LookupError_(f"cannot read findings file {path}: {exc}") from exc
    except ValueError as exc:
        raise LookupError_(f"findings file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise LookupError_(f"{path} is not a JScope findings file (no 'findings' key)")
    return data


def classification(f: dict) -> dict[str, Any]:
    ev_types = {e.get("type", "") for e in f.get("evidence", [])}
    return classify(f.get("category", ""), f.get("metadata", {}) or {}, ev_types, f.get("confidence", "LOW"))


def ranked(data: dict) -> list[dict]:
    """Findings in 'where to start testing' order. Rank is 1-based and stable for a given payload, so `show 2`
    means the same thing as the row labelled 2 in the last `findings` listing."""
    by_id = {f["id"]: f for f in data["findings"]}
    order = [p for p in data.get("priority", []) if p["id"] in by_id]
    seen = {p["id"] for p in order}
    rest = [{"id": f["id"], "priority": 0, "reasons": []} for f in data["findings"] if f["id"] not in seen]
    out = []
    for rank, p in enumerate(order + rest, 1):
        f = by_id[p["id"]]
        cl = classification(f)
        out.append({"rank": rank, "id": f["id"], "priority": p["priority"], "reasons": p.get("reasons", []),
                    "confidence": f["confidence"], "category": f["category"], "subject": f["subject"],
                    "evidence_class": cl["evidence_class"], "verification": cl["verification_status"],
                    "finding": f})
    return out


def filter_ranked(rows: list[dict], *, min_confidence: str | None = None, category: str | None = None,
                  unverified: bool = False, query: str | None = None) -> list[dict]:
    out = rows
    if min_confidence:
        cutoff = CONF_ORDER.index(min_confidence)
        out = [r for r in out if CONF_ORDER.index(r["confidence"]) <= cutoff]
    if category:
        out = [r for r in out if r["category"] == category]
    if unverified:
        out = [r for r in out if r["verification"] == "unverified"]
    if query:
        q = query.lower()
        out = [r for r in out if q in r["subject"].lower() or q in r["category"].lower() or q in r["id"].lower()]
    return out


def resolve(rows: list[dict], ref: str) -> dict:
    """`3` / `#3` -> rank, `JS-0004` / `0004` -> id, anything else -> unique substring of the subject."""
    ref = ref.strip()
    if not ref:
        raise LookupError_("empty finding reference")
    num = ref[1:] if ref.startswith("#") else ref
    if num.isdigit():
        n = int(num)
        # a bare number is a rank; a zero-padded 4+ digit number ("0004") is an id; "JS-0004" is handled below
        if len(num) >= 4:
            by_id = [r for r in rows if r["id"].upper() == f"JS-{n:04d}"]
            if by_id:
                return by_id[0]
        by_rank = [r for r in rows if r["rank"] == n]
        if by_rank:
            return by_rank[0]
        raise LookupError_(f"no finding #{n} (this analysis has {len(rows)})")
    exact = [r for r in rows if r["id"].lower() == ref.lower()]
    if exact:
        return exact[0]
    hits = [r for r in rows if ref.lower() in r["subject"].lower() or ref.lower() in r["id"].lower()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise LookupError_(f"no finding matches {ref!r}")
    raise LookupError_(f"{ref!r} matches {len(hits)} findings; use a rank or id", hits[:10])


def route_context(data: dict, subject: str) -> list[dict]:
    """Routes that call this subject (as an endpoint), with guard/role state. Static observation only."""
    out = []
    for c in data.get("route_map", []) or []:
        if subject in (c.get("endpoints") or []) or c.get("route") == subject:
            out.append(c)
    return out


def related(rows: list[dict], row: dict) -> list[dict]:
    ids = set(row["finding"].get("related") or [])
    return [r for r in rows if r["id"] in ids]


def source_context(file: str, line: int, radius: int = 3) -> list[tuple[int, str]]:
    """Lines around an evidence location, if the file is still on disk. Empty (not an error) when it is not."""
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return [(n, lines[n - 1][:200]) for n in range(lo, hi + 1)]


def next_actions(row: dict, data: dict, *, has_base_url: bool) -> list[str]:
    acts = []
    f = row["finding"]
    cl = classification(f)
    if f["category"] == "endpoint" and has_base_url and cl["verification_status"] == "unverified":
        acts.append(f"confirm       check that {f['subject']} responds (read-only GET/OPTIONS; asks before sending)")
    if f["category"] in ("dataflow", "idor", "authorization") and has_base_url and cl["verification_status"] != "confirmed":
        acts.append(f"verify {row['rank']}     try to reproduce it (active test; needs your authorization)")
    if route_context(data, f["subject"]):
        acts.append("graph         see where it sits in the route map")
    if f.get("related"):
        acts.append("show <rank>    inspect a related finding")
    acts.append(f"show {row['rank']} --full  complete evidence chain")
    return acts


def summary(data: dict) -> dict[str, Any]:
    rows = ranked(data)
    conf: dict[str, int] = {}
    ver: dict[str, int] = {}
    for r in rows:
        conf[r["confidence"]] = conf.get(r["confidence"], 0) + 1
        ver[r["verification"]] = ver.get(r["verification"], 0) + 1
    return {"findings": len(rows), "by_confidence": {k: conf[k] for k in CONF_ORDER if k in conf},
            "by_verification": ver,
            "unprotected_routes": sum(1 for c in data.get("route_map", []) or [] if c.get("unguarded")),
            "routes": len(data.get("route_map", []) or []),
            "frameworks": data.get("summary", {}).get("frameworks", []),
            "files": data.get("summary", {}).get("file_count", 0),
            "runtime_requests": (data.get("runtime") or {}).get("requests_sent", 0)}


# ------------------------------------------------------------------ rendering (plain text, no decoration)
def render_list(rows: list[dict], total: int, limit: int | None) -> str:
    if not rows:
        return "no findings match"
    shown = rows if limit is None else rows[:limit]
    w = max(len(r["category"]) for r in shown)
    out = [f"{'#':>3}  {'PRI':>3}  {'CONFIDENCE':<13} {'STATE':<11} {'CATEGORY':<{w}}  SUBJECT"]
    for r in shown:
        state = {"unverified": "static", "probable": "probable", "confirmed": "confirmed",
                 "inconclusive": "inconclusive", "rejected": "rejected"}.get(r["verification"], r["verification"])
        out.append(f"{r['rank']:>3}  {r['priority']:>3}  {r['confidence']:<13} {state:<11} {r['category']:<{w}}  {r['subject']}")
    if limit is not None and len(rows) > limit:
        out.append(f"... {len(rows) - limit} more ({total} total); use --all, --limit N, or filter with --category / --min-confidence")
    return "\n".join(out)


def render_show(row: dict, data: dict, rows: list[dict], *, has_base_url: bool, context_lines: bool = False) -> str:
    f = row["finding"]
    cl = classification(f)
    out = [f"#{row['rank']}  {f['id']}  {f['category']}: {f['subject']}", ""]
    out.append(f"confidence   {f['confidence']}   priority {row['priority']}")
    out.append(f"state        {cl['evidence_class']}   verification: {cl['verification_status']}")
    for lim in cl.get("limitations", [])[:3]:
        out.append(f"limitation   {lim}")
    if row["reasons"]:
        out += ["", "why it ranks here"] + [f"  - {r}" for r in row["reasons"][:5]]
    if f.get("suggested_test"):
        out += ["", f"suggested test  {f['suggested_test']}"]
    routes = route_context(data, f["subject"])
    if routes:
        out += ["", "reached from"]
        for c in routes[:5]:
            prot = "UNPROTECTED" if c.get("unguarded") else "guards=" + ",".join(c.get("guards") or ["meta"])
            if c.get("roles"):
                prot += " roles=" + ",".join(c["roles"])
            out.append(f"  route {c['route']}  {prot}")
    ev = f.get("evidence", [])
    out += ["", f"evidence ({len(ev)})"]
    for e in ev[:6]:
        loc = f"{Path(e['file']).name}:{e['line']}" if e.get("file") else "-"
        out.append(f"  [{e['type']}] {loc}  {e['description']}")
        if e.get("snippet"):
            out.append(f"      {e['snippet'][:160]}")
        if context_lines and e.get("file") and e.get("line"):
            for n, text in source_context(e["file"], int(e["line"])):
                out.append(f"      {'>' if n == e['line'] else ' '} {n:>5} | {text}")
    if len(ev) > 6:
        out.append(f"  ... {len(ev) - 6} more (--full)")
    rel = related(rows, row)
    if rel:
        out += ["", "related"] + [f"  #{r['rank']} {r['category']}: {r['subject']}" for r in rel[:5]]
    out += ["", "next"] + [f"  {a}" for a in next_actions(row, data, has_base_url=has_base_url)]
    return "\n".join(out)


def render_status(sess, data: dict | None) -> str:
    if not sess.active:
        return "no active investigation.\nstart one with: jscope <url-or-path>"
    out = [f"target     {sess.target}"]
    if sess.kind == "url":
        out.append(f"scope      {sess.host} (exact host; runtime commands are limited to it)")
    if sess.findings_file:
        out.append(f"findings   {sess.findings_file}")
    if data is None:
        out += ["", "not analyzed yet: jscope " + sess.target]
        return "\n".join(out)
    s = summary(data)
    conf = ", ".join(f"{k}={v}" for k, v in s["by_confidence"].items()) or "none"
    out += ["", f"analysis   {s['files']} file(s), {s['findings']} finding(s): {conf}",
            f"routes     {s['routes']} ({s['unprotected_routes']} without a guard)"]
    v = s["by_verification"]
    out.append("evidence   " + ", ".join(f"{v.get(k, 0)} {k}" for k in ("unverified", "probable", "confirmed", "rejected", "inconclusive")
                                         if v.get(k)) + (f"; {s['runtime_requests']} runtime request(s) sent" if s["runtime_requests"] else "; no runtime requests sent"))
    nxt = ["findings", "show 1", "graph", "report"]
    if sess.kind == "url":
        nxt.insert(2, "confirm")
    out += ["", "next       " + " | ".join(nxt)]
    return "\n".join(out)

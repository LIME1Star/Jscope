"""Scan-to-scan diffing (Phase 3).

Compares two saved scan records at three levels: files (by content hash), findings (by stable
`category|subject` key, NOT the order-based JS-#### id) and the knowledge graph's route map.

The graph-level diff is the interesting one: "this route lost its guard" or "this route now reaches a
new endpoint" is a change in application *behavior*, which a file diff cannot express. These changes
are inherently worth re-testing, so they feed the deterministic priority ranking (see priority.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jscope.reporting.priority import PriorityDelta, finding_key

_ORDER = {"SUPPRESSED": 0, "INFORMATIONAL": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CONFIRMED": 5}


def _protection(chain: dict) -> set[str]:
    return {f"guard:{g}" for g in chain.get("guards", [])} | {f"role:{r}" for r in chain.get("roles", [])}


@dataclass
class ScanDiff:
    old_id: str
    new_id: str
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    findings_new: list[dict] = field(default_factory=list)
    findings_resolved: list[dict] = field(default_factory=list)
    findings_changed: list[dict] = field(default_factory=list)
    routes_added: list[dict] = field(default_factory=list)
    routes_removed: list[dict] = field(default_factory=list)
    routes_changed: list[dict] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([self.files_added, self.files_removed, self.files_modified, self.findings_new,
                        self.findings_resolved, self.findings_changed, self.routes_added,
                        self.routes_removed, self.routes_changed])

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}

    def priority_delta(self) -> PriorityDelta:
        return PriorityDelta(
            new_keys={f["key"] for f in self.findings_new},
            raised_keys={f["key"] for f in self.findings_changed if f["direction"] == "up"},
            weakened_routes={r["id"] for r in self.routes_changed if r["change"] == "weakened"})

    def regressions(self, min_confidence: str = "HIGH") -> list[str]:
        """Human-readable reasons a CI/cron run should alert. Deliberately narrow: new findings at/above
        `min_confidence`, confidence rising to it, and routes that lost protection."""
        bar = _ORDER[min_confidence]
        out = [f"new {f['confidence']} finding: {f['category']} {f['subject']}"
               for f in self.findings_new if _ORDER[f["confidence"]] >= bar]
        out += [f"{f['category']} {f['subject']} rose {f['old']} -> {f['new']}"
                for f in self.findings_changed if f["direction"] == "up" and _ORDER[f["new"]] >= bar]
        out += [f"route {r['route']} lost client-side protection ({', '.join(sorted(r['lost']))})"
                for r in self.routes_changed if r["change"] == "weakened"]
        return out


def _brief(f: dict) -> dict:
    return {"key": finding_key(f["category"], f["subject"]), "id": f["id"], "category": f["category"],
            "subject": f["subject"], "confidence": f["confidence"], "attack_surface": f.get("attack_surface")}


def diff_scans(old: dict, new: dict) -> ScanDiff:
    """`old`/`new` are scan records as written by Workspace (they carry `scan_id`, `files`, `payload`)."""
    d = ScanDiff(old_id=old["scan_id"], new_id=new["scan_id"])

    of, nf = old.get("files", {}), new.get("files", {})
    d.files_added = sorted(set(nf) - set(of))
    d.files_removed = sorted(set(of) - set(nf))
    d.files_modified = sorted(p for p in set(of) & set(nf) if of[p] != nf[p])

    ofi = {finding_key(f["category"], f["subject"]): f for f in old["payload"]["findings"]}
    nfi = {finding_key(f["category"], f["subject"]): f for f in new["payload"]["findings"]}
    d.findings_new = [_brief(nfi[k]) for k in sorted(set(nfi) - set(ofi))]
    d.findings_resolved = [_brief(ofi[k]) for k in sorted(set(ofi) - set(nfi))]
    for k in sorted(set(ofi) & set(nfi)):
        a, b = ofi[k]["confidence"], nfi[k]["confidence"]
        if a != b:
            d.findings_changed.append({**_brief(nfi[k]), "old": a, "new": b,
                                       "direction": "up" if _ORDER[b] > _ORDER[a] else "down"})

    orm = {c["id"]: c for c in old["payload"].get("route_map", [])}
    nrm = {c["id"]: c for c in new["payload"].get("route_map", [])}
    d.routes_added = [{"route": nrm[i]["route"], "id": i, "unguarded": nrm[i]["unguarded"],
                       "endpoints": nrm[i]["endpoints"]} for i in sorted(set(nrm) - set(orm))]
    d.routes_removed = [{"route": orm[i]["route"], "id": i} for i in sorted(set(orm) - set(nrm))]
    for i in sorted(set(orm) & set(nrm)):
        o, n = orm[i], nrm[i]
        po, pn = _protection(o), _protection(n)
        if not o["unguarded"] and n["unguarded"] or pn < po:
            change = "weakened"
        elif pn > po:
            change = "strengthened"
        elif pn != po:
            change = "changed"
        else:
            change = None
        ep_add = sorted(set(n["endpoints"]) - set(o["endpoints"]))
        ep_rem = sorted(set(o["endpoints"]) - set(n["endpoints"]))
        if change or ep_add or ep_rem:
            d.routes_changed.append({
                "route": n["route"], "id": i, "change": change or "endpoints_only",
                "lost": sorted(po - pn), "gained": sorted(pn - po),
                "endpoints_added": ep_add, "endpoints_removed": ep_rem,
                "now_unguarded": n["unguarded"]})
    return d


def render_diff(d: ScanDiff) -> str:
    if d.is_empty():
        return f"[changes since scan {d.old_id}] none"
    L = [f"[changes since scan {d.old_id}]  (-> {d.new_id})"]
    L.append(f"  files    : +{len(d.files_added)} -{len(d.files_removed)} ~{len(d.files_modified)}")
    for r in d.routes_changed:
        if r["change"] == "weakened":
            L.append(f"  !! route {r['route']} LOST protection: {', '.join(r['lost']) or 'all guards'}")
    for r in d.routes_changed:
        if r["change"] == "strengthened":
            L.append(f"  +  route {r['route']} gained protection: {', '.join(r['gained'])}")
        for e in r["endpoints_added"]:
            L.append(f"  +  route {r['route']} now reaches {e}")
        for e in r["endpoints_removed"]:
            L.append(f"  -  route {r['route']} no longer reaches {e}")
    for r in d.routes_added:
        L.append(f"  +  new route {r['route']}" + ("  (UNPROTECTED)" if r["unguarded"] else ""))
    for r in d.routes_removed:
        L.append(f"  -  route removed {r['route']}")
    for f in d.findings_new:
        L.append(f"  +  new [{f['confidence']}] {f['category']}: {f['subject']}")
    for f in d.findings_changed:
        arrow = "^" if f["direction"] == "up" else "v"
        L.append(f"  {arrow}  {f['category']}: {f['subject']}  {f['old']} -> {f['new']}")
    for f in d.findings_resolved:
        L.append(f"  -  gone [{f['confidence']}] {f['category']}: {f['subject']}")
    return "\n".join(L)

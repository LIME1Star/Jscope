"""Deterministic, explainable prioritization ("where do I start testing?").

No ML. Each finding gets an integer priority from a fixed rule table; every
point is accompanied by a human-readable reason so the ranking can be argued
with. Rules follow design-brainstorm.md section 4:
  1. auth/authz-adjacent surfaces rank highest (broken access control is the
     most valuable bug class in bounty programs)
  2. cross-analyzer agreement outranks single-analyzer findings
  3. findings reachable from a route with NO client-side protection rank
     above those behind a guard
  4. higher confidence breaks ties
"""

from __future__ import annotations

from dataclasses import dataclass, field

from jscope.core.evidence import Confidence, Finding
from jscope.core.graph import KnowledgeGraph

SURFACE_BASE = {
    "authorization": 40, "admin": 38, "auth": 34, "idor_candidate": 34, "internal": 32, "debug": 30,
    "payment": 30, "graphql": 28, "token_storage": 26, "upload": 26, "export": 24, "cookie_handling": 22,
    "source_map": 22, "service_worker": 14,
    # Phase 4
    "undocumented_api": 36, "unauthenticated_write": 30, "deprecated_api": 20, "csrf_candidate": 18,
    "supply_chain": 16, "csp_weak": 12, "wasm": 14,
    # 0.5 data-flow surfaces
    "dom_xss_candidate": 36, "code_injection_candidate": 40, "open_redirect_candidate": 24,
    "sql_injection_candidate": 38, "command_injection_candidate": 40,
}
CONF_POINTS = {Confidence.CONFIRMED: 12, Confidence.HIGH: 9, Confidence.MEDIUM: 6, Confidence.LOW: 3,
               Confidence.INFORMATIONAL: 0}


def finding_key(category: str, subject: str) -> str:
    """Stable identity across scans. `JS-0001` ids are order-based and NOT stable; this is."""
    return f"{category}|{subject}"


@dataclass
class PriorityDelta:
    """What changed since the previous scan (Phase 3). Empty on a first scan: a baseline is not 'new'."""
    new_keys: set[str] = field(default_factory=set)
    raised_keys: set[str] = field(default_factory=set)
    weakened_routes: set[str] = field(default_factory=set)      # route node ids that lost protection


NEW_POINTS, RAISED_POINTS, WEAKENED_POINTS = 12, 8, 14
HIDDEN_POINTS, RUNTIME_POINTS = 10, 10


def prioritize(findings: list[Finding], graph: KnowledgeGraph | None = None,
               delta: PriorityDelta | None = None) -> list[tuple[Finding, int, list[str]]]:
    ranked = []
    for f in findings:
        pts, why = 0, []
        if f.attack_surface:
            base = SURFACE_BASE.get(f.attack_surface, 10)
            pts += base
            why.append(f"+{base} attack surface '{f.attack_surface}'")
        else:
            continue                                    # priority list is about attack surfaces
        c = CONF_POINTS.get(f.confidence, 0)
        pts += c
        why.append(f"+{c} confidence {f.confidence.value}")
        if any(e.type.value == "CROSS_ANALYZER_AGREEMENT" for e in f.evidence):
            pts += 8
            why.append("+8 independent analyzers agree")
        if f.metadata.get("client_referenced") is False:
            unresolved = f.metadata.get("client_unresolved_calls", 0)
            if unresolved:
                pts += HIDDEN_POINTS // 2
                why.append(f"+{HIDDEN_POINTS // 2} documented in a spec/schema but matched by no resolvable client call "
                           f"(halved: {unresolved} client request(s) have unresolvable URLs, so a dynamic caller is possible)")
            else:
                pts += HIDDEN_POINTS
                why.append(f"+{HIDDEN_POINTS} documented in a spec/schema but matched by no client call (UI never exercises it)")
        rt = [e for e in f.evidence if e.type.value.startswith("RUNTIME_")]
        if rt:
            if any(e.type.value == "RUNTIME_CONTEXT" for e in rt):
                pts += RUNTIME_POINTS
                why.append(f"+{RUNTIME_POINTS} confirmed to respond on the live origin (opt-in probe)")
            else:
                pts -= RUNTIME_POINTS
                why.append(f"-{RUNTIME_POINTS} probe got a genuine not-found at the tested base URL")
        if f.metadata.get("absence_based"):
            pts -= 6
            why.append("-6 finding is based on the absence of a guard")
        if graph is not None and f.category == "endpoint" and f.attack_surface == "auth":
            why.append("+0 auth endpoints are expected to be reachable without a session")
        elif graph is not None and f.category == "endpoint":
            routes = graph.routes_reaching(f"endpoint:{f.subject}")
            if routes:
                unprot = [r for r in routes if graph.route_protection(r.id)["unguarded"]]
                if unprot:
                    pts += 10
                    why.append(f"+10 reachable from route with no client-side protection ({unprot[0].label})")
                else:
                    why.append("+0 reachable only via client-guarded routes (still verify server-side)")
        if delta is not None:
            key = finding_key(f.category, f.subject)
            if key in delta.new_keys:
                pts += NEW_POINTS
                why.append(f"+{NEW_POINTS} new since previous scan")
            elif key in delta.raised_keys:
                pts += RAISED_POINTS
                why.append(f"+{RAISED_POINTS} confidence rose since previous scan")
            if graph is not None and f.category == "endpoint" and delta.weakened_routes:
                hit = [r for r in graph.routes_reaching(f"endpoint:{f.subject}") if r.id in delta.weakened_routes]
                if hit:
                    pts += WEAKENED_POINTS
                    why.append(f"+{WEAKENED_POINTS} reachable from route that lost client-side protection ({hit[0].label})")
        ranked.append((f, pts, why))
    ranked.sort(key=lambda t: (-t[1], t[0].id))
    return ranked

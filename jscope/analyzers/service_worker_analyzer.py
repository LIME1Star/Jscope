"""Service Worker Analyzer.

Two views of the same feature, from opposite sides:
  * registration (page side):  navigator.serviceWorker.register('/sw.js')
  * capabilities (worker side): fetch interception, push, background sync,
    offline caching, message channel, immediate takeover, importScripts,
    Workbox precache manifests.
When the registered script is also present in the project the registration
gains ARTIFACT_RESOLVED evidence. Precache manifests are useful recon:
they enumerate shipped assets, including ones no page links to.
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing import queries as Q
from jscope.parsing.ast_engine import ParsedFile

_SW_EVENTS = {"install", "activate", "fetch", "push", "sync", "periodicsync", "notificationclick",
              "notificationclose", "message", "backgroundfetchsuccess", "pushsubscriptionchange"}
_CAPABILITY = {
    "fetch": ("capability:fetch_interception",
              "Worker intercepts every in-scope request. Test cache poisoning, whether authenticated responses get cached "
              "and served to the next user, and whether the scope is broader than intended."),
    "push": ("capability:push_notifications",
             "Check the push-subscription registration endpoint for authorization, and what the payload handler does with attacker-influenced data."),
    "notificationclick": ("capability:push_notifications",
                          "Check how notification click data selects the opened URL (open redirect / javascript: handling)."),
    "sync": ("capability:background_sync",
             "Queued requests replay later, possibly with stale credentials. Test replay authorization and idempotency."),
    "periodicsync": ("capability:background_sync",
                     "Periodic background requests run without a visible page. Test their authorization."),
    "message": ("capability:message_channel",
                "Check the message handler validates event.source/origin: any page in scope may be able to drive the worker."),
}
_WORKBOX = ("precacheAndRoute", "registerRoute", "workbox", "precache", "StaleWhileRevalidate", "NetworkFirst")
_SW_NAME = re.compile(r"(^|[-_./])(sw|service-?worker|workbox[-\w]*)(\.[\w.-]+)?\.js$", re.I)


class ServiceWorkerAnalyzer(Analyzer):
    name = "service_worker_analyzer"
    depends_on: list[str] = []
    produces_categories = ["service_worker"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        index = Q.FileIndex(ctx.files)
        cands: dict[str, Candidate] = {}

        def add(subject: str, ev: list[Evidence], test: str | None, meta: dict | None = None):
            c = cands.get(subject)
            if c is None:
                c = cands[subject] = Candidate(category="service_worker", subject=subject, analyzer=self.name,
                                               evidence=[], attack_surface="service_worker", suggested_test=test,
                                               metadata=dict(meta or {}))
            c.evidence += ev

        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue

            def ev(node, desc, typ=ET.AST_PATTERN_MATCH):
                out = [Evidence(typ, desc, self.name, pf.path, pf.line_of(node), pf.node_text(node)[:100].replace("\n", " "))]
                if ctx.ast.is_in_dead_branch(pf, node):
                    out.append(Evidence(ET.DEAD_CODE, "sits in a statically dead branch", self.name))
                if is_test_path(pf.path):
                    out.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock", self.name))
                return out

            calls = Q.iter_calls(ctx.ast, pf)
            sw_events = []
            for s in calls:
                if s.callee.endswith("addEventListener") and s.args_resolved and s.args_resolved[0].value in _SW_EVENTS:
                    recv = s.callee.rsplit(".", 1)[0] if "." in s.callee else ""
                    if recv in ("self", "this", "globalThis", "") or recv.endswith("self"):
                        sw_events.append(s)
            is_sw = bool(sw_events) or any(s.callee in ("self.skipWaiting", "self.clients.claim", "importScripts")
                                           for s in calls) \
                or any(m in pf.text for m in ("ServiceWorkerGlobalScope", "self.__WB_MANIFEST")) \
                or (bool(_SW_NAME.search(pf.path.replace("\\", "/"))) and any(w in pf.text for w in _WORKBOX))
            # -- page side: registration
            for s in calls:
                if s.callee.endswith("serviceWorker.register") and s.args_resolved and s.args_resolved[0].value:
                    script = s.args_resolved[0].value
                    e = ev(s.node, f"serviceWorker.register('{script}')")
                    target = index.by_basename(script)
                    if target is not None:
                        e.append(Evidence(ET.ARTIFACT_RESOLVED, f"registered worker script found in project: {target.path}", self.name, target.path))
                    scope = None
                    if len(s.args_resolved) > 1 and "scope" in s.args_raw[1]:
                        scope = s.args_raw[1]
                    add(f"registration:{script}", e,
                        "Fetch the worker script from the live origin; check its scope header (Service-Worker-Allowed) and "
                        "whether it caches authenticated pages.", {"script": script, "options": scope})
            if not is_sw:
                continue
            # -- worker side
            for s in sw_events:
                evname = s.args_resolved[0].value
                if evname in _CAPABILITY:
                    subj, test = _CAPABILITY[evname]
                    add(subj, ev(s.node, f"worker handles '{evname}' event"), test, {"events": [evname]})
                elif evname in ("install", "activate"):
                    pass
            for s in calls:
                if s.callee in ("caches.open", "self.caches.open") and s.args_resolved and s.args_resolved[0].value:
                    add("capability:offline_cache", ev(s.node, f"opens cache '{s.args_resolved[0].value}'"),
                        "Check what gets cached: authenticated API responses or HTML in a shared cache can leak across sessions.",
                        {"caches": [s.args_resolved[0].value]})
                elif s.callee in ("self.skipWaiting", "self.clients.claim"):
                    add("behavior:immediate_takeover", ev(s.node, f"{s.callee}() -- new worker takes control immediately"),
                        "A malicious or buggy worker version activates without waiting for page close; relevant if the worker script URL is attacker-influenced.")
                elif s.callee == "importScripts" and s.args_resolved:
                    for r, raw in zip(s.args_resolved, s.args_raw):
                        if r.value:
                            add(f"dependency:importScripts:{r.value}", ev(s.node, f"importScripts('{r.value}')"),
                                "Third-party script runs with worker privileges over every in-scope request; check origin, integrity and takeover risk." if r.value.startswith("http")
                                else "First-party script loaded into the worker; include it in the analysis.")
                elif Q.last_segment(s.callee) in ("precacheAndRoute", "precache") and s.node is not None:
                    args = Q.call_args(s.node)
                    for item in Q.array_items(args[0]) if args and args[0].type == "array" else []:
                        url = None
                        if item.type == "object":
                            u = Q.object_props(pf, item).get("url")
                            if u is not None:
                                rv = ctx.ast.resolve_value(pf, u, Q.bindings_for(ctx.ast, pf))
                                url = rv.value
                        elif item.type == "string":
                            url = pf.node_text(item).strip("'\"")
                        if url and len(cands) < 400:
                            add(f"precache:{url}", ev(item, f"Workbox precache entry {url}"),
                                "Precached assets reveal shipped files: fetch them, especially ones no page links to (old bundles, admin pages, source maps).")
            if "self.__WB_MANIFEST" in pf.text:
                node = pf.tree.root_node
                add("precache:__WB_MANIFEST_placeholder",
                    [Evidence(ET.MOCK_OR_PLACEHOLDER, "self.__WB_MANIFEST placeholder was never replaced by the build", self.name, pf.path)]
                    + [Evidence(ET.LITERAL_STRING_MATCH, "Workbox manifest injection marker present", self.name, pf.path)] * 2,
                    "Build-time placeholder only; the real precache list lives in the built worker.")
        return list(cands.values())

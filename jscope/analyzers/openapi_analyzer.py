"""OpenAPI / Swagger Analyzer (Phase 4).

A spec is the server team's own statement of the API. JScope reads it offline and correlates it with what the
CLIENT actually calls, in both directions:

  * documented AND called   -> the matching `endpoint` finding gains ARTIFACT_RESOLVED from this analyzer, which (being an
                               independent source) also earns CROSS_ANALYZER_AGREEMENT. Spec security metadata rides along.
  * called but NOT documented, while the spec documents siblings under the same prefix -> `undocumented_api`
                               (shadow/legacy/beta routes are classically under-reviewed).
  * documented, sensitive, and referenced by no analyzed client code -> `api_operation` with client_referenced=False
                               (functionality the UI never exposes: test authorization directly).

Precision guards: an undocumented-API claim needs a documented sibling prefix (a spec for one service must not
condemn calls to another); "never called by the client" is only asserted when the endpoint analyzer actually ran and
found at least one call; non-sensitive, unreferenced operations are summarised, not listed one by one.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlparse

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import (classify, is_static_asset, is_test_path, path_segments, segs_match, split_origin)
from jscope.core.artifacts import KIND_OPENAPI, Artifact, structured
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind

_METHODS = ("get", "put", "post", "delete", "patch", "options", "head")
_WRITE = {"POST", "PUT", "PATCH", "DELETE"}
_INTERNAL_HOST = ("localhost", "127.0.0.1", "0.0.0.0", ".local", ".internal", "staging", "stage.", "dev.", ".dev.", "test.", "uat", "sandbox", "preprod")


def _resolve(doc: dict, ref_obj):
    """Resolve a local `$ref` ('#/components/parameters/x'); anything else is returned as-is."""
    seen = 0
    while isinstance(ref_obj, dict) and "$ref" in ref_obj and seen < 5:
        ref = str(ref_obj["$ref"])
        if not ref.startswith("#/"):
            return {}
        node = doc
        for part in ref[2:].split("/"):
            node = node.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(node, dict) else {}
        ref_obj, seen = node, seen + 1
    return ref_obj if isinstance(ref_obj, dict) else {}


def _bases(doc: dict) -> tuple[list[str], list[str]]:
    """(base paths, hosts) from OAS3 `servers` or Swagger2 host/basePath."""
    paths, hosts = [], []
    if "servers" in doc:
        for s in doc.get("servers") or []:
            url = str((s or {}).get("url", ""))
            for name, var in ((s or {}).get("variables") or {}).items():
                url = url.replace("{" + name + "}", str((var or {}).get("default", "")))
            u = urlparse(url if "://" in url else "//x" + url if url.startswith("/") else "//" + url)
            if "://" in url and u.netloc:
                hosts.append(u.netloc.lower())
            paths.append(u.path.rstrip("/"))
    else:
        if doc.get("host"):
            hosts.append(str(doc["host"]).lower())
        paths.append(str(doc.get("basePath", "")).rstrip("/"))
    return sorted(set(paths)) or [""], sorted(set(hosts))


def parse_operations(doc: dict) -> list[dict]:
    ops = []
    global_sec = doc.get("security")
    schemes = list((doc.get("components") or {}).get("securitySchemes", {}) or doc.get("securityDefinitions", {}) or {})
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared_params = [_resolve(doc, p) for p in item.get("parameters", []) or []]
        for m in _METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = shared_params + [_resolve(doc, p) for p in op.get("parameters", []) or []]
            bodies = list(((op.get("requestBody") or {}).get("content") or {}).keys()) or list(op.get("consumes") or doc.get("consumes") or [])
            if "security" in op:
                sec, sec_src = op["security"], "operation"
            elif global_sec is not None:
                sec, sec_src = global_sec, "global"
            else:
                sec, sec_src = None, "undeclared"
            if sec == []:
                security = "none-explicit"
            elif sec is None:
                security = "undeclared"
            else:
                security = sorted({k for req in sec if isinstance(req, dict) for k in req}) or ["declared"]
            ops.append({
                "method": m.upper(), "path": str(path), "operation_id": op.get("operationId"),
                "summary": (op.get("summary") or "")[:80], "tags": [str(t) for t in op.get("tags", []) or []],
                "path_params": [p.get("name") for p in params if p.get("in") == "path"],
                "query_params": [p.get("name") for p in params if p.get("in") == "query"],
                "content_types": [str(b) for b in bodies], "security": security, "security_source": sec_src,
                "deprecated": bool(op.get("deprecated")), "has_schemes": bool(schemes),
                "internal_flag": bool(op.get("x-internal") or op.get("x-hidden")),
            })
    return ops


class OpenApiAnalyzer(Analyzer):
    name = "openapi_analyzer"
    depends_on = ["framework_detector"]
    run_after = ["endpoint_analyzer", "html_analyzer"]   # soft: client-call index is filled by these when enabled
    produces_categories = ["api_spec", "api_operation", "undocumented_api", "endpoint"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for art in ctx.artifacts_of(KIND_OPENAPI):
            doc = structured(art)
            if not isinstance(doc, dict):
                ctx.diagnostics.append(f"[openapi_analyzer] {art.path}: could not parse (YAML needs `pip install pyyaml`)")
                continue
            try:
                out.extend(self._spec(art, doc, ctx))
            except Exception as exc:                          # noqa: BLE001
                ctx.diagnostics.append(f"[openapi_analyzer] {art.path}: {type(exc).__name__}: {exc}")
        return out

    # ------------------------------------------------------------------
    def _spec(self, art: Artifact, doc: dict, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        fname = PurePosixPath(art.path.replace("\\", "/")).name
        test = is_test_path(art.path)
        penalty = [Evidence(ET.TEST_FIXTURE_CONTEXT, "spec lives in a test/fixture path", self.name)] if test else []
        version = str(doc.get("openapi") or f"swagger {doc.get('swagger')}")
        ops = parse_operations(doc)
        bases, hosts = _bases(doc)
        base0 = bases[0]
        js = ctx.shared.get("js_endpoints")                    # None => endpoint_analyzer did not run: no client claims at all
        client_known = bool(js) and bool(ctx.shared.get("endpoint_analyzer_ran"))

        def full(op):                                          # the path as it appears on the wire
            return (base0 + op["path"]) if op["path"].startswith("/") else op["path"]

        # ---- 1) the spec itself
        server_urls = [str(s.get("url")) for s in doc.get("servers", []) or [] if isinstance(s, dict)] or hosts
        internal_hosts = [h for h in hosts + server_urls if any(t in h.lower() for t in _INTERNAL_HOST)]
        unauth_all = sum(1 for o in ops if o["security"] in ("undeclared", "none-explicit"))
        spec_ev = [Evidence(ET.ARTIFACT_RESOLVED, f"OpenAPI document parsed ({version}, {len(ops)} operation(s))", self.name, art.path),
                   Evidence(ET.AST_PATTERN_MATCH, "structured parse of paths/servers/security", self.name, art.path)]
        if internal_hosts:
            spec_ev.append(Evidence(ET.NAMING_CONVENTION, "server list names a non-production host: " + ", ".join(internal_hosts[:3]), self.name, art.path))
        out.append(Candidate(
            category="api_spec", subject=f"{fname} ({version})", analyzer=self.name, evidence=spec_ev + penalty,
            attack_surface="internal" if internal_hosts else None,
            suggested_test=("The spec lists non-production servers (" + ", ".join(internal_hosts[:3]) + "): check whether they resolve and expose the same API with weaker controls."
                            if internal_hosts else None),
            metadata={"file": art.path, "servers": server_urls, "operations": len(ops), "security_schemes_defined": bool(ops and ops[0]["has_schemes"]),
                      "ops_without_declared_auth": unauth_all}))

        # ---- 2) match each operation against the client's calls
        matches: dict[tuple[str, str], list[tuple[str, dict]]] = {}      # (METHOD, spec path) -> [(js subject, info)]
        by_path: dict[str, int] = {}
        for o in ops:
            by_path[o["path"]] = by_path.get(o["path"], 0) + 1
        spec_segs = [(o, path_segments(full(o)), path_segments(o["path"])) for o in ops]
        if client_known:
            for subject, info in js.items():
                host, jpath = split_origin(subject)
                if host and host not in hosts:
                    continue                                           # third-party API: not this spec's business
                jsegs = path_segments(jpath)
                best: dict[str, tuple[int, dict]] = {}                 # METHOD -> (specificity, op): literal beats {template}
                for o, sfull, sraw in spec_segs:
                    segs = sfull if segs_match(jsegs, sfull) else sraw if (not host and segs_match(jsegs, sraw)) else None
                    if segs is None:
                        continue
                    ok = (o["method"] in info["reliable_methods"]
                          or (info["fetch"] and (o["method"] == "GET" or by_path[o["path"]] == 1))
                          or (not info["methods"] and by_path[o["path"]] == 1))
                    if not ok:
                        continue
                    spec_lit = sum(1 for a, b in zip(jsegs, segs) if a == b and a != "{}")
                    if o["method"] not in best or spec_lit > best[o["method"]][0]:
                        best[o["method"]] = (spec_lit, o)
                for m, (_, o) in best.items():
                    matches.setdefault((o["method"], o["path"]), []).append((subject, info))

        for o, sfull, _ in spec_segs:
            wire = full(o)
            sub = f"{o['method']} {wire}"
            tag = classify(wire)
            multipart = any("multipart" in c or "octet-stream" in c for c in o["content_types"])
            idor = any(p and (p.lower().endswith("id") or p.lower() == "id") for p in o["path_params"])
            explicit_open = o["security"] == "none-explicit"
            undeclared = o["security"] == "undeclared"
            auth_path = tag == "auth"
            unauth_write = o["method"] in _WRITE and not auth_path and (explicit_open or undeclared)
            hits = matches.get((o["method"], o["path"]), [])
            referenced = bool(hits)
            surface = tag or ("upload" if multipart else "idor_candidate" if idor else "unauthenticated_write" if unauth_write
                              else "deprecated_api" if o["deprecated"] else None)
            hidden = bool(surface) and client_known and not referenced and surface not in ("deprecated_api",)

            # --- enrichment of the client's own endpoint findings (agreement with endpoint_analyzer)
            for subject, info in hits:
                host, jpath = split_origin(subject)
                ev = [Evidence(ET.ARTIFACT_RESOLVED, f"spec {fname} documents {sub}" + (f" (security: {o['security']})" if o["security"] != "undeclared" else " (no security declared)"),
                               self.name, art.path),
                      ]
                out.append(Candidate(category="endpoint", subject=subject, analyzer=self.name, evidence=ev + penalty,
                                     metadata={"spec_operation": sub, "spec_security": o["security"], "spec_file": art.path,
                                               "spec_deprecated": o["deprecated"]}))
                ctx.graph.add_node(f"spec:{sub}", NodeKind.SPEC_OPERATION, sub, file=art.path, security=o["security"])
                ctx.graph.add_node(f"endpoint:{subject}", NodeKind.ENDPOINT, subject)
                ctx.graph.add_edge(f"spec:{sub}", f"endpoint:{subject}", EdgeKind.DOCUMENTS, self.name, "ARTIFACT_RESOLVED", art.path)

            # --- the operation itself, only when it is interesting
            if surface is None and not (referenced and (explicit_open or o["deprecated"])):
                continue
            ev = [Evidence(ET.ARTIFACT_RESOLVED, f"operation defined in spec {fname}", self.name, art.path),
                  Evidence(ET.AST_PATTERN_MATCH, f"paths['{o['path']}'].{o['method'].lower()} parsed", self.name, art.path)]
            if tag:
                ev.append(Evidence(ET.NAMING_CONVENTION, f"path matches '{tag}' naming convention", self.name))
            if explicit_open:
                ev.append(Evidence(ET.LITERAL_STRING_MATCH, "operation declares `security: []` (explicitly public)", self.name, art.path))
            tests = []
            if explicit_open and o["method"] in _WRITE:
                tests.append("The spec itself marks this write operation as public: call it with no credentials and check it really is intended.")
            elif undeclared and o["method"] in _WRITE and not auth_path:
                tests.append("No security requirement is declared for this write operation (the spec may simply omit it): call it unauthenticated.")
            if multipart:
                tests.append("File-accepting operation: test type/size/filename handling and stored-content execution.")
            if idor:
                tests.append(f"Path parameter(s) {', '.join(p for p in o['path_params'] if p)} look like object IDs: swap in another account's IDs (BOLA/IDOR).")
            if o["deprecated"]:
                tests.append("Deprecated operations are often left running without current security fixes.")
            if hidden:
                unresolved = ctx.shared.get("unresolved_client_calls", 0)
                tests.append("No resolvable client call matches this operation, so the UI may never expose it and authorization is often an afterthought: test it directly with a low-privilege and an unauthenticated session."
                             + (f" Caveat: {unresolved} client request call(s) have URLs JScope could not resolve, so a dynamic caller is possible." if unresolved else ""))
            out.append(Candidate(
                category="api_operation", subject=sub, analyzer=self.name, evidence=ev + penalty, attack_surface=surface,
                suggested_test=" ".join(tests) or None,
                metadata={"spec_file": art.path, "operation_id": o["operation_id"], "tags": o["tags"], "security": o["security"],
                          "path_params": o["path_params"], "content_types": o["content_types"], "deprecated": o["deprecated"],
                          "client_referenced": (referenced if client_known else None),
                          "client_unresolved_calls": ctx.shared.get("unresolved_client_calls", 0),
                          **({"absence_based": True} if surface == "unauthenticated_write" and undeclared and not explicit_open else {})}))

        # ---- 3) client calls the spec does not document (only inside an API family the spec does document)
        if client_known:
            prefixes = {tuple(path_segments(b)) for b in bases if b}
            first_segs = {s[0] for _, s, _ in spec_segs if s and s[0] != "{}"}
            for subject, info in sorted(js.items()):
                host, jpath = split_origin(subject)
                if (host and host not in hosts) or is_static_asset(jpath):
                    continue
                jsegs = path_segments(jpath)
                if not jsegs:
                    continue
                in_family = any(tuple(jsegs[:len(p)]) == p for p in prefixes) if prefixes else jsegs[0] in first_segs
                if not in_family:
                    continue
                path_documented = any(segs_match(jsegs, sf) or (not host and segs_match(jsegs, sr)) for _, sf, sr in spec_segs)
                if path_documented:
                    continue
                siblings = [o for o, sf, _ in spec_segs if sf[:max(1, len(jsegs) - 1)] == jsegs[:max(1, len(jsegs) - 1)]]
                if not siblings and not prefixes:
                    siblings = [o for o, sf, _ in spec_segs if sf and sf[0] == jsegs[0]]
                if not siblings and prefixes:
                    siblings = [o for o, sf, _ in spec_segs][:3]
                site = info["sites"][0] if info["sites"] else (None, None)
                tag = classify(jpath)
                out.append(Candidate(
                    category="undocumented_api", subject=subject, analyzer=self.name,
                    evidence=[Evidence(ET.ARTIFACT_RESOLVED, f"spec {fname} documents {len(spec_segs)} operation(s) in this API family, none matching this path", self.name, art.path),
                              Evidence(ET.AST_PATTERN_MATCH, "client code calls this path", self.name, site[0], site[1])]
                    + ([Evidence(ET.NAMING_CONVENTION, f"path matches '{tag}' naming convention", self.name)] if tag else []) + penalty,
                    attack_surface="undocumented_api",
                    suggested_test="The client uses an endpoint the API spec omits. Undocumented routes (internal, legacy, beta) tend to get less review: test authentication, authorization and input handling, and compare against documented siblings.",
                    metadata={"spec_file": art.path, "sites": [f"{f}:{l}" for f, l in info["sites"][:5]]}))
        return out

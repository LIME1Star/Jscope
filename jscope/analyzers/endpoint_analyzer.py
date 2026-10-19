"""Endpoint Analyzer.

Understanding over extraction: doesn't just regex for path-shaped strings.
Looks at fetch/axios/$.ajax/XHR call *shapes* via the AST, tries to resolve
the URL argument through simple const propagation, and classifies the path
by naming convention (admin/internal/debug/versioned) to seed attack-surface
tagging. Depends on framework_detector so it can flag /api/* differently
when Next.js is present (Server Actions/API routes have a different auth
model than an arbitrary fetch target).
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType
from jscope.parsing.ast_engine import ParsedFile

_PATH_RE = re.compile(r"^(https?://[^\s'\"]+|/[a-zA-Z0-9_\-./{}\[\]:]*)$")

_SENSITIVE_PATTERNS = {
    "admin": re.compile(r"/(admin|administrator)(/|$)", re.I),
    "internal": re.compile(r"/(internal|_internal)(/|$)", re.I),
    "debug": re.compile(r"/(_debug|debug)(/|$)", re.I),
    "export": re.compile(r"/(export|download)(/|$)", re.I),
    "upload": re.compile(r"/(upload)(/|$)", re.I),
    "payment": re.compile(r"/(payment|billing|checkout|stripe)(/|$)", re.I),
    "idor_candidate": re.compile(r"(^|/)[{:\[]+(id|[a-z]+_?id)[}\]]*(/|$)|(^|/)(id|user_?id|account_?id)(/|$)", re.I),
    "graphql": re.compile(r"/graphql", re.I),
    "auth": re.compile(r"/(auth|login|logout|register|password|token|oauth)(/|$)", re.I),
}

_METHOD_FROM_CALLEE = {
    "axios.get": "GET", "axios.post": "POST", "axios.put": "PUT",
    "axios.delete": "DELETE", "axios.patch": "PATCH",
    "$.get": "GET", "$.post": "POST",
}


def _classify(path: str) -> str | None:
    for tag, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(path):
            return tag
    return None


class EndpointAnalyzer(Analyzer):
    name = "endpoint_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["endpoint"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        ctx.shared.setdefault("js_endpoints", {})
        ctx.shared["endpoint_analyzer_ran"] = True     # consumers only make "client never calls X" claims if this is set
        return super().analyze_project(ctx)

    def analyze_file(self, pf: ParsedFile, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for site in ctx.ast.find_calls(pf):
            request_like = site.callee == "fetch" or site.callee.startswith(("axios", "$.get", "$.post", "$.ajax"))
            resolved = site.args_resolved[0] if site.args_resolved else None
            if resolved is None or resolved.value is None or resolved.is_placeholder:
                if request_like:
                    # a request whose URL we cannot resolve: it may be the "missing" caller of a documented operation
                    ctx.shared["unresolved_client_calls"] = ctx.shared.get("unresolved_client_calls", 0) + 1
                continue
            path = resolved.value
            if not _PATH_RE.match(path):
                if request_like and ("${" in path or "`" in path or not path.startswith(("/", "http"))):
                    ctx.shared["unresolved_client_calls"] = ctx.shared.get("unresolved_client_calls", 0) + 1   # dynamic URL
                continue
            if "${" in path:
                # unresolved template interpolation -- still informative but weaker
                pass

            evidence = [Evidence(
                type=EvidenceType.AST_PATTERN_MATCH,
                description=f"{site.callee}() call with this URL argument",
                analyzer=self.name,
                file=pf.path,
                line=site.line,
                snippet=site.args_raw[0][:120],
            )]
            if resolved.is_literal:
                evidence.append(Evidence(
                    type=EvidenceType.LITERAL_STRING_MATCH,
                    description="URL is a literal string, not dynamically constructed",
                    analyzer=self.name,
                ))
            if resolved.resolved_via_symbol:
                evidence.append(Evidence(
                    type=EvidenceType.SYMBOL_RESOLVED,
                    description="URL resolved through a local variable binding, not a raw literal in the call",
                    analyzer=self.name,
                ))

            tag = _classify(path)
            if tag:
                evidence.append(Evidence(
                    type=EvidenceType.NAMING_CONVENTION,
                    description=f"path matches '{tag}' naming convention",
                    analyzer=self.name,
                ))

            if "Next.js" in ctx.framework_hints and path.startswith("/api/"):
                evidence.append(Evidence(
                    type=EvidenceType.FRAMEWORK_CONTEXT,
                    description="Next.js detected in project; /api/* path matches its API route convention",
                    analyzer=self.name,
                ))

            if ctx.ast.is_in_dead_branch(pf, site.node):
                evidence.append(Evidence(
                    type=EvidenceType.DEAD_CODE,
                    description="call is inside a branch gated on a falsy/dev-only condition",
                    analyzer=self.name,
                ))

            method = _METHOD_FROM_CALLEE.get(site.callee, "GET" if site.callee == "fetch" else None)
            suggested_test = None
            if tag == "idor_candidate":
                suggested_test = "Vary the ID parameter across accounts/sessions and diff authorization results."
            elif tag == "admin" or tag == "internal":
                suggested_test = "Request as an unauthenticated / low-privilege user and check for missing access control."
            elif tag == "auth":
                suggested_test = "Test auth flow for JWT/session weaknesses, rate limiting, and response differences on valid vs invalid input."

            if not any(e.type == EvidenceType.DEAD_CODE for e in evidence):
                # shared fact for api_correlation: "the client really calls this" (not dead code)
                info = ctx.shared.setdefault("js_endpoints", {}).setdefault(
                    path, {"methods": set(), "reliable_methods": set(), "fetch": False, "sites": []})
                if method:
                    info["methods"].add(method)
                    if site.callee in _METHOD_FROM_CALLEE:       # axios.post etc. state the method; bare fetch() does not
                        info["reliable_methods"].add(method)
                if site.callee == "fetch":
                    info["fetch"] = True
                info["sites"].append((pf.path, site.line))

            out.append(Candidate(
                category="endpoint",
                subject=path,
                analyzer=self.name,
                evidence=evidence,
                attack_surface=tag,
                suggested_test=suggested_test,
                metadata={"method": method, "callee": site.callee},
            ))
        return out

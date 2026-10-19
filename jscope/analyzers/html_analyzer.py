"""HTML Analyzer (Phase 4).

Server-rendered and hybrid apps hide most of their attack surface in markup, not JS: forms, hidden fields, upload
inputs, third-party scripts. Findings stay evidence-first:
  * forms become `form` findings and, when the action is a path, `endpoint` candidates -- so an endpoint reached by BOTH
    a <form> and a JS call earns CROSS_ANALYZER_AGREEMENT like any other independent corroboration
  * absence-based checks (no CSRF token) are tagged `absence_based` and are LOW by construction
  * external-script-without-SRI is only reported when the page's own origin is knowable from the document
    (<base>, canonical, og:url); offline we cannot otherwise tell "third party" from "same site", so we say nothing
Inline <script> bodies are NOT analyzed here: the pipeline turns them into ParsedFiles for the JS analyzers.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

from bs4 import Comment

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import PATH_RE, classify, is_test_path
from jscope.core.artifacts import KIND_HTML
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.core.graph import EdgeKind, NodeKind
from jscope.parsing.html import soup

_CSRF_NAME = re.compile(r"(csrf|xsrf|authenticity_token|_token$|__requestverificationtoken|antiforgery)", re.I)
_CSRF_META = re.compile(r"(csrf|xsrf)", re.I)
_WRITE = {"post", "put", "patch", "delete"}


def _origin_host(doc) -> str | None:
    for tag, attr, key in ((doc.find("base", href=True), "href", None),
                           (doc.find("link", rel="canonical", href=True), "href", None),
                           (doc.find("meta", property="og:url", content=True), "content", None)):
        if tag:
            host = urlparse(tag.get(attr, "")).netloc
            if host:
                return host.lower()
    return None


def _snippet(tag) -> str:
    return re.sub(r"\s+", " ", str(tag))[:140]


class HtmlAnalyzer(Analyzer):
    name = "html_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["form", "form_csrf", "cleartext_credentials", "html_resource", "csp", "html_comment", "endpoint"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for art in ctx.artifacts_of(KIND_HTML):
            try:
                out.extend(self._page(art, ctx))
            except Exception as exc:                       # noqa: BLE001  one malformed page must not sink the rest
                ctx.diagnostics.append(f"[html_analyzer] {art.path}: {type(exc).__name__}: {exc}")
        return out

    # ------------------------------------------------------------------
    def _page(self, art, ctx: ProjectContext) -> list[Candidate]:
        doc = soup(art)
        out: list[Candidate] = []
        page = PurePosixPath(art.path.replace("\\", "/")).name
        test = is_test_path(art.path)
        g = ctx.graph
        pid = f"page:{art.path}"
        g.add_node(pid, NodeKind.PAGE, page, file=art.path)

        def ev(typ, desc, node=None, snippet=None):
            line = getattr(node, "sourceline", None) if node is not None else None
            items = [Evidence(typ, desc, self.name, art.path, line, snippet or (_snippet(node) if node is not None else None))]
            return items

        def test_penalty():
            return [Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock fixture", self.name)] if test else []

        has_csrf_meta = any(_CSRF_META.search(m.get("name", "")) for m in doc.find_all("meta"))

        # ---- scripts -> graph (page loads file)
        for tag in doc.find_all("script", src=True):
            src = tag["src"].strip()
            parsed = urlparse(src)
            if not parsed.netloc:
                target = PurePosixPath(parsed.path).name
                for pf in ctx.files:
                    if pf.origin == "disk" and PurePosixPath(pf.path.replace("\\", "/")).name == target and target:
                        fid = f"file:{pf.path}"
                        g.add_node(fid, NodeKind.FILE, pf.path)
                        g.add_edge(pid, fid, EdgeKind.LOADS, self.name, "ARTIFACT_RESOLVED", art.path,
                                   getattr(tag, "sourceline", None))
                        break

        # ---- external scripts without SRI (only when our own origin is knowable)
        host = _origin_host(doc)
        if host:
            for tag in list(doc.find_all("script", src=True)) + list(doc.find_all("link", href=True, rel="stylesheet")):
                url = tag.get("src") or tag.get("href")
                u = urlparse(url)
                if u.netloc and u.netloc.lower() != host and not tag.get("integrity"):
                    out.append(Candidate(
                        category="html_resource", subject=url, analyzer=self.name,
                        evidence=ev(ET.AST_PATTERN_MATCH, f"cross-origin ({u.netloc}) resource loaded without Subresource Integrity", tag) + test_penalty(),
                        attack_surface="supply_chain",
                        suggested_test="If the third party (or its CDN account/domain) is compromised or expires, this page runs attacker code. Check for takeover of the host and whether an SRI hash or self-hosting is feasible.",
                        metadata={"page": art.path, "origin_inferred_from": "document"}))

        # ---- meta CSP
        for m in doc.find_all("meta", attrs={"http-equiv": re.compile("content-security-policy", re.I)}):
            pol = m.get("content", "")
            weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in pol] + (["wildcard source"] if re.search(r"(^|[\s;])\*([\s;]|$)", pol) else [])
            if weak:
                out.append(Candidate(
                    category="csp", subject=f"{page}: weak meta CSP ({', '.join(weak)})", analyzer=self.name,
                    evidence=ev(ET.AST_PATTERN_MATCH, "CSP <meta> allows " + ", ".join(weak), m)
                    + [Evidence(ET.LITERAL_STRING_MATCH, "policy text contains the weak directive", self.name)] + test_penalty(),
                    attack_surface="csp_weak",
                    suggested_test="A script-src that allows inline/eval weakens XSS containment: look for an HTML/DOM injection sink to pair with it. Also compare against the real response header, which this offline file cannot show."))

        # ---- comments that point at sensitive paths
        for c in doc.find_all(string=lambda s: isinstance(s, Comment)):
            for m in re.finditer(r"(?<![\w.])(/[a-zA-Z0-9_\-./]{3,})", str(c)):
                path = m.group(1)
                tag = classify(path)
                if tag in ("admin", "internal", "debug"):
                    out.append(Candidate(
                        category="html_comment", subject=path, analyzer=self.name,
                        evidence=[Evidence(ET.LITERAL_STRING_MATCH, "path mentioned in an HTML comment", self.name, art.path, None, str(c).strip()[:120]),
                                  Evidence(ET.NAMING_CONVENTION, f"path matches '{tag}' naming convention", self.name)] + test_penalty(),
                        attack_surface=tag,
                        suggested_test="Request the path directly; comments often reference routes the UI no longer links to."))

        # ---- forms
        for i, form in enumerate(doc.find_all("form"), 1):
            method = (form.get("method") or "get").strip().lower()
            action = (form.get("action") or "").strip()
            inputs = form.find_all(["input", "textarea", "select"])
            types = {(x.get("type") or "text").lower() for x in inputs}
            names = [x.get("name") for x in inputs if x.get("name")]
            has_pw, has_file = "password" in types, "file" in types or "multipart" in (form.get("enctype") or "")
            has_csrf = any(_CSRF_NAME.search(n or "") for n in names) or has_csrf_meta
            label = action or "(self)"
            subject = f"{method.upper()} {label} [{page}]"
            surface = "auth" if has_pw else "upload" if has_file else classify(action) if action else None
            tests = []
            if has_pw:
                tests.append("Test credential handling: rate limiting/lockout, response differences for valid vs invalid users, password-reset and MFA bypass.")
            if has_file:
                tests.append("Test upload handling: extension/content-type/magic-byte checks, path traversal in filename, oversized files, stored-XSS via SVG/HTML.")
            if method in _WRITE and not has_pw and not has_file:
                tests.append("State-changing form: replay it from another origin/session to check CSRF protection and server-side authorization.")
            fid = f"form:{art.path}#{i}"
            g.add_node(fid, NodeKind.FORM, subject, file=art.path, method=method.upper(), fields=sorted(set(names)))
            g.add_edge(pid, fid, EdgeKind.CONTAINS_FORM, self.name, "AST_PATTERN_MATCH", art.path, getattr(form, "sourceline", None))

            fe = ev(ET.AST_PATTERN_MATCH, f"<form method={method.upper()}> with {len(inputs)} field(s)" + (" incl. password" if has_pw else "") + (" incl. file upload" if has_file else ""), form, _snippet(form)[:140])
            out.append(Candidate(category="form", subject=subject, analyzer=self.name, evidence=fe + test_penalty(),
                                 attack_surface=surface, suggested_test=" ".join(tests) or None,
                                 metadata={"page": art.path, "method": method.upper(), "action": action, "fields": sorted(set(names)),
                                           "has_password": has_pw, "has_file": has_file, "has_csrf_token": has_csrf}))

            u = urlparse(action)
            if has_pw and u.scheme == "http":
                out.append(Candidate(
                    category="cleartext_credentials", subject=f"{action} [{page}]", analyzer=self.name,
                    evidence=fe[:1] + [Evidence(ET.LITERAL_STRING_MATCH, "password field submits to a literal http:// URL", self.name, art.path, getattr(form, "sourceline", None), action[:100])] + test_penalty(),
                    attack_surface="auth",
                    suggested_test="Credentials posted over cleartext HTTP are exposed to on-path attackers; confirm whether the origin redirects to HTTPS and whether HSTS is set."))

            if method in _WRITE and not has_csrf:
                out.append(Candidate(
                    category="form_csrf", subject=subject, analyzer=self.name,
                    evidence=fe[:1] + [Evidence(ET.LITERAL_STRING_MATCH, "no CSRF-style hidden field in the form and no csrf <meta> in the page", self.name)] + test_penalty(),
                    attack_surface="csrf_candidate",
                    suggested_test="Submit the request cross-site without a token. Cookies with SameSite=Lax/Strict or a custom-header requirement may already protect it: this is an absence-based hint only.",
                    metadata={"absence_based": True}))

            # the form's action is an endpoint too: lets markup and JS corroborate each other
            path = u.path if (u.netloc or action.startswith("/")) else None
            if path and not u.query and PATH_RE.match(path) and (not u.netloc or u.scheme in ("http", "https")):
                idx = ctx.shared.setdefault("js_endpoints", {}).setdefault(
                    path, {"methods": set(), "reliable_methods": set(), "fetch": False, "sites": []})
                idx["methods"].add(method.upper())
                idx["reliable_methods"].add(method.upper())     # a <form> states its method explicitly
                idx["sites"].append((art.path, getattr(form, "sourceline", None)))
                g.add_node(f"endpoint:{path}", NodeKind.ENDPOINT, path)
                g.add_edge(fid, f"endpoint:{path}", EdgeKind.SUBMITS_TO, self.name, "AST_PATTERN_MATCH", art.path, getattr(form, "sourceline", None))
                etag = classify(path)
                out.append(Candidate(
                    category="endpoint", subject=path, analyzer=self.name,
                    evidence=fe[:1] + [Evidence(ET.LITERAL_STRING_MATCH, "literal form action", self.name)]
                    + ([Evidence(ET.NAMING_CONVENTION, f"path matches '{etag}' naming convention", self.name)] if etag else []) + test_penalty(),
                    attack_surface=etag or surface, metadata={"method": method.upper(), "callee": "form"}))
        return out

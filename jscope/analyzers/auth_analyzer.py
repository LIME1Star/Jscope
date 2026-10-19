"""Authentication Analyzer.

Reconstructs HOW the app authenticates: which flows exist (login, logout,
registration, password reset, email verification, MFA, OAuth, refresh) and
which mechanisms carry the credential (bearer header, cookies, client-side
JWT decoding, CSRF tokens, interceptors). Independent of the storage and
endpoint analyzers by design (own AST scan), so agreement between them is
real corroboration rather than shared code.
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import PATH_RE, SENSITIVE_KEY_RE, is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing import queries as Q

_FLOWS: list[tuple[str, re.Pattern, str]] = [
    ("login", re.compile(r"/(login|signin|sign-in|authenticate|auth/token|sessions?)(/|$|\?)", re.I),
     "Test credential stuffing / rate limiting, user enumeration via response or timing differences, and lockout bypass."),
    ("logout", re.compile(r"/(logout|signout|sign-out)(/|$|\?)", re.I),
     "Check the server actually invalidates the session/token (replay the old token after logout)."),
    ("register", re.compile(r"/(register|signup|sign-up)(/|$|\?)", re.I),
     "Test mass assignment on the signup body (role/isAdmin fields), duplicate-email handling, and email verification bypass."),
    ("password_reset", re.compile(r"/(forgot[-_]?password|reset[-_]?password|password[-_]?reset|recover)(/|$|\?)", re.I),
     "Test reset-token entropy/expiry/reuse, host-header poisoning in reset links, and enumeration via responses."),
    ("email_verification", re.compile(r"/(verify[-_]?email|email[-_]?verif\w*|confirm[-_]?email|activate)(/|$|\?)", re.I),
     "Test whether verification can be skipped or the token predicted/reused."),
    ("mfa", re.compile(r"/(mfa|2fa|two[-_]?factor|totp|otp|verify[-_]?code)(/|$|\?)", re.I),
     "Test OTP brute force limits, response-code manipulation, and whether the MFA step can be skipped by calling post-login APIs directly."),
    ("token_refresh", re.compile(r"/(refresh|token/refresh)(/|$|\?)", re.I),
     "Test refresh-token rotation/reuse detection and whether a stolen refresh token outlives logout/password change."),
    ("oauth", re.compile(r"/(oauth2?|authorize|openid|sso|saml)(/|$|\?)", re.I),
     "Test redirect_uri validation, state/nonce enforcement, and PKCE downgrade."),
]
_RESP_TYPE = re.compile(r"response_type=([a-z_ %20]+)", re.I)
_CUSTOM_HEADERS = re.compile(r"^(x-(auth|api|access|csrf|xsrf)[-\w]*|authorization|api-key)$", re.I)


class AuthAnalyzer(Analyzer):
    name = "auth_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["auth"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        cands: dict[str, Candidate] = {}

        def add(subject: str, ev: list[Evidence], test: str | None, meta: dict | None = None,
                surface: str = "auth"):
            c = cands.get(subject)
            if c is None:
                c = cands[subject] = Candidate(category="auth", subject=subject, analyzer=self.name, evidence=[],
                                               attack_surface=surface, suggested_test=test, metadata=dict(meta or {}))
            c.evidence += ev
            for k, v in (meta or {}).items():
                if isinstance(v, list):
                    cur = c.metadata.setdefault(k, [])
                    cur += [x for x in v if x not in cur]

        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue

            def ctxev(node) -> list[Evidence]:
                out = []
                if ctx.ast.is_in_dead_branch(pf, node):
                    out.append(Evidence(ET.DEAD_CODE, "sits in a statically dead branch", self.name))
                if is_test_path(pf.path):
                    out.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "file looks like a test/mock", self.name))
                return out

            def here(node, typ, desc):
                return Evidence(typ, desc, self.name, pf.path, pf.line_of(node), pf.node_text(node)[:100].replace("\n", " "))

            # --- flows via HTTP calls --------------------------------------
            for site in ctx.ast.find_calls(pf):
                if not site.args_resolved or site.args_resolved[0].value is None:
                    continue
                path = site.args_resolved[0].value
                if site.args_resolved[0].is_placeholder or not PATH_RE.match(path):
                    continue
                for flow, rx, test in _FLOWS:
                    if rx.search(path):
                        add(f"flow:{flow}",
                            [here(site.node, ET.AST_PATTERN_MATCH, f"{site.callee}() to {path}"),
                             Evidence(ET.NAMING_CONVENTION, f"path matches the '{flow}' flow convention", self.name)]
                            + ctxev(site.node), test, {"paths": [path]})
                        break

            # --- mechanisms via calls --------------------------------------
            for site in Q.iter_calls(ctx.ast, pf):
                leaf = Q.last_segment(site.callee)
                if leaf in ("jwtDecode", "jwt_decode", "jwt-decode") or site.callee == "jwt_decode":
                    add("mechanism:client_jwt_decode",
                        [here(site.node, ET.AST_PATTERN_MATCH, "client decodes a JWT")] + ctxev(site.node),
                        "Claims are read client-side. Test whether the server trusts unsigned/tampered claims "
                        "(alg=none, role claim edits) and whether UI role logic can be bypassed by editing the token.")
                elif leaf == "atob" and site.args_raw and re.search(r"split\(\s*['\"]\.['\"]\s*\)\s*\[\s*1\s*\]", site.args_raw[0]):
                    add("mechanism:client_jwt_decode",
                        [here(site.node, ET.AST_PATTERN_MATCH, "manual JWT payload decode: atob(token.split('.')[1])")] + ctxev(site.node),
                        "Claims are read client-side. Test server-side validation of tampered claims.")
                elif site.callee.endswith("interceptors.request.use"):
                    add("mechanism:request_interceptor",
                        [here(site.node, ET.AST_PATTERN_MATCH, "axios request interceptor (typically attaches credentials)")] + ctxev(site.node),
                        "Find what the interceptor attaches; then call APIs without it to see which endpoints do not enforce auth.")
                elif site.callee.endswith("interceptors.response.use") and "401" in pf.text:
                    add("behavior:unauthorized_handling",
                        [here(site.node, ET.AST_PATTERN_MATCH, "response interceptor with 401 handling (token refresh / forced logout)")] + ctxev(site.node),
                        "Test the refresh/retry path: concurrent requests, replayed refresh tokens, open-redirect on logout.")

            # --- mechanisms via literals / object keys ---------------------
            for node in ctx.ast.walk(pf.tree.root_node):
                if node.type == "pair":
                    k = Q.key_name(pf, node.child_by_field_name("key"))
                    v = node.child_by_field_name("value")
                    if k is None:
                        continue
                    if k.lower() == "authorization":
                        txt = pf.node_text(v) if v is not None else ""
                        scheme = "basic" if re.search(r"['\"`]Basic\b", txt) else "bearer" if "Bearer" in txt else "authorization_header"
                        ev = [here(node, ET.AST_PATTERN_MATCH, f"Authorization header set ({scheme})")]
                        if scheme != "authorization_header":
                            ev.append(Evidence(ET.LITERAL_STRING_MATCH, f"'{scheme}' scheme literal present", self.name))
                        test = ("Basic credentials are base64, not encrypted: check where they come from and whether they are static."
                                if scheme == "basic" else
                                "Call authenticated APIs with this header removed/replaced and diff responses; test token scope and expiry.")
                        add(f"mechanism:{scheme}", ev + ctxev(node), test)
                    elif _CUSTOM_HEADERS.match(k) and k.lower() != "authorization":
                        add(f"mechanism:header:{k.lower()}", [here(node, ET.AST_PATTERN_MATCH, f"custom auth/CSRF header '{k}' set")] + ctxev(node),
                            "Remove or tamper with this header per endpoint to find endpoints that do not validate it.")
                    elif k in ("withCredentials",) and v is not None and pf.node_text(v) == "true":
                        add("mechanism:cookie_credentials", [here(node, ET.AST_PATTERN_MATCH, "withCredentials: true (cookie-based session)")] + ctxev(node),
                            "Cookie-authenticated cross-origin calls: test CSRF (SameSite, token checks) and CORS reflection of credentials.")
                    elif k == "credentials" and v is not None and pf.node_text(v).strip("'\"") == "include":
                        add("mechanism:cookie_credentials", [here(node, ET.AST_PATTERN_MATCH, "fetch credentials: 'include' (cookie-based session)")] + ctxev(node),
                            "Cookie-authenticated cross-origin calls: test CSRF (SameSite, token checks) and CORS reflection of credentials.")
                elif node.type in ("string", "template_string"):
                    txt = pf.node_text(node).strip("'\"`")
                    m = _RESP_TYPE.search(txt)
                    if m and "client_id" in txt:
                        rt = m.group(1).strip().split("&")[0].replace("%20", " ")
                        pkce = "code_challenge" in txt
                        meta = {"response_types": [rt], "pkce": [pkce]}
                        add("flow:oauth", [here(node, ET.AST_PATTERN_MATCH, f"OAuth authorize URL built (response_type={rt}, pkce={pkce})")] + ctxev(node),
                            "Test redirect_uri validation, state/nonce enforcement, and PKCE downgrade.", meta)
                        if "token" in rt.split():
                            add("weakness:oauth_implicit_flow",
                                [here(node, ET.AST_PATTERN_MATCH, f"response_type={rt} (implicit flow: token returned in URL fragment)")]
                                + ctxev(node),
                                "Implicit flow leaks tokens via fragments/referrers/history; test redirect_uri open redirects to steal them.")
                    elif re.search(r"\bX-?(CSRF|XSRF)-?Token\b|\b_csrf\b", txt, re.I) and len(txt) < 40:
                        add("mechanism:csrf_token", [here(node, ET.LITERAL_STRING_MATCH, "CSRF token name literal")] + ctxev(node),
                            "Test per-endpoint CSRF enforcement: omit/replay the token, and try method override.")

            # --- token persisted in script-readable storage ----------------
            for site in Q.iter_calls(ctx.ast, pf):
                p = site.callee.split(".")
                if len(p) >= 2 and p[-1] == "setItem" and p[-2] in ("localStorage", "sessionStorage") \
                        and site.args_resolved and site.args_resolved[0].value \
                        and SENSITIVE_KEY_RE.search(site.args_resolved[0].value):
                    key = site.args_resolved[0].value
                    add(f"session:token_in_{p[-2]}",
                        [here(site.node, ET.AST_PATTERN_MATCH, f"credential-like key '{key}' written to {p[-2]}")]
                        + ([Evidence(ET.SYMBOL_RESOLVED, "key resolved through a constant", self.name)]
                           if site.args_resolved[0].resolved_via_symbol else []) + ctxev(site.node),
                        "Token is readable by any script on the origin. Hunt XSS sinks; check token lifetime/scope.",
                        {"keys": [key]})
        return list(cands.values())

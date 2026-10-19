"""Redaction rules (FR-08, NFR-03). Applied to everything runtime/verification code stores or exports.

Rules are documented in docs/VERIFICATION.md. Redaction is by default and not optional for exported evidence:
  * Authorization / Cookie / Set-Cookie / X-API-Key style headers  -> value replaced
  * query-string and form parameters whose NAME looks sensitive    -> value replaced
  * JWTs, `Bearer ...`, AWS/Stripe/GitHub/Slack-style keys, long hex/base64 runs after a secret-ish key -> replaced
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token",
                     "x-xsrf-token", "x-amz-security-token", "api-key", "apikey"}
SENSITIVE_PARAM = re.compile(r"(token|secret|passw(or)?d|pwd|credential|api[_-]?key|session|sid|auth|jwt|signature|otp|code)$", re.I)
_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer " + MASK),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}\b"), "[REDACTED-STRIPE-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"(?i)((?:token|secret|passw(?:or)?d|api[_-]?key|session(?:id)?)\s*[=:]\s*)[\"']?[^\s\"'&;,]{6,}"), r"\1" + MASK),
]


def redact_text(text: str | None) -> str | None:
    if not text:
        return text
    for pat, rep in _PATTERNS:
        text = pat.sub(rep, text)
    return text


def redact_headers(headers: dict | None) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        out[k] = MASK if k.lower() in SENSITIVE_HEADERS else redact_text(str(v))
    return out


def redact_url(url: str) -> str:
    try:
        u = urlsplit(url)
        q = [(k, MASK if SENSITIVE_PARAM.search(k) else redact_text(v)) for k, v in parse_qsl(u.query, keep_blank_values=True)]
        netloc = u.netloc.rsplit("@", 1)[-1]
        return urlunsplit((u.scheme, netloc, u.path, urlencode(q, safe="[]"), u.fragment))
    except ValueError:
        return redact_text(url) or ""


def redact_storage_value(key: str, value: str) -> str:
    return MASK if SENSITIVE_PARAM.search(key) or re.search(r"(?i)(token|secret|jwt|auth|session)", key) else (redact_text(value) or "")[:200]


def redact_obj(obj):
    """Deep redaction of dict/list/str structures (used for request/response evidence)."""
    if isinstance(obj, dict):
        return {k: (MASK if isinstance(k, str) and (k.lower() in SENSITIVE_HEADERS or SENSITIVE_PARAM.search(k)) and isinstance(v, str)
                    else redact_obj(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj

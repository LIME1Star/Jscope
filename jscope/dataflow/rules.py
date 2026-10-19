"""Sources, sinks, sanitizers and validators for the data-flow engine (FR-01).

Everything the engine believes about the web platform lives here as plain data so it can be reviewed and extended
without touching the engine. Sink *classes* group sinks that are neutralised by the same kind of sanitizer:
    html        DOM HTML insertion / client-side HTML rendering
    code        dynamic code evaluation / script loading
    navigation  location changes, window.open
    sql         database query text
    command     OS command execution
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SINK_CLASSES = ("html", "code", "navigation", "sql", "command")
ALL = frozenset(SINK_CLASSES)


@dataclass(frozen=True)
class Mitigation:
    """A sanitizer / validator applied to a value. `effective` classes are neutralised, `uncertain` classes MAY be,
    anything else is untouched (an ineffective mitigation is recorded for the report but changes nothing)."""
    name: str
    effective: frozenset = frozenset()
    uncertain: frozenset = frozenset()
    note: str = ""


# ---------------------------------------------------------------------------------------------------- sources
URL_MEMBER = re.compile(r"^(?:(?:window|self|globalThis|top|parent)\.)?(?:document\.)?location\.(hash|search|href|pathname)$")
SOURCE_DOTTED = {
    "document.URL": ("url", "document.URL"), "document.documentURI": ("url", "document.documentURI"),
    "document.referrer": ("referrer", "document.referrer"), "document.cookie": ("cookie", "document.cookie"),
    "window.name": ("window_name", "window.name"), "name": None,
}
URL_KIND = {"hash": "url_hash", "search": "url_query", "href": "url", "pathname": "url_path"}
STORAGE_OBJECTS = {"localStorage", "sessionStorage"}
FORM_CALL_RE = re.compile(r"(getElementById|querySelector|querySelectorAll|getElementsBy\w+|forms)\b")
NETWORK_CALLEES = {"fetch", "axios", "$http.get", "$http.post", "$.get", "$.post", "$.getJSON", "ky", "got"}
NETWORK_PREFIX = ("axios.",)
HUMAN_SOURCE = {
    "url_hash": "URL fragment (location.hash)", "url_query": "URL query string (location.search)",
    "url": "page URL", "url_path": "URL path", "referrer": "document.referrer", "cookie": "document.cookie",
    "window_name": "window.name", "postmessage": "postMessage event data", "storage": "web storage",
    "form_input": "user-controlled form input", "network_response": "network response body",
}

# ---------------------------------------------------------------------------------------------------- sinks
HTML_ASSIGN_PROPS = {"innerHTML": "innerHTML", "outerHTML": "outerHTML", "srcdoc": "iframe.srcdoc"}
CODE_ASSIGN_PROPS = {"src": "script.src (only when the element is a <script>)", "text": None}
NAV_ASSIGN_DOTTED = re.compile(r"^(?:(?:window|self|top)\.)?(?:document\.)?location(?:\.href)?$")
JQUERY_HTML_METHODS = {"html", "append", "prepend", "after", "before", "replaceWith", "wrap", "wrapAll", "appendTo", "prependTo"}
JQUERY_RECEIVER = re.compile(r"^(?:\$|jQuery)\(")
DB_PACKAGES = {"mysql", "mysql2", "pg", "sqlite3", "better-sqlite3", "mssql", "knex", "sequelize", "typeorm", "oracledb",
               "pg-promise", "slonik", "@prisma/client", "mysql2/promise", "sql.js", "alasql"}
DB_METHODS = {"query", "execute", "raw", "queryRaw", "$queryRawUnsafe", "$executeRawUnsafe", "exec", "run", "all", "get"}
CMD_PACKAGES = {"child_process", "node:child_process", "execa", "shelljs", "cross-spawn"}
CMD_FUNCS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork", "shell.exec"}

# ---------------------------------------------------------------------------------------------------- sanitizers
_HTML = frozenset({"html"})
SANITIZERS: list[tuple[re.Pattern, Mitigation]] = [
    (re.compile(r"(^|\.)(dompurify\.)?sanitize$|^sanitizeHtml$|^xss$|(^|\.)filterXSS$", re.I),
     Mitigation("HTML sanitizer (DOMPurify/sanitize-html/xss)", effective=_HTML)),
    (re.compile(r"(^|\.)(escapeHtml|escapeHTML|escape)$|^he\.(encode|escape)$|validator\.escape$"),
     Mitigation("HTML escaping", effective=_HTML, note="does not make a value safe as a URL, SQL or shell string")),
    (re.compile(r"^(encodeURIComponent)$"),
     Mitigation("encodeURIComponent", effective=_HTML, uncertain=frozenset({"navigation"}),
                note="neutralises markup but is not a URL validator")),
    (re.compile(r"^(encodeURI|escape|encodeURL)$"),
     Mitigation("encodeURI", uncertain=_HTML, note="leaves < > \" ' ( ) intact")),
    (re.compile(r"^(Number|parseInt|parseFloat|Boolean|BigInt)$|^Math\.(floor|ceil|round|abs|trunc)$|^Number\.parse(Int|Float)$"),
     Mitigation("numeric coercion", effective=ALL, note="value can only be a number/boolean afterwards")),
    (re.compile(r"(^|\.)quote$|^shellescape$|^escapeShellArg$"),
     Mitigation("shell quoting", effective=frozenset({"command"}))),
]
# A distinct, narrow table for SQL escapers so `escape` on a random object does not count as SQL escaping.
DB_ESCAPERS = re.compile(r"(^|\.)(mysql|connection|pool|db|client|sqlstring|SqlString|pg)\.(escape|escapeId|escapeLiteral|format)$")
PARTIAL_REPLACE = Mitigation("string replace()", uncertain=frozenset({"html", "navigation", "code"}),
                             note="partial filtering by replace() is rarely complete")
# Methods that transform a string but do NOT neutralise it. Taint passes straight through.
PASS_METHODS = {"trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "slice", "substring", "substr", "split", "join",
                "concat", "toString", "padStart", "padEnd", "repeat", "normalize", "at", "charAt", "json", "text", "blob",
                "get", "getAll", "toJSON", "valueOf", "flat", "reverse", "sort", "pop", "shift", "values", "entries", "keys",
                "decodeURIComponent", "decodeURI", "atob", "btoa", "stringify", "parse", "from", "assign", "freeze",
                "clone", "cloneDeep", "map", "filter", "find", "reduce", "forEach", "some", "every", "flatMap", "entries"}
PASSTHROUGH_FUNCS = {"String", "decodeURIComponent", "decodeURI", "atob", "btoa", "JSON.parse", "JSON.stringify", "Object.assign",
                     "Object.values", "Object.entries", "Object.keys", "Array.from", "Array.of", "structuredClone",
                     "Object.freeze", "unescape", "Symbol", "Promise.resolve", "Promise.all", "Promise.race", "Promise.allSettled",
                     "ref", "reactive", "computed", "shallowRef", "toRef", "toRefs", "useState", "useMemo", "useRef", "useCallback",
                     "useReducer", "Array", "Object", "Buffer.from", "Reflect.get"}
PASSTHROUGH_CTORS = {"URLSearchParams", "URL", "String", "Array", "Object", "Set", "Map", "Buffer", "Blob", "Uint8Array", "FormData"}
CLEAN_FUNCS = {"Array.isArray", "isNaN", "Number.isInteger", "Number.isFinite", "Number.isNaN", "console.log", "console.error",
               "console.warn", "console.info", "console.debug", "Date.now", "Math.random", "Math.max", "Math.min", "setState"}

# ---------------------------------------------------------------------------------------------------- validators
_SAFE_ATOM = r"(?:\[[A-Za-z0-9_\-\\wd.\s]+\]|\\w|\\d|[A-Za-z0-9_\-])"
_STRICT_RE = re.compile(r"^\^\(?(?:" + _SAFE_ATOM + r"(?:[+*]|\{\d+(?:,\d*)?\})?)+\)?\$$")


def regex_is_strict_allowlist(src: str) -> bool:
    """True for an anchored pattern built only from alphanumeric classes (`^[a-z0-9_-]+$`, `^\\d{1,6}$`).
    No `.`, no negated class, no alternation: those can admit markup, `javascript:` or quotes. Anything we cannot
    positively show is strict is reported as UNCERTAIN, never as effective."""
    src = src.strip()
    if "[^" in src or "|" in src or ".*" in src or ".+" in src:
        return False
    body = src.replace("\\.", "")                 # escaped dot is allowed only inside a class below
    if "." in re.sub(r"\[[^\]]*\]", "", body):
        return False
    return bool(_STRICT_RE.match(src))


def sink_label(kind: str) -> str:
    return {"html": "DOM HTML insertion", "code": "dynamic code execution", "navigation": "URL navigation",
            "sql": "database query", "command": "OS command execution"}.get(kind, kind)

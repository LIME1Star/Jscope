"""Helpers shared by analyzers. Kept tiny on purpose: analyzers must stay
independently usable, so only genuinely common vocabulary lives here."""

from __future__ import annotations

import os
import re

from jscope.analyzers.endpoint_analyzer import _PATH_RE as PATH_RE, _classify as classify  # noqa: F401

TEST_PATH_RE = re.compile(r"(__tests__|__mocks__|\.test\.|\.spec\.|/test/|/tests/|/mock/|/fixtures?/)", re.I)

GUARD_NAME_RE = re.compile(
    r"(protected|private|require|guard|authenticated|withauth|authorized|rolegate|permission|"
    r"canactivate|authgate|loginrequired)", re.I)

SENSITIVE_KEY_RE = re.compile(
    r"(token|jwt|auth|session|secret|passw(or)?d|credential|api[_-]?key|refresh|bearer|otp)", re.I)


_ANALYSIS_ROOTS: list[str] = []


def set_analysis_roots(paths) -> None:
    """Remember the directories being analyzed so test-path heuristics only look *inside* the analysis root.

    Without this, a project that merely lives under e.g. `/home/me/tests/app/` would have every file treated as a test
    fixture (and its findings demoted), purely because of where it sits on disk."""
    roots: list[str] = []
    for p in paths:
        ap = os.path.abspath(str(p))
        roots.append((ap if os.path.isdir(ap) else os.path.dirname(ap)).replace("\\", "/").rstrip("/"))
    _ANALYSIS_ROOTS[:] = roots


def is_test_path(path: str) -> bool:
    norm = path.replace("\\", "/")
    if _ANALYSIS_ROOTS:
        absp = os.path.abspath(path).replace("\\", "/")
        for root in _ANALYSIS_ROOTS:
            if absp.startswith(root + "/"):
                norm = absp[len(root):]          # keeps a leading "/" so a top-level `tests/` dir still matches
                break
    elif not norm.startswith("/"):
        norm = "/" + norm
    return bool(TEST_PATH_RE.search(norm))


# --------------------------------------------------------------------------
# API path matching (Phase 4): spec paths <-> client paths
# --------------------------------------------------------------------------
from urllib.parse import urlparse  # noqa: E402

_PARAM_SEG = re.compile(r"^(\{[^}]*\}|\$\{[^}]*\}|:[A-Za-z_]\w*|\[[^\]]*\]|<[^>]*>)$")
_STATIC_EXT = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|wasm|html?|webp|avif)$", re.I)


def path_segments(path: str) -> list[str]:
    """Normalize a path to segments, collapsing every parameter style ({id} ${id} :id [id] <id>) to '{}'."""
    path = re.sub(r"\$\{[^}]*\}", "{}", path.split("?")[0].split("#")[0])
    segs = [s for s in path.split("/") if s]
    return ["{}" if (_PARAM_SEG.match(s) or "{}" in s) else s for s in segs]


def segs_match(a: list[str], b: list[str]) -> bool:
    return len(a) == len(b) and all(x == y or x == "{}" or y == "{}" for x, y in zip(a, b))


def split_origin(url: str) -> tuple[str | None, str]:
    """('host', '/path') for an absolute URL, (None, '/path') for a relative one."""
    if "://" in url:
        u = urlparse(url)
        return u.netloc.lower(), u.path or "/"
    return None, url


def is_static_asset(path: str) -> bool:
    return bool(_STATIC_EXT.search(path.split("?")[0]))

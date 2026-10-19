"""HTML / Vue SFC helpers (Phase 4).

Inline `<script>` bodies (and a `.vue` file's `<script>` block) are turned into ordinary ParsedFiles so EVERY existing
analyzer (endpoints, secrets, auth, storage, GraphQL...) runs on them unchanged. Source is left-padded with newlines so
reported line numbers match the original document.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from jscope.core.artifacts import KIND_VUE, Artifact
from jscope.parsing.ast_engine import ASTEngine, ParsedFile

_JS_TYPES = {"", "module", "text/javascript", "application/javascript", "text/babel", "application/x-javascript",
             "text/ecmascript", "application/ecmascript"}


def soup(art: Artifact) -> BeautifulSoup:
    if "soup" not in art.memo:
        art.memo["soup"] = BeautifulSoup(art.text, "html.parser")
    return art.memo["soup"]


def script_tags(art: Artifact):
    """(tag, is_executable_js, lang) for every <script>."""
    out = []
    for tag in soup(art).find_all("script"):
        typ = (tag.get("type") or "").strip().lower()
        lang = (tag.get("lang") or "js").strip().lower()
        out.append((tag, typ in _JS_TYPES, lang))
    return out


def extract_inline_scripts(art: Artifact, ast: ASTEngine) -> tuple[list[ParsedFile], list[str]]:
    files: list[ParsedFile] = []
    diags: list[str] = []
    n = 0
    for tag, is_js, lang in script_tags(art):
        if tag.get("src") and art.kind != KIND_VUE:
            continue                                        # external script: it is its own file
        body = tag.string if tag.string is not None else "".join(tag.strings)
        if not is_js or not body or not body.strip():
            continue
        if lang not in ("js", "javascript", "jsx"):
            diags.append(f"[html] {art.path}: <script lang=\"{lang}\"> not analyzed (JavaScript grammar only)")
            continue
        n += 1
        line = getattr(tag, "sourceline", None) or 1
        padded = ("\n" * (line - 1) + body).encode("utf-8")
        suffix = "#script" if art.kind == KIND_VUE else f"#inline-{n}"
        pf = ast.parse_bytes(padded, path=art.path + suffix)
        pf.origin = "vue-sfc" if art.kind == KIND_VUE else "html-inline"
        files.append(pf)
    return files, diags

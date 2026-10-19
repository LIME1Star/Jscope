"""Non-JavaScript artifacts (Phase 4).

JScope started as a JavaScript tool; the PRD's final phase widens it to the other client-side and
API-description artifacts that sit next to a web app's JS: HTML pages, Vue single-file components,
OpenAPI/Swagger specs, GraphQL schemas (SDL or introspection JSON) and WebAssembly modules.

Collection is purely offline and content-sniffed (a `.json` file is only treated as an OpenAPI spec if it
parses as one), so dropping a whole downloaded site into a directory just works and unrelated JSON is ignored.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jscope.parsing.ast_engine import ASTEngine

KIND_HTML = "html"
KIND_VUE = "vue"
KIND_OPENAPI = "openapi"
KIND_GRAPHQL_SCHEMA = "graphql_schema"
KIND_WASM = "wasm"
ALL_KINDS = (KIND_HTML, KIND_VUE, KIND_OPENAPI, KIND_GRAPHQL_SCHEMA, KIND_WASM)

_HTML_EXT = (".html", ".htm")
_DATA_EXT = (".json", ".yaml", ".yml")
_GQL_EXT = (".graphql", ".gql", ".graphqls")
_MAX_ARTIFACT_BYTES = 20 * 1024 * 1024
_WASM_MAGIC = b"\x00asm"


@dataclass
class Artifact:
    kind: str
    path: str
    data: bytes
    content_hash: str
    origin: str = "disk"                                   # "disk" | "html-inline" ...
    memo: dict[str, Any] = field(default_factory=dict, repr=False)   # parse-once cache shared by pipeline + analyzers

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def _load_structured(text: str, path: str) -> Any | None:
    """JSON or (if PyYAML is installed) YAML. Returns None when it cannot be parsed."""
    if path.lower().endswith(".json") or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except ValueError:
            return None
    try:
        import yaml
    except ImportError:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:       # noqa: BLE001 -- any YAML error just means "not a spec we can read"
        return None


def structured(art: Artifact) -> Any | None:
    if "structured" not in art.memo:
        art.memo["structured"] = _load_structured(art.text, art.path)
    return art.memo["structured"]


def _is_openapi(doc: Any) -> bool:
    return (isinstance(doc, dict) and isinstance(doc.get("paths"), dict)
            and (str(doc.get("openapi", "")).startswith("3") or str(doc.get("swagger", "")).startswith("2")))


def _is_introspection(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    schema = (doc.get("data") or doc).get("__schema") if isinstance(doc.get("data") or doc, dict) else None
    return isinstance(schema, dict) and isinstance(schema.get("types"), list)


def classify_artifact(path: str, data: bytes) -> str | None:
    """Content-sniffing classifier. Returns an artifact kind or None (not an artifact we handle)."""
    low = path.lower()
    if low.endswith(".wasm") or data[:4] == _WASM_MAGIC:
        return KIND_WASM if data[:4] == _WASM_MAGIC else None
    if low.endswith(_HTML_EXT):
        return KIND_HTML
    if low.endswith(".vue"):
        return KIND_VUE
    if low.endswith(_GQL_EXT):
        text = data[:200_000].decode("utf-8", errors="replace")
        return KIND_GRAPHQL_SCHEMA if _looks_like_sdl(text) else None
    if low.endswith(_DATA_EXT):
        head = data[:4096].decode("utf-8", errors="replace").lower()
        if "openapi" in head or "swagger" in head:
            doc = _load_structured(data.decode("utf-8", errors="replace"), path)
            if _is_openapi(doc):
                return KIND_OPENAPI
        if "__schema" in data[:2_000_000].decode("utf-8", errors="replace"):
            doc = _load_structured(data.decode("utf-8", errors="replace"), path)
            if _is_introspection(doc):
                return KIND_GRAPHQL_SCHEMA
    return None


def _looks_like_sdl(text: str) -> bool:
    import re
    return bool(re.search(r"^\s*(extend\s+)?(type|input|interface|enum|schema|union|scalar)\s+\w*", text, re.M)
                and re.search(r"\btype\s+(Query|Mutation|Subscription)\b|\bschema\s*\{", text))


def collect_artifacts(paths: list[str], exclude: list[str], kinds: tuple[str, ...] = ALL_KINDS) -> list[Artifact]:
    out: dict[str, Artifact] = {}

    def consider(f: Path):
        if not f.is_file() or f.stat().st_size > _MAX_ARTIFACT_BYTES:
            return
        rel = str(f)
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            return
        suffix = f.suffix.lower()
        if suffix not in _HTML_EXT + _DATA_EXT + _GQL_EXT + (".wasm", ".vue"):
            return
        data = f.read_bytes()
        kind = classify_artifact(rel, data)
        if kind and kind in kinds:
            out[rel] = Artifact(kind, rel, data, ASTEngine.hash_bytes(data))

    for p in paths:
        path = Path(p)
        if path.is_file():
            consider(path)
        elif path.is_dir():
            for f in path.rglob("*"):
                consider(f)
    return [out[k] for k in sorted(out)]

"""Source Map Analyzer.

Finds `//# sourceMappingURL=` references and, OFFLINE, tries to resolve them:
inline data: URIs, or a .map sitting next to the bundle on disk. A resolved
map with sourcesContent means the application's ORIGINAL source (names,
comments, un-minified logic) is recoverable -- the single biggest accelerant
for every other analyzer. `expand_source_maps()` (used by the pipeline when
`source_maps.expand: true`) feeds recovered app sources back in as virtual
files so the other analyzers run on readable code.

Never touches the network: if the .map isn't on disk the finding is only
"a map is referenced", and the suggested test is to fetch it from the origin.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import is_test_path
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing.ast_engine import ASTEngine, ParsedFile

_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_SENSITIVE_SRC = re.compile(r"(\.env|secret|credential|private|/admin|internal|config/prod|\.pem$|\.key$)", re.I)
MAX_MAP_BYTES = 50 * 1024 * 1024


def load_map(pf: ParsedFile) -> tuple[str, dict | None, str]:
    """-> (reference, parsed map or None, how it was resolved)."""
    matches = _MAP_RE.findall(pf.text)
    if not matches:
        return "", None, "none"
    ref = matches[-1]
    try:
        if ref.startswith("data:"):
            payload = ref.split(",", 1)[1]
            raw = base64.b64decode(payload) if ";base64" in ref.split(",", 1)[0] else payload.encode()
            return ref[:60] + "...", json.loads(raw), "inline"
        if "://" in ref or pf.origin != "disk":
            return ref, None, "remote"
        candidate = (Path(pf.path).parent / ref).resolve()
        if candidate.is_file() and candidate.stat().st_size <= MAX_MAP_BYTES:
            return ref, json.loads(candidate.read_text(encoding="utf-8", errors="replace")), "disk"
    except (OSError, ValueError, json.JSONDecodeError, IndexError):
        return ref, None, "unparseable"
    return ref, None, "not_on_disk"


def app_sources(smap: dict) -> list[tuple[str, str]]:
    """(source path, content) for non-vendor sources that embed content."""
    out = []
    contents = smap.get("sourcesContent") or []
    for name, content in zip(smap.get("sources", []), contents):
        if not content or "node_modules" in name or name.startswith(("webpack/bootstrap", "(webpack)")):
            continue
        out.append((name, content))
    return out


class SourceMapAnalyzer(Analyzer):
    name = "source_map_analyzer"
    depends_on: list[str] = []
    produces_categories = ["source_map"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for pf in ctx.files:
            if pf.skipped_reason or pf.origin != "disk":
                continue
            ref, smap, how = load_map(pf)
            if how == "none":
                continue
            ev = [Evidence(ET.LITERAL_STRING_MATCH, f"sourceMappingURL comment references '{ref}'", self.name, pf.path)]
            meta: dict = {"bundle": pf.path, "reference": ref, "resolved": how}
            test = ("Request the .map next to this bundle on the live origin (same path + '.map'). "
                    "If it is served, the original source is recoverable.")
            if is_test_path(pf.path):
                ev.append(Evidence(ET.TEST_FIXTURE_CONTEXT, "bundle lives in a test/mock location", self.name))
            if smap is not None:
                srcs = smap.get("sources", [])
                app = app_sources(smap)
                meta.update({"sources_total": len(srcs), "app_sources_with_content": len(app),
                             "app_sources_sample": [n for n, _ in app[:25]]})
                ev.append(Evidence(ET.ARTIFACT_RESOLVED,
                                   f"map resolved ({how}) and parsed: {len(srcs)} sources, {len(app)} application sources with embedded content",
                                   self.name, pf.path))
                if app:
                    ev.append(Evidence(ET.ARTIFACT_RESOLVED, "original application source is recoverable from sourcesContent", self.name, pf.path))
                hits = [n for n in srcs if _SENSITIVE_SRC.search(n)]
                if hits:
                    ev.append(Evidence(ET.NAMING_CONVENTION, f"map lists sensitive-looking sources: {', '.join(hits[:3])}", self.name, pf.path))
                    meta["sensitive_sources"] = hits[:10]
                test = ("Original source is recoverable. Run `jscope analyze --expand-source-maps` to analyze it, "
                        "and confirm whether the .map is publicly served on the origin.")
            out.append(Candidate(category="source_map", subject=f"sourcemap:{Path(pf.path).name}", analyzer=self.name,
                                 evidence=ev, attack_surface="source_map", suggested_test=test, metadata=meta))
        return out


def expand_source_maps(files: list[ParsedFile], ast: ASTEngine) -> tuple[list[ParsedFile], int]:
    """Return extra virtual ParsedFiles for recovered JS application sources."""
    extra: list[ParsedFile] = []
    for pf in files:
        if pf.origin != "disk" or pf.skipped_reason:
            continue
        _, smap, how = load_map(pf)
        if smap is None:
            continue
        for name, content in app_sources(smap):
            if not name.lower().split("?")[0].endswith((".js", ".jsx", ".mjs", ".cjs")):
                continue            # TS/Vue/Svelte sources can't be parsed by the JS grammar
            vpf = ast.parse_bytes(content.encode("utf-8", errors="replace"), path=f"{pf.path}!/{name}")
            vpf.origin = "sourcemap"
            extra.append(vpf)
    return extra, len(extra)

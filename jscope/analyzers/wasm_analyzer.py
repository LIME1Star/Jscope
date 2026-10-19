"""WebAssembly Analyzer (Phase 4).

WASM modules hide client logic (validation, licensing, crypto, anti-abuse) and often embed endpoints. This analyzer is
static and offline: it parses the module's structure, derives the toolchain and the host capabilities the module imports
(fetch/eval/storage/websocket), extracts endpoint- and secret-shaped strings, and ties the module to the JS that loads it.

Strings found inside a real data segment get AST_PATTERN_MATCH (we know where they live); strings found only by a raw byte
scan get literal-match weight only.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import PATH_RE, classify, is_test_path
from jscope.analyzers.secret_analyzer import _PATTERNS as SECRET_PATTERNS
from jscope.core.artifacts import KIND_WASM, Artifact
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing.wasm import parse_wasm, printable_strings

_URL = re.compile(r"https?://[^\s\"'<>\\\x00-\x1f]{6,}")
_APIPATH = re.compile(r"(?<![\w.:/])/(?:api|v\d+|graphql|rest|admin|internal|auth|oauth|_debug|debug)(?:/[A-Za-z0-9_\-.{}:]+)*")
_HOST_CAPS = [("fetch", re.compile(r"fetch|xmlhttprequest|xhr", re.I), "makes network requests from inside the module"),
              ("eval", re.compile(r"(^|_)(eval|function_new|newfunction)(_|$)|__wbg_eval", re.I), "can evaluate dynamic JavaScript"),
              ("storage", re.compile(r"localstorage|sessionstorage|indexeddb|cookie", re.I), "reads/writes browser storage"),
              ("websocket", re.compile(r"websocket", re.I), "opens WebSockets"),
              ("crypto", re.compile(r"crypto|subtle|getrandomvalues", re.I), "uses WebCrypto/random from the host")]


def _toolchain(info: dict) -> str | None:
    mods = {i["module"] for i in info["imports"]}
    names = " ".join(i["name"] for i in info["imports"])
    exps = " ".join(e["name"] for e in info["exports"])
    prod = " ".join(" ".join(v) for v in info["producers"].values()).lower()
    if "wbg" in mods or "__wbindgen" in exps:
        return "Rust/wasm-bindgen"
    if "gojs" in mods:
        return "Go"
    if "emscripten" in names or any(m == "env" for m in mods) and "emscripten" in prod:
        return "Emscripten (C/C++)"
    if "wasi_snapshot_preview1" in mods or "wasi_unstable" in mods:
        return "WASI"
    if "__new" in exps and "__pin" in exps:
        return "AssemblyScript"
    if "rust" in prod:
        return "Rust"
    if "clang" in prod or "c++" in prod:
        return "C/C++"
    return None


class WasmAnalyzer(Analyzer):
    name = "wasm_analyzer"
    depends_on = ["framework_detector"]
    produces_categories = ["wasm_module", "endpoint", "secret"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for art in ctx.artifacts_of(KIND_WASM):
            try:
                out.extend(self._module(art, ctx))
            except Exception as exc:                       # noqa: BLE001
                ctx.diagnostics.append(f"[wasm_analyzer] {art.path}: {type(exc).__name__}: {exc}")
        return out

    def _module(self, art: Artifact, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        fname = PurePosixPath(art.path.replace("\\", "/")).name
        penalty = [Evidence(ET.TEST_FIXTURE_CONTEXT, "module lives in a test/fixture path", self.name)] if is_test_path(art.path) else []
        info = parse_wasm(art.data)
        if info["version"] is None:
            ctx.diagnostics.append(f"[wasm_analyzer] {art.path}: not a valid WebAssembly module")
            return out
        if info["truncated"]:
            ctx.diagnostics.append(f"[wasm_analyzer] {art.path}: module is truncated or malformed; partial results")
        tool = _toolchain(info)
        caps = []
        for key, rx, what in _HOST_CAPS:
            hit = [i["name"] for i in info["imports"] if rx.search(i["name"])]
            if hit:
                caps.append((key, what, hit[0]))
        refs = [pf.path for pf in ctx.files if pf.origin in ("disk", "html-inline", "vue-sfc") and not pf.skipped_reason and fname in pf.text]
        refs += [a.path for a in ctx.artifacts if a.kind in ("html", "vue") and fname in a.text]
        mem = info["memories"][0] if info["memories"] else None

        ev = [Evidence(ET.ARTIFACT_RESOLVED, f"WebAssembly module parsed (v{info['version']}, {len(info['sections'])} section(s), "
                       f"{len(info['imports'])} import(s), {len(info['exports'])} export(s)" + (f", {tool}" if tool else "") + ")", self.name, art.path),
              Evidence(ET.AST_PATTERN_MATCH, "binary section table read", self.name, art.path)]
        for r in sorted(set(refs))[:3]:
            ev.append(Evidence(ET.IMPORT_CHAIN, f"referenced by {PurePosixPath(r.replace(chr(92), '/')).name}", self.name, r))
        tests = ["Client logic compiled to WASM is harder to review but not hidden: dump its exports/strings and check whether validation, licensing or "
                 "access decisions made here are re-checked by the server."]
        if caps:
            tests.append("It imports host capabilities (" + ", ".join(c[0] for c in caps) + "): follow the data it sends out or evaluates.")
        if info["has_name_section"]:
            tests.append("A `name` section is present, so function names are recoverable (easier reverse engineering).")
        out.append(Candidate(
            category="wasm_module", subject=fname, analyzer=self.name, evidence=ev + penalty, attack_surface="wasm",
            suggested_test=" ".join(tests),
            metadata={"file": art.path, "toolchain": tool, "imports": len(info["imports"]), "exports": [e["name"] for e in info["exports"]][:40],
                      "host_capabilities": [c[0] for c in caps], "has_name_section": info["has_name_section"], "referenced_by": sorted(set(refs))[:10],
                      "memory": mem, "customs": info["customs"], "truncated": info["truncated"]}))

        # ---- strings: endpoints and secrets
        lo, hi = info["data_range"] or (0, 0)
        seen: set[str] = set()
        for off, s in printable_strings(art.data):
            in_data = lo <= off < hi
            where = "inside a data segment" if in_data else "found by raw byte scan only"
            base = [Evidence(ET.AST_PATTERN_MATCH, f"string located {where}", self.name, art.path)] if in_data else []
            for service_pat, (rx, service) in SECRET_PATTERNS.items():
                m = rx.search(s)
                if not m:
                    continue
                v = m.group(0)
                subject = f"{service}:{v[:8]}...{v[-4:]}" if len(v) > 14 else f"{service}:{v}"
                if subject in seen:
                    continue
                seen.add(subject)
                out.append(Candidate(category="secret", subject=subject, analyzer=self.name,
                                     evidence=[Evidence(ET.LITERAL_STRING_MATCH, f"{service} {service_pat} pattern inside WASM module", self.name, art.path, None, v[:60])] + base + penalty,
                                     suggested_test="Credentials compiled into a client WASM module are public. Verify the secret is live, scope it, and rotate if so.",
                                     metadata={"source": "wasm"}))
            cands = [m.group(0).rstrip(".,);") for m in _URL.finditer(s)] + [m.group(0) for m in _APIPATH.finditer(s)]
            for c in cands:
                path = c
                if not PATH_RE.match(path) or path in seen or len(path) < 4:
                    continue
                seen.add(path)
                tag = classify(path)
                out.append(Candidate(
                    category="endpoint", subject=path, analyzer=self.name,
                    evidence=[Evidence(ET.LITERAL_STRING_MATCH, "endpoint-shaped string embedded in WASM module", self.name, art.path, None, path[:100])] + base
                    + ([Evidence(ET.NAMING_CONVENTION, f"path matches '{tag}' naming convention", self.name)] if tag else []) + penalty,
                    attack_surface=tag, metadata={"source": "wasm", "callee": "wasm-string"},
                    suggested_test="Endpoints compiled into WASM are invisible to JS-only recon. Request it with and without a session and compare with the endpoints the JS client uses."))
        return out

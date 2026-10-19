"""Module resolution (FR-02): maps an import specifier to a file that is part of the analyzed project.

Supported, in order: relative paths (extension probing incl. the TypeScript ESM habit of writing `./x.js` for `x.ts`,
and `dir/index.*`), tsconfig/jsconfig `baseUrl` + `paths` (wildcards, `extends` chain), explicit `module_aliases` from
the JScope config (bundler aliases such as `@` -> `src`). Bare package specifiers resolve to nothing and are reported as
EXTERNAL; anything else that fails is reported as UNRESOLVED with a reason. Resolution never touches the network and
never leaves the set of files given to the analyzer.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

PROBE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue")
_JS_TO_TS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}


@dataclass
class Resolution:
    path: str | None
    status: str            # "resolved" | "external" | "unresolved"
    reason: str = ""
    via: str = "relative"  # relative | tsconfig-paths | tsconfig-baseUrl | config-alias


def _strip_jsonc(text: str) -> str:
    """tsconfig.json is JSON-with-comments-and-trailing-commas. Strip both without touching string contents."""
    out, i, n, in_str, esc = [], 0, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


@dataclass
class TsConfig:
    directory: str
    base_url: str | None = None                       # absolute directory
    paths: dict[str, list[str]] = field(default_factory=dict)
    paths_base: str | None = None                     # directory `paths` targets are relative to
    source: str = ""


def load_tsconfig(path: Path, _seen: set[str] | None = None) -> TsConfig | None:
    _seen = _seen or set()
    key = str(path.resolve())
    if key in _seen:
        return None
    _seen.add(key)
    try:
        raw = json.loads(_strip_jsonc(path.read_text(encoding="utf-8", errors="replace")))
    except (OSError, ValueError):
        return None
    cfg = TsConfig(directory=str(path.parent), source=str(path))
    ext = raw.get("extends")
    if isinstance(ext, str) and ext.startswith("."):
        parent = (path.parent / ext)
        for cand in (parent, parent.with_suffix(".json")):
            if cand.is_file():
                base = load_tsconfig(cand, _seen)
                if base:
                    cfg.base_url, cfg.paths, cfg.paths_base = base.base_url, dict(base.paths), base.paths_base
                break
    co = raw.get("compilerOptions") or {}
    if isinstance(co.get("baseUrl"), str):
        cfg.base_url = str((path.parent / co["baseUrl"]).resolve())
    if isinstance(co.get("paths"), dict):
        cfg.paths = {k: [x for x in v if isinstance(x, str)] for k, v in co["paths"].items() if isinstance(v, list)}
        cfg.paths_base = cfg.base_url or str(path.parent.resolve())
    return cfg


class ModuleResolver:
    def __init__(self, files: list[str], aliases: dict[str, str] | None = None, roots: list[str] | None = None):
        self.files = {os.path.normpath(os.path.abspath(f)): f for f in files}
        self.aliases = dict(aliases or {})
        self._tscache: dict[str, TsConfig | None] = {}
        dirs = [os.path.dirname(a) for a in self.files] or ["."]
        self.root = os.path.commonpath(dirs) if dirs else "."
        self.search_roots = [os.path.abspath(r) for r in (roots or [])]
        self.tsconfig_files: list[str] = []

    # -- tsconfig discovery ----------------------------------------------------------------------
    def tsconfig_for(self, file: str) -> TsConfig | None:
        d = os.path.dirname(os.path.abspath(file))
        ceiling = self.root
        for _ in range(4):                       # allow the config to sit a few levels above the analyzed folder
            ceiling = os.path.dirname(ceiling) or ceiling
        return self.tsconfig_for_dir(d, ceiling)

    def tsconfig_for_dir(self, d: str, ceiling: str) -> TsConfig | None:
        while True:
            if d in self._tscache:
                return self._tscache[d]
            for name in ("tsconfig.json", "jsconfig.json"):
                p = Path(d) / name
                if p.is_file():
                    cfg = load_tsconfig(p)
                    if cfg:
                        self.tsconfig_files.append(str(p))
                        self._tscache[d] = cfg
                        return cfg
            if d == ceiling or d == os.path.dirname(d):
                self._tscache[d] = None
                return None
            d = os.path.dirname(d)

    # -- probing ---------------------------------------------------------------------------------
    def _probe(self, base: str) -> str | None:
        base = os.path.normpath(base)
        if base in self.files:
            return self.files[base]
        stem, ext = os.path.splitext(base)
        for alt in _JS_TO_TS.get(ext, ()):                     # ./x.js written in TS source really means ./x.ts
            if stem + alt in self.files:
                return self.files[stem + alt]
        for e in PROBE_EXTS:
            if base + e in self.files:
                return self.files[base + e]
        for e in PROBE_EXTS:
            idx = os.path.join(base, "index" + e)
            if idx in self.files:
                return self.files[idx]
        return None

    def resolve(self, spec: str, from_file: str) -> Resolution:
        if not spec:
            return Resolution(None, "unresolved", "empty specifier")
        spec = spec.split("?")[0]
        fdir = os.path.dirname(os.path.abspath(from_file))
        if spec.startswith((".", "/")):
            base = spec if spec.startswith("/") else os.path.join(fdir, spec)
            hit = self._probe(base)
            if hit:
                return Resolution(hit, "resolved", via="relative")
            return Resolution(None, "unresolved", f"no file matches '{spec}' relative to {os.path.basename(fdir) or '.'}/")
        tried: list[str] = []
        cfg = self.tsconfig_for(from_file)
        if cfg and cfg.paths:
            for pattern, targets in cfg.paths.items():
                m = self._match_pattern(pattern, spec)
                if m is None:
                    continue
                for t in targets:
                    cand = os.path.join(cfg.paths_base or cfg.directory, t.replace("*", m))
                    tried.append(cand)
                    hit = self._probe(cand)
                    if hit:
                        return Resolution(hit, "resolved", via="tsconfig-paths")
        for alias, target in self.aliases.items():
            if spec == alias or spec.startswith(alias.rstrip("/") + "/"):
                rest = spec[len(alias):].lstrip("/")
                cand = os.path.join(target if os.path.isabs(target) else os.path.join(self.root, target), rest) \
                    if rest else (target if os.path.isabs(target) else os.path.join(self.root, target))
                tried.append(cand)
                hit = self._probe(cand)
                if hit:
                    return Resolution(hit, "resolved", via="config-alias")
        if cfg and cfg.base_url:
            cand = os.path.join(cfg.base_url, spec)
            hit = self._probe(cand)
            if hit:
                return Resolution(hit, "resolved", via="tsconfig-baseUrl")
        if tried:
            return Resolution(None, "unresolved", f"alias matched but no file found (tried {len(tried)} location(s))")
        if spec.startswith(("@/", "~/", "#")):
            return Resolution(None, "unresolved", f"'{spec}' looks like a bundler alias but none is configured "
                                                  "(add tsconfig `paths` or config `module_aliases`)")
        return Resolution(None, "external", "package import (not part of the analyzed files)")

    @staticmethod
    def _match_pattern(pattern: str, spec: str) -> str | None:
        if "*" not in pattern:
            return "" if pattern == spec else None
        pre, post = pattern.split("*", 1)
        if spec.startswith(pre) and spec.endswith(post) and len(spec) >= len(pre) + len(post):
            return spec[len(pre):len(spec) - len(post) if post else len(spec)]
        return None

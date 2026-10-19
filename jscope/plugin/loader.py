"""Plugin loader.

A plugin is a Python module that exposes either
    ANALYZERS = [MyAnalyzer, ...]            (classes or instances), or
    def register() -> list[Analyzer | type]
Plugins are discovered from (1) directories listed in `plugins.paths` and
(2) installed packages exposing the `jscope.analyzers` entry-point group.

Trust model (see docs/PLUGINS.md):
  * plugins can only PROPOSE evidence; the AnalyzerManager enforces that at runtime
  * every plugin analyzer gets tier "community" unless its name appears in
    `plugins.verified`; core analyzers are tier "core"
  * a finding supported ONLY by community-tier analyzers is capped at
    `plugins.community_confidence_cap` (default MEDIUM)

Loading a plugin executes its Python code. Only load plugins you trust --
the tier system limits what a plugin can do to the *report*, not to your machine.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path

from jscope.analyzers.base import Analyzer

PLUGIN_API_VERSION = "0.2"


@dataclass
class LoadResult:
    analyzers: list[Analyzer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)      # analyzer name -> where it came from
    warnings: list[str] = field(default_factory=list)          # FR-09: plugins running WITHOUT isolation, policy notes
    isolated: set[str] = field(default_factory=set)            # analyzer names running in the sandbox


def _coerce(obj, origin: str, res: LoadResult, taken: set[str], verified: set[str]) -> None:
    inst = obj() if inspect.isclass(obj) else obj
    if not isinstance(inst, Analyzer):
        res.errors.append(f"{origin}: {inst!r} is not an Analyzer subclass; skipped")
        return
    if not inst.name or inst.name == "base":
        res.errors.append(f"{origin}: analyzer {type(inst).__name__} must define a unique `name`; skipped")
        return
    if inst.name in taken:
        res.errors.append(f"{origin}: analyzer name '{inst.name}' already registered; skipped")
        return
    inst.tier = "verified" if inst.name in verified else "community"
    taken.add(inst.name)
    res.analyzers.append(inst)
    res.sources[inst.name] = origin


def _from_module(mod, origin: str, res: LoadResult, taken: set[str], verified: set[str]) -> None:   # noqa: C901
    items = list(getattr(mod, "ANALYZERS", []) or [])
    if not items and callable(getattr(mod, "register", None)):
        items = list(mod.register() or [])
    if not items:
        res.errors.append(f"{origin}: defines neither ANALYZERS nor register(); skipped")
        return
    for it in items:
        try:
            _coerce(it, origin, res, taken, verified)
        except Exception as exc:
            res.errors.append(f"{origin}: could not instantiate {it!r}: {type(exc).__name__}: {exc}")


def _load_isolated(f: Path, res: LoadResult, taken: set[str], verified: set[str], isolation: str, policy) -> bool:
    """FR-09: discover the plugin INSIDE the sandbox (its code never runs in this process unless it is verified and
    isolation == "auto"). Returns True when the file was handled here, False to fall back to in-process import."""
    from jscope.plugin.sandbox import SandboxedAnalyzer, discover
    metas, err, violations = discover(str(f), policy)
    if err:
        res.errors.append(f"{f}: {err}")
        return True
    if violations:
        res.warnings.append(f"plugin {f.name} attempted forbidden operations while loading (blocked): {'; '.join(violations)}")
    wants_in_process = isolation == "auto" and any(m["name"] in verified for m in metas)
    if wants_in_process:
        return False                                            # operator explicitly trusts this analyzer by name
    for m in metas:
        if not m.get("name") or m["name"] == "base":
            res.errors.append(f"{f}: analyzer {m.get('class')} must define a unique `name`; skipped")
            continue
        if m["name"] in taken:
            res.errors.append(f"{f}: analyzer name '{m['name']}' already registered; skipped")
            continue
        taken.add(m["name"])
        an = SandboxedAnalyzer(m, str(f), policy, tier="verified" if m["name"] in verified else "community")
        res.analyzers.append(an)
        res.sources[an.name] = str(f)
        res.isolated.add(an.name)
    return True


def load_plugins(paths: list[str], core_names: set[str], verified: set[str] | None = None,
                 use_entry_points: bool = True, isolation: str = "none", sandbox_policy=None) -> LoadResult:
    """isolation: "none" (in-process, full trust), "auto" (community plugins sandboxed, verified-by-name in-process),
    "always" (everything from `paths` sandboxed). Entry-point plugins are installed packages and always run in-process."""
    res = LoadResult()
    taken = set(core_names)
    verified = verified or set()
    if isolation not in ("none", "auto", "always"):
        res.errors.append(f"unknown plugins.isolation {isolation!r}; falling back to 'always'")
        isolation = "always"
    if isolation != "none" and sandbox_policy is None:
        from jscope.plugin.sandbox import SandboxPolicy
        sandbox_policy = SandboxPolicy()

    for p in paths:
        base = Path(p).expanduser()
        files = [base] if base.is_file() else sorted(base.glob("*.py")) if base.is_dir() else []
        if not files:
            res.errors.append(f"plugin path not found or empty: {p}")
        for f in files:
            if f.name.startswith("_"):
                continue
            if isolation != "none" and _load_isolated(f, res, taken, verified, isolation, sandbox_policy):
                continue
            modname = f"jscope_plugin_{f.stem}"
            try:
                spec = importlib.util.spec_from_file_location(modname, f)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[modname] = mod
                spec.loader.exec_module(mod)                   # executes plugin code
            except Exception as exc:
                res.errors.append(f"{f}: import failed: {type(exc).__name__}: {exc}")
                continue
            before = len(res.analyzers)
            _from_module(mod, str(f), res, taken, verified)
            for a in res.analyzers[before:]:
                res.warnings.append(f"plugin '{a.name}' ({f.name}) runs WITHOUT isolation"
                                    + (" (plugins.isolation=none)" if isolation == "none" else " (verified by name)")
                                    + ": it has the same access to this machine as JScope itself")

    if use_entry_points:
        try:
            eps = importlib.metadata.entry_points(group="jscope.analyzers")
        except TypeError:                                       # very old importlib.metadata
            eps = []
        for ep in eps:
            try:
                obj = ep.load()
            except Exception as exc:
                res.errors.append(f"entry-point {ep.name}: import failed: {type(exc).__name__}: {exc}")
                continue
            before = len(res.analyzers)
            if inspect.ismodule(obj):
                _from_module(obj, f"entry-point:{ep.name}", res, taken, verified)
            else:
                try:
                    _coerce(obj, f"entry-point:{ep.name}", res, taken, verified)
                except Exception as exc:
                    res.errors.append(f"entry-point {ep.name}: {type(exc).__name__}: {exc}")
    return res


TEMPLATE = '''"""{name}: a JScope analyzer plugin.

Rules of the road (docs/EVIDENCE_SCHEMA.md, docs/PLUGINS.md):
  * you PROPOSE Candidates backed by typed Evidence; the Evidence Engine decides
    what becomes a finding and at what confidence
  * evidence.analyzer must be your analyzer's name (it is enforced)
  * you cannot emit CROSS_ANALYZER_AGREEMENT -- the engine adds it when a
    DIFFERENT analyzer independently proposes the same (category, subject)
  * prefer AST evidence over bare string matches; always add negative evidence
    (DEAD_CODE, TEST_FIXTURE_CONTEXT) when you can see it
"""

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType
from jscope.parsing import queries as Q


class {cls}(Analyzer):
    name = "{name}"
    depends_on = ["framework_detector"]
    produces_categories = ["{name}"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out = []
        for pf in ctx.files:
            if pf.skipped_reason or pf.tree is None:
                continue
            for site in Q.iter_calls(ctx.ast, pf):
                if site.callee != "dangerousThing":       # <- your detection here
                    continue
                evidence = [Evidence(
                    type=EvidenceType.AST_PATTERN_MATCH,
                    description="call to dangerousThing()",
                    analyzer=self.name, file=pf.path, line=site.line,
                    snippet=(site.args_raw[0][:80] if site.args_raw else None),
                )]
                if ctx.ast.is_in_dead_branch(pf, site.node):
                    evidence.append(Evidence(EvidenceType.DEAD_CODE, "in a dead branch", self.name))
                out.append(Candidate(
                    category="{name}", subject=f"dangerousThing@{{pf.path}}:{{site.line}}",
                    analyzer=self.name, evidence=evidence,
                    suggested_test="What should a human try next?",
                ))
        return out


ANALYZERS = [{cls}]
'''


def scaffold(name: str, out_dir: str) -> Path:
    ident = "".join(ch if ch.isalnum() else "_" for ch in name).strip("_").lower()
    if not ident or ident[0].isdigit():
        raise ValueError("plugin name must start with a letter and contain letters/digits/underscores")
    cls = "".join(p.capitalize() for p in ident.split("_")) + "Analyzer"
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    target = d / f"{ident}.py"
    if target.exists():
        raise FileExistsError(str(target))
    target.write_text(TEMPLATE.format(name=ident, cls=cls))
    return target

"""Parent side of plugin isolation (FR-09): run untrusted plugin code in a restricted child process.

What the parent guarantees, regardless of what the plugin does:
  * plugin code is never imported into the JScope process (discovery also happens in the child)
  * the child gets a scrubbed environment (no tokens, no HOME), an empty temp cwd, hard wall-clock timeout, rlimits
  * its output is parsed as data and validated: only Candidate-shaped dicts, bounded sizes, known evidence types
  * a plugin can never create a Finding or a confirmed status: output goes through AnalyzerManager like any analyzer's
  * every run is recorded (identity, version, outcome, duration, policy violations)
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jscope
from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType

WORKER = str(Path(__file__).with_name("_worker.py"))
JSCOPE_ROOT = str(Path(jscope.__file__).resolve().parent.parent)
MARK = "@@JSCOPE-RESULT@@"
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


@dataclass
class SandboxPolicy:
    timeout_seconds: float = 30.0
    memory_mb: int = 1024
    grant_read: list[str] = field(default_factory=list)       # extra read-only roots the plugin may open
    max_candidates: int = 5000


@dataclass
class PluginRun:
    plugin: str
    analyzer: str
    version: str
    tier: str
    isolation: str                                            # "process" | "none"
    outcome: str = "pending"                                  # ok | error | timeout | resource_exhausted | policy_violation | invalid_output
    duration_s: float = 0.0
    violations: list[str] = field(default_factory=list)
    detail: str = ""
    candidates: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _child_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}


def _run_worker(request: dict, policy: SandboxPolicy) -> tuple[dict | None, str, str]:
    """Returns (parsed_result|None, outcome_if_failed, detail)."""
    with tempfile.TemporaryDirectory(prefix="jscope-sbx-") as cwd:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-B", WORKER], input=json.dumps(request), capture_output=True, text=True, cwd=cwd,
                env=_child_env(), timeout=policy.timeout_seconds)
        except subprocess.TimeoutExpired:
            return None, "timeout", f"killed after {policy.timeout_seconds:g}s wall-clock limit"
    out = proc.stdout or ""
    if len(out.encode("utf-8", "ignore")) > MAX_OUTPUT_BYTES:
        return None, "invalid_output", "plugin output exceeded the size limit"
    idx = out.rfind(MARK)
    if idx < 0:
        if proc.returncode < 0:
            return None, "resource_exhausted", f"worker terminated by signal {-proc.returncode} (CPU/memory limit?)"
        return None, "error", f"worker produced no result (exit {proc.returncode}): {(proc.stderr or '')[-300:].strip()}"
    try:
        return json.loads(out[idx + len(MARK):].strip().splitlines()[0]), "", ""
    except (ValueError, IndexError):
        return None, "invalid_output", "worker result was not valid JSON"


def _base_request(op: str, plugin_path: str, policy: SandboxPolicy) -> dict:
    return {"op": op, "plugin_path": os.path.abspath(plugin_path), "jscope_root": JSCOPE_ROOT,
            "limits": {"cpu_seconds": int(policy.timeout_seconds), "memory_mb": policy.memory_mb},
            "grant_read": policy.grant_read}


def discover(plugin_path: str, policy: SandboxPolicy) -> tuple[list[dict], str | None, list[str]]:
    """Import the plugin inside the sandbox and report its analyzers' metadata. Returns (metas, error, violations)."""
    res, outcome, detail = _run_worker(_base_request("discover", plugin_path, policy), policy)
    if res is None:
        return [], f"sandboxed import failed ({outcome}): {detail}", []
    if not res.get("ok"):
        return [], f"import failed in sandbox: {res.get('error')}", res.get("violations", [])
    if not res.get("declared"):
        return [], "defines neither ANALYZERS nor register(); skipped", []
    return res.get("analyzers", []), None, res.get("violations", [])


class _Foreign:
    """Stand-in for a non-Candidate object the plugin returned; keeps the manager's wording identical."""


def _foreign(name: str):
    return type(name, (_Foreign,), {})()


class SandboxedAnalyzer(Analyzer):
    """Proxy Analyzer whose analyze_project runs in the sandbox worker."""

    def __init__(self, meta: dict, plugin_path: str, policy: SandboxPolicy, tier: str = "community"):
        self.name = meta["name"]
        self.version = meta.get("version", "0.1.0")
        self.depends_on = list(meta.get("depends_on", []))
        self.run_after = list(meta.get("run_after", []))
        self.produces_categories = list(meta.get("produces_categories", []))
        self.tier = tier
        self.plugin_path = plugin_path
        self.policy = policy
        self.sandboxed = True

    def analyze_project(self, ctx: ProjectContext) -> list[Any]:
        run = PluginRun(self.plugin_path, self.name, self.version, self.tier, "process")
        ctx.shared.setdefault("plugin_runs", []).append(run)
        t0 = time.monotonic()
        req = _base_request("analyze", self.plugin_path, self.policy)
        req.update({
            "analyzer": self.name, "max_candidates": self.policy.max_candidates,
            "files": [{"path": pf.path, "data": base64.b64encode(pf.source).decode(), "origin": pf.origin}
                      for pf in ctx.files if not pf.skipped_reason],
            "artifacts": [{"kind": a.kind, "path": a.path, "data": base64.b64encode(a.data).decode(),
                           "content_hash": a.content_hash, "origin": a.origin} for a in ctx.artifacts],
            "framework_hints": _json_safe(ctx.framework_hints), "config": _json_safe(ctx.config), "shared": _json_safe(ctx.shared),
        })
        res, outcome, detail = _run_worker(req, self.policy)
        run.duration_s = round(time.monotonic() - t0, 3)
        if res is None:
            run.outcome, run.detail = outcome, detail
            ctx.diagnostics.append(f"[plugin-isolation] {self.name}: {outcome}: {detail}")
            return []
        run.violations = list(res.get("violations", []))
        if not res.get("ok"):
            err = res.get("error", "")
            run.outcome = "resource_exhausted" if err.startswith("MemoryError") else "error"
            run.detail = err
            if run.violations:
                ctx.diagnostics.append(f"[plugin-isolation] {self.name} attempted forbidden operations: {'; '.join(run.violations)}")
            raise RuntimeError(err)                                   # manager records "[name] crashed: ..." like any analyzer
        if res.get("returned"):
            run.outcome = "invalid_output"
            return _foreign_list(res["returned"])
        out: list[Any] = []
        for d in res.get("candidates", []):
            if "_rejected" in d:
                out.append(_foreign(str(d["_rejected"])))
                continue
            c = _candidate_from_dict(d, ctx)
            if c is not None:
                out.append(c)
        run.candidates = len(out)
        run.outcome = "policy_violation" if run.violations else "ok"
        if run.violations:
            ctx.diagnostics.append(f"[plugin-isolation] {self.name} attempted forbidden operations (blocked): {'; '.join(run.violations)}")
        for d in res.get("diagnostics", []):
            ctx.diagnostics.append(f"[{self.name}] {d}")
        return out


def _foreign_list(name: str):
    return _foreign(name)


def _json_safe(obj, depth=0):
    if depth > 5:
        return None
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {str(k): _json_safe(v, depth + 1) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(v, depth + 1) for v in obj]
    return None


_VALID_TYPES = {e.value: e for e in EvidenceType}


def _candidate_from_dict(d: dict, ctx: ProjectContext) -> Candidate | None:
    try:
        ev = []
        for e in d.get("evidence", []):
            t = _VALID_TYPES.get(e.get("type"))
            if t is None:
                ctx.diagnostics.append(f"[plugin-isolation] unknown evidence type {e.get('type')!r} dropped")
                continue
            ev.append(Evidence(t, str(e.get("description", "")), str(e.get("analyzer", "")), e.get("file"),
                               e.get("line") if isinstance(e.get("line"), int) else None, e.get("snippet"), dict(e.get("metadata") or {})))
        return Candidate(category=str(d["category"]), subject=str(d["subject"]), analyzer=str(d.get("analyzer", "")), evidence=ev,
                         attack_surface=d.get("attack_surface"), suggested_test=d.get("suggested_test"),
                         related=list(d.get("related") or []), metadata=dict(d.get("metadata") or {}))
    except (KeyError, TypeError, ValueError) as exc:
        ctx.diagnostics.append(f"[plugin-isolation] malformed candidate dropped: {type(exc).__name__}")
        return None

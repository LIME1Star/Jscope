"""Sandbox worker (FR-09). Runs in a SEPARATE Python process started with `-I` by jscope.plugin.sandbox.

Defence-in-depth, not a hard security boundary (see docs/PLUGIN_ISOLATION.md):
  1. scrubbed environment, empty temp cwd, request on stdin, result on the original stdout as one JSON line
  2. POSIX resource limits: CPU seconds, address space, open files, file size 0 (no file can be written)
  3. a Python audit hook (cannot be removed once installed) that denies: new sockets / DNS, process creation, ctypes,
     any write/delete/rename/chmod, reads outside an allow-list of roots, and imports of network/process modules.
     Every denied attempt is recorded and returned to the parent as a `violation`.
"""

from __future__ import annotations

import base64
import json
import os
import sys

_REAL_STDOUT = sys.stdout
_violations: list[str] = []
_BLOCKED_IMPORTS = {"ctypes", "_ctypes", "subprocess", "_posixsubprocess", "socket", "_socket", "ssl", "_ssl", "multiprocessing",
                    "http.client", "urllib.request", "ftplib", "smtplib", "telnetlib", "poplib", "imaplib", "asyncio.subprocess",
                    "requests", "urllib3", "httpx", "aiohttp", "pty", "webbrowser", "mmap", "_multiprocessing", "ensurepip"}
_DENY_ALWAYS = {
    "socket.__new__", "socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "socket.sendto", "socket.sendmsg", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
    "os.forkpty", "os.startfile", "ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata", "ctypes.call_function",
    "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.link", "os.symlink", "os.truncate",
    "os.mkfifo", "os.mknod", "os.chroot", "os.kill", "os.killpg", "os.setuid", "os.setgid", "shutil.copyfile", "shutil.copytree",
    "shutil.rmtree", "shutil.move", "shutil.make_archive", "shutil.unpack_archive", "tempfile.mkstemp", "tempfile.mkdtemp",
    "winreg.OpenKey", "webbrowser.open", "pty.spawn", "sys.addaudithook_removed",
}
_READ_ROOTS: list[str] = []


def _deny(event: str, detail: str = "") -> None:
    msg = f"{event}{(' ' + detail) if detail else ''}"
    if msg not in _violations:
        _violations.append(msg)
    raise PermissionError(f"JScope sandbox: {msg} is not permitted for plugins")


def _under(path: str) -> bool:
    try:
        p = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return any(p == r or p.startswith(r.rstrip(os.sep) + os.sep) for r in _READ_ROOTS)


def _hook(event: str, args: tuple) -> None:
    if event in _DENY_ALWAYS:
        _deny(event, repr(args[:1])[:80])
    if event == "import":
        name = str(args[0])
        if name in _BLOCKED_IMPORTS or name.split(".")[0] in {"ctypes", "_ctypes", "subprocess", "socket", "multiprocessing"}:
            _deny("import", name)
        return
    if event == "open":
        path, mode, flags = args[0], args[1], args[2] if len(args) > 2 else 0
        if isinstance(path, int):
            return                                                    # already-open fd
        m = mode or "r"
        if any(c in str(m) for c in "wax+") or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            _deny("open-for-write", str(path)[:80])
        if not _under(os.fsdecode(path)):
            _deny("read-outside-allowed-roots", str(path)[:80])
        return
    if event in ("os.listdir", "os.scandir", "glob.glob", "os.walk"):
        p = args[0]
        if p is not None and not isinstance(p, int) and not _under(os.fsdecode(p)):
            _deny("list-outside-allowed-roots", str(p)[:80])
        return
    if event in ("os.putenv", "os.unsetenv"):
        return


def _limits(cfg: dict) -> None:
    try:
        import resource
    except ImportError:                                               # Windows: only the audit hook + parent timeout apply
        return
    cpu = int(cfg.get("cpu_seconds", 30))
    mem = int(cfg.get("memory_mb", 1024)) * 1024 * 1024
    for res, val in ((resource.RLIMIT_CPU, (cpu, cpu + 1)), (resource.RLIMIT_AS, (mem, mem)),
                     (resource.RLIMIT_NOFILE, (128, 128)), (resource.RLIMIT_FSIZE, (0, 0)), (resource.RLIMIT_CORE, (0, 0))):
        try:
            resource.setrlimit(res, val)
        except (ValueError, OSError):
            pass


def _serialize_candidate(c) -> dict:
    from jscope.core.evidence import Candidate
    if not isinstance(c, Candidate):
        return {"_rejected": type(c).__name__}
    return {
        "category": str(c.category)[:200], "subject": str(c.subject)[:1000], "analyzer": str(c.analyzer)[:200],
        "attack_surface": c.attack_surface if c.attack_surface is None else str(c.attack_surface)[:100],
        "suggested_test": c.suggested_test if c.suggested_test is None else str(c.suggested_test)[:2000],
        "related": [str(x)[:500] for x in (c.related or [])][:50],
        "metadata": _json_safe(c.metadata),
        "evidence": [{"type": getattr(e.type, "value", str(e.type)), "description": str(e.description)[:2000], "analyzer": str(e.analyzer)[:200],
                      "file": None if e.file is None else str(e.file)[:1000], "line": e.line if isinstance(e.line, int) else None,
                      "snippet": None if e.snippet is None else str(e.snippet)[:2000], "metadata": _json_safe(e.metadata)}
                     for e in (c.evidence or [])][:200],
    }


def _json_safe(obj, depth=0):
    if depth > 6:
        return None
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {str(k)[:100]: _json_safe(v, depth + 1) for k, v in list(obj.items())[:200]}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(v, depth + 1) for v in list(obj)[:200]]
    return str(obj)[:200]


def _find_analyzers(plugin_path: str):
    import importlib.util
    import inspect
    from jscope.analyzers.base import Analyzer
    spec = importlib.util.spec_from_file_location("jscope_sandboxed_plugin", plugin_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    items = list(getattr(mod, "ANALYZERS", []) or [])
    if not items and callable(getattr(mod, "register", None)):
        items = list(mod.register() or [])
    out = []
    for it in items:
        inst = it() if inspect.isclass(it) else it
        if isinstance(inst, Analyzer):
            out.append(inst)
    return out, bool(items)


def main() -> int:
    req = json.loads(sys.stdin.read())
    sys.path.insert(0, req["jscope_root"])
    # Import everything the plugin API needs BEFORE the hook goes in; the hook then only polices what the plugin does.
    import jscope.analyzers.base  # noqa: F401
    import jscope.core.evidence  # noqa: F401
    import jscope.parsing.ast_engine  # noqa: F401
    import jscope.parsing.queries  # noqa: F401
    import jscope.core.artifacts  # noqa: F401
    import jscope.core.graph  # noqa: F401
    import jscope.parsing.html  # noqa: F401
    import importlib.util, inspect, glob, tempfile, shutil, re, collections, itertools, functools, dataclasses, typing, enum  # noqa: F401,E401

    roots = {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, req["jscope_root"], "/dev/null", "/dev/urandom")}
    roots |= {os.path.realpath(p) for p in sys.path if p and os.path.exists(p)}
    roots |= {os.path.realpath(req["plugin_path"]), os.path.realpath(os.path.dirname(req["plugin_path"]))}
    roots |= {os.path.realpath(p) for p in req.get("grant_read", [])}
    _READ_ROOTS.extend(sorted(roots))
    sys.stdout = sys.stderr                                           # plugin prints must not corrupt the result channel
    _limits(req.get("limits", {}))
    sys.addaudithook(_hook)

    result: dict = {"ok": True}
    try:
        analyzers, declared = _find_analyzers(req["plugin_path"])
        if req["op"] == "discover":
            result["declared"] = declared
            result["analyzers"] = [{"name": a.name, "version": getattr(a, "version", "0.1.0"), "class": type(a).__name__,
                                    "depends_on": list(a.depends_on), "run_after": list(getattr(a, "run_after", [])),
                                    "produces_categories": list(a.produces_categories)} for a in analyzers]
        else:
            target = next((a for a in analyzers if a.name == req["analyzer"]), None)
            if target is None:
                raise RuntimeError(f"analyzer {req['analyzer']!r} not found in plugin")
            from jscope.analyzers.base import ProjectContext
            from jscope.core.artifacts import Artifact
            from jscope.parsing.ast_engine import ASTEngine
            ast = ASTEngine(max_bytes=req.get("max_file_bytes", 5 * 1024 * 1024))
            files = [ast.parse_bytes(base64.b64decode(f["data"]), path=f["path"]) for f in req["files"]]
            for pf, f in zip(files, req["files"]):
                pf.origin = f.get("origin", "disk")
            arts = [Artifact(kind=a["kind"], path=a["path"], data=base64.b64decode(a["data"]), content_hash=a["content_hash"],
                             origin=a.get("origin", "disk")) for a in req.get("artifacts", [])]
            ctx = ProjectContext(files=files, ast=ast, framework_hints=req.get("framework_hints", {}), config=req.get("config", {}),
                                 artifacts=arts, shared=req.get("shared", {}))
            out = target.analyze_project(ctx)
            if not isinstance(out, list):
                result["returned"] = type(out).__name__
                out = []
            result["candidates"] = [_serialize_candidate(c) for c in out[: req.get("max_candidates", 5000)]]
            result["diagnostics"] = [str(d)[:500] for d in ctx.diagnostics][:100]
    except BaseException as exc:                                      # noqa: BLE001 - includes MemoryError, PermissionError
        result = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    result["violations"] = list(_violations)
    _REAL_STDOUT.write("\n@@JSCOPE-RESULT@@" + json.dumps(result) + "\n")
    _REAL_STDOUT.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

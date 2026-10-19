"""Workspaces: named targets, immutable scan history, incremental rescans (Phase 3).

Layout (all JSON, human-inspectable, safe to commit or rsync):

    .jscope-ws/
      workspace.json                   {"version": 1, "targets": {name: {"paths": [...]}}}
      targets/<name>/index.json        {"scans": [{id, timestamp, fingerprint, finding_count}]}
      targets/<name>/scans/0001.json   {scan_id, timestamp, fingerprint, files{path:hash}, payload}

Incremental rescans, stated precisely: a scan is skipped when its *fingerprint* (every input file's content
hash + the analysis-relevant config + plugin source hashes + the JScope version) equals the previous scan's.
When ANY file changed the whole target is re-analyzed, because route -> component -> API correlation is
cross-file: re-analyzing only the changed file would silently produce a wrong graph. Skipping is therefore
all-or-nothing, which is the only form that is both fast in the common cron case ("nothing changed") and
never wrong. (tree-sitter trees are not serializable, so there is no per-file parse cache on disk.)
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jscope import __version__
from jscope.config import Config
from jscope.pipeline import collect_manifest, run_analysis
from jscope.reporting import json_report
from jscope.workspace.diff import ScanDiff, diff_scans

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SCAN_RE = re.compile(r"^\d{4,}$")
DIRNAME = ".jscope-ws"


from jscope.workspace.common import WorkspaceError, _atomic_write


@dataclass
class ScanOutcome:
    status: str                       # "scanned" | "unchanged"
    record: dict[str, Any]            # the scan record now considered latest
    previous: dict[str, Any] | None
    diff: ScanDiff | None             # None on a first scan (a baseline has no diff)
    result: Any = None                # AnalysisResult when status == "scanned" (graph, findings objects)


def config_fingerprint(config: Config) -> str:
    """Hash of every setting that can change analysis OUTPUT. Output-format/verbosity are excluded on
    purpose, and so is concurrency. Plugin *source* is hashed too: editing a plugin must invalidate."""
    relevant = {k: config.get(k) for k in ("analyzers.enabled", "min_confidence", "exclude", "max_file_bytes",
                                            "source_maps.expand", "artifacts.enabled", "plugins.verified",
                                            "plugins.community_confidence_cap")}
    plugin_hashes = {}
    for p in config.get("plugins.paths", []) or []:
        pp = Path(p)
        for f in ([pp] if pp.is_file() else sorted(pp.rglob("*.py")) if pp.is_dir() else []):
            plugin_hashes[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
    blob = json.dumps({"cfg": relevant, "plugins": plugin_hashes, "v": __version__}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def scan_fingerprint(manifest: dict[str, str], config: Config) -> str:
    blob = json.dumps({"files": manifest, "cfg": config_fingerprint(config)}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / DIRNAME

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def init(cls, root: str | Path) -> "Workspace":
        ws = cls(Path(root))
        if (ws.dir / "workspace.json").exists():
            raise WorkspaceError(f"workspace already exists at {ws.dir}")
        _atomic_write(ws.dir / "workspace.json", {"version": 1, "targets": {}})
        return ws

    @classmethod
    def open(cls, root: str | Path) -> "Workspace":
        ws = cls(Path(root))
        if not (ws.dir / "workspace.json").exists():
            raise WorkspaceError(f"no workspace at {ws.dir} (run `jscope ws init`)")
        return ws

    def _meta(self) -> dict:
        return json.loads((self.dir / "workspace.json").read_text())

    @staticmethod
    def _check_name(name: str) -> str:
        if not _NAME_RE.match(name):
            raise WorkspaceError(f"invalid target name {name!r} (letters, digits, '_', '.', '-'; max 64)")
        return name

    def _tdir(self, name: str) -> Path:
        return self.dir / "targets" / self._check_name(name)

    # -- targets ----------------------------------------------------------
    def add_target(self, name: str, paths: list[str]) -> None:
        self._check_name(name)
        meta = self._meta()
        if name in meta["targets"]:
            raise WorkspaceError(f"target {name!r} already exists")
        missing = [p for p in paths if not Path(p).exists()]
        if missing:
            raise WorkspaceError(f"path(s) not found: {', '.join(missing)}")
        meta["targets"][name] = {"paths": [str(Path(p).resolve()) for p in paths]}
        _atomic_write(self.dir / "workspace.json", meta)

    def remove_target(self, name: str) -> None:
        meta = self._meta()
        if name not in meta["targets"]:
            raise WorkspaceError(f"no such target {name!r}")
        del meta["targets"][name]
        _atomic_write(self.dir / "workspace.json", meta)
        shutil.rmtree(self._tdir(name), ignore_errors=True)      # name validated by _tdir

    def targets(self) -> dict[str, dict]:
        return self._meta()["targets"]

    # -- history ----------------------------------------------------------
    def history(self, name: str) -> list[dict]:
        idx = self._tdir(name) / "index.json"
        return json.loads(idx.read_text())["scans"] if idx.exists() else []

    def load_scan(self, name: str, ref: str = "latest") -> dict:
        hist = self.history(name)
        if not hist:
            raise WorkspaceError(f"target {name!r} has no scans yet")
        if ref == "latest":
            sid = hist[-1]["id"]
        elif ref == "previous":
            if len(hist) < 2:
                raise WorkspaceError(f"target {name!r} has only one scan")
            sid = hist[-2]["id"]
        else:
            sid = ref.zfill(4)
            if not _SCAN_RE.match(sid):
                raise WorkspaceError(f"invalid scan id {ref!r}")
        path = self._tdir(name) / "scans" / f"{sid}.json"
        if not path.exists():
            raise WorkspaceError(f"no scan {sid} for target {name!r}")
        return json.loads(path.read_text())

    # -- scanning ---------------------------------------------------------
    def scan(self, name: str, config: Config, force: bool = False, now: datetime | None = None) -> ScanOutcome:
        targets = self.targets()
        if name not in targets:
            raise WorkspaceError(f"no such target {name!r}")
        paths = targets[name]["paths"]
        hist = self.history(name)
        prev = self.load_scan(name, "latest") if hist else None

        manifest = collect_manifest(paths, config)
        fp = scan_fingerprint(manifest, config)
        if prev is not None and prev["fingerprint"] == fp and not force:
            return ScanOutcome("unchanged", prev, prev, None)

        res = run_analysis(paths, config)
        payload = json_report.payload(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics,
                                   dataflow=res.dataflow, file_diagnostics=res.file_diagnostics)
        sid = f"{(int(hist[-1]['id']) + 1) if hist else 1:04d}"
        ts = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"scan_id": sid, "target": name, "timestamp": ts, "fingerprint": fp,
                  "jscope_version": __version__, "files": manifest, "payload": payload}
        diff = diff_scans(prev, record) if prev is not None else None
        # re-render priority with the delta so the stored ranking already reflects "what changed"
        if diff is not None:
            payload = json_report.payload(res.findings, res.frameworks, res.file_count, res.graph,
                                          res.diagnostics, diff.priority_delta(), dataflow=res.dataflow,
                                          file_diagnostics=res.file_diagnostics)
            record["payload"] = payload
        _atomic_write(self._tdir(name) / "scans" / f"{sid}.json", record)
        _atomic_write(self._tdir(name) / "index.json", {"scans": hist + [{
            "id": sid, "timestamp": ts, "fingerprint": fp, "finding_count": len(res.findings),
            "file_count": len(manifest)}]})
        return ScanOutcome("scanned", record, prev, diff, res)

    # -- multi-target overview -------------------------------------------
    def summary(self) -> list[dict]:
        rows = []
        for name in sorted(self.targets()):
            hist = self.history(name)
            if not hist:
                rows.append({"target": name, "scans": 0})
                continue
            rec = self.load_scan(name, "latest")
            fs = rec["payload"]["findings"]
            conf: dict[str, int] = {}
            for f in fs:
                conf[f["confidence"]] = conf.get(f["confidence"], 0) + 1
            top = rec["payload"]["priority"][0] if rec["payload"]["priority"] else None
            top_f = next((f for f in fs if top and f["id"] == top["id"]), None)
            rows.append({
                "target": name, "scans": len(hist), "last_scan": rec["timestamp"], "files": len(rec["files"]),
                "findings": len(fs), "by_confidence": conf, "frameworks": rec["payload"]["summary"]["frameworks"],
                "unprotected_routes": sum(1 for c in rec["payload"].get("route_map", []) if c["unguarded"]),
                "top": {"id": top_f["id"], "subject": top_f["subject"], "priority": top["priority"]} if top_f else None})
        return rows

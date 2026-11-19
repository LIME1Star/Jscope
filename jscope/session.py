"""Investigation context: what JScope already knows about the current investigation.

One small JSON file (`.jscope/session.json`, found by walking up from the cwd) records the current target, the
authorized host, and where the latest findings live. Every command -- direct or from the interactive shell -- reads
it through this module, so nothing has to be re-typed. It stores *pointers and scope*, never findings or
credentials: findings stay in their own file, so evidence integrity does not depend on the session.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from jscope.workspace.common import _atomic_write

STATE_DIR = ".jscope"
SESSION_FILE = "session.json"
SCHEMA = "jscope-session/1"


class SessionError(Exception):
    """A user-correctable problem with the investigation context."""


def slug(text: str) -> str:
    text = re.sub(r"^https?://", "", text)
    text = re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-")
    return text[:80] or "target"


def is_url_like(target: str) -> bool:
    """True for things that should be fetched rather than read from disk."""
    if "://" in target:
        return True
    if Path(target).exists():
        return False
    host = target.split("/", 1)[0]
    return "." in host and " " not in target and not target.startswith((".", "/", "~"))


def normalize_url(target: str) -> str:
    return target if "://" in target else "https://" + target


@dataclass
class Session:
    target: str = ""
    kind: str = ""                    # "url" | "path" | ""
    base_url: str | None = None       # origin for runtime commands (url targets only)
    host: str | None = None           # the single host runtime commands may touch by default
    out_dir: str | None = None
    findings_file: str | None = None
    allow_private: bool = False
    updated_at: str = ""
    root: str = field(default="", repr=False)   # directory containing .jscope (not persisted)

    # ------------------------------------------------------------ persistence
    @staticmethod
    def find_root(start: Path | None = None) -> Path | None:
        cur = (start or Path.cwd()).resolve()
        for d in (cur, *cur.parents):
            if (d / STATE_DIR / SESSION_FILE).is_file():
                return d
        return None

    @classmethod
    def load(cls, start: Path | None = None) -> "Session":
        root = cls.find_root(start)
        if root is None:
            return cls(root=str((start or Path.cwd()).resolve()))
        try:
            raw = json.loads((root / STATE_DIR / SESSION_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(root=str(root))          # corrupt context must never block direct usage
        known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw and k != "root"}
        s = cls(**known)
        s.root = str(root)
        return s

    def save(self) -> None:
        root = Path(self.root or Path.cwd())
        self.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        data = {k: v for k, v in asdict(self).items() if k != "root"}
        data["schema"] = SCHEMA
        _atomic_write(root / STATE_DIR / SESSION_FILE, data)

    # ------------------------------------------------------------ mutation
    def set_target(self, target: str, *, allow_private: bool | None = None) -> None:
        """Point the investigation at a new target. A different target resets target-bound state so a stale
        findings file or host can never be applied to the wrong system."""
        if target != self.target:
            self.out_dir = self.findings_file = None
        self.target = target
        if is_url_like(target):
            url = normalize_url(target)
            p = urlparse(url)
            self.kind = "url"
            self.base_url = f"{p.scheme}://{p.netloc}"
            self.host = p.netloc
        else:
            self.kind = "path"
            self.base_url = self.host = None
        if allow_private is not None:
            self.allow_private = allow_private

    def record_analysis(self, findings_file: str | Path, out_dir: str | Path | None = None) -> None:
        self.findings_file = str(Path(findings_file).resolve())
        if out_dir:
            self.out_dir = str(Path(out_dir).resolve())
        self.save()

    # ------------------------------------------------------------ queries
    @property
    def active(self) -> bool:
        return bool(self.target)

    def require_findings(self) -> Path:
        if not self.findings_file:
            raise SessionError("no analysis yet -- run `jscope <target>` first (or pass a findings file)")
        p = Path(self.findings_file)
        if not p.is_file():
            raise SessionError(f"findings file is missing: {p} -- re-run `jscope {self.target or '<target>'}`")
        return p

    def label(self) -> str:
        return self.host or (Path(self.target).name if self.target else "")

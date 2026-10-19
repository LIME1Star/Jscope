"""Domain-centric assessment scope and audit records.

This module deliberately separates discovered hosts from hosts approved for the
current assessment. Workspace history is knowledge, never standing permission.
No network activity is performed here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from jscope.workspace.common import WorkspaceError, _atomic_write

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Normalize a DNS name or URL to a hostname; reject ambiguous/non-domain inputs."""
    raw = value.strip()
    if not raw:
        raise WorkspaceError("target domain cannot be empty")
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise WorkspaceError("target must be a DNS domain or an http(s) URL without credentials")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise WorkspaceError("provide a domain/origin only, not a path, query, or fragment")
        host = parsed.hostname
    else:
        if any(ch in raw for ch in "/?#@"):
            raise WorkspaceError(f"invalid domain {value!r}; provide a hostname only")
        host = raw.rstrip(".")
        if ":" in host:
            raise WorkspaceError("ports and IP literals are not supported as domain workspace roots")
    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise WorkspaceError(f"invalid internationalized domain: {value!r}") from exc
    if len(host) > 253 or "." not in host or host.startswith("."):
        raise WorkspaceError(f"{value!r} is not a fully qualified DNS domain")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WorkspaceError("domain-centric workspaces require a DNS name, not an IP address")
    labels = host.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise WorkspaceError(f"invalid DNS hostname: {value!r}")
    return host


def validate_scope_file(path: str | Path, root_domain: str) -> dict[str, Any]:
    """Parse a host-per-line authorization file; no DNS/network calls are made."""
    root = normalize_domain(root_domain)
    file_path = Path(path)
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise WorkspaceError(f"cannot read scope file {str(path)!r}: {exc}") from exc
    approved: list[str] = []
    rejected: list[dict[str, str | int]] = []
    for number, line in enumerate(lines, 1):
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        try:
            host = normalize_domain(item)
            if host != root and not host.endswith("." + root):
                raise WorkspaceError(f"host is outside root domain {root}")
            approved.append(host)
        except WorkspaceError as exc:
            rejected.append({"line": number, "value": item, "reason": str(exc)})
    # Preserve order while removing duplicates.
    approved = list(dict.fromkeys(approved))
    return {
        "path": str(file_path.resolve()),
        "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
        "approved_hosts": approved,
        "rejected_entries": rejected,
        "valid": not rejected and bool(approved),
    }


def create_assessment_record(root: str, known_hosts: list[str] | None = None,
                             approved_hosts: list[str] | None = None,
                             limits: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a new assessment manifest; approvals are explicit and per-run."""
    domain = normalize_domain(root)
    known = list(dict.fromkeys(normalize_domain(h) for h in (known_hosts or [domain])))
    approved = list(dict.fromkeys(normalize_domain(h) for h in (approved_hosts or [])))
    invalid = [h for h in known + approved if h != domain and not h.endswith("." + domain)]
    if invalid:
        raise WorkspaceError(f"hosts outside root domain {domain}: {', '.join(invalid)}")
    if not set(approved).issubset(set(known)):
        raise WorkspaceError("every approved host must first be present in the known-host list")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "schema": "jscope-assessment/1",
        "assessment_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3),
        "root_domain": domain,
        "created_at": now,
        "status": "approved" if approved else "planned",
        "authorization": {"fresh_for_this_run": True, "approved_at": now if approved else None, "approved_hosts": approved},
        "hosts": {h: {"state": "approved" if h in approved else "known", "discovery_source": "user-supplied" if h == domain else "scope-input"} for h in known},
        "limits": limits or {"max_requests": 500, "rate_per_second": 2.0, "depth": "deep"},
        "stages": [],
        "findings": [],
        "evidence": [],
        "coverage": {"tested_hosts": [], "untested_hosts": known, "limitations": []},
    }


def record_stage(manifest: dict[str, Any], stage: str, outcome: str, detail: str = "") -> None:
    manifest.setdefault("stages", []).append({
        "stage": stage, "outcome": outcome,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "detail": detail,
    })


def write_assessment(root: str | Path, manifest: dict[str, Any]) -> Path:
    """Atomically persist a manifest under .jscope-ws/assessments."""
    root = Path(root)
    out = root / ".jscope-ws" / "assessments" / f"{manifest['assessment_id']}.json"
    _atomic_write(out, manifest)
    return out

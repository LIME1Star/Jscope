"""Deterministic, scope-aware assessment orchestration primitives.

This module intentionally ships conservative baseline/passive stages and module
contracts. Active checks are opt-in modules and must use the supplied guarded
transport; discovery never grants authorization.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from jscope.security_transport import PolicyError, TransportPolicy, GuardedSession, normalize_host


class AssessmentError(RuntimeError):
    pass


def _stable_id(prefix: str, value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"{prefix}-{hashlib.sha256(blob).hexdigest()[:12]}"


@dataclass(frozen=True)
class ModuleMetadata:
    name: str
    version: str = "1.0"
    required_permissions: tuple[str, ...] = ()
    traffic: str = "passive"
    authentication: str = "optional"
    impact: str = "low"
    input_types: tuple[str, ...] = ("endpoint",)
    evidence_required: bool = True
    request_budget: int = 10
    time_budget_seconds: float = 30.0


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: str = "observed"
    parameters: list[str] = field(default_factory=list)
    auth_context: str | None = None
    status: int | None = None
    content_type: str | None = None
    endpoint_id: str = ""

    def __post_init__(self):
        if not self.endpoint_id:
            self.endpoint_id = _stable_id("EP", [self.method.upper(), self.url])


@dataclass
class Relationship:
    source_id: str
    target_id: str
    relation: str
    provenance: dict[str, Any]
    confidence: str = "medium"
    observed: bool = False
    relationship_id: str = ""

    def __post_init__(self):
        if not self.relationship_id:
            self.relationship_id = _stable_id("REL", [self.source_id, self.target_id, self.relation, self.provenance])


@dataclass
class FindingRecord:
    title: str
    category: str
    severity: str
    confidence: str
    endpoint: str
    method: str
    summary: str
    expected: str = ""
    observed: str = ""
    remediation: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_endpoints: list[str] = field(default_factory=list)
    status: str = "hypothesis"
    finding_id: str = ""
    validated_at: str | None = None

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = _stable_id("JSF", [self.category, self.method.upper(), self.endpoint, self.title])


class EvidenceStore:
    """Stores sanitized, content-addressed evidence records."""
    SENSITIVE = re.compile(r"(?i)(authorization|cookie|set-cookie|token|api[_-]?key|password|secret)(\s*[:=]\s*)([^&\s,;]+)")

    def __init__(self):
        self.records: dict[str, dict[str, Any]] = {}

    @classmethod
    def sanitize(cls, value: str, limit: int = 4000) -> str:
        value = re.sub(r"(?im)(authorization|proxy-authorization|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+", r"\1\2[REDACTED]", value)
        value = cls.SENSITIVE.sub(r"\1\2[REDACTED]", value)
        value = re.sub(r"(?i)([?&](?:token|key|password|secret|access_token)=)[^&#\s]+", r"\1[REDACTED]", value)
        return value[:limit]

    def add(self, kind: str, content: str, metadata: dict[str, Any] | None = None) -> str:
        clean = self.sanitize(content)
        digest = hashlib.sha256(clean.encode()).hexdigest()
        evidence_id = "E-" + digest[:16]
        self.records.setdefault(evidence_id, {
            "evidence_id": evidence_id, "kind": kind, "sha256": digest,
            "content": clean, "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        return evidence_id


class ModuleRegistry:
    def __init__(self):
        self._modules: dict[str, tuple[ModuleMetadata, Callable]] = {}

    def register(self, metadata: ModuleMetadata, runner: Callable) -> None:
        if metadata.name in self._modules:
            raise AssessmentError(f"duplicate module: {metadata.name}")
        if metadata.traffic not in {"passive", "active"} or metadata.impact not in {"low", "moderate", "high"}:
            raise AssessmentError("invalid module capability metadata")
        if metadata.request_budget < 0 or metadata.time_budget_seconds <= 0:
            raise AssessmentError("invalid module budgets")
        self._modules[metadata.name] = (metadata, runner)

    def get(self, name: str):
        return self._modules[name]

    def all(self):
        return [metadata for metadata, _ in self._modules.values()]


class CorrelationEngine:
    """Creates traceable relationships; references are hypotheses, not authorization."""
    def correlate(self, resources: list[dict[str, Any]]) -> list[Relationship]:
        by_url = {}
        by_path = {}
        for item in resources:
            if item.get("url"):
                by_url[item["url"]] = item
                try:
                    by_path[urlsplit(item["url"]).path] = item
                except ValueError:
                    pass
        links = []
        for item in resources:
            source_id = item.get("id") or _stable_id("R", item)
            text = item.get("content", "")
            base = item.get("url", "")
            pattern = r"""(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*['"]([^'"]+)['"]|(?:src|href)\s*=\s*['"]([^'"]+)['"]"""
            for match in re.finditer(pattern, text, re.I):
                raw = match.group(1) or match.group(2)
                absolute = urljoin(base, raw) if base else raw
                target = by_url.get(absolute) or by_path.get(urlsplit(absolute).path)
                if target:
                    target_id = target.get("id") or _stable_id("R", target)
                    links.append(Relationship(source_id, target_id, "references", {
                        "source_url": base, "reference": raw, "resolved_url": absolute,
                        "method": "static-string-reference",
                    }, confidence="medium", observed=False))
        return links


class AssessmentOrchestrator:
    STAGES = ("authorization", "inventory", "passive_discovery", "baseline", "low_impact",
              "correlation", "additional_approval", "active_testing", "validation", "reporting")

    def __init__(self, assessment_id: str, manifest_path: str | Path,
                 policy: TransportPolicy, registry: ModuleRegistry | None = None):
        self.assessment_id = assessment_id
        self.manifest_path = Path(manifest_path)
        self.policy = policy
        self.registry = registry or ModuleRegistry()
        self.evidence = EvidenceStore()
        self.endpoints: dict[str, Endpoint] = {}
        self.relationships: list[Relationship] = []
        self.findings: dict[str, FindingRecord] = {}
        self.events: list[dict[str, Any]] = []
        self.cancelled = False
        if policy.assessment_id != assessment_id:
            raise AssessmentError("transport assessment ID mismatch")
        self._validate_authorization()

    def _validate_authorization(self):
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            stat = self.manifest_path.stat()
        except (OSError, ValueError) as exc:
            raise AssessmentError("authorization manifest unavailable or corrupt") from exc
        if data.get("schema") != "jscope-assessment/1" or data.get("assessment_id") != self.assessment_id:
            raise AssessmentError("authorization manifest identity/schema mismatch")
        auth = data.get("authorization")
        if not isinstance(auth, dict) or auth.get("fresh_for_this_run") is not True:
            raise AssessmentError("assessment lacks fresh authorization")
        approved = auth.get("approved_hosts")
        if not isinstance(approved, list) or not approved:
            raise AssessmentError("assessment has no approved hosts")
        normalized = {normalize_host(h) for h in approved}
        if normalized != {normalize_host(h) for h in self.policy.hosts}:
            raise AssessmentError("transport scope does not match approved manifest hosts")
        if data.get("status") != "approved":
            raise AssessmentError("assessment is not in approved state")
        self.manifest_digest = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self._manifest_mtime_ns = stat.st_mtime_ns
        self._manifest_size = stat.st_size
        self.manifest = data

    def revalidate(self):
        try:
            stat = self.manifest_path.stat()
            digest = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise AssessmentError("authorization manifest unavailable") from exc
        if (stat.st_mtime_ns != self._manifest_mtime_ns or stat.st_size != self._manifest_size
                or digest != self.manifest_digest):
            raise AssessmentError("authorization manifest changed; restart approval review")
        self._validate_authorization()

    def add_endpoint(self, endpoint: Endpoint):
        self.revalidate()
        host = normalize_host(urlsplit(endpoint.url).hostname or "")
        if host not in {normalize_host(h) for h in self.policy.hosts}:
            raise AssessmentError("endpoint host is not explicitly approved")
        self.endpoints.setdefault(endpoint.endpoint_id, endpoint)

    def add_finding(self, finding: FindingRecord):
        # Dedupe key includes category, method and endpoint; title alone is insufficient.
        self.findings.setdefault(finding.finding_id, finding)

    def cancel(self):
        self.cancelled = True
        self.policy.event("assessment-cancelled", outcome="info", reason="operator-request")

    def run_modules(self, names: list[str], context: dict[str, Any] | None = None):
        results = []
        for name in names:
            if self.cancelled:
                break
            self.revalidate()
            metadata, runner = self.registry.get(name)
            if metadata.traffic == "active":
                if "active_testing" not in self.manifest.get("authorization", {}).get("permissions", ["active_testing"]):
                    raise AssessmentError(f"active permission missing for module {name}")
                if self.manifest.get("status") != "approved":
                    raise AssessmentError("active testing requires approved assessment")
            start = time.monotonic()
            before = self.policy._count
            global_budget = self.policy.total_budget
            self.policy.total_budget = min(global_budget, before + metadata.request_budget)
            try:
                result = runner(context or {}, self)
                if time.monotonic() - start > metadata.time_budget_seconds:
                    raise AssessmentError(f"module time budget exceeded: {name}")
                results.append({"module": name, "status": "completed", "result": result})
            except Exception as exc:
                results.append({"module": name, "status": "failed", "error": type(exc).__name__})
                self.policy.event("module-failed", outcome="error", reason=type(exc).__name__)
            finally:
                self.policy.total_budget = global_budget
        return results

    def to_dict(self):
        return {
            "schema_version": "jscope-assessment-result/1",
            "assessment_id": self.assessment_id,
            "manifest_sha256": self.manifest_digest,
            "status": "cancelled" if self.cancelled else "completed",
            "endpoints": [asdict(x) for x in self.endpoints.values()],
            "relationships": [asdict(x) for x in self.relationships],
            "findings": [asdict(x) for x in self.findings.values()],
            "evidence": list(self.evidence.records.values()),
            "coverage": {"known_endpoints": len(self.endpoints), "finding_count": len(self.findings)},
        }

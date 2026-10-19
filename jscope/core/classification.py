"""Finding classification (FR-08): what KIND of statement is a finding, and how far has it been verified?

Two orthogonal axes, deliberately separate from `confidence`:

  evidence_class        observed_fact | static_inference | security_hypothesis | verified_behavior | confirmed_vulnerability
  verification_status   unverified | probable | confirmed | inconclusive | rejected

`confidence` says how sure JScope is that a code pattern EXISTS and means what it looks like. It never says the
weakness is exploitable. Only verification can move a finding to confirmed_vulnerability, and only by the documented
procedure for its class (docs/VERIFICATION.md).
"""

from __future__ import annotations

from typing import Any

from jscope import __version__

EVIDENCE_CLASSES = ("observed_fact", "static_inference", "security_hypothesis", "verified_behavior", "confirmed_vulnerability")
VERIFICATION_STATUSES = ("unverified", "probable", "confirmed", "inconclusive", "rejected")
SCHEMA_VERSION = "0.5"

HYPOTHESIS_CATEGORIES = {"dataflow", "authorization", "idor", "csrf", "xss", "redirect", "cors", "session"}


def classify(category: str, metadata: dict[str, Any], evidence_types: set[str], confidence: str) -> dict[str, Any]:
    ver = metadata.get("verification") or {}
    status = ver.get("status") or metadata.get("verification_status") or "unverified"
    if status not in VERIFICATION_STATUSES:
        status = "unverified"
    explicit = metadata.get("evidence_class")
    if status == "confirmed" and ver.get("procedure"):
        cls = "confirmed_vulnerability"
    elif status == "probable":
        cls = "verified_behavior" if ver.get("behavior_reproduced") else "security_hypothesis"
    elif status == "rejected" and ver.get("procedure"):
        cls = "verified_behavior"
    elif explicit in EVIDENCE_CLASSES and explicit not in ("verified_behavior", "confirmed_vulnerability"):
        cls = explicit                                  # an analyzer cannot claim verification by labelling itself
    elif "RUNTIME_CONTEXT" in evidence_types or "RUNTIME_NOT_FOUND" in evidence_types:
        cls = "observed_fact"
    elif category in HYPOTHESIS_CATEGORIES or metadata.get("attack_surface_hypothesis"):
        cls = "security_hypothesis"
    else:
        cls = "static_inference"
    out: dict[str, Any] = {
        "evidence_class": cls,
        "verification_status": status,
        "analysis_version": __version__,
        "confidence_note": "confidence measures how well the evidence supports that this pattern exists; it is not proof of exploitability",
    }
    if metadata.get("limitations"):
        out["limitations"] = list(metadata["limitations"])
    if ver:
        out["verification"] = ver
    return out

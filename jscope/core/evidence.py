"""
Evidence Engine
===============

This is the architectural spine of JScope, per the design philosophy:

    "Detectors propose, the engine decides."

Analyzers NEVER get to emit a "finding" directly. They emit `Candidate`
objects backed by typed `Evidence`. Only the `EvidenceEngine` can promote a
candidate into a user-visible `Finding`, and only after running it through a
deterministic, fully-explainable confidence function.

This is deliberate: it's the one architectural boundary that prevents a
noisy (or badly-written, e.g. community-contributed) analyzer from
polluting output. An analyzer can be as trigger-happy as it wants when
proposing candidates -- the engine is what keeps the signal-to-noise ratio
high, and it does so via a rule, not a vibe.

Confidence is a deterministic function over the *set* of evidence types
present on a candidate (see `score_candidate`). It is intentionally NOT a
black-box/ML score -- security practitioners don't trust "73% confidence"
without a reason, so JScope always shows the reasoning chain that produced
a score, not just the number.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


# --------------------------------------------------------------------------
# Evidence vocabulary
# --------------------------------------------------------------------------

class EvidenceType(str, Enum):
    """Fixed vocabulary of evidence kinds. See jscope/docs/EVIDENCE_SCHEMA.md
    for the versioned spec that plugin authors should target."""

    # --- positive evidence (increases confidence) ---
    LITERAL_STRING_MATCH = "LITERAL_STRING_MATCH"          # weakest signal
    NAMING_CONVENTION = "NAMING_CONVENTION"                 # e.g. /admin/, /_debug/
    AST_PATTERN_MATCH = "AST_PATTERN_MATCH"                 # matches a known call/shape
    IMPORT_CHAIN = "IMPORT_CHAIN"                            # resolved through import/export graph
    SYMBOL_RESOLVED = "SYMBOL_RESOLVED"                      # value resolved through a variable, not a raw literal
    FRAMEWORK_CONTEXT = "FRAMEWORK_CONTEXT"                  # a FrameworkProfile corroborates this
    DATA_FLOW = "DATA_FLOW"                                  # tracked from source to sink
    DATA_FLOW_PARTIAL = "DATA_FLOW_PARTIAL"                  # source->sink path that relies on an assumption or an uncertain validator (0.5)
    CALL_GRAPH_REACHABLE = "CALL_GRAPH_REACHABLE"            # reachable from a known entry point
    CROSS_ANALYZER_AGREEMENT = "CROSS_ANALYZER_AGREEMENT"    # 2+ independent analyzers agree
    ARTIFACT_RESOLVED = "ARTIFACT_RESOLVED"                  # a referenced artifact (source map, worker script, module) was found and parsed
    RUNTIME_CONTEXT = "RUNTIME_CONTEXT"                      # confirmed via opt-in runtime probe (Phase 4: `jscope confirm`)

    # --- negative evidence (decreases confidence / suppresses) ---
    DEAD_CODE = "DEAD_CODE"                                  # gated behind if(false)/unreachable branch
    UNREACHABLE = "UNREACHABLE"                              # no discovered call path from any entry point
    TEST_FIXTURE_CONTEXT = "TEST_FIXTURE_CONTEXT"             # lives in *.test.js, __tests__/, __mocks__/
    MOCK_OR_PLACEHOLDER = "MOCK_OR_PLACEHOLDER"               # e.g. process.env.X never substituted
    VENDOR_CODE = "VENDOR_CODE"                               # matched a known vendor/library fingerprint
    RUNTIME_NOT_FOUND = "RUNTIME_NOT_FOUND"                   # opt-in runtime probe got a genuine not-found (Phase 4)


# Deterministic weight table. This is the ENTIRE scoring model for v1 -- no
# hidden ML layer. Changing a weight is a reviewable, diffable, documented
# decision (see "confidence-level changelog discipline" in the design doc).
EVIDENCE_WEIGHTS: dict[EvidenceType, int] = {
    EvidenceType.LITERAL_STRING_MATCH: 1,
    EvidenceType.NAMING_CONVENTION: 1,
    EvidenceType.AST_PATTERN_MATCH: 2,
    EvidenceType.IMPORT_CHAIN: 2,
    EvidenceType.SYMBOL_RESOLVED: 3,
    EvidenceType.FRAMEWORK_CONTEXT: 2,
    EvidenceType.DATA_FLOW: 3,
    EvidenceType.DATA_FLOW_PARTIAL: 1,
    EvidenceType.CALL_GRAPH_REACHABLE: 3,
    EvidenceType.CROSS_ANALYZER_AGREEMENT: 4,
    EvidenceType.ARTIFACT_RESOLVED: 3,
    EvidenceType.RUNTIME_CONTEXT: 6,
    # negative
    EvidenceType.DEAD_CODE: -4,
    EvidenceType.UNREACHABLE: -3,
    EvidenceType.TEST_FIXTURE_CONTEXT: -3,
    EvidenceType.MOCK_OR_PLACEHOLDER: -3,
    EvidenceType.VENDOR_CODE: -2,
    EvidenceType.RUNTIME_NOT_FOUND: -3,
}

# Diminishing returns: a 2nd/3rd piece of evidence of the *same* type is
# worth less than the 1st. Prevents an analyzer from "farming" confidence
# by emitting ten near-duplicate LITERAL_STRING_MATCH evidence for one
# candidate. Index 0 = 1st occurrence multiplier, index 1 = 2nd, etc.
_DIMINISHING_RETURNS = [1.0, 0.5, 0.25]
_DIMINISHING_FLOOR = 0.1


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    SUPPRESSED = "SUPPRESSED"  # never shown by default; below the noise floor


# Score thresholds -> confidence level. Deliberately conservative: reaching
# CONFIRMED without a runtime probe requires several independently-typed,
# agreeing pieces of evidence, not just "a lot of the same weak thing".
_THRESHOLDS: list[tuple[int, Confidence]] = [
    (10, Confidence.CONFIRMED),
    (7, Confidence.HIGH),
    (4, Confidence.MEDIUM),
    (2, Confidence.LOW),
    (1, Confidence.INFORMATIONAL),
]

MIN_DISPLAY_SCORE = 1  # candidates scoring below this are SUPPRESSED entirely


@dataclass(frozen=True)
class Evidence:
    """A single, typed, attributable piece of evidence for a candidate."""

    type: EvidenceType
    description: str
    analyzer: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> int:
        return EVIDENCE_WEIGHTS[self.type]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "description": self.description,
            "analyzer": self.analyzer,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "weight": self.weight,
            "metadata": self.metadata,
        }


@dataclass
class Candidate:
    """What an analyzer proposes. NOT visible to the user until/unless the
    EvidenceEngine promotes it to a Finding."""

    category: str          # e.g. "endpoint", "secret", "auth", "framework"
    subject: str            # the artifact itself, e.g. the URL or key name -- used for de-dup
    analyzer: str
    evidence: list[Evidence] = field(default_factory=list)
    attack_surface: str | None = None      # e.g. "admin", "idor_candidate", "payments"
    suggested_test: str | None = None
    related: list[str] = field(default_factory=list)  # subjects of related candidates
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.category, self.subject)


@dataclass
class Finding:
    """A user-visible, promoted result. Every Finding is fully reconstructible
    back to the evidence that produced it -- that's the whole point."""

    id: str
    category: str
    subject: str
    confidence: Confidence
    score: int
    evidence: list[Evidence]
    contributing_analyzers: list[str]
    attack_surface: str | None
    suggested_test: str | None
    reasoning: list[str]
    related: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from jscope.core.classification import classify      # local import: classification imports jscope.__version__ only
        return {
            "id": self.id,
            "classification": classify(self.category, self.metadata, {e.type.value for e in self.evidence}, self.confidence.value),
            "category": self.category,
            "subject": self.subject,
            "confidence": self.confidence.value,
            "score": self.score,
            "attack_surface": self.attack_surface,
            "suggested_test": self.suggested_test,
            "reasoning": self.reasoning,
            "contributing_analyzers": self.contributing_analyzers,
            "related": self.related,
            "metadata": self.metadata,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def score_evidence(evidence: Iterable[Evidence]) -> tuple[int, list[str]]:
    """Deterministic scoring function. Returns (score, reasoning_lines).

    Reasoning lines are meant to be shown verbatim to the user -- this is
    what makes a score legible instead of a magic number.
    """
    evidence = list(evidence)
    reasoning: list[str] = []
    total = 0.0

    by_type: dict[EvidenceType, list[Evidence]] = {}
    for e in evidence:
        by_type.setdefault(e.type, []).append(e)

    for etype, items in by_type.items():
        base_weight = EVIDENCE_WEIGHTS[etype]
        for i, item in enumerate(items):
            if base_weight >= 0:
                multiplier = _DIMINISHING_RETURNS[i] if i < len(_DIMINISHING_RETURNS) else _DIMINISHING_FLOOR
            else:
                multiplier = 1.0  # penalties are never discounted
            contribution = base_weight * multiplier
            total += contribution
            if i == 0:
                reasoning.append(
                    f"{etype.value} (+{contribution:g}): {item.description}"
                    if contribution >= 0
                    else f"{etype.value} ({contribution:g}): {item.description}"
                )
            else:
                reasoning.append(
                    f"{etype.value} #{i + 1} (+{contribution:g}, diminished): {item.description}"
                )

    return round(total), reasoning


def confidence_for_score(score: int) -> Confidence:
    if score < MIN_DISPLAY_SCORE:
        return Confidence.SUPPRESSED
    for threshold, level in _THRESHOLDS:
        if score >= threshold:
            return level
    return Confidence.SUPPRESSED


_LEVEL = {
    Confidence.CONFIRMED: 5, Confidence.HIGH: 4, Confidence.MEDIUM: 3,
    Confidence.LOW: 2, Confidence.INFORMATIONAL: 1, Confidence.SUPPRESSED: 0,
}


class EvidenceEngine:
    """Collects candidates from all analyzers, merges duplicates (adding
    CROSS_ANALYZER_AGREEMENT evidence automatically when independent
    analyzers converge on the same subject), scores them, and promotes
    the ones that clear the bar into Findings.
    """

    def __init__(self, min_display_confidence: Confidence = Confidence.LOW,
                 analyzer_tiers: dict[str, str] | None = None,
                 community_cap: Confidence = Confidence.MEDIUM):
        self._candidates: dict[tuple[str, str], Candidate] = {}
        self._order: list[tuple[str, str]] = []
        self.min_display_confidence = min_display_confidence
        # analyzer name -> "core" | "verified" | "community". A candidate whose
        # contributing analyzers are ALL community-tier is capped at `community_cap`:
        # unreviewed plugins can inform a finding but cannot, alone, make it HIGH/CONFIRMED.
        self.analyzer_tiers = analyzer_tiers or {}
        self.community_cap = community_cap

    def propose(self, candidate: Candidate) -> None:
        """An analyzer calls this. It does NOT create a finding."""
        if not isinstance(candidate, Candidate):
            raise TypeError(
                f"propose() only accepts Candidate objects, got {type(candidate).__name__}; "
                "analyzers cannot emit Findings"
            )
        key = candidate.dedup_key
        if key not in self._candidates:
            self._candidates[key] = candidate
            self._order.append(key)
            return

        existing = self._candidates[key]
        existing.evidence.extend(candidate.evidence)
        existing.related.extend(candidate.related)
        if candidate.attack_surface and not existing.attack_surface:
            existing.attack_surface = candidate.attack_surface
        if candidate.suggested_test and not existing.suggested_test:
            existing.suggested_test = candidate.suggested_test
        existing.metadata.update(candidate.metadata)

    def _apply_cross_analyzer_agreement(self, candidate: Candidate) -> list[Evidence]:
        analyzers = {e.analyzer for e in candidate.evidence}
        if len(analyzers) < 2:
            return []
        return [
            Evidence(
                type=EvidenceType.CROSS_ANALYZER_AGREEMENT,
                description=(
                    f"{len(analyzers)} independent analyzers agree on this subject: "
                    + ", ".join(sorted(analyzers))
                ),
                analyzer="evidence_engine",
            )
        ]

    def promote(self) -> list[Finding]:
        """Run scoring + promotion over every proposed candidate. Idempotent-ish:
        safe to call once after all analyzers have run."""
        findings: list[Finding] = []
        counters = itertools.count(1)

        order_levels = _LEVEL
        min_level = order_levels[self.min_display_confidence]

        for key in self._order:
            candidate = self._candidates[key]
            auto_evidence = self._apply_cross_analyzer_agreement(candidate)
            all_evidence = candidate.evidence + auto_evidence
            score, reasoning = score_evidence(all_evidence)
            confidence = confidence_for_score(score)

            contributing = sorted({e.analyzer for e in candidate.evidence})
            tiers = {a: self.analyzer_tiers.get(a, "core") for a in contributing}
            if (contributing and all(t == "community" for t in tiers.values())
                    and order_levels[confidence] > order_levels[self.community_cap]):
                reasoning.append(
                    f"CAPPED at {self.community_cap.value}: every contributing analyzer is "
                    f"community-tier ({', '.join(contributing)}); needs a core/verified analyzer to rise further"
                )
                confidence = self.community_cap

            if order_levels[confidence] < min_level:
                continue  # still SUPPRESSED/below threshold -- never shown

            finding_id = f"JS-{next(counters):04d}"
            findings.append(
                Finding(
                    id=finding_id,
                    category=candidate.category,
                    subject=candidate.subject,
                    confidence=confidence,
                    score=score,
                    evidence=all_evidence,
                    contributing_analyzers=contributing,
                    attack_surface=candidate.attack_surface,
                    suggested_test=candidate.suggested_test,
                    reasoning=reasoning,
                    related=sorted(set(candidate.related)),
                    metadata={**candidate.metadata, "analyzer_tiers": tiers},
                )
            )

        # Stable, useful default ordering: confidence desc, then score desc.
        level_rank = {c: i for i, (_, c) in enumerate(_THRESHOLDS)}
        findings.sort(key=lambda f: (level_rank.get(f.confidence, 99), -f.score))
        return findings

    @property
    def candidate_count(self) -> int:
        return len(self._candidates)


# --------------------------------------------------------------------------
# Runtime evidence (Phase 4)
# --------------------------------------------------------------------------

RUNTIME_ANALYZER = "runtime_prober"
_RUNTIME_TYPES = {EvidenceType.RUNTIME_CONTEXT, EvidenceType.RUNTIME_NOT_FOUND}


def apply_runtime_evidence(finding: Finding, extra: list[Evidence],
                           community_cap: Confidence = Confidence.MEDIUM) -> Finding:
    """Re-score an existing Finding with evidence from the opt-in runtime prober.

    This is the ONLY door through which RUNTIME_* evidence reaches a finding. The AnalyzerManager strips
    these types from every analyzer (core, verified and community), so a plugin cannot fake a live
    confirmation; this function in turn accepts nothing except evidence attributed to the prober.
    """
    for e in extra:
        if e.type not in _RUNTIME_TYPES or e.analyzer != RUNTIME_ANALYZER:
            raise ValueError("apply_runtime_evidence only accepts RUNTIME_* evidence from the runtime prober")
    base = [e for e in finding.evidence if e.type not in _RUNTIME_TYPES]      # re-probing replaces old probe results
    all_evidence = base + list(extra)
    score, reasoning = score_evidence(all_evidence)
    confidence = confidence_for_score(score)
    if confidence == Confidence.SUPPRESSED:           # a live probe downgrades a finding; it never silently deletes one
        confidence = Confidence.INFORMATIONAL
        reasoning.append("FLOORED at INFORMATIONAL: runtime evidence lowers confidence but does not remove the finding")
    contributing = sorted({e.analyzer for e in all_evidence if e.analyzer != "evidence_engine"})
    tiers = dict(finding.metadata.get("analyzer_tiers", {}))
    for a in contributing:
        tiers.setdefault(a, "core")
    if all(tiers.get(a) == "community" for a in contributing) and _LEVEL[confidence] > _LEVEL[community_cap]:
        reasoning.append(f"CAPPED at {community_cap.value}: every contributing analyzer is community-tier")
        confidence = community_cap
    meta = dict(finding.metadata)
    meta["analyzer_tiers"] = tiers
    meta["runtime_checked"] = True
    return Finding(
        id=finding.id, category=finding.category, subject=finding.subject, confidence=confidence, score=score,
        evidence=all_evidence, contributing_analyzers=contributing, attack_surface=finding.attack_surface,
        suggested_test=finding.suggested_test, reasoning=reasoning, related=list(finding.related), metadata=meta)

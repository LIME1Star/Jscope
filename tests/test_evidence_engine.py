from jscope.core.evidence import (
    Candidate, Confidence, Evidence, EvidenceEngine, EvidenceType, score_evidence,
)


def test_single_weak_evidence_stays_low_or_suppressed():
    score, _ = score_evidence([
        Evidence(EvidenceType.LITERAL_STRING_MATCH, "x", "a"),
    ])
    assert score == 1


def test_cross_analyzer_agreement_boosts_confidence():
    engine = EvidenceEngine()
    engine.propose(Candidate(
        category="endpoint", subject="/api/admin/x", analyzer="a1",
        evidence=[Evidence(EvidenceType.AST_PATTERN_MATCH, "found by a1", "a1")],
    ))
    engine.propose(Candidate(
        category="endpoint", subject="/api/admin/x", analyzer="a2",
        evidence=[Evidence(EvidenceType.SYMBOL_RESOLVED, "found by a2", "a2")],
    ))
    findings = engine.promote()
    assert len(findings) == 1
    f = findings[0]
    assert any(e.type == EvidenceType.CROSS_ANALYZER_AGREEMENT for e in f.evidence)
    assert f.contributing_analyzers == ["a1", "a2"]


def test_negative_evidence_suppresses_finding():
    engine = EvidenceEngine()
    engine.propose(Candidate(
        category="secret", subject="fake-key", analyzer="secret_analyzer",
        evidence=[
            Evidence(EvidenceType.LITERAL_STRING_MATCH, "matches pattern", "secret_analyzer"),
            Evidence(EvidenceType.TEST_FIXTURE_CONTEXT, "lives in __tests__", "secret_analyzer"),
        ],
    ))
    findings = engine.promote()
    assert findings == []  # score = 1 - 3 = -2, below MIN_DISPLAY_SCORE


def test_min_display_confidence_filters_output():
    engine = EvidenceEngine(min_display_confidence=Confidence.HIGH)
    engine.propose(Candidate(
        category="endpoint", subject="/x", analyzer="a1",
        evidence=[Evidence(EvidenceType.LITERAL_STRING_MATCH, "weak", "a1")],
    ))
    assert engine.promote() == []


def test_diminishing_returns_on_duplicate_evidence_type():
    score_one, _ = score_evidence([Evidence(EvidenceType.SYMBOL_RESOLVED, "x", "a")])
    score_two, _ = score_evidence([
        Evidence(EvidenceType.SYMBOL_RESOLVED, "x", "a"),
        Evidence(EvidenceType.SYMBOL_RESOLVED, "y", "a"),
    ])
    # second occurrence contributes less than a full second unit (diminishing returns)
    assert score_two > score_one
    assert score_two < score_one * 2


def test_dedup_merges_candidates_with_same_key():
    engine = EvidenceEngine()
    engine.propose(Candidate(category="secret", subject="k", analyzer="a1",
                              evidence=[Evidence(EvidenceType.LITERAL_STRING_MATCH, "1", "a1")]))
    engine.propose(Candidate(category="secret", subject="k", analyzer="a1",
                              evidence=[Evidence(EvidenceType.AST_PATTERN_MATCH, "2", "a1")]))
    assert engine.candidate_count == 1

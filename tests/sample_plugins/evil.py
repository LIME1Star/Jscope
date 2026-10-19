from jscope.analyzers.base import Analyzer
from jscope.core.evidence import Candidate, Evidence, EvidenceType, Finding, Confidence


class Evil(Analyzer):
    name = "evil"

    def analyze_project(self, ctx):
        f = Finding(id="JS-9999", category="x", subject="forged", confidence=Confidence.CONFIRMED, score=99,
                    evidence=[], contributing_analyzers=["evil"], attack_surface=None, suggested_test=None, reasoning=[])
        spoof = Candidate(category="endpoint", subject="/api/admin/users", analyzer="evil", evidence=[
            Evidence(EvidenceType.AST_PATTERN_MATCH, "pretend", "endpoint_analyzer"),     # spoofed analyzer name
            Evidence(EvidenceType.CROSS_ANALYZER_AGREEMENT, "forged agreement", "evil"),  # engine-only type
            Evidence(EvidenceType.RUNTIME_CONTEXT, "forged runtime", "evil")])
        return [f, spoof, "not a candidate"]


ANALYZERS = [Evil]

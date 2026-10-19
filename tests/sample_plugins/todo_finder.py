from jscope.analyzers.base import Analyzer
from jscope.core.evidence import Candidate, Evidence, EvidenceType


class TodoFinder(Analyzer):
    name = "todo_finder"
    depends_on = ["framework_detector"]

    def analyze_project(self, ctx):
        out = []
        for pf in ctx.files:
            if "dangerousThing" in pf.text:
                out.append(Candidate(
                    category="todo", subject=f"dangerous@{pf.path}", analyzer=self.name,
                    evidence=[Evidence(EvidenceType.AST_PATTERN_MATCH, "calls dangerousThing", self.name, pf.path),
                              Evidence(EvidenceType.SYMBOL_RESOLVED, "resolved", self.name),
                              Evidence(EvidenceType.DATA_FLOW, "flows", self.name),
                              Evidence(EvidenceType.CALL_GRAPH_REACHABLE, "reachable", self.name)]))
        return out


ANALYZERS = [TodoFinder]

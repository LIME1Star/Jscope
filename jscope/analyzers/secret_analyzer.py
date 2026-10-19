"""Secret Analyzer.

Regex is the entry evidence (LITERAL_STRING_MATCH / AST_PATTERN_MATCH), but
context downgrades or upgrades it:
  - inside process.env.X / import.meta.env.X with no literal value -> informational placeholder
  - file path contains test/mock/spec/__tests__ -> TEST_FIXTURE_CONTEXT penalty
  - value assigned to a var literally named *_KEY/*_SECRET/*_TOKEN -> AST_PATTERN_MATCH boost
No secret is ever "confirmed" by regex alone -- that requires
CROSS_ANALYZER_AGREEMENT or (future) RUNTIME_CONTEXT.
"""

from __future__ import annotations

import re

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType
from jscope.parsing.ast_engine import ParsedFile

# pattern name -> (regex, service)
_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "aws_access_key": (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS"),
    "google_api_key": (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google/Firebase"),
    "stripe_live_key": (re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "Stripe"),
    "stripe_publishable_key": (re.compile(r"\bpk_live_[0-9a-zA-Z]{20,}\b"), "Stripe"),
    "slack_token": (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack"),
    "supabase_url": (re.compile(r"\bhttps://[a-z0-9]{20}\.supabase\.co\b"), "Supabase"),
    "jwt_like": (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT"),
    "generic_private_key": (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PKI"),
}

_TEST_PATH_RE = re.compile(r"(__tests__|__mocks__|\.test\.|\.spec\.|/test/|/tests/|/mock/|/fixtures?/)", re.I)
_SENSITIVE_VAR_RE = re.compile(r"(KEY|SECRET|TOKEN|CREDENTIAL|PASSWORD)$", re.I)


class SecretAnalyzer(Analyzer):
    name = "secret_analyzer"
    depends_on = []
    produces_categories = ["secret"]

    def analyze_file(self, pf: ParsedFile, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        is_test_path = bool(_TEST_PATH_RE.search(pf.path))

        for node, text, line in ctx.ast.find_string_literals(pf):
            for pattern_name, (regex, service) in _PATTERNS.items():
                m = regex.search(text)
                if not m:
                    continue
                matched = m.group(0)
                subject = f"{service}:{matched[:8]}...{matched[-4:]}" if len(matched) > 14 else f"{service}:{matched}"

                evidence = [Evidence(
                    type=EvidenceType.LITERAL_STRING_MATCH,
                    description=f"string literal matches {service} {pattern_name} pattern",
                    analyzer=self.name,
                    file=pf.path,
                    line=line,
                    snippet=matched[:60],
                )]

                # look at the enclosing variable_declarator (if any) for naming context
                parent = node.parent
                while parent is not None and parent.type != "variable_declarator":
                    parent = parent.parent
                if parent is not None:
                    name_node = parent.child_by_field_name("name")
                    if name_node is not None and _SENSITIVE_VAR_RE.search(pf.node_text(name_node)):
                        evidence.append(Evidence(
                            type=EvidenceType.AST_PATTERN_MATCH,
                            description=f"assigned to variable '{pf.node_text(name_node)}' matching secret-naming convention",
                            analyzer=self.name,
                        ))

                if is_test_path:
                    evidence.append(Evidence(
                        type=EvidenceType.TEST_FIXTURE_CONTEXT,
                        description="file path looks like a test/mock/fixture file",
                        analyzer=self.name,
                    ))

                if ctx.ast.is_in_dead_branch(pf, node):
                    evidence.append(Evidence(
                        type=EvidenceType.DEAD_CODE,
                        description="literal is inside a branch gated on a falsy/dev-only condition",
                        analyzer=self.name,
                    ))

                out.append(Candidate(
                    category="secret",
                    subject=subject,
                    analyzer=self.name,
                    evidence=evidence,
                    attack_surface=None,
                    suggested_test=f"Verify if this {service} credential is live/scoped; check for excess privilege if confirmed valid.",
                    metadata={"pattern": pattern_name, "service": service},
                ))

        return out

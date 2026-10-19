# JScope Evidence Schema (v0.2)

This is the contract every analyzer -- core or plugin -- targets. If you're
writing a plugin, this is the only doc you need to read to understand how
your output turns into (or fails to turn into) a user-visible finding.

## The core rule

> Analyzers propose `Candidate`s. Only the `EvidenceEngine` promotes a
> `Candidate` into a `Finding`. Analyzers never create Findings directly.

In 0.2 this is enforced **at runtime** by `AnalyzerManager` (Python type hints enforce
nothing): non-`Candidate` returns are dropped, evidence is re-attributed to the analyzer that
produced it (no spoofing another analyzer's name to fake agreement), engine-only evidence
types are stripped, and each candidate is capped at 60 evidence items.

## Evidence types

| Type | Weight | Meaning |
|---|---|---|
| `LITERAL_STRING_MATCH` | +1 | Weakest signal: a raw string literal matched a pattern. |
| `NAMING_CONVENTION` | +1 | Lexical pattern (`/admin/`, `/_debug/`) -- legitimate but never sufficient alone. |
| `AST_PATTERN_MATCH` | +2 | Matches a known call/expression *shape*, not just a string. |
| `IMPORT_CHAIN` | +2 | Resolved through the import/export graph. |
| `FRAMEWORK_CONTEXT` | +2 | A `FrameworkProfile` corroborates this (e.g. Next.js + `/api/*`). |
| `SYMBOL_RESOLVED` | +3 | Value resolved through a variable binding, not a literal at the use site. |
| `DATA_FLOW` | +3 | Tracked from a source to a sink. |
| `CALL_GRAPH_REACHABLE` | +3 | Reachable from a known entry point. |
| `ARTIFACT_RESOLVED` | +3 | **(new in 0.2)** A referenced artifact was found and parsed: a source map on disk, a registered worker script present in the project. |
| `CROSS_ANALYZER_AGREEMENT` | +4 | Auto-applied by the engine when 2+ independently-named analyzers agree on the same `(category, subject)`. You cannot emit this yourself -- the AnalyzerManager drops it at runtime. |
| `RUNTIME_CONTEXT` | +6 | Confirmed via the opt-in `jscope confirm` probe (safe methods, allow-listed hosts). Prober-only; analyzers cannot emit it. |
| `RUNTIME_NOT_FOUND` | -3 | The probe got a genuine 404/410 at the tested base URL. Downgrades, never deletes (floor: INFORMATIONAL). Prober-only. |
| `DEAD_CODE` | -4 | Inside a branch gated on a statically-false condition. |
| `UNREACHABLE` | -3 | No discovered call path from any entry point. |
| `TEST_FIXTURE_CONTEXT` | -3 | Lives in `__tests__/`, `*.test.js`, `*.spec.js`, `/mock/`, `/fixtures?/`. |
| `MOCK_OR_PLACEHOLDER` | -3 | e.g. `process.env.X` with no literal ever substituted. |
| `VENDOR_CODE` | -2 | Matched a known vendor/library fingerprint. |

Negative-weight evidence is never subject to diminishing returns -- repeated
penalties all count fully. Positive-weight evidence of the *same type* on
the same candidate is diminished (1st = 100%, 2nd = 50%, 3rd = 25%, floor
10%) specifically to stop an analyzer from "farming" confidence by emitting
many near-duplicate weak signals.

## Confidence thresholds

Deterministic sum -> level. No ML, no hidden weighting. This is exactly
`jscope/core/evidence.py::_THRESHOLDS`, reproduced here for reference:

```
score >= 10  -> CONFIRMED
score >=  7  -> HIGH
score >=  4  -> MEDIUM
score >=  2  -> LOW
score >=  1  -> INFORMATIONAL
score <   1  -> SUPPRESSED (never shown)
```

Changing a weight or threshold is a reviewable diff against this table --
see the "confidence-level changelog discipline" note in the design doc.
Silent confidence inflation across a PR is the fastest way to reintroduce
the noise problem JScope exists to solve.

## Writing an analyzer (plugin sketch)

```python
from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType

class MyAnalyzer(Analyzer):
    name = "my_analyzer"
    depends_on = ["framework_detector"]   # topologically sorted by AnalyzerManager
    produces_categories = ["my_category"]

    def analyze_file(self, pf, ctx: ProjectContext) -> list[Candidate]:
        # ... inspect pf.tree / ctx.ast helpers ...
        return [Candidate(
            category="my_category",
            subject="the artifact, used as the de-dup key",
            analyzer=self.name,
            evidence=[Evidence(
                type=EvidenceType.AST_PATTERN_MATCH,
                description="human-readable reason this evidence exists",
                analyzer=self.name,
                file=pf.path,
                line=42,
            )],
            attack_surface=None,       # or "admin" / "idor_candidate" / etc.
            suggested_test=None,       # actionable next step, if you have one
        )]
```

Never fabricate `CROSS_ANALYZER_AGREEMENT` evidence yourself -- the engine
adds it automatically when it detects real agreement across analyzer names.

## Trust tiers (new in 0.2)

Every analyzer has a `tier`: `core` (built in), `verified` (listed in `plugins.verified`),
or `community` (any other plugin). A finding whose contributing analyzers are *all*
community-tier is capped at `plugins.community_confidence_cap` (default `MEDIUM`) and its
reasoning says so. A core or verified analyzer agreeing lifts the cap -- which is exactly
the signal you want. See `docs/PLUGINS.md`.

## Versioning

This is v0.2 (Phase 2). Changes since 0.1: added `ARTIFACT_RESOLVED` (+3); runtime
enforcement of the propose/promote boundary; trust tiers. No existing weight or threshold
changed. See `CHANGELOG.md`.

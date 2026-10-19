"""Framework Detector.

No deps on other analyzers -- it runs first, and other analyzers (Endpoint,
Router) consult `ctx.framework_hints` afterward for framework-aware
suppression/classification (design-brainstorm.md §3.3).

v1 scope, deliberately phased down per design-brainstorm.md §5:
React + Next.js get deep-ish treatment; Vue/Nuxt basic; everything else is
"detected, generic analysis applied" via a lexical marker table.
"""

from __future__ import annotations

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.core.evidence import Candidate, Evidence, EvidenceType
from jscope.parsing.ast_engine import ParsedFile

# marker -> (framework, evidence description)
_MARKERS: dict[str, tuple[str, str]] = {
    "__NEXT_DATA__": ("Next.js", "found __NEXT_DATA__ runtime marker"),
    "_next/static": ("Next.js", "found _next/static chunk path convention"),
    "__next_f": ("Next.js", "found Next.js App Router flight marker (__next_f)"),
    "ReactDOM": ("React", "found ReactDOM global reference"),
    "react.production.min": ("React", "found React production bundle fingerprint"),
    "__vue__": ("Vue", "found __vue__ instance marker"),
    "Vue.config": ("Vue", "found Vue.config reference"),
    "_nuxt/": ("Nuxt", "found _nuxt/ chunk path convention"),
    "__NUXT__": ("Nuxt", "found __NUXT__ runtime marker"),
    "ng-version": ("Angular", "found ng-version attribute reference"),
    "@angular/core": ("Angular", "found @angular/core import reference"),
    "svelte-hydrate": ("Svelte", "found svelte-hydrate marker"),
    "__SVELTEKIT__": ("Svelte", "found SvelteKit runtime marker"),
    "__remixContext": ("Remix", "found __remixContext runtime marker"),
    "astro-island": ("Astro", "found astro-island custom element marker"),
}


class FrameworkDetector(Analyzer):
    name = "framework_detector"
    depends_on = []
    produces_categories = ["framework"]

    def analyze_file(self, pf: ParsedFile, ctx: ProjectContext) -> list[Candidate]:
        text = pf.text
        out: list[Candidate] = []
        for marker, (framework, desc) in _MARKERS.items():
            if marker in text:
                line = text[: text.index(marker)].count("\n") + 1
                out.append(Candidate(
                    category="framework",
                    subject=framework,
                    analyzer=self.name,
                    evidence=[Evidence(
                        type=EvidenceType.LITERAL_STRING_MATCH,
                        description=desc,
                        analyzer=self.name,
                        file=pf.path,
                        line=line,
                        snippet=marker,
                    )],
                ))
        return out

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        candidates = super().analyze_project(ctx)
        # aggregate: bump confidence by adding a second, cross-file
        # NAMING_CONVENTION-style piece of evidence when a framework shows
        # up in 2+ files (more than a stray string in a vendor chunk).
        counts: dict[str, int] = {}
        for c in candidates:
            counts[c.subject] = counts.get(c.subject, 0) + 1
        for c in candidates:
            if counts[c.subject] >= 2:
                c.evidence.append(Evidence(
                    type=EvidenceType.AST_PATTERN_MATCH,
                    description=f"{c.subject} marker recurs across {counts[c.subject]} files",
                    analyzer=self.name,
                ))
            # populate framework_hints for downstream analyzers
            ctx.framework_hints.setdefault(c.subject, 0)
            ctx.framework_hints[c.subject] += 1
        return candidates

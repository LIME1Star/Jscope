# Assessment engine interfaces

`AssessmentOrchestrator` in `jscope.assessment_engine` is constructed with an assessment ID, an assessment-manifest path, and a `TransportPolicy` whose approved host set must exactly match the manifest. It fails closed on a missing, corrupt, stale, unapproved, or mismatched manifest. `revalidate()` should be called before each active stage.

`ModuleMetadata` records traffic type, required permissions, authentication expectations, impact, input types, evidence expectations, and nominal per-module budgets. Register deterministic runners through `ModuleRegistry`. Runners receive `(context, orchestrator)` and must use the supplied assessment's guarded transport. The current budget checks are post-run checks and do not safely preempt a hung or hostile module; do not load untrusted modules in-process.

`Endpoint`, `Relationship`, `FindingRecord`, and `EvidenceStore` are the shared data model. Correlation relationships include source URL, original reference, resolved URL, and a method label. These are inferred links, not proof of reachability, authorization, or vulnerability.

`assessment_reporting` produces JSON (`jscope-assessment-result/1`) and Markdown exports. Report schemas are currently minimal and should be versioned when fields change. Active API authorization testing (including BOLA) requires application-specific expected access rules and synthetic test accounts/objects; no generic check should infer a vulnerability from identifier changes or status codes alone.

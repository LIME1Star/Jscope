# Writing and trusting JScope plugins

```bash
jscope plugin-new my_check --out ./plugins     # scaffolds ./plugins/my_check.py
jscope analyze ./target --plugin-path ./plugins
jscope plugins --plugin-path ./plugins          # list analyzers with their trust tier
```

A plugin module exposes `ANALYZERS = [MyAnalyzer]` or a `register()` function. Packages can also
publish analyzers through the `jscope.analyzers` entry-point group.

## What a plugin can and cannot do

| Can | Cannot (enforced at runtime) |
|---|---|
| Propose `Candidate`s with typed `Evidence` | Emit a `Finding` (dropped, logged in diagnostics) |
| Depend on other analyzers via `depends_on` | Emit `CROSS_ANALYZER_AGREEMENT` or `RUNTIME_CONTEXT` evidence (stripped) |
| Read the AST (`jscope.parsing.queries`) and the knowledge graph (`ctx.graph`) | Attribute evidence to another analyzer (re-attributed to the plugin) |
| Add graph nodes/edges for facts it observed | Exceed 60 evidence items per candidate (truncated) |
| | Crash the run (isolated; shown under `[diagnostics]`) |

## Trust tiers

`core` (built in) / `verified` (named in `plugins.verified` in your config) / `community` (everything else).
A finding backed **only** by community-tier analyzers is capped at `plugins.community_confidence_cap`
(default `MEDIUM`). When a core analyzer independently agrees, the cap lifts.

**Loading a plugin executes its Python code with your privileges.** Tiers limit what a plugin can do to
your *report*, not to your machine. Read plugins before you load them.

## Writing evidence that scores honestly

Prefer AST evidence over bare string matches; always add negative evidence (`DEAD_CODE`,
`TEST_FIXTURE_CONTEXT`) when you can see it; use `ctx.ast.is_in_dead_branch(pf, node)`.
Never hand-roll confidence: choose the evidence types that are true and let the engine score them.

# Roadmap

The original four-phase plan is implemented. What remains is hardening and depth, listed honestly.

## Analysis depth
- Alias-aware module resolution (tsconfig / webpack aliases), `.ts` / `.tsx` parsing, Vue `<template>` analysis.
- Cross-file / inter-procedural data flow; resolving template-literal request URLs (shrinks the "unresolved client calls" caveat).
- Disassembly-level WASM analysis; HAR and browser-storage snapshot ingestion.

## Performance and workflow
- Per-file parse cache (rescans are all-or-nothing today: skipped when nothing changed, otherwise a full re-analysis).
- Workspace paths are machine-absolute; scan records contain evidence snippets and should be treated as sensitive.

## Accuracy
- A real-world golden corpus. The false-positive regression suite and the benchmark gate (12 fixtures) are synthetic today.
- AI redaction is pattern-based; review `--dry-run` output on sensitive targets.

## Security hardening
See [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md): connection-pinned DNS on every network path, one unified transport,
and module preemption for untrusted plugins.

# AI layer (Phase 3)

AI **explains and prioritizes existing findings. It cannot create, remove, re-score or re-rank them.**

```bash
jscope ai findings.json --dry-run      # prints the exact payload; sends nothing
jscope ai ws:acme                      # latest workspace scan -> commentary block
export ANTHROPIC_API_KEY=...           # required for a real call
```
Config (`jscope.yml`): `ai.provider` (anthropic), `ai.model`, `ai.top_n`, `ai.redact_paths`, `ai.api_key_env`.

## Guarantees (each has a test)
1. Output is a separate block labelled "generated text, NOT evidence". Scores/ranking are computed before and
   independent of AI.
2. Any finding id in the reply that wasn't sent is dropped (also inside free text). Duplicates dropped.
3. The reply must be strict JSON in a fixed shape; otherwise it is discarded, never displayed raw.
4. **Redaction before sending:** credential-shaped strings are masked everywhere, secret findings' subjects and
   snippets are replaced, file paths are reduced to basenames (`--send-paths` to override).
5. Only the top `top_n` findings are sent, with at most 6 evidence items each, snippets clipped to 120 chars.
6. JS content is treated as untrusted (prompt-injection aware): sent inside a data block with an explicit
   instruction, and rule 3 means injected text cannot reach the report.

## Limits
- Redaction is pattern-based (the secret analyzer's patterns). A custom-format secret in a non-secret finding's
  snippet would not be masked. Use `--dry-run` on sensitive targets.
- The AI sees evidence text, not your source files. Its explanations are only as good as that evidence.
- The `ai` command contacts a third party by design; JScope's analysis itself remains fully offline.

# Phase 4: artifacts beyond JavaScript

Drop a whole downloaded site into a directory. JScope classifies files **by content**, so an unrelated `package.json` is ignored and a
spec named `api.json` is found. Everything is offline. Disable with `artifacts.enabled: false`.

| Kind | Detected as | Analyzer | What you get |
|---|---|---|---|
| `html` | `.html/.htm` | `html_analyzer` | forms (`upload` / `auth` surfaces), cleartext credential posts, missing-CSRF hint (absence-based, LOW), cross-origin script without SRI (only if the page's origin is knowable), weak meta CSP, sensitive paths in comments; form actions become `endpoint` candidates |
| html / `vue` | inline `<script>`, `.vue` `<script>` | *(all JS analyzers)* | the script body is parsed as a normal JS file; line numbers match the original document |
| `openapi` | `.json/.yaml/.yml` with `openapi:`/`swagger:` + `paths` | `openapi_analyzer` | see below |
| `graphql_schema` | `.graphql/.gql` SDL, or introspection JSON | `graphql_schema_analyzer` | root fields, ID-argument (IDOR) candidates, write fields, auth-directive gaps |
| `wasm` | `\x00asm` magic | `wasm_analyzer` | imports/exports, toolchain, host capabilities (fetch/eval/storage), embedded endpoints and secrets, which JS loads it |

## Correlation (the point of Phase 4)

* **Documented and called**: the client's `endpoint` finding gains the spec as an independent source (-> `CROSS_ANALYZER_AGREEMENT`) plus the spec's security metadata. The most specific spec path wins (`/users/me` beats `/users/{id}`).
* **Called but undocumented** (`undocumented_api`): only reported inside an API family the spec *does* document, never for third-party hosts or static assets.
* **Documented, sensitive, never called** (`client_referenced=false`): functionality the UI does not expose. This claim is only made when the endpoint analyzer ran and found client calls, and it carries a caveat (and half the ranking boost) when the client has request URLs JScope could not resolve.
* **GraphQL**: client operations are matched to schema root fields; unused write/sensitive fields are flagged the same way.

`absence_based` findings (no CSRF token, no security declared, missing auth directive) are LOW by construction and say so.

## Writing analyzers against artifacts

`ctx.artifacts_of("openapi")` returns `Artifact` objects (`.path`, `.data`, `.text`, `.memo` parse-once cache). Share facts with other analyzers through
`ctx.shared`, order them with `run_after` (soft) rather than `depends_on` (hard), and **never** make "the client doesn't do X" claims unless you checked that
the analyzer producing the client index actually ran (see `endpoint_analyzer_ran`).

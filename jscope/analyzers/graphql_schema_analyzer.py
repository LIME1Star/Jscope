"""GraphQL Schema Analyzer (Phase 4).

Reads a schema you already have (SDL file, or introspection JSON saved earlier) and correlates it with the operations the
client really sends (from graphql_analyzer):

  * client operation + schema agree on a root field -> the client operation finding gains ARTIFACT_RESOLVED from this
    analyzer, and with it CROSS_ANALYZER_AGREEMENT
  * sensitive or write root fields no analyzed client operation uses -> `graphql_schema_field` with client_referenced=False
    (the UI never calls it: test authorization directly)
  * root fields missing an auth directive that >=3 sibling root fields carry -> `graphql_authz_gap` (absence-based, LOW)
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from jscope.analyzers.base import Analyzer, ProjectContext
from jscope.analyzers.common import is_test_path
from jscope.core.artifacts import KIND_GRAPHQL_SCHEMA, Artifact, structured
from jscope.core.evidence import Candidate, Evidence, EvidenceType as ET
from jscope.parsing.graphql_schema import parse_introspection, parse_sdl

_AUTH_DIRECTIVE = re.compile(r"(auth|hasrole|haspermission|permission|protected|private|rbac|authorize|requires|scope|guard)", re.I)
_SENSITIVE = [
    ("admin", re.compile(r"(admin|sudo|superuser|impersonat|grant|revoke|role|permission)", re.I)),
    ("internal", re.compile(r"(internal|private)", re.I)),
    ("debug", re.compile(r"(debug|diagnostic|_dump)", re.I)),
    ("payment", re.compile(r"(payment|refund|invoice|billing|charge|payout|subscription(?!s?$))", re.I)),
    ("export", re.compile(r"(export|download|backup)", re.I)),
    ("upload", re.compile(r"(upload|import)", re.I)),
    ("auth", re.compile(r"(password|token|apikey|api_key|secret|session|login|signin|resetpass)", re.I)),
]
_ID_ARG = re.compile(r"(^id$|id$)", re.I)


def _sensitive(name: str) -> str | None:
    for tag, rx in _SENSITIVE:
        if rx.search(name):
            return tag
    return None


class GraphQLSchemaAnalyzer(Analyzer):
    name = "graphql_schema_analyzer"
    depends_on = ["framework_detector"]
    run_after = ["graphql_analyzer"]
    produces_categories = ["graphql_schema", "graphql_schema_field", "graphql_authz_gap", "graphql"]

    def analyze_project(self, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        for art in ctx.artifacts_of(KIND_GRAPHQL_SCHEMA):
            try:
                out.extend(self._schema(art, ctx))
            except Exception as exc:                       # noqa: BLE001
                ctx.diagnostics.append(f"[graphql_schema_analyzer] {art.path}: {type(exc).__name__}: {exc}")
        return out

    def _schema(self, art: Artifact, ctx: ProjectContext) -> list[Candidate]:
        out: list[Candidate] = []
        fname = PurePosixPath(art.path.replace("\\", "/")).name
        penalty = [Evidence(ET.TEST_FIXTURE_CONTEXT, "schema lives in a test/fixture path", self.name)] if is_test_path(art.path) else []
        doc = structured(art) if art.path.lower().endswith(".json") else None
        introspection = isinstance(doc, dict)
        schema = parse_introspection(doc) if introspection else parse_sdl(art.text)
        types, roots = schema["types"], schema["roots"]
        client_ops = ctx.shared.get("graphql_ops") or None   # None => analyzer did not run OR found no client operations: no "unused" claims
        used: dict[str, set[str]] = {"query": set(), "mutation": set(), "subscription": set()}
        for op in (client_ops or {}).values():
            used.setdefault(op.get("operation") or "query", set()).update(op.get("root_fields", []))

        counts = {r: len(types.get(tn, {}).get("fields", {})) for r, tn in roots.items() if tn}
        out.append(Candidate(
            category="graphql_schema", subject=fname, analyzer=self.name,
            evidence=[Evidence(ET.ARTIFACT_RESOLVED, f"GraphQL schema parsed ({'introspection JSON' if introspection else 'SDL'}; "
                               + ", ".join(f"{k}={v}" for k, v in counts.items()) + f"; {len(types)} types)", self.name, art.path),
                      Evidence(ET.AST_PATTERN_MATCH, "root operation types located", self.name, art.path)] + penalty,
            attack_surface="graphql" if introspection else None,
            suggested_test=("This is an introspection result: check whether introspection is still enabled on the live endpoint, "
                            "and diff the live schema against this one for newly added fields." if introspection else None),
            metadata={"file": art.path, "format": "introspection" if introspection else "sdl", "root_field_counts": counts,
                      "type_count": len(types)}))

        for op_kind, tname in roots.items():
            if not tname or tname not in types:
                continue
            fields = types[tname]["fields"]
            guarded = [f for f, d in fields.items() if any(_AUTH_DIRECTIVE.search(x) for x in d["directives"])]
            for fld, d in fields.items():
                sens = _sensitive(fld)
                id_args = [a for a, t in d["args"].items() if t.rstrip("!").startswith("ID") or _ID_ARG.search(a)]
                interesting = op_kind in ("mutation", "subscription") or bool(sens) or bool(id_args)
                referenced = (fld in used.get(op_kind, set())) if client_ops is not None else None
                subject = f"{op_kind}:{fld}"
                if interesting:
                    surface = sens or ("idor_candidate" if id_args else "graphql")
                    ev = [Evidence(ET.ARTIFACT_RESOLVED, f"root field defined in schema {fname}", self.name, art.path),
                          Evidence(ET.AST_PATTERN_MATCH, f"{tname}.{fld}({', '.join(f'{a}: {t}' for a, t in d['args'].items())}): {d['type']}", self.name, art.path)]
                    if sens:
                        ev.append(Evidence(ET.NAMING_CONVENTION, f"field name matches '{sens}' naming convention", self.name))
                    tests = []
                    if op_kind == "mutation":
                        tests.append("Call this mutation unauthenticated and as a low-privilege user; check field-level authorization, mass assignment through input types, and rate limits.")
                    if id_args:
                        tests.append(f"Argument(s) {', '.join(id_args)} look like object IDs: swap in another account's IDs (BOLA/IDOR).")
                    if referenced is False:
                        tests.append("No resolvable client operation uses this field, so the UI may never exercise it: authorization here is often an afterthought. Test it directly.")
                    out.append(Candidate(
                        category="graphql_schema_field", subject=subject, analyzer=self.name, evidence=ev + penalty,
                        attack_surface=surface, suggested_test=" ".join(tests) or None,
                        metadata={"schema_file": art.path, "args": d["args"], "returns": d["type"], "directives": d["directives"],
                                  "client_referenced": referenced}))
                if len(guarded) >= 3 and fld not in guarded and op_kind != "subscription":
                    out.append(Candidate(
                        category="graphql_authz_gap", subject=subject, analyzer=self.name,
                        evidence=[Evidence(ET.AST_PATTERN_MATCH, f"{tname}.{fld} has no auth-style directive, while {len(guarded)} sibling root field(s) do", self.name, art.path),
                                  Evidence(ET.LITERAL_STRING_MATCH, "siblings carrying a directive: " + ", ".join(guarded[:4]), self.name)] + penalty,
                        attack_surface="authorization",
                        suggested_test="Authorization is declared per field here and this one has no declaration. Call it without credentials: a missing directive is a classic gap (the schema may enforce it elsewhere, e.g. in a resolver).",
                        metadata={"absence_based": True, "schema_file": art.path}))

        # corroborate the client's own operation findings (-> CROSS_ANALYZER_AGREEMENT)
        for subject, op in (client_ops or {}).items():
            kind = op.get("operation") or "query"
            tname = roots.get(kind)
            fields = types.get(tname, {}).get("fields", {}) if tname else {}
            known = [f for f in op.get("root_fields", []) if f in fields]
            if known:
                out.append(Candidate(
                    category="graphql", subject=subject, analyzer=self.name,
                    evidence=[Evidence(ET.ARTIFACT_RESOLVED, f"schema {fname} defines root field(s) {', '.join(known[:3])} on {tname}", self.name, art.path)] + penalty))
        return out

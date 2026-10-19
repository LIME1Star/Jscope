"""Minimal, dependency-free GraphQL schema reader (SDL + introspection JSON) -> a common dict shape.

    {"roots": {"query": "Query", "mutation": "Mutation", "subscription": None},
     "types": {"Query": {"kind": "type", "fields": {"user": {"args": {"id": "ID!"}, "type": "User", "directives": []}}}}}

It is deliberately a *reader*, not a validator: it extracts what the offline-recon use case needs (root fields, argument
types, directives) and tolerates what it does not understand rather than rejecting the document.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r'"""[\s\S]*?"""|"(?:[^"\\]|\\.)*"|#[^\n]*|[A-Za-z_]\w*|-?\d+(?:\.\d+)?|\.\.\.|[!:(){}\[\]@=,|&$]')
_KINDS = {"type", "interface", "input", "enum", "union", "scalar", "directive", "schema", "extend", "fragment"}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text) if not (t.startswith("#") or t.startswith('"') or t == ",")]


def _parse_type(toks: list[str], i: int) -> tuple[str, int]:
    out = ""
    while i < len(toks) and toks[i] == "[":
        out, i = out + "[", i + 1
    if i < len(toks):
        out, i = out + toks[i], i + 1
    while i < len(toks) and toks[i] in ("]", "!"):
        out, i = out + toks[i], i + 1
    return out, i


def _skip_parens(toks: list[str], i: int) -> int:
    depth = 0
    while i < len(toks):
        if toks[i] == "(":
            depth += 1
        elif toks[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _directives(toks: list[str], i: int) -> tuple[list[str], int]:
    names = []
    while i < len(toks) and toks[i] == "@":
        i += 1
        if i < len(toks):
            names.append(toks[i])
            i += 1
        if i < len(toks) and toks[i] == "(":
            i = _skip_parens(toks, i)
    return names, i


def parse_sdl(text: str) -> dict[str, Any]:
    toks = _tokens(text)
    types: dict[str, dict] = {}
    roots: dict[str, str | None] = {"query": None, "mutation": None, "subscription": None}
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t == "extend":
            i += 1
            continue
        if t == "schema":
            i += 1
            _, i = _directives(toks, i)
            if i < n and toks[i] == "{":
                i += 1
                while i < n and toks[i] != "}":
                    if toks[i] in roots and i + 2 < n and toks[i + 1] == ":":
                        roots[toks[i]] = toks[i + 2]
                        i += 3
                    else:
                        i += 1
            i += 1
            continue
        if t in ("type", "interface", "input") and i + 1 < n:
            kind, name, i = t, toks[i + 1], i + 2
            if i < n and toks[i] == "implements":
                while i < n and toks[i] not in ("{", "@"):
                    i += 1
            _, i = _directives(toks, i)
            fields: dict[str, dict] = {}
            if i < n and toks[i] == "{":
                i += 1
                while i < n and toks[i] != "}":
                    fname = toks[i]
                    i += 1
                    args: dict[str, str] = {}
                    if i < n and toks[i] == "(":
                        j, end = i + 1, _skip_parens(toks, i)
                        while j < end - 1:
                            if j + 1 < end and toks[j + 1] == ":" and re.match(r"[A-Za-z_]", toks[j]):
                                aname = toks[j]
                                atype, j = _parse_type(toks, j + 2)
                                args[aname] = atype
                                if j < end and toks[j] == "=":          # default value: skip one token
                                    j += 2
                                _, j = _directives(toks, j)
                            else:
                                j += 1
                        i = end
                    ftype = ""
                    if i < n and toks[i] == ":":
                        ftype, i = _parse_type(toks, i + 1)
                    dirs, i = _directives(toks, i)
                    if kind == "input":                     # input fields look like `name: Type = default @d`
                        if i < n and toks[i] == "=":
                            i += 2
                    fields[fname] = {"args": args, "type": ftype, "directives": dirs}
            types.setdefault(name, {"kind": kind, "fields": {}})["fields"].update(fields)
            i += 1
            continue
        i += 1
    for r, default in (("query", "Query"), ("mutation", "Mutation"), ("subscription", "Subscription")):
        if roots[r] is None and default in types:
            roots[r] = default
    return {"roots": roots, "types": types}


def _unwrap(t: dict | None) -> str:
    if not t:
        return ""
    kind, name = t.get("kind"), t.get("name")
    if kind == "NON_NULL":
        return _unwrap(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + _unwrap(t.get("ofType")) + "]"
    return name or ""


def parse_introspection(doc: dict) -> dict[str, Any]:
    schema = (doc.get("data") or doc)["__schema"]
    roots = {"query": (schema.get("queryType") or {}).get("name"),
             "mutation": (schema.get("mutationType") or {}).get("name"),
             "subscription": (schema.get("subscriptionType") or {}).get("name")}
    types: dict[str, dict] = {}
    for t in schema.get("types", []):
        name = t.get("name") or ""
        if name.startswith("__"):
            continue
        fields = {}
        for f in (t.get("fields") or t.get("inputFields") or []):
            fields[f["name"]] = {"args": {a["name"]: _unwrap(a.get("type")) for a in f.get("args", []) or []},
                                 "type": _unwrap(f.get("type")), "directives": [],
                                 "deprecated": bool(f.get("isDeprecated"))}
        types[name] = {"kind": str(t.get("kind", "OBJECT")).lower(), "fields": fields}
    return {"roots": roots, "types": types}

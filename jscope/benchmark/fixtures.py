"""Benchmark fixtures (FR-06): small, hand-verified applications with documented ground truth.

Each fixture is a tiny project plus a `BenchmarkEntry` that states what JScope SHOULD conclude and why. Fixtures come in
matched vulnerable/patched/absent triples wherever practical, because a detector that cannot tell them apart is not
measuring anything. `difficult` fixtures are known-hard cases (documented limitations, not failures) that are reported
separately so they never silently drag down the headline numbers.

Real downloadable third-party applications are deliberately NOT vendored here (licensing + reproducibility): the
benchmark is built from synthetic, framework-representative fixtures modelled on common real-world patterns, which is
what FR-06 asks for when "licensing and test reproducibility permit" -- synthetic fixtures always do.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BenchmarkEntry:
    name: str
    vuln_class: str                       # dom_xss | open_redirect | sql_injection | command_injection | idor | none
    files: dict[str, str]
    expect_flag: bool                     # should JScope (at default min-confidence) report this vuln_class present?
    ground_truth_basis: str               # why we know this (hand-verified code review of the fixture)
    test_conditions: str = "default analyzer config, min_confidence=LOW, dataflow_analyzer enabled"
    difficult: bool = False               # a known-hard case; reported separately, not folded into headline precision/recall
    note: str = ""
    framework: str = "vanilla"
    minified: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)


def _entries() -> list[BenchmarkEntry]:
    e: list[BenchmarkEntry] = []

    e.append(BenchmarkEntry("dom_xss_vulnerable", "dom_xss", {
        "app.js": "const q = new URLSearchParams(location.search).get('q');\ndocument.getElementById('out').innerHTML = q;\n"
    }, True, "innerHTML assigned directly from an unsanitised URL query parameter"))
    e.append(BenchmarkEntry("dom_xss_patched_sanitized", "dom_xss", {
        "app.js": "import DOMPurify from 'dompurify';\nconst q = new URLSearchParams(location.search).get('q');\n"
                 "document.getElementById('out').innerHTML = DOMPurify.sanitize(q);\n"
    }, False, "value passes through DOMPurify.sanitize() before reaching innerHTML"))
    e.append(BenchmarkEntry("dom_xss_patched_textcontent", "dom_xss", {
        "app.js": "const q = new URLSearchParams(location.search).get('q');\ndocument.getElementById('out').textContent = q;\n"
    }, False, "textContent is not an HTML sink; value is rendered as text, not markup"))
    e.append(BenchmarkEntry("dom_xss_vulnerable_react", "dom_xss", {
        "Page.jsx": "import React from 'react';\nexport function Page() {\n  const h = new URLSearchParams(window.location.search).get('h') ?? '';\n"
                   "  return <div dangerouslySetInnerHTML={{ __html: h }} />;\n}\n"
    }, True, "dangerouslySetInnerHTML fed directly from the URL", framework="react"))
    e.append(BenchmarkEntry("dom_xss_safe_react_text_prop", "dom_xss", {
        "Page.jsx": "import React from 'react';\nexport function Page({ title }) { const h = new URLSearchParams(window.location.search).get('h');"
                   "\n  return <div title={h}>{title}</div>;\n}\n"
    }, False, "URL value flows only into a text prop, never into dangerouslySetInnerHTML", framework="react"))

    e.append(BenchmarkEntry("open_redirect_vulnerable", "open_redirect", {
        "nav.js": "const next = new URLSearchParams(location.search).get('next');\nlocation.href = next;\n"
    }, True, "location.href assigned directly from an unsanitised query parameter"))
    e.append(BenchmarkEntry("open_redirect_patched_allowlist", "open_redirect", {
        "nav.js": "const next = new URLSearchParams(location.search).get('next');\nconst ALLOWED = ['/home', '/profile'];\n"
                 "if (ALLOWED.includes(next)) { location.href = next; }\n"
    }, False, "destination is checked against a fixed allow-list of literal paths before navigation"))

    e.append(BenchmarkEntry("sql_injection_vulnerable", "sql_injection", {
        "db.js": "const mysql = require('mysql');\nfunction getUser(id) { return conn.query('SELECT * FROM users WHERE id = ' + id); }\n"
                "getUser(new URLSearchParams(location.search).get('id'));\n"
    }, True, "query string concatenated directly into SQL text"))
    e.append(BenchmarkEntry("sql_injection_patched_parameterized", "sql_injection", {
        "db.js": "const mysql = require('mysql');\nfunction getUser(id) { return conn.query('SELECT * FROM users WHERE id = ?', [id]); }\n"
                "getUser(new URLSearchParams(location.search).get('id'));\n"
    }, False, "value passed as a bound parameter, never concatenated into the query text"))

    e.append(BenchmarkEntry("command_injection_vulnerable", "command_injection", {
        "run.js": "const cp = require('child_process');\nconst name = new URLSearchParams(location.search).get('name');\n"
                 "cp.exec('echo ' + name);\n"
    }, True, "shell command string built via concatenation with untrusted input"))
    e.append(BenchmarkEntry("command_injection_safe_no_shell_package", "command_injection", {
        "run.js": "const name = new URLSearchParams(location.search).get('name');\nthing.exec('echo ' + name);\n"
    }, False, "no child_process/execa/etc. package is used; `.exec()` here is an unrelated API"))

    e.append(BenchmarkEntry("clean_app_no_findings", "none", {
        "app.js": "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));\nconst el = document.getElementById('x');\n"
                 "el.textContent = 'static label';\n"
    }, False, "no untrusted source reaches any sink at all"))

    # -- difficult / documented-limitation cases: reported separately, never silently lowering headline numbers --
    e.append(BenchmarkEntry("difficult_minified_bundle", "dom_xss", {
        "bundle.min.js": "function a(b){return document.getElementById(\"x\").innerHTML=b}a(new URLSearchParams(location.search).get(\"q\"))"
    }, True, "same vulnerable pattern, minified: tests that minification alone does not defeat detection",
        difficult=True, minified=True, note="minified identifiers; verifies the engine isn't name-dependent"))
    e.append(BenchmarkEntry("difficult_dynamic_alias_unresolved", "dom_xss", {
        "app.js": "import { render } from '@app/render';\nrender(location.hash);\n"       # no tsconfig/alias config provided on purpose
    }, False, "alias has no configuration in this fixture, so the import is legitimately UNRESOLVED; JScope must not "
             "guess a vulnerability out of an unresolved import -- expected outcome is 'not flagged', not a false negative",
        difficult=True, note="documents the resolver's honest behaviour on an unconfigured bundler alias"))
    return e


ENTRIES: list[BenchmarkEntry] = _entries()


def by_class() -> dict[str, list[BenchmarkEntry]]:
    out: dict[str, list[BenchmarkEntry]] = {}
    for e in ENTRIES:
        out.setdefault(e.vuln_class, []).append(e)
    return out

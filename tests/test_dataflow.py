"""FR-01 / FR-02: interprocedural data flow, module resolution, TypeScript, diagnostics."""

import json
from pathlib import Path

import pytest

from jscope.config import Config
from jscope.core.evidence import Confidence, EvidenceType as ET
from jscope.dataflow.modules import ModuleResolver
from jscope.pipeline import run_analysis


def project(tmp_path, files: dict[str, str]) -> Path:
    root = tmp_path / "app"
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    return root


def scan(tmp_path, files, **cfg):
    root = project(tmp_path, files)
    config = Config()
    config.data["analyzers"]["enabled"] = ["framework_detector", "dataflow_analyzer"]
    config.data.update(cfg)
    res = run_analysis([str(root)], config)
    return res, [f for f in res.findings if f.category == "dataflow"]


def flows(res):
    return res.dataflow["flows"] if hasattr(res, "dataflow") else []


# ----------------------------------------------------------------------------------------------- basics
def test_direct_source_to_sink(tmp_path):
    res, fs = scan(tmp_path, {"a.js": "const q = location.hash;\ndocument.getElementById('x').innerHTML = q;\n"})
    assert len(fs) == 1
    f = fs[0]
    assert f.metadata["sink_class"] == "html" and f.metadata["source_kind"] == "url_hash"
    assert f.metadata["verification_status"] == "unverified"
    assert f.confidence != Confidence.CONFIRMED                      # static evidence alone never confirms
    assert any(e.type == ET.DATA_FLOW for e in f.evidence)


def test_constant_does_not_flow(tmp_path):
    _, fs = scan(tmp_path, {"a.js": "const q = 'hello';\nel.innerHTML = q;\nel.innerHTML = '<b>' + q + '</b>';\n"})
    assert fs == []


def test_textcontent_is_not_a_sink(tmp_path):
    _, fs = scan(tmp_path, {"a.js": "el.textContent = location.search;\nel.innerText = location.hash;\n"})
    assert fs == []


def test_cross_function_and_template_literal(tmp_path):
    src = """
function render(html) { return `<div>${html}</div>`; }
function show(x) { const out = render(x); document.body.innerHTML = out; }
show(new URLSearchParams(location.search).get('q'));
"""
    res, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1
    steps = [s["step"] for s in fs[0].metadata["flow"]["path"]]
    assert any("render()" in s for s in steps) and any("show()" in s for s in steps)


# ----------------------------------------------------------------------------------------------- cross-file
CROSS = {
    "src/util/html.js": "export function wrap(v) { return '<p>' + v + '</p>'; }\nexport const unused = 1;\n",
    "src/lib/dom.js": "import { wrap } from '../util/html';\nexport function paint(el, v) { el.innerHTML = wrap(v); }\n",
    "src/main.js": "import { paint } from './lib/dom.js';\nconst x = location.hash.slice(1);\npaint(document.body, x);\n",
}


def test_flow_crosses_three_files_and_gets_import_chain(tmp_path):
    res, fs = scan(tmp_path, CROSS)
    assert len(fs) == 1
    f = fs[0]
    assert f.metadata["cross_file"] is True
    files = {s["file"].split("/")[-1] for s in f.metadata["flow"]["path"]}
    assert {"main.js", "dom.js"} <= files
    assert any(e.type == ET.IMPORT_CHAIN for e in f.evidence)
    assert f.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_commonjs_require_and_module_exports(tmp_path):
    files = {
        "a.js": "const { render } = require('./b');\nrender(location.search);\n",
        "b.js": "module.exports = { render: function (v) { document.write(v); } };\n",
    }
    _, fs = scan(tmp_path, files)
    assert len(fs) == 1 and fs[0].metadata["sink_class"] == "html"


def test_default_export_and_namespace_import(tmp_path):
    files = {
        "a.js": "import draw from './b.js';\nimport * as u from './c.js';\ndraw(location.hash);\nu.go(document.referrer);\n",
        "b.js": "export default function (v) { eval(v); }\n",
        "c.js": "export const go = (u) => { location.href = u; };\n",
    }
    _, fs = scan(tmp_path, files)
    kinds = {f.metadata["sink_class"] for f in fs}
    assert kinds == {"code", "navigation"}


def test_dynamic_import_resolves(tmp_path):
    files = {
        "a.js": "async function load() { const m = await import('./b.js'); m.run(location.hash); }\nload();\n",
        "b.js": "export function run(v) { document.body.innerHTML = v; }\n",
    }
    _, fs = scan(tmp_path, files)
    assert len(fs) == 1 and fs[0].metadata["cross_file"]


def test_reexport_barrel(tmp_path):
    files = {
        "index.js": "export { sink } from './impl.js';\n",
        "impl.js": "export function sink(v) { document.write(v); }\n",
        "use.js": "import { sink } from './index.js';\nsink(location.search);\n",
    }
    _, fs = scan(tmp_path, files)
    assert len(fs) == 1


def test_circular_imports_do_not_hang(tmp_path):
    files = {
        "a.js": "import { b } from './b.js';\nexport function a(v) { return b(v); }\n",
        "b.js": "import { a } from './a.js';\nexport function b(v) { document.body.innerHTML = v; return v; }\nexport const c = () => a(location.hash);\n",
    }
    _, fs = scan(tmp_path, files)
    assert len(fs) == 1


# ----------------------------------------------------------------------------------------------- sanitization / validation
def test_effective_sanitizer_suppresses_but_is_recorded(tmp_path):
    src = "import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(location.hash);\n"
    res, fs = scan(tmp_path, {"a.js": src})
    assert fs == []
    fl = [x for x in res.dataflow["flows"] if x["status"] == "sanitized"]
    assert len(fl) == 1 and fl[0]["mitigations"][0]["effective_for"] == ["html"]


def test_sanitizer_is_sink_class_specific(tmp_path):
    src = "const s = DOMPurify.sanitize(location.hash);\nlocation.href = s;\n"          # HTML sanitizer does not make a URL safe
    _, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1 and fs[0].metadata["sink_class"] == "navigation"


def test_numeric_coercion_neutralises_everything(tmp_path):
    _, fs = scan(tmp_path, {"a.js": "el.innerHTML = Number(location.hash.slice(1));\neval(parseInt(location.search));\n"})
    assert fs == []


def test_partial_replace_is_uncertain_not_clean(tmp_path):
    res, fs = scan(tmp_path, {"a.js": "el.innerHTML = location.hash.replace(/</g, '');\n"})
    assert len(fs) == 1
    assert fs[0].metadata["flow_status"] == "uncertain"
    assert any(e.type == ET.DATA_FLOW_PARTIAL for e in fs[0].evidence)
    assert not any(e.type == ET.DATA_FLOW for e in fs[0].evidence)


def test_strict_regex_guard_is_effective_loose_is_uncertain(tmp_path):
    strict = "const v = location.hash.slice(1);\nif (/^[a-z0-9_-]+$/i.test(v)) { el.innerHTML = v; }\n"
    loose = "const v = location.hash.slice(1);\nif (/<.*>/.test(v) === false) { }\nif (/^.*$/.test(v)) { el.innerHTML = v; }\n"
    res, fs = scan(tmp_path, {"a.js": strict})
    assert fs == []
    res2, fs2 = scan(tmp_path / "x", {"a.js": loose})
    assert len(fs2) == 1 and fs2[0].metadata["flow_status"] == "uncertain"


def test_allowlist_and_early_return_guard(tmp_path):
    src = """
const page = location.hash.slice(1);
const ALLOWED = ['home', 'about'];
if (!ALLOWED.includes(page)) { throw new Error('bad'); }
document.body.innerHTML = page;
"""
    _, fs = scan(tmp_path, {"a.js": src})
    assert fs == []


def test_guard_in_one_branch_does_not_protect_the_other(tmp_path):
    src = """
const v = location.hash.slice(1);
if (/^\\d+$/.test(v)) { el.innerHTML = v; } else { el.innerHTML = v; }
"""
    res, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1 and fs[0].metadata["flow_status"] == "candidate"


# ----------------------------------------------------------------------------------------------- reachability / uncertainty
def test_dead_branch_is_downgraded_not_dropped(tmp_path):
    res, fs = scan(tmp_path, {"a.js": "if (false) { el.innerHTML = location.hash; }\n"})
    assert fs == []                                                   # below the default LOW display threshold...
    assert res.dataflow["counts"]["unreachable"] == 1                 # ...but still represented in the analysis
    res, fs = scan(tmp_path / "v", {"a.js": "if (false) { el.innerHTML = location.hash; }\n"}, min_confidence="INFORMATIONAL")
    assert len(fs) == 1
    assert fs[0].metadata["flow_status"] == "unreachable"
    assert fs[0].confidence == Confidence.INFORMATIONAL


def test_unresolved_call_becomes_explicit_assumption(tmp_path):
    src = "import { mystery } from 'some-pkg';\nel.innerHTML = mystery(location.hash);\n"
    res, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1
    assert fs[0].metadata["flow"]["assumptions"]
    assert any(e.type == ET.DATA_FLOW_PARTIAL for e in fs[0].evidence)
    assert fs[0].confidence in (Confidence.LOW, Confidence.INFORMATIONAL)
    assert any(l["kind"] == "unresolved-call" for l in res.dataflow["limitations"])


def test_unresolved_import_is_reported(tmp_path):
    res, _ = scan(tmp_path, {"a.js": "import { x } from './missing.js';\nx(location.hash);\n"})
    assert any("missing.js" in d["specifier"] for d in res.dataflow["unresolved_imports"])
    assert any("unresolved-import" in d for ds in res.file_diagnostics.values() for d in ds)


def test_object_fields_are_tracked_separately(tmp_path):
    src = "const o = { safe: 'x', bad: location.hash };\nel.innerHTML = o.safe;\n"
    _, fs = scan(tmp_path, {"a.js": src})
    assert fs == []
    src2 = "const o = { safe: 'x', bad: location.hash };\nel.innerHTML = o.bad;\n"
    _, fs2 = scan(tmp_path / "y", {"a.js": src2})
    assert len(fs2) == 1


# ----------------------------------------------------------------------------------------------- async & callbacks
def test_promise_chain_from_fetch(tmp_path):
    src = "fetch('/api/x').then(r => r.json()).then(d => { document.body.innerHTML = d.html; });\n"
    _, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1 and fs[0].metadata["source_kind"] == "network_response"


def test_async_await_fetch(tmp_path):
    src = "async function f() { const r = await fetch('/a'); const d = await r.json(); el.innerHTML = d.body; }\nf();\n"
    _, fs = scan(tmp_path, {"a.js": src})
    assert len(fs) == 1


def test_callback_passed_across_files(tmp_path):
    files = {
        "run.js": "export function withValue(cb) { cb(location.hash); }\n",
        "main.js": "import { withValue } from './run.js';\nwithValue(v => { document.body.innerHTML = v; });\n",
    }
    _, fs = scan(tmp_path, files)
    assert len(fs) == 1 and fs[0].metadata["cross_file"]


def test_postmessage_and_origin_check(tmp_path):
    bad = "window.addEventListener('message', e => { document.body.innerHTML = e.data; });\n"
    good = "window.addEventListener('message', e => { if (e.origin !== 'https://trusted.example') return; document.body.innerHTML = e.data; });\n"
    _, fs = scan(tmp_path, {"a.js": bad})
    assert len(fs) == 1 and fs[0].metadata["source_kind"] == "postmessage"
    res2, fs2 = scan(tmp_path / "g", {"a.js": good})
    assert fs2 == [] and any(f["status"] == "sanitized" for f in res2.dataflow["flows"])


# ----------------------------------------------------------------------------------------------- sinks
@pytest.mark.parametrize("code,cls", [
    ("document.write(location.hash)", "html"),
    ("el.insertAdjacentHTML('beforeend', location.hash)", "html"),
    ("eval(location.hash)", "code"),
    ("new Function(location.hash)", "code"),
    ("setTimeout(location.hash, 10)", "code"),
    ("location.assign(location.hash.slice(1))", "navigation"),
    ("window.open(document.referrer)", "navigation"),
    ("$('#x').html(location.hash)", "html"),
    ("location.href = localStorage.getItem('next')", "navigation"),
])
def test_sink_catalogue(tmp_path, code, cls):
    _, fs = scan(tmp_path, {"a.js": code + ";\n"})
    assert [f.metadata["sink_class"] for f in fs] == [cls]


def test_timeout_with_function_is_not_code_sink(tmp_path):
    _, fs = scan(tmp_path, {"a.js": "setTimeout(() => { go(); }, 10);\n"})
    assert fs == []


def test_command_and_sql_sinks_need_their_packages(tmp_path):
    present = {"a.js": "const cp = require('child_process');\nconst mysql = require('mysql');\n"
                       "const id = location.search;\ncp.exec('ls ' + id);\nconn.query('SELECT * FROM t WHERE id=' + id);\n"}
    absent = {"a.js": "const id = location.search;\nthing.exec('ls ' + id);\nthing.query('SELECT ' + id);\n"}
    _, fs = scan(tmp_path, present)
    assert {f.metadata["sink_class"] for f in fs} == {"command", "sql"}
    _, fs2 = scan(tmp_path / "z", absent)
    assert fs2 == []


def test_parameterised_query_is_not_flagged(tmp_path):
    src = "const mysql = require('mysql');\nconn.query('SELECT * FROM t WHERE id = ?', [location.search]);\n"
    _, fs = scan(tmp_path, {"a.js": src})
    assert fs == []


# ----------------------------------------------------------------------------------------------- TypeScript / JSX / Vue
def test_typescript_with_types_and_generics(tmp_path):
    files = {
        "a.ts": "import { show } from './b';\ninterface P { q: string }\nconst p: P = { q: location.hash as string };\nshow<string>(p.q!);\n",
        "b.ts": "export function show<T extends string>(v: T): void { (document.body as HTMLElement).innerHTML = v; }\n",
    }
    res, fs = scan(tmp_path, files)
    assert len(fs) == 1 and fs[0].metadata["cross_file"]
    assert not any("syntax error" in d for ds in res.file_diagnostics.values() for d in ds)


def test_tsx_dangerously_set_inner_html(tmp_path):
    src = ("import React from 'react';\nexport function Page({ html }: { html: string }) {\n"
           "  const h = new URLSearchParams(window.location.search).get('h') ?? '';\n"
           "  return <div dangerouslySetInnerHTML={{ __html: h }} />;\n}\n")
    _, fs = scan(tmp_path, {"Page.tsx": src})
    assert len(fs) == 1 and fs[0].metadata["flow"]["sink"]["name"] == "dangerouslySetInnerHTML"


def test_jsx_safe_prop_not_flagged(tmp_path):
    src = "export const A = () => <div title={location.hash} dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />;\n"
    _, fs = scan(tmp_path, {"A.jsx": src})
    assert fs == []


def test_vue_v_html_flow(tmp_path):
    vue = """<template>
  <div v-html="content"></div>
</template>
<script>
import { ref } from 'vue';
export default { setup() { const content = ref(location.hash); return { content }; } };
</script>
"""
    root = project(tmp_path, {"Comp.vue": vue})
    config = Config()
    config.data["analyzers"]["enabled"] = ["framework_detector", "dataflow_analyzer"]
    res = run_analysis([str(root)], config)
    fs = [f for f in res.findings if f.category == "dataflow"]
    assert len(fs) == 1 and fs[0].metadata["flow"]["sink"]["name"] == "v-html"


def test_syntax_errors_are_diagnosed_not_hidden(tmp_path):
    res, _ = scan(tmp_path, {"broken.js": "function (( {\nconst a = ;\n", "ok.js": "var x = 1;\n"})
    d = [x for p, ds in res.file_diagnostics.items() for x in ds if "broken.js" in p]
    assert d and "partially analyzed" in d[0]


# ----------------------------------------------------------------------------------------------- module resolution (FR-02)
def test_tsconfig_paths_alias_resolves(tmp_path):
    files = {
        "tsconfig.json": '{ // comment\n "compilerOptions": { "baseUrl": ".", "paths": { "@lib/*": ["src/lib/*"], },\n },\n}',
        "src/lib/dom.ts": "export function paint(v: string) { document.body.innerHTML = v; }\n",
        "src/app/main.ts": "import { paint } from '@lib/dom';\npaint(location.hash);\n",
    }
    res, fs = scan(tmp_path, files)
    assert len(fs) == 1 and fs[0].metadata["cross_file"]
    assert res.dataflow["unresolved_imports"] == []


def test_alias_without_config_is_unresolved_with_a_reason(tmp_path):
    files = {"src/a.ts": "import { f } from '@/lib/f';\nf(location.hash);\n"}
    res, fs = scan(tmp_path, files)
    assert fs == []
    assert "bundler alias" in res.dataflow["unresolved_imports"][0]["reason"]


def test_config_module_aliases(tmp_path):
    files = {"src/lib/f.js": "export const f = v => eval(v);\n", "src/a.js": "import { f } from '@/lib/f';\nf(location.hash);\n"}
    root = project(tmp_path, files)
    config = Config()
    config.data["analyzers"]["enabled"] = ["dataflow_analyzer"]
    config.data["module_aliases"] = {"@": str(root / "src")}
    res = run_analysis([str(root)], config)
    assert len([f for f in res.findings if f.category == "dataflow"]) == 1


def test_resolver_extension_and_index_probing(tmp_path):
    root = project(tmp_path, {"a/index.ts": "", "b.tsx": "", "c.js": "", "d.mjs": ""})
    files = [str(p) for p in root.rglob("*") if p.is_file()]
    r = ModuleResolver(files)
    src = str(root / "main.ts")
    assert r.resolve("./a", src).path.endswith("a/index.ts")
    assert r.resolve("./b", src).path.endswith("b.tsx")
    assert r.resolve("./c.js", src).path.endswith("c.js")
    assert r.resolve("./d", src).path.endswith("d.mjs")
    assert r.resolve("./nope", src).status == "unresolved"
    assert r.resolve("lodash", src).status == "external"


def test_ts_style_js_specifier_maps_to_ts_source(tmp_path):
    root = project(tmp_path, {"x.ts": ""})
    r = ModuleResolver([str(root / "x.ts")])
    assert r.resolve("./x.js", str(root / "y.ts")).path.endswith("x.ts")


def test_dataflow_included_in_json_payload(tmp_path):
    from jscope.reporting import json_report
    res, _ = scan(tmp_path, {"a.js": "el.innerHTML = location.hash;\n"})
    assert res.dataflow["counts"]["candidate"] == 1

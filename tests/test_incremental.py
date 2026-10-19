"""FR-07: dependency-aware incremental analysis."""
import json
import shutil
from pathlib import Path

from jscope.config import Config
from jscope.pipeline import run_analysis

APP = {
    "src/util.js": "export function wrap(v) { return '<p>' + v + '</p>'; }\n",
    "src/dom.js": "import { wrap } from './util.js';\nexport function paint(el, v) { el.innerHTML = wrap(v); }\n",
    "src/main.js": "import { paint } from './dom.js';\npaint(document.body, location.hash);\n",
    "src/other.js": "document.write(location.search);\n",
    "src/lonely.js": "export const x = 1;\n",
}


def write(root: Path, files):
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)


def scan(root, cache=None):
    cfg = Config()
    cfg.data["analyzers"]["enabled"] = ["framework_detector", "dataflow_analyzer"]
    cfg.data["min_confidence"] = "INFORMATIONAL"
    if cache:
        cfg.data["incremental"]["cache_dir"] = str(cache)
    return run_analysis([str(root)], cfg)


def view(res):
    return sorted((f.subject, f.confidence.value, f.score) for f in res.findings if f.category == "dataflow")


def flows(res):
    return sorted(json.dumps(f, sort_keys=True) for f in res.dataflow["flows"])


def names(paths):
    return sorted(Path(p).name for p in paths)


def test_unchanged_project_reuses_everything(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    r1 = scan(root, cache)
    r2 = scan(root, cache)
    assert r2.__dict__["dataflow"] and view(r1) == view(r2) and flows(r1) == flows(r2)
    assert any("reused 5 file(s), re-analyzed 0" in d for d in r2.diagnostics)


def test_changed_file_reanalyzes_all_dependents_only(tmp_path):
    from jscope.analyzers.dataflow_analyzer import DataFlowAnalyzer
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    scan(root, cache)
    (root / "src/util.js").write_text("export function wrap(v) { return DOMPurify.sanitize(v); }\n")
    r = scan(root, cache)
    d = [x for x in r.diagnostics if x.startswith("[incremental]")][0]
    assert "reused 2 file(s), re-analyzed 3" in d                    # util + dom + main re-run; other + lonely reused
    assert view(r) == view(scan(root))                               # equals a clean scan
    assert all("main.js" not in s for s, *_ in view(r))              # sanitiser in util now neutralises the flow


def test_removed_file_removes_stale_findings_and_relationships(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    r1 = scan(root, cache)
    assert any("other.js" in s for s, *_ in view(r1))
    (root / "src/other.js").unlink()
    r2 = scan(root, cache)
    assert all("other.js" not in s for s, *_ in view(r2))
    assert any("dropped 1 removed" in d for d in r2.diagnostics)
    assert view(r2) == view(scan(root))


def test_removed_dependency_changes_importer(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    scan(root, cache)
    (root / "src/dom.js").unlink()
    r = scan(root, cache)
    assert view(r) == view(scan(root))
    assert any(u["specifier"] == "./dom.js" for u in r.dataflow["unresolved_imports"])


def test_incremental_equals_clean_after_edit_sequence(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    scan(root, cache)
    steps = [("src/other.js", "el.innerHTML = location.hash;\n"), ("src/lonely.js", "export const x = location.search;\n"),
             ("src/new.js", "import { x } from './lonely.js';\neval(x);\n"), ("src/main.js", "var a = 1;\n")]
    for rel, src in steps:
        (root / rel).write_text(src)
        inc, clean = scan(root, cache), scan(root)
        assert view(inc) == view(clean), rel
        assert flows(inc) == flows(clean), rel


def test_corrupt_or_foreign_cache_falls_back_to_full_scan(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, APP)
    scan(root, cache)
    (cache / "dataflow-cache.json").write_text("{not json")
    r = scan(root, cache)
    assert view(r) == view(scan(root)) and any("re-analyzed 5" in d for d in r.diagnostics)
    (cache / "dataflow-cache.json").write_text(json.dumps({"cache_version": 1, "engine": "old", "entries": {}}))
    assert view(scan(root, cache)) == view(scan(root))


def test_missing_cache_dir_is_created_and_disabled_flag_works(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "deep" / "cache"
    write(root, APP)
    scan(root, cache)
    assert (cache / "dataflow-cache.json").exists()
    cfg = Config()
    cfg.data["incremental"].update(cache_dir=str(cache), enabled=False)
    r = run_analysis([str(root)], cfg)
    assert not any(d.startswith("[incremental]") for d in r.diagnostics)


def test_tsconfig_change_invalidates(tmp_path):
    root, cache = tmp_path / "app", tmp_path / "cache"
    write(root, {"tsconfig.json": '{"compilerOptions":{"baseUrl":".","paths":{"@l/*":["lib/*"]}}}',
                 "lib/f.ts": "export const f = (v: string) => eval(v);\n", "a.ts": "import { f } from '@l/f';\nf(location.hash);\n"})
    r1 = scan(root, cache)
    assert len(view(r1)) == 1
    (root / "tsconfig.json").write_text('{"compilerOptions":{"baseUrl":".","paths":{"@l/*":["nowhere/*"]}}}')
    r2 = scan(root, cache)
    assert view(r2) == view(scan(root)) == []

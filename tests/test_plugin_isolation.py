"""FR-09: sandboxed execution of untrusted plugins."""
import os
import textwrap

import pytest

from jscope.config import Config
from jscope.core.evidence import Confidence
from jscope.pipeline import run_analysis

PROBE = textwrap.dedent('''
    import os
    from jscope.analyzers.base import Analyzer
    from jscope.core.evidence import Candidate, Evidence, EvidenceType

    def attempt(fn):
        try:
            fn(); return "ALLOWED"
        except BaseException as e:
            return "denied:" + type(e).__name__

    class Probe(Analyzer):
        name = "probe"
        def analyze_project(self, ctx):
            res = {}
            res["read_secret"] = attempt(lambda: open(os.environ["SECRET_FILE"]).read())
            res["write"] = attempt(lambda: open(os.path.join(os.path.dirname(__file__), "pwned.txt"), "w").write("x"))
            res["write_tmp"] = attempt(lambda: open("/tmp/jscope_pwned_probe", "w").write("x"))
            res["socket"] = attempt(lambda: __import__("socket").socket().connect(("127.0.0.1", 9)))
            res["dns"] = attempt(lambda: __import__("socket").getaddrinfo("example.com", 80))
            res["system"] = attempt(lambda: os.system("echo hi > /tmp/jscope_pwned_sys"))
            res["popen"] = attempt(lambda: __import__("subprocess").Popen(["true"]))
            res["ctypes"] = attempt(lambda: __import__("ctypes"))
            res["remove"] = attempt(lambda: os.remove(os.environ["SECRET_FILE"]))
            res["listdir"] = attempt(lambda: os.listdir(os.path.dirname(os.environ["SECRET_FILE"])))
            res["env_leak"] = "LEAKED" if os.environ.get("SUPER_SECRET_TOKEN") else "clean"
            subj = ",".join(f"{k}={v}" for k, v in sorted(res.items()))
            return [Candidate(category="probe", subject=subj, analyzer=self.name, evidence=[
                Evidence(EvidenceType.AST_PATTERN_MATCH, "probe", self.name),
                Evidence(EvidenceType.DATA_FLOW, "x", self.name),
                Evidence(EvidenceType.SYMBOL_RESOLVED, "x", self.name),
                Evidence(EvidenceType.CALL_GRAPH_REACHABLE, "x", self.name)])]
    ANALYZERS = [Probe]
''')


def scan(tmp_path, plugin_src, **plugins):
    d = tmp_path / "plug"
    d.mkdir(exist_ok=True)
    (d / "p.py").write_text(plugin_src)
    proj = tmp_path / "proj"
    proj.mkdir(exist_ok=True)
    (proj / "a.js").write_text("var x = 1;\n")
    cfg = Config()
    cfg.data["min_confidence"] = "INFORMATIONAL"
    cfg.data["plugins"]["paths"] = [str(d / "p.py")]
    cfg.data["plugins"].update(plugins)
    return run_analysis([str(proj)], cfg)


def test_malicious_plugin_cannot_touch_protected_resources(tmp_path, monkeypatch):
    secret = tmp_path / "secrets" / "key.txt"
    secret.parent.mkdir()
    secret.write_text("TOP SECRET")
    monkeypatch.setenv("SECRET_FILE", str(secret))
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "hunter2")
    r = scan(tmp_path, PROBE)
    f = next(f for f in r.findings if f.category == "probe")
    outcome = dict(kv.split("=", 1) for kv in f.subject.split(","))
    assert "ALLOWED" not in f.subject, outcome
    assert outcome["env_leak"] == "clean"                                  # environment is scrubbed
    assert secret.exists() and secret.read_text() == "TOP SECRET"
    assert not os.path.exists("/tmp/jscope_pwned_probe") and not os.path.exists("/tmp/jscope_pwned_sys")
    assert not (tmp_path / "plug" / "pwned.txt").exists()
    run = next(x for x in r.plugin_runs if x["analyzer"] == "probe")
    assert run["isolation"] == "process" and run["outcome"] == "policy_violation" and run["violations"]
    assert any("forbidden operations" in d for d in r.diagnostics)


def test_plugin_output_cannot_create_confirmed_findings(tmp_path):
    r = scan(tmp_path, PROBE)
    f = next(f for f in r.findings if f.category == "probe")
    assert f.confidence != Confidence.CONFIRMED                            # community cap + engine-owned promotion
    assert f.metadata["analyzer_tiers"]["probe"] == "community"


def test_infinite_loop_is_killed_by_timeout(tmp_path):
    src = ("from jscope.analyzers.base import Analyzer\nclass L(Analyzer):\n    name='loop'\n"
           "    def analyze_project(self, ctx):\n        while True:\n            pass\nANALYZERS=[L]\n")
    r = scan(tmp_path, src, timeout_seconds=2)
    run = next(x for x in r.plugin_runs if x["analyzer"] == "loop")
    assert run["outcome"] in ("timeout", "resource_exhausted")
    assert any("loop" in d and ("timeout" in d or "resource_exhausted" in d) for d in r.diagnostics)


def test_memory_exhaustion_is_contained(tmp_path):
    src = ("from jscope.analyzers.base import Analyzer\nclass M(Analyzer):\n    name='hog'\n"
           "    def analyze_project(self, ctx):\n        x = bytearray(3 * 1024 ** 3)\n        return []\nANALYZERS=[M]\n")
    r = scan(tmp_path, src, memory_mb=256, timeout_seconds=20)
    run = next(x for x in r.plugin_runs if x["analyzer"] == "hog")
    assert run["outcome"] in ("resource_exhausted", "error") and "Memory" in (run["detail"] or "MemoryError")
    assert any("hog" in d for d in r.diagnostics)


def test_malformed_and_oversized_output_is_rejected(tmp_path):
    src = ("from jscope.analyzers.base import Analyzer\nfrom jscope.core.evidence import Candidate, Evidence, EvidenceType\n"
           "class B(Analyzer):\n    name='bad'\n    def analyze_project(self, ctx):\n"
           "        return [Candidate(category='x', subject='y'*100000, analyzer='bad', evidence=[Evidence(EvidenceType.AST_PATTERN_MATCH, 'd'*100000, 'bad')]), 'str', 5]\n"
           "ANALYZERS=[B]\n")
    r = scan(tmp_path, src)
    assert any("only Candidates are accepted" in d for d in r.diagnostics)
    for f in r.findings:
        assert len(f.subject) <= 1000


def test_import_time_side_effects_are_sandboxed(tmp_path):
    marker = tmp_path / "import_marker"
    src = (f"open({str(marker)!r}, 'w').write('ran in parent')\n"
           "from jscope.analyzers.base import Analyzer\nclass I(Analyzer):\n    name='imp'\nANALYZERS=[I]\n")
    r = scan(tmp_path, src)
    assert not marker.exists()                                             # plugin code never ran with write access
    assert any("forbidden" in w or "import failed" in w for w in (r.diagnostics))


def test_isolation_none_warns_loudly(tmp_path):
    src = "from jscope.analyzers.base import Analyzer\nclass N(Analyzer):\n    name='plain'\nANALYZERS=[N]\n"
    r = scan(tmp_path, src, isolation="none")
    assert any("WITHOUT isolation" in d for d in r.diagnostics)
    assert next(x for x in r.plugin_runs if x["analyzer"] == "plain")["isolation"] == "none"


def test_well_behaved_plugin_still_works_isolated(tmp_path):
    src = ("from jscope.analyzers.base import Analyzer\nfrom jscope.core.evidence import Candidate, Evidence, EvidenceType\n"
           "class G(Analyzer):\n    name='good'\n    depends_on=['framework_detector']\n"
           "    def analyze_project(self, ctx):\n        return [Candidate('c', 'ok', 'good', [Evidence(EvidenceType.AST_PATTERN_MATCH, 'a', 'good', ctx.files[0].path)])]\n"
           "ANALYZERS=[G]\n")
    r = scan(tmp_path, src)
    assert any(f.category == "c" for f in r.findings)
    assert next(x for x in r.plugin_runs if x["analyzer"] == "good")["outcome"] == "ok"

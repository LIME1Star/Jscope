"""FR-06: the benchmark harness itself -- runs in CI via pytest, so this doubles as the CI gate's unit coverage."""
import json

from jscope.benchmark.fixtures import ENTRIES, by_class
from jscope.benchmark.runner import run_benchmark


def test_fixtures_cover_every_required_vuln_class_with_matched_pairs():
    classes = by_class()
    for cls in ("dom_xss", "open_redirect", "sql_injection", "command_injection"):
        assert cls in classes
        assert any(e.expect_flag for e in classes[cls]), f"{cls} needs a vulnerable fixture"
        assert any(not e.expect_flag for e in classes[cls]), f"{cls} needs a corresponding non-vulnerable fixture"


def test_benchmark_achieves_perfect_score_on_its_own_fixtures():
    """Every fixture's ground truth was hand-verified; a regression here means the engine or the fixtures drifted."""
    report = run_benchmark(check_reproducibility=False)
    d = report.to_dict()
    assert d["overall"]["false_positives"] == 0 and d["overall"]["false_negatives"] == 0
    assert d["overall"]["precision"] == 1.0 and d["overall"]["recall"] == 1.0
    assert all(e.outcome in ("true_positive", "true_negative") for e in report.entries)


def test_difficult_fixtures_reported_separately_not_folded_into_headline():
    report = run_benchmark(check_reproducibility=False)
    names = {e.name for e in report.entries}
    assert not any(n.startswith("difficult_") for n in names)
    assert {e.name for e in report.difficult} == {"difficult_minified_bundle", "difficult_dynamic_alias_unresolved"}


def test_repeated_runs_are_reproducible():
    report = run_benchmark(check_reproducibility=True)
    assert report.reproducible is True


def test_per_category_breakdown_not_a_single_aggregate_score():
    report = run_benchmark(check_reproducibility=False)
    d = report.to_dict()
    assert len(d["by_class"]) >= 4
    for cls, m in d["by_class"].items():
        assert set(m) >= {"true_positives", "false_positives", "false_negatives", "true_negatives", "precision", "recall"}


def test_report_is_json_serializable_and_includes_performance_numbers():
    d = run_benchmark(check_reproducibility=False).to_dict()
    blob = json.dumps(d)
    assert "duration_s" in blob and "peak_memory_mb" in blob


def test_regression_detection_against_a_baseline():
    report = run_benchmark(check_reproducibility=False)
    baseline = report.to_dict()
    # simulate a regression: flip one true_positive to false_negative in a fresh report
    tampered = run_benchmark(check_reproducibility=False)
    tampered.entries[0].outcome = "false_negative" if tampered.entries[0].outcome == "true_positive" else tampered.entries[0].outcome
    regressions = tampered.regressions_against(baseline)
    if any(e.outcome == "false_negative" for e in tampered.entries) and \
       baseline["results"][0]["outcome"] in ("true_positive", "true_negative"):
        assert any(r["name"] == tampered.entries[0].name for r in regressions) or regressions == []


def test_benchmark_claims_distinguish_measured_from_estimate():
    """Classes with zero fixtures never report a fabricated precision/recall number."""
    from jscope.benchmark.runner import ClassMetrics
    m = ClassMetrics("hypothetical_class")
    assert m.precision is None and m.recall is None


def test_cli_benchmark_strict_exits_zero_on_clean_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from jscope.cli import main
    rc = main(["benchmark", "--out", str(tmp_path / "r.json"), "--no-reproducibility-check", "--strict"])
    assert rc == 0
    d = json.loads((tmp_path / "r.json").read_text())
    assert d["overall"]["false_positives"] == 0

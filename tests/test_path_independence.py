"""Findings must not depend on where the project happens to live on disk."""
import shutil
from pathlib import Path

from jscope.analyzers.common import is_test_path, set_analysis_roots
from jscope.config import Config
from jscope.pipeline import run_analysis

SAMPLE = Path(__file__).parent / "sample_react"


def _subjects(path):
    return sorted((f.category, f.subject) for f in run_analysis([str(path)], Config.load(None)).findings)


def test_parent_directory_named_tests_does_not_demote_findings(tmp_path):
    inside_tests = tmp_path / "tests" / "fixtures" / "proj"
    shutil.copytree(SAMPLE, inside_tests)
    plain = tmp_path / "plain_proj"
    shutil.copytree(SAMPLE, plain)
    assert _subjects(inside_tests) == _subjects(plain)


def test_test_dirs_inside_the_analysis_root_are_still_detected(tmp_path):
    set_analysis_roots([str(tmp_path / "proj")])
    assert is_test_path(str(tmp_path / "proj" / "tests" / "a.js"))
    assert is_test_path(str(tmp_path / "proj" / "src" / "__tests__" / "a.js"))
    assert not is_test_path(str(tmp_path / "proj" / "src" / "a.js"))
    set_analysis_roots([])

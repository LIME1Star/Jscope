"""Benchmark runner (FR-06): executes fixtures, scores against ground truth, measures reproducibility and performance.

`vuln_class -> sink_class` lets a single lookup table decide whether a fixture's expected vulnerability class was (or
was not) reported, from the dataflow payload already on AnalysisResult -- no string-matching on finding text.
"""

from __future__ import annotations

import statistics
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from jscope.benchmark.fixtures import ENTRIES, BenchmarkEntry
from jscope.config import Config
from jscope.pipeline import run_analysis

CLASS_TO_SINK = {"dom_xss": "html", "open_redirect": "navigation", "sql_injection": "sql", "command_injection": "command",
                 "code_injection": "code"}


@dataclass
class EntryResult:
    name: str
    vuln_class: str
    difficult: bool
    expected: bool
    actual: bool
    outcome: str                        # true_positive | true_negative | false_positive | false_negative
    duration_s: float
    findings: int
    note: str = ""


@dataclass
class ClassMetrics:
    vuln_class: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None

    def to_dict(self) -> dict[str, Any]:
        return {"vuln_class": self.vuln_class, "true_positives": self.tp, "false_positives": self.fp,
                "false_negatives": self.fn, "true_negatives": self.tn, "precision": self.precision, "recall": self.recall}


@dataclass
class BenchmarkReport:
    entries: list[EntryResult] = field(default_factory=list)
    by_class: dict[str, ClassMetrics] = field(default_factory=dict)
    difficult: list[EntryResult] = field(default_factory=list)
    duration_s: float = 0.0
    peak_memory_mb: float = 0.0
    reproducible: bool | None = None
    reproducibility_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        agg_tp = sum(m.tp for m in self.by_class.values())
        agg_fp = sum(m.fp for m in self.by_class.values())
        agg_fn = sum(m.fn for m in self.by_class.values())
        return {
            "schema": "jscope-benchmark/1", "entries": len(self.entries), "difficult_entries": len(self.difficult),
            "duration_s": round(self.duration_s, 3), "peak_memory_mb": round(self.peak_memory_mb, 1),
            "reproducible": self.reproducible, "reproducibility_detail": self.reproducibility_detail,
            "overall": {"true_positives": agg_tp, "false_positives": agg_fp, "false_negatives": agg_fn,
                        "precision": (agg_tp / (agg_tp + agg_fp)) if (agg_tp + agg_fp) else None,
                        "recall": (agg_tp / (agg_tp + agg_fn)) if (agg_tp + agg_fn) else None},
            "by_class": {k: v.to_dict() for k, v in sorted(self.by_class.items())},
            "results": [e.__dict__ for e in self.entries],
            "difficult_results": [e.__dict__ for e in self.difficult],
        }

    def regressions_against(self, baseline: dict) -> list[dict]:
        """Entries that passed in `baseline` but fail now, by name -- each a line item CI can block a release on."""
        base_by_name = {r["name"]: r["outcome"] for r in baseline.get("results", [])}
        out = []
        for e in self.entries:
            prev = base_by_name.get(e.name)
            if prev in ("true_positive", "true_negative") and e.outcome not in ("true_positive", "true_negative"):
                out.append({"name": e.name, "was": prev, "now": e.outcome})
        return out


def _run_one(entry: BenchmarkEntry) -> tuple[bool, int, float]:
    with TemporaryDirectory(prefix="jscope-bench-") as d:
        root = Path(d)
        for rel, src in entry.files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src)
        cfg = Config()
        cfg.data["analyzers"]["enabled"] = ["framework_detector", "dataflow_analyzer"]
        cfg.data["min_confidence"] = "LOW"
        t0 = time.monotonic()
        res = run_analysis([str(root)], cfg)
        dt = time.monotonic() - t0
    wanted_sink = CLASS_TO_SINK.get(entry.vuln_class)
    flagged = wanted_sink is not None and any(
        f.category == "dataflow" and f.metadata.get("sink_class") == wanted_sink for f in res.findings)
    return flagged, len(res.findings), dt


def run_benchmark(entries: list[BenchmarkEntry] | None = None, check_reproducibility: bool = True) -> BenchmarkReport:
    entries = entries if entries is not None else ENTRIES
    report = BenchmarkReport()
    tracemalloc.start()
    t0 = time.monotonic()
    for entry in entries:
        actual, n, dt = _run_one(entry)
        if entry.expect_flag and actual:
            outcome = "true_positive"
        elif entry.expect_flag and not actual:
            outcome = "false_negative"
        elif not entry.expect_flag and actual:
            outcome = "false_positive"
        else:
            outcome = "true_negative"
        er = EntryResult(entry.name, entry.vuln_class, entry.difficult, entry.expect_flag, actual, outcome, dt, n, entry.note)
        if entry.difficult:
            report.difficult.append(er)
            continue
        report.entries.append(er)
        m = report.by_class.setdefault(entry.vuln_class, ClassMetrics(entry.vuln_class))
        setattr(m, {"true_positive": "tp", "false_positive": "fp", "false_negative": "fn", "true_negative": "tn"}[outcome],
               getattr(m, {"true_positive": "tp", "false_positive": "fp", "false_negative": "fn", "true_negative": "tn"}[outcome]) + 1)
    report.duration_s = time.monotonic() - t0
    report.peak_memory_mb = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
    tracemalloc.stop()

    if check_reproducibility:
        sample = [e for e in entries if not e.difficult][:4] or entries[:4]
        runs = []
        for entry in sample:
            flagged, n, _ = _run_one(entry)
            runs.append((flagged, n))
        runs2 = []
        for entry in sample:
            flagged, n, _ = _run_one(entry)
            runs2.append((flagged, n))
        report.reproducible = runs == runs2
        report.reproducibility_detail = "repeated runs of the same fixtures produced identical flagged/finding-count results" \
            if report.reproducible else f"non-deterministic output detected: {runs} != {runs2}"
    return report

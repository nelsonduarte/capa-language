"""Smoke tests for evaluation/runtime/.

The harness itself spawns subprocesses against the downstream
demo repos, which are not present in CI. These tests therefore
cover the import / aggregation / plotting paths against mock
data, not the live subprocess timing.
"""

import unittest
from dataclasses import dataclass

from evaluation.runtime import harness, plot, workloads


class TestWorkloadRegistry(unittest.TestCase):
    def test_three_macros_registered(self):
        self.assertEqual(
            set(workloads.WORKLOADS),
            {"policy_eval", "sbom_watch", "audit_trail"},
        )

    def test_backend_names_stable(self):
        # The two backend identifiers are referenced by name in
        # the plot script + paper figure; tighten them with a
        # test so they cannot be renamed without flagging it.
        self.assertEqual(workloads.BACKEND_CAPA_PYTHON, "capa_python")
        self.assertEqual(workloads.BACKEND_CAPA_WASM, "capa_wasm")


class TestHarnessAggregation(unittest.TestCase):
    def test_aggregate_basic(self):
        trials = [
            harness.Trial(
                workload="w1", backend="capa_python", trial=0,
                seconds=0.30, peak_rss_mb=10.0, returncode=0,
                stdout_bytes=100, stderr_bytes=0,
            ),
            harness.Trial(
                workload="w1", backend="capa_python", trial=1,
                seconds=0.32, peak_rss_mb=11.0, returncode=0,
                stdout_bytes=100, stderr_bytes=0,
            ),
            harness.Trial(
                workload="w1", backend="capa_wasm", trial=0,
                seconds=0.45, peak_rss_mb=20.0, returncode=0,
                stdout_bytes=100, stderr_bytes=0,
            ),
        ]
        aggs = harness._aggregate(trials)
        by_b = {a.backend: a for a in aggs}
        self.assertAlmostEqual(by_b["capa_python"].seconds_mean, 0.31)
        self.assertEqual(by_b["capa_python"].n_ok, 2)
        self.assertEqual(by_b["capa_wasm"].n_ok, 1)
        self.assertEqual(by_b["capa_wasm"].rss_mb_max, 20.0)


class TestPlot(unittest.TestCase):
    def test_md_generation_does_not_crash(self):
        # Inline mock rows; we just want to know _write_md runs
        # cleanly and the headline ratio comes out of the math.
        rows = [
            plot.Row(
                workload="w1", backend="capa_python", n_ok=3, n_trials=3,
                seconds_mean=0.30, seconds_min=0.28, seconds_max=0.32,
                seconds_stdev=0.01, rss_mb_max=10.0,
            ),
            plot.Row(
                workload="w1", backend="capa_wasm", n_ok=3, n_trials=3,
                seconds_mean=0.60, seconds_min=0.55, seconds_max=0.65,
                seconds_stdev=0.04, rss_mb_max=20.0,
            ),
        ]
        # Redirect summary.md to a tempdir so we don't clobber
        # the real artefact.
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            saved = plot.SUMMARY_MD
            plot.SUMMARY_MD = Path(td) / "summary.md"
            try:
                plot._write_md(rows)
                body = plot.SUMMARY_MD.read_text(encoding="utf-8")
            finally:
                plot.SUMMARY_MD = saved
        self.assertIn("2.00x", body)
        self.assertIn("Headline", body)


if __name__ == "__main__":
    unittest.main()

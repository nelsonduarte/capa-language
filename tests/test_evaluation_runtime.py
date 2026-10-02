"""Smoke tests for evaluation/runtime/.

The harness itself spawns subprocesses against the downstream
demo repos, which are not present in CI. These tests therefore
cover the import / aggregation / plotting paths against mock
data, not the live subprocess timing.
"""

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from evaluation.runtime import harness, plot, workloads
from evaluation.shared.runner_utils import repo_root


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


class TestDemoDirectory(unittest.TestCase):
    """Where the downstream demos are is supplied, not assumed.

    The registry used to place them under one machine's home layout.
    The location now comes from ``CAPA_DEMO_REPOS``, and defaults to a
    ``repos`` directory next to the compiler checkout.
    """

    def test_the_environment_names_the_directory(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                workloads.repos_dir({workloads.REPOS_ENV: td}), Path(td)
            )

    def test_the_default_is_next_to_the_checkout(self):
        expected = repo_root().parent / "repos"
        self.assertEqual(workloads.repos_dir({}), expected)
        # An empty value is "not set", not "the current directory".
        self.assertEqual(workloads.repos_dir({workloads.REPOS_ENV: ""}), expected)

    def test_the_default_does_not_consult_the_home_directory(self):
        with mock.patch.object(
            Path, "home", side_effect=AssertionError("home layout consulted")
        ):
            workloads.repos_dir({})

    def test_every_workload_runs_under_that_directory(self):
        for w in workloads.WORKLOADS.values():
            with self.subTest(w.name):
                self.assertEqual(w.cwd.parent, workloads.REPOS)


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

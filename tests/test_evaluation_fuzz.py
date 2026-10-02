"""Smoke tests for the evaluation/fuzz/ harness.

These guard against three regressions:

- The harness module imports cleanly (so a typo in an attack
  category cannot lurk uncaught).
- Each attack-category module yields at least one Attack record,
  and every record has a non-empty source.
- Running the slice-1 category (``cat_fs_traversal``) against
  ``capa --check`` rejects every attack. If this ever fails, a
  static-soundness escape has been introduced and the fuzz panel
  found it.

Slice 6 will add the full panel; this file grows by one parametrised
test per new category at that point.
"""

import csv
import re
import tempfile
import unittest
from pathlib import Path

from evaluation.fuzz import harness
from evaluation.fuzz.attacks import cat_fs_traversal


class TestFuzzHarnessSmoke(unittest.TestCase):
    def test_categories_registered(self):
        # All 9 categories from slices 1 + 6 must be registered.
        for cat in (
            "cat_fs_traversal", "cat_env_leak", "cat_net_punch",
            "cat_time_channel", "cat_subprocess",
            "cat_unsafe_smuggle", "cat_capability_in_data",
            "cat_capability_aliasing", "cat_llm_dispatch_escape",
        ):
            self.assertIn(cat, harness.ALL_CATEGORIES)

    def test_fs_traversal_generates_attacks(self):
        attacks = cat_fs_traversal.generate()
        self.assertGreaterEqual(len(attacks), 3)
        for a in attacks:
            self.assertTrue(a.attack_id)
            self.assertTrue(a.source.strip())
            self.assertTrue(a.description.strip())

    def test_fs_traversal_all_rejected(self):
        # Running the full category should reject every attack.
        # An escape here is a paper-relevant soundness regression.
        results = harness.run_category("cat_fs_traversal")
        escaped = [r for r in results if not r.rejected]
        self.assertEqual(
            escaped, [],
            f"static-soundness escape: {escaped}",
        )

    def test_llm_dispatch_panel_all_rejected(self):
        # The LLM-agent-escape category includes the user-cap
        # aliasing attack that slipped through pre-2026-05-24.
        # Verifying every attempt is rejected here keeps that
        # regression from coming back.
        results = harness.run_category("cat_llm_dispatch_escape")
        escaped = [r for r in results if not r.rejected]
        self.assertEqual(
            escaped, [],
            f"LLM-dispatch escape: {[(r.attack_id, r.rejection_reason) for r in escaped]}",
        )


class TestRejectionReasonIsPortable(unittest.TestCase):
    """The recorded reason must not depend on the machine that ran it.

    The compiler's diagnostic begins with the path it was given, and
    the harness gives it a temporary file, so the raw first error line
    carries the builder's temporary directory. ``results.csv`` is
    committed, which is how 138 rows of one machine's path were
    published. The harness names the attack instead.
    """

    def test_a_live_reason_names_the_attack_not_the_temp_file(self):
        temp_dir = str(Path(tempfile.gettempdir()))
        results = harness.run_category("cat_fs_traversal")
        self.assertGreaterEqual(len(results), 3)
        for r in results:
            with self.subTest(r.attack_id):
                self.assertRegex(
                    r.rejection_reason,
                    rf"^{re.escape(r.attack_id)}\.capa:\d+:\d+: error: ",
                )
                self.assertNotIn(temp_dir, r.rejection_reason)
                self.assertNotIn(
                    str(Path(temp_dir).resolve()), r.rejection_reason
                )

    def test_every_spelling_of_the_path_is_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "tmpabc123.capa"
            path.write_text("", encoding="utf-8")
            for spelling in (str(path), str(path.resolve())):
                with self.subTest(spelling=spelling == str(path)):
                    line = f"{spelling}:2:14: error: no ({spelling})"
                    self.assertEqual(
                        harness._without_builder_path(line, path, "a.capa"),
                        "a.capa:2:14: error: no (a.capa)",
                    )

    def test_a_line_with_no_path_is_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "tmpabc123.capa"
            self.assertEqual(
                harness._without_builder_path(
                    "capa: internal error", path, "a.capa"
                ),
                "capa: internal error",
            )

    def test_an_unrecognised_spelling_is_refused_not_recorded(self):
        # Fail closed: if the compiler ever prints the temporary file
        # in a form the harness does not know, the row must not be
        # written with a machine path in it.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "tmpabc123.capa"
            other = f"//?/elsewhere/{path.name}:1:1: error: no"
            with self.assertRaises(RuntimeError):
                harness._without_builder_path(other, path, "a.capa")

    def test_the_committed_results_are_in_the_portable_form(self):
        csv_path = Path(harness.__file__).parent / "results.csv"
        with csv_path.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertGreaterEqual(len(rows), 138)
        for row in rows:
            with self.subTest(row["attack_id"]):
                self.assertRegex(
                    row["rejection_reason"],
                    rf"^{re.escape(row['attack_id'])}\.capa:\d+:\d+: error: ",
                )


if __name__ == "__main__":
    unittest.main()

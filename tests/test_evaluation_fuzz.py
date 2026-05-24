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

import unittest

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


if __name__ == "__main__":
    unittest.main()

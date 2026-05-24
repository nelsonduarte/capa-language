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
        self.assertIn("cat_fs_traversal", harness.ALL_CATEGORIES)

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


if __name__ == "__main__":
    unittest.main()

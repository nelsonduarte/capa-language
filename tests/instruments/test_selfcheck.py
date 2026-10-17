"""The evaluator self-test: every planted one-clause error in the evaluator
is caught by the hand-written anchors, with no compiler involved.

This is the check of the rule that survives the removal of any executor:
the anchor table is a second statement of the rule, written by hand.
"""

import random
import unittest

from tests.instruments.absolute import _anchors as AN, _rule as R
from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._evaluator_mutants import MUTANTS
from tests.instruments.absolute._run import anchors_for, configuration


class EvaluatorSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = configuration()

    def generator(self) -> Gen:
        return Gen(random.Random(0), self.cfg.kinds)

    def test_the_generator_names_its_kinds(self):
        # No default registry: a caller that forgot the configuration's kinds
        # would draw over the public kinds alone, silently, in the private
        # configuration too.
        with self.assertRaises(TypeError):
            Gen(random.Random(0))

    def test_true_evaluator_reproduces_every_anchor(self):
        fails = AN.check_anchors(self.generator(), self.cfg.anchors)
        self.assertEqual(fails, [], [(a.title, want, got) for a, want, got in fails])

    def test_every_clause_has_an_anchor_or_is_a_gap_of_the_loaded_grammar(self):
        gaps = AN.clauses_without_anchor(self.cfg.anchors, self.cfg.kinds)
        holes = {c: kinds for c, kinds in gaps.items() if kinds}
        self.assertEqual(holes, {}, "clauses exercised by a loaded kind but pinned by no anchor: %s" % holes)
        if self.cfg.private:
            self.assertEqual(gaps, {}, "every clause must have an anchor in the full configuration")

    def test_every_evaluator_mutant_fails_at_least_one_anchor(self):
        mutants = dict(MUTANTS)
        mutants.update(self.cfg.mutants)
        holes = []
        for name, apply in mutants.items():
            g = self.generator()
            apply(g)
            # The anchors are rebuilt from the MUTATED generator: the anchor's
            # expectation is hand-written text, its evaluator is the mutant's.
            fails = AN.check_anchors(g, anchors_for(g))
            with self.subTest(mutant=name):
                self.assertTrue(fails, "evaluator mutant %s fails no anchor: a hole in the anchor table" % name)
            if not fails:
                holes.append(name)
        self.assertEqual(holes, [])

    def test_anchors_are_hand_written_not_computed(self):
        # Every anchor states its expectation as literal text; the slug and
        # the clause id are part of its identity.
        for a in self.cfg.anchors:
            self.assertIn(a.clause, R.CLAUSE_IDS)
            self.assertIsInstance(a.expected_stdout, str)
            self.assertIn(a.expected_exit, ("OK", "ABORT"))
        self.assertEqual(len({a.slug for a in self.cfg.anchors}), len(self.cfg.anchors), "anchor titles must be distinct")


if __name__ == "__main__":
    unittest.main()

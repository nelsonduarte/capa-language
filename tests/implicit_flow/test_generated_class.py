"""The secret-conditioned early-exit class, scored over its full enumeration.

``_generated`` states the rule once and emits the cross product of exit
kind, enclosing-construct chain, sink position and branching arm with the
verdict the rule predicts. The sink position has three values, because a
sink placed BEFORE the exit leaks or not according to whether it sits
inside the loop the exit ENDS. Four corpora are scored here, in BOTH
directions (a member accepted is a leak, a negative refused is a false
alarm):

- depth 2, one arm per level:              219 programs
- depth 3, one arm per level:              978 programs
- depth 2, every arm per level (uniform):  513 programs
- depth 2, two branching levels, mixed:    234 programs

The verdict is the ONLY thing scored, and only under the harness's
preconditions: an empty corpus, a wrong compiler, or a refusal that carries
a non-IFC error fails the test rather than counting as a pass.
"""

import unittest

from tests.implicit_flow import _generated as G
from tests.implicit_flow._harness import (
    ACCEPT, REFUSE, assert_verdict, check_source, provenance_ok,
)


def _score(tc, corpus, expected_size):
    programs = list(corpus)
    tc.assertTrue(provenance_ok())
    tc.assertEqual(len(programs), expected_size, "the enumeration changed size")
    tc.assertTrue(programs, "empty corpus")
    verdicts = {v for _, _, v in programs}
    tc.assertEqual(verdicts, {ACCEPT, REFUSE}, "a corpus must carry both verdicts")
    for name, src, want in programs:
        with tc.subTest(program=name):
            assert_verdict(tc, name, check_source(src), want)


class GeneratedDepth2(unittest.TestCase):
    def test_219(self):
        _score(self, G.generate(2, arm_axis=False), 219)


class GeneratedDepth3(unittest.TestCase):
    def test_978(self):
        _score(self, G.generate(3, arm_axis=False), 978)


class GeneratedArmAxis(unittest.TestCase):
    def test_513(self):
        _score(self, G.generate(2, arm_axis=True), 513)


class GeneratedMixedArms(unittest.TestCase):
    def test_234(self):
        _score(self, G.generate_mixed(), 234)


class ScorerPreconditions(unittest.TestCase):
    """The scorer refuses to score nothing and refuses a non-IFC refusal."""

    def test_empty_corpus_is_a_failure(self):
        with self.assertRaises(AssertionError):
            _score(self, iter(()), 0)

    def test_non_ifc_refusal_is_a_failure(self):
        # A type error is a refusal, but not one the class predicts.
        src = "fun main(stdio: Stdio)\n    let x: Int = \"no\"\n"
        with self.assertRaises(AssertionError):
            assert_verdict(self, "type_error", check_source(src), REFUSE)

    def test_the_rule_has_both_verdicts_at_every_depth(self):
        for corpus in (G.generate(2, False), G.generate(2, True), G.generate_mixed()):
            self.assertEqual({v for _, _, v in corpus}, {ACCEPT, REFUSE})

    def test_every_sink_position_carries_both_verdicts(self):
        # A position whose predicate collapsed to one verdict would score
        # a full mark while testing nothing, so each of the three has to
        # produce members AND negatives.
        seen = {}
        for name, _, want in G.generate(2, arm_axis=True):
            seen.setdefault(G.position_of(name), set()).add(want)
        self.assertEqual(set(seen), set(G.SINKS), seen)
        for position, verdicts in seen.items():
            with self.subTest(position=position):
                self.assertEqual(verdicts, {ACCEPT, REFUSE})


if __name__ == "__main__":
    unittest.main()

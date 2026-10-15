"""Instrument (a), the absolute rule oracle, as the gate runs it.

Order: the evaluator must reproduce every anchor (or no corpus is written);
the grammar completeness pin; the legs over the corpora, the anchor
programs and the controls; the route-agreement sample; then the register
diff, which must be GREEN: every non-CORRECT (member, leg) is a registered
entry and every registered entry holds.

The Python legs run in the main matrix; the Wasm leg runs where the
toolchain is present and is named in ``tests/test_wasm_harness_present``
so it cannot skip silently in the one job that must run it.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from tests.instruments._outcome import CORRECT, outcome_type
from tests.instruments._provenance import REPO_ROOT, provenance_ok
from tests.instruments._register import diff, load_merged
from tests.instruments._runner import route_divergences
from tests.instruments.absolute import _run as A
from tests.instruments.absolute._corpus import source_text
from tests.instruments.absolute._pin import pin


class _Oracle:
    """Mixin: the concrete classes below add TestCase, so this is not collected."""
    LEGS: tuple = ()
    CLI_LEGS: tuple = ()
    #: Whether a loaded extension may add its legs to this class.
    EXTENSIBLE = False

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="capa_absolute_"))
        cls.cfg = A.configuration()
        cls.programs = A.generate(cls.cfg, cls.work)
        cls.LEGS = cls.LEGS + tuple(l for l in cls.cfg.legs if l not in cls.LEGS and cls.EXTENSIBLE)
        cls.CLI_LEGS = cls.CLI_LEGS + tuple(l for l in cls.cfg.cli_legs if l not in cls.CLI_LEGS and cls.EXTENSIBLE)
        cls.oracle = A.run(REPO_ROOT, cls.programs, cls.LEGS + cls.CLI_LEGS, cls.work)
        cls.register = load_merged()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_compiler_under_test_is_this_repository(self):
        self.assertTrue(provenance_ok())

    def test_register_holds(self):
        d = diff(self.register, A.INSTRUMENT, self.oracle.outcomes, self.LEGS)
        self.assertTrue(d.green, d.report())

    def test_every_anchor_program_is_correct_or_registered(self):
        # The anchors run against their HAND-WRITTEN expectation on every leg.
        registered = {k for k in self.register if k.startswith(A.INSTRUMENT + "|anchor_")}
        for (mid, leg), o in self.oracle.outcomes.items():
            if not mid.startswith("anchor_") or leg not in self.LEGS or o == CORRECT:
                continue
            key = "%s|%s|%s" % (A.INSTRUMENT, mid, leg)
            with self.subTest(anchor=mid, leg=leg):
                self.assertIn(key, registered, "anchor %s on %s read %s" % (mid, leg, o))

    def test_route_agreement(self):
        for cli in self.CLI_LEGS:
            with self.subTest(route=cli):
                div, _nc = route_divergences(self.oracle.rows, A.route_sample(self.programs), cli)
                self.assertEqual(div, [], "the command-line route disagrees with the in-process leg: %s" % div)


class AbsoluteOraclePythonLegs(_Oracle, unittest.TestCase):
    LEGS = A.PUBLIC_LEGS
    CLI_LEGS = A.PUBLIC_CLI_LEGS
    EXTENSIBLE = True

    def test_grammar_completeness_pin(self):
        result = pin(source_text(p) for p in self.programs if not p.name.startswith("ctl_"))
        self.assertTrue(result.green, result.report())

    def test_outcome_summary_is_the_registered_shape(self):
        # Every non-CORRECT outcome on the public legs is one of the
        # registered classes; nothing is dropped and nothing is VOID.
        kinds = {outcome_type(o) for o in self.oracle.outcomes.values()}
        self.assertNotIn("VOID", kinds)
        self.assertEqual(len(self.oracle.outcomes), len(self.programs) * len(self.LEGS))


class GrammarPinNegatives(unittest.TestCase):
    """The pin must be able to say RED: a corpus that produces almost
    nothing lists what it lacks, and an exclusion the corpus contradicts is
    named as stale."""

    def test_a_trivial_corpus_is_uncovered(self):
        from tests.instruments.absolute._rule import HEADER, MAIN
        result = pin([HEADER + MAIN + '    stdio.println("x")\n'])
        self.assertFalse(result.green)
        self.assertIn("IfExpr", result.uncovered)
        self.assertIn("WhileStmt", result.uncovered)
        self.assertEqual(result.stale, [])

    def test_a_produced_class_listed_as_excluded_is_stale(self):
        from tests.instruments.absolute._rule import EXCLUDED, HEADER, MAIN
        src = HEADER + MAIN + "    let v = (if true then 1 else 2)\n" + '    stdio.println("${v}")\n'
        planted = dict(EXCLUDED)
        planted["IfExpr"] = "planted: the corpus contradicts this"
        result = pin([src], excluded=planted)
        self.assertFalse(result.green)
        self.assertEqual(result.stale, ["IfExpr"])


def _have_wasm_toolchain() -> bool:
    from tests.test_properties import _HAVE_WASM_TOOLCHAIN
    return _HAVE_WASM_TOOLCHAIN


@unittest.skipUnless(_have_wasm_toolchain(), "wasm-tools and/or wasmtime-py not installed")
class AbsoluteOracleWasmLeg(_Oracle, unittest.TestCase):
    LEGS = A.PUBLIC_WASM_LEGS
    CLI_LEGS = ("cli_wasm",)


if __name__ == "__main__":
    unittest.main()

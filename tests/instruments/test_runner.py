"""The bounded runner: the positive controls per outcome class, the
provenance controls, and the route-agreement check.

Each control asserts its outcome class DIRECTLY, never through the
register: a harness whose bound, comparison, refusal or provenance path
went blind fails one of these before any register is consulted.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from tests.instruments import _runner as RU
from tests.instruments._outcome import ACCEPT, check_outcome, outcome_type, run_outcome
from tests.instruments._provenance import REPO_ROOT, package_hash, provenance_ok
from tests.instruments.absolute._corpus import CONTROLS, expectation, write_controls

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _outcomes(programs, rows, legs):
    out = {}
    for p in programs:
        exp = expectation(p)
        for leg in legs:
            row = rows[(p.name, leg)]
            out[(p.name, leg)] = check_outcome(ACCEPT, row) if leg == "check" else run_outcome(exp, row)
    return out


class ControlsOnPythonLegs(unittest.TestCase):
    LEGS = ("check", "run", "ir")

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="capa_ctl_"))
        cls.programs = write_controls(cls.work)
        cls.rows = RU.run_legs(REPO_ROOT, cls.LEGS, cls.programs, workdir=cls.work)
        cls.outcomes = _outcomes(cls.programs, cls.rows, cls.LEGS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_compiler_under_test_is_this_repository(self):
        self.assertTrue(provenance_ok())

    def test_every_control_reads_exactly_its_outcome_class(self):
        for name, (_src, _exit, _out, asserted) in CONTROLS.items():
            for leg in self.LEGS:
                with self.subTest(control=name, leg=leg):
                    got = self.outcomes[(name + ".capa", leg)]
                    self.assertEqual(outcome_type(got), asserted[leg],
                                     "%s on %s read %s: %r" % (name, leg, got, self.rows[(name + ".capa", leg)]))

    def test_a_hang_costs_about_the_bound(self):
        for leg in ("run", "ir"):
            wall = self.rows[("ctl_timeout.capa", leg)]["wall"]
            self.assertGreaterEqual(wall, RU.PROGRAM_BOUND_S * 0.9)
            self.assertLess(wall, RU.PROGRAM_BOUND_S + 10)

    def test_a_hang_on_one_leg_does_not_void_the_others(self):
        # The timeout control hangs the run and ir legs; the check leg and
        # every other program keep their rows.
        for name in CONTROLS:
            if name == "ctl_timeout":
                continue
            for leg in self.LEGS:
                self.assertNotEqual(self.outcomes[(name + ".capa", leg)], "VOID")

    def test_the_rows_after_a_hang_continue_from_the_next_program(self):
        names = [p.name for p in self.programs]
        after = names[names.index("ctl_timeout.capa") + 1:]
        self.assertTrue(after, "the timeout control must not be the last program")
        for name in after:
            self.assertIn(outcome_type(self.outcomes[(name, "ir")]), ("CORRECT", "WRONG", "REFUSED", "BROKEN"))


class ProvenanceControls(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="capa_prov_"))
        self.programs = write_controls(self.work)[:2]

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_a_child_that_lies_about_its_hash_voids_every_row(self):
        rows = RU.run_leg(REPO_ROOT, "ir", self.programs, workdir=self.work, child=FIXTURES / "lying_child.py")
        self.assertEqual({r["outcome"] for r in rows.values()}, {"VOID"})
        self.assertEqual(len(rows), len(self.programs))

    def test_a_child_from_another_tree_voids_every_row(self):
        rows = RU.run_leg(REPO_ROOT, "ir", self.programs, workdir=self.work, child=FIXTURES / "wrong_tree_child.py")
        self.assertEqual({r["outcome"] for r in rows.values()}, {"VOID"})

    def test_the_parent_hash_is_the_whole_package(self):
        h, n = package_hash(REPO_ROOT)
        self.assertEqual(len(h), 16)
        self.assertGreater(n, 100)

    def test_a_command_line_child_computes_its_own_hash(self):
        rows = RU.run_cli_leg(REPO_ROOT, "cli_check", self.programs)
        for row in rows.values():
            self.assertNotEqual(row["outcome"], "VOID", row)


class RouteAgreementTests(unittest.TestCase):
    def test_divergence_and_not_comparable(self):
        progs = [RU.Program("a.capa", Path("a.capa")), RU.Program("b.capa", Path("b.capa")),
                 RU.Program("c.capa", Path("c.capa"))]
        rows = {
            ("a.capa", "ir"): {"outcome": "OK", "stdout": "1\n"}, ("a.capa", "cli_ir"): {"outcome": "OK", "stdout": "1\r\n"},
            ("b.capa", "ir"): {"outcome": "OK", "stdout": "1\n"}, ("b.capa", "cli_ir"): {"outcome": "OK", "stdout": "2\n"},
            ("c.capa", "ir"): {"outcome": "BROKEN", "stdout": ""}, ("c.capa", "cli_ir"): {"outcome": "OK", "stdout": "x"},
        }
        div, nc = RU.route_divergences(rows, progs, "cli_ir")
        self.assertEqual([d[0] for d in div], ["b.capa"])
        self.assertEqual([n[0] for n in nc], ["c.capa"])

    def test_an_abort_of_any_kind_agrees_with_an_abort(self):
        progs = [RU.Program("a.capa", Path("a.capa"))]
        rows = {("a.capa", "ir"): {"outcome": "ABORT:OverflowError", "stdout": "x"},
                ("a.capa", "cli_ir"): {"outcome": "ABORT:rc1", "stdout": "x"}}
        div, _nc = RU.route_divergences(rows, progs, "cli_ir")
        self.assertEqual(div, [])

    def test_a_timeout_on_the_route_diverges(self):
        progs = [RU.Program("a.capa", Path("a.capa"))]
        rows = {("a.capa", "ir"): {"outcome": "OK", "stdout": "x"},
                ("a.capa", "cli_ir"): {"outcome": "TIMEOUT", "stdout": ""}}
        div, _nc = RU.route_divergences(rows, progs, "cli_ir")
        self.assertEqual(len(div), 1)


if __name__ == "__main__":
    unittest.main()

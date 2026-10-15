"""Instrument (b), analysis versus execution, as the gate runs it.

Every case declares the verdict it expects. The public set is the cases
whose flow the analysis flags today plus a CLEAN-expected control; the
twin of every case runs through the bounded runner; the register diff
must be GREEN. The twin-builder faults are planted here on the public set
and must be caught WITHOUT executing a single twin.
"""

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.instruments._outcome import CORRECT
from tests.instruments._private import private_path
from tests.instruments._provenance import REPO_ROOT, provenance_ok
from tests.instruments._register import diff, load_merged, member_id
from tests.instruments.analysis_execution import _twin as T

INSTRUMENT = "analysis_execution"
PUBLIC_CASES = Path(__file__).resolve().parent / "analysis_execution" / "cases"
PYTHON_LEGS = ("run", "ir")
WASM_LEGS = ("run", "ir", "wasm")


def _cases():
    cases = T.load_cases(PUBLIC_CASES)
    priv = private_path("analysis_execution", "cases")
    if priv is not None:
        cases += T.load_cases(priv)
    return cases


def _outcomes(cases, verdicts):
    return {(member_id(c.name, c.source), T.LEG): verdicts[c.name].outcome(c.expected) for c in cases}


class _Gate:
    """Mixin: the concrete classes below add TestCase, so this is not collected."""
    LEGS: tuple = ()

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="capa_ae_"))
        cls.cases = _cases()
        cls.verdicts = T.run_cases(REPO_ROOT, cls.cases, cls.work, cls.LEGS)
        cls.register = load_merged()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_compiler_under_test_is_this_repository(self):
        self.assertTrue(provenance_ok())

    def test_register_holds(self):
        d = diff(self.register, INSTRUMENT, _outcomes(self.cases, self.verdicts), (T.LEG,))
        self.assertTrue(d.green, d.report() + "\n" + "\n".join(
            "  %s %s %s" % (v.case, v.verdict, v.detail) for v in self.verdicts.values()))

    def test_the_clean_control_is_clean_and_silent(self):
        # Asserted directly, never through the register: an analysis that
        # flags everything turns this RED instead of reading other cases as fixed.
        v = self.verdicts["ctl_clean_no_flow.capa"]
        self.assertEqual(v.verdict, T.CLEAN, v)
        self.assertEqual(v.tier, "SILENT")

    def test_every_flagged_case_delivered_its_marker(self):
        for c in self.cases:
            v = self.verdicts[c.name]
            if v.verdict.startswith("FLAGGED"):
                with self.subTest(case=c.name):
                    self.assertEqual(v.verdict, T.FLAGGED_CONFIRMED, v)


class AnalysisExecutionPythonLegs(_Gate, unittest.TestCase):
    LEGS = PYTHON_LEGS

    def test_twin_faults_are_caught_without_executing_a_twin(self):
        # Under a builder fault that leaves the secret read in the twin, every
        # case reads SECRET-IN-TWIN and no twin reaches the execution path:
        # the per-leg working directories (created only when a twin is about
        # to run) must not exist under the fault's work directory.
        public = T.load_cases(PUBLIC_CASES)
        for fault in ("swaporder", "nosubst"):
            with self.subTest(fault=fault):
                work = self.work / ("fault_" + fault)
                verdicts = T.run_cases(REPO_ROOT, public, work, self.LEGS, fault=fault)
                self.assertEqual({v.verdict for v in verdicts.values()}, {T.SECRET_IN_TWIN})
                executed = sorted(str(p.relative_to(work)) for leg in self.LEGS for p in work.glob("*/" + leg))
                self.assertEqual(executed, [], "a twin was executed under the fault")

    def test_the_execution_path_leaves_its_working_directories(self):
        # The negative above is meaningful only if execution DOES create
        # those directories: the control run on one case must leave one per leg.
        case = [c for c in T.load_cases(PUBLIC_CASES) if c.expected == T.CLEAN][0]
        work = self.work / "exec_marker"
        T.run_cases(REPO_ROOT, [case], work, self.LEGS)
        for leg in self.LEGS:
            self.assertTrue((work / case.name[:-5] / leg).is_dir())

    def test_an_empty_marker_is_unconfirmed_on_every_flagged_case(self):
        public = [c for c in T.load_cases(PUBLIC_CASES) if c.expected == T.FLAGGED_CONFIRMED]
        verdicts = T.run_cases(REPO_ROOT, public, self.work / "fault_emptymarker", self.LEGS, fault="emptymarker")
        self.assertEqual({v.verdict for v in verdicts.values()}, {T.FLAGGED_UNCONFIRMED})

    def test_an_aliased_capability_read_is_never_run(self):
        # A twin that still reads a secret through an alias of the capability
        # is never run: the guard resolves receivers through the analyzer's
        # own types. Measured on this tree, the analyzer REFUSES a `let`
        # rebinding of a capability outright, which is the other fail-closed
        # exit; should rebinding ever be accepted, the guard is what stands.
        src = ('// expect: FLAGGED-CONFIRMED\n'
               'fun main(stdio: Stdio, env: Env)\n'
               '    let a = env.get("A").unwrap_or("none")\n'
               '    let e2 = env\n'
               '    let k = e2.get("K").unwrap_or("none")\n'
               '    stdio.println("${a}${k}")\n')
        case = T.Case("alias.capa", self.work / "alias.capa", src, T.FLAGGED_CONFIRMED)
        v, _tp, _an, _n = T.prepare(case, self.work / "alias")
        self.assertIsNotNone(v)
        self.assertIn(v.verdict, (T.REFUSED, T.SECRET_IN_TWIN), v)
        hits, _res = T.secret_sources_in(T.build_twin(src)[0])
        self.assertTrue(hits, "the guard must see the aliased read whatever the analyzer decides")

    def test_a_non_literal_key_is_a_secret_in_the_twin(self):
        src = ('// expect: FLAGGED-CONFIRMED\n'
               'fun main(stdio: Stdio, env: Env)\n'
               '    let nm = "K"\n'
               '    let k = env.get(nm).unwrap_or("none")\n'
               '    stdio.println(k)\n')
        case = T.Case("nonliteral.capa", self.work / "nonliteral.capa", src, T.FLAGGED_CONFIRMED)
        v, _tp, _an, _n = T.prepare(case, self.work / "nonliteral")
        self.assertEqual(v.verdict, T.SECRET_IN_TWIN, v)

    def test_a_file_written_under_any_name_is_an_observable(self):
        src = ('// expect: FLAGGED-CONFIRMED\n'
               'fun main(stdio: Stdio, fs: Fs, env: Env)\n'
               '    let k = env.get("K").unwrap_or("none")\n'
               '    let r = fs.write("some_other_name.txt", k)\n'
               '    stdio.println("written")\n')
        case = T.Case("other_name.capa", self.work / "other_name.capa", src, T.FLAGGED_CONFIRMED)
        v = T.run_cases(REPO_ROOT, [case], self.work / "other_name", self.LEGS)["other_name.capa"]
        self.assertEqual(v.verdict, T.FLAGGED_CONFIRMED, v)

    def test_public_cases_define_no_unused_function(self):
        for c in T.load_cases(PUBLIC_CASES):
            declared = set(re.findall(r"^fun (\w+)", c.source, re.M)) - {"main"}
            unused = sorted(n for n in declared if len(re.findall(r"\b%s\b" % n, c.source)) < 2)
            with self.subTest(case=c.name):
                self.assertEqual(unused, [], "a public case must not carry a dead helper")

    def test_case_loader_requires_a_declared_expectation(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x.capa").write_text("fun main(stdio: Stdio)\n    stdio.println(\"x\")\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                T.load_cases(d)


class DecideTable(unittest.TestCase):
    """The verdict function over synthetic rows: no compiler, no case shape.
    Each row of the table is one branch of ``decide``."""

    LEGS = ("run", "ir")

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="capa_decide_"))
        self.cwds = {}
        for leg in self.LEGS:
            d = self.work / leg
            d.mkdir()
            self.cwds[leg] = d

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _row(self, outcome="OK", stdout="", stderr="", exc=""):
        return {"outcome": outcome, "stdout": stdout, "stderr": stderr, "exc": exc}

    def _decide(self, tier, strict, rows):
        an = T.Analysis(True, tier, strict, ())
        case = T.Case("x.capa", self.work / "x.capa", "", T.FLAGGED_CONFIRMED)
        return T.decide(case, an, 1, rows, self.cwds, self.LEGS).verdict

    def test_table(self):
        seen = self._row(stdout=T.MARKER + "\n")
        unseen = self._row(stdout="public\n")
        broken = self._row(outcome="BROKEN")
        table = [
            ("silent, marker seen on a leg", "SILENT", False, {"run": seen, "ir": unseen}, T.MISMATCH),
            ("silent, every leg ran, marker unseen", "SILENT", False, {"run": unseen, "ir": unseen}, T.CLEAN),
            ("silent, some legs ran", "SILENT", False, {"run": unseen, "ir": broken}, T.TWIN_PARTIAL),
            ("silent, no leg ran", "SILENT", False, {"run": broken, "ir": broken}, T.TWIN_BROKEN),
            ("flagged, marker on every leg", "WARN", False, {"run": seen, "ir": seen}, T.FLAGGED_CONFIRMED),
            ("flagged, marker missing on a leg", "WARN", False, {"run": seen, "ir": unseen}, T.FLAGGED_UNCONFIRMED),
            ("strict program flagged only at WARN", "WARN", True, {"run": seen, "ir": seen}, T.TIER_DOWNGRADE),
            ("strict program flagged at ERROR", "ERROR", True, {"run": seen, "ir": seen}, T.FLAGGED_CONFIRMED),
            ("marker in stderr counts", "WARN", False, {"run": self._row(stderr=T.MARKER), "ir": seen}, T.FLAGGED_CONFIRMED),
            ("marker in the abort message counts", "WARN", False,
             {"run": self._row(outcome="ABORT:RuntimeError", exc=T.MARKER), "ir": seen}, T.FLAGGED_CONFIRMED),
            ("a timeout passes through", "SILENT", False, {"run": self._row(outcome="TIMEOUT"), "ir": unseen}, "TIMEOUT"),
            ("a void passes through", "WARN", False, {"run": self._row(outcome="VOID"), "ir": seen}, "VOID"),
        ]
        for title, tier, strict, rows, want in table:
            with self.subTest(case=title):
                self.assertEqual(self._decide(tier, strict, rows), want)

    def test_a_file_written_under_the_leg_directory_is_an_observable(self):
        (self.cwds["run"] / "anything.txt").write_text(T.MARKER, encoding="utf-8")
        rows = {"run": self._row(stdout="x"), "ir": self._row(stdout=T.MARKER)}
        self.assertEqual(self._decide("WARN", False, rows), T.FLAGGED_CONFIRMED)


def _have_wasm_toolchain() -> bool:
    from tests.test_properties import _HAVE_WASM_TOOLCHAIN
    return _HAVE_WASM_TOOLCHAIN


@unittest.skipUnless(_have_wasm_toolchain(), "wasm-tools and/or wasmtime-py not installed")
class AnalysisExecutionWasmLeg(_Gate, unittest.TestCase):
    LEGS = WASM_LEGS


if __name__ == "__main__":
    unittest.main()

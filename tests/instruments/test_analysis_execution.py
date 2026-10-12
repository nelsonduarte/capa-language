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
        public = T.load_cases(PUBLIC_CASES)
        for fault in ("swaporder", "nosubst"):
            with self.subTest(fault=fault):
                work = self.work / ("fault_" + fault)
                verdicts = T.run_cases(REPO_ROOT, public, work, self.LEGS, fault=fault)
                self.assertEqual({v.verdict for v in verdicts.values()}, {T.SECRET_IN_TWIN})
                self.assertEqual(sorted(work.rglob("list_*.txt")), [], "a twin was executed under the fault")

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


def _have_wasm_toolchain() -> bool:
    from tests.test_properties import _HAVE_WASM_TOOLCHAIN
    return _HAVE_WASM_TOOLCHAIN


@unittest.skipUnless(_have_wasm_toolchain(), "wasm-tools and/or wasmtime-py not installed")
class AnalysisExecutionWasmLeg(_Gate, unittest.TestCase):
    LEGS = WASM_LEGS


if __name__ == "__main__":
    unittest.main()

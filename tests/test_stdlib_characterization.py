"""Three-backend characterization of the built-in method surface.

Step 0 of the standard-library design (.claude/STDLIB_DESIGN.md, section
10): land BEFORE any change to the surface, because the behaviour it pins
was previously unguarded. The parity harness in tests/test_ir_wasm_parity.py
runs examples/wasm/; a census of every method call in its programs, with
the receiver type taken from the analyzer (139 programs when this corpus
landed), found 14 of the 92 declared non-capability methods it never
calls: JsonValue as_bool / as_int / as_number / is_null, List is_empty,
Map is_empty, Option is_none / or_else, Result is_err, String ends_with /
is_empty / split / trim_end / trim_start. A Python-runtime semantic change
to any of those survived every existing test (measured at the base commit
for Map.is_empty inverted and String.ends_with as starts_with, in both
Python emitters). Every other declared method the earlier gap list named
IS called by the parity corpus; that list was wrong.

WHAT THIS ASSERTS

- ``TestCorpusCoverage``: the corpus under tests/stdlib_characterization/
  CALLS every method declared on every non-capability owner of
  ``capa.builtins.METHODS``. The set of called methods is COMPUTED by
  analysing each program and reading the receiver type of every method
  call, never listed by hand, so a method added to the table without a
  corpus program fails here.
- ``TestThreeBackendAgreement``: for every program in ``_AGREEING`` the
  legacy Python transpiler, the CIR Python emitter (``--ir``) and the Wasm
  backend produce byte-identical, non-empty stdout.
- ``TestLegacyVsCir``: the two Python paths agree on EVERY corpus program,
  including the known-divergent ones (their divergence is Wasm-only). Runs
  without the Wasm toolchain.
- ``TestKnownDivergent``: the programs in ``_KNOWN_DIVERGENT`` are
  RECORDED as defects, never blessed as correct. The list is DERIVED from
  the instrument register (``tests/instrument_register.json``, instrument
  ``stdlib_characterization``): each entry pins the exact per-backend
  vector (exit class and stdout) of EVERY leg, the Python legs included,
  as the key the register stores, and the generic test asserts that the
  three legs still produce exactly those vectors. When it goes red
  because the backends now agree the defect is fixed: delete the entry
  and promote the program to ``_AGREEING``; when it goes red because a
  leg changed its answer, re-measure, do not re-pin. The structural
  assertions a key cannot express (the non-NaN subsequence lost its order;
  the Wasm failure names the un-emitted callee) stay as hand-written
  tests the entry points at through its ``pins`` field.
- ``TestKnownDivergentIsPinned``: every ``_KNOWN_DIVERGENT`` member is
  pinned by construction (an entry has no shape without an outcome), and
  every pin an entry points at exists and names the member. Pentest
  finding F5: a program could be added to the list with no pin at all,
  and the suite stayed green (measured EXIT=0), so a divergence could be
  RECORDED without anyone asserting what it is -- which is the whole point
  of the list. The reverse direction (a pin left behind after a program
  is promoted to ``_AGREEING``) deliberately gets NO guard here: it is
  already caught three ways by tests that ship today -- the inventory
  test, the agreement test, and the stale pin itself, which fails once
  the program agrees. A fourth mechanism for it would be a mirror of
  knowledge that already has one owner.
- ``TestCapabilitySurface``: the manifest's capability and obligation
  surface for every corpus program is exactly the Stdio the program
  declares, with no linear obligation. The manifest's ``calls`` list is
  DERIVED from the AST walk and legitimately names collection methods, so
  this deliberately does not assert any name is absent.
- ``TestCorpusInventory``: every ``.capa`` in the corpus directory is
  listed exactly once, and every listed file exists.

The runners are imported from the parity harness so there is one
definition of "run this program on backend X"; this module adds programs,
not a second runner.
"""

from __future__ import annotations

import inspect
import shutil
import tempfile
import unittest
from pathlib import Path

from capa import capa_ast as A
from capa.builtins import METHODS
from capa.manifest import build_manifest
from capa.typesys import CAPABILITY_NAMES, TyName

from tests._declared_methods import declared_methods
from tests.instruments._outcome import norm_text, wrong
from tests.instruments._register import (
    PUBLIC_REGISTER, composite_vector, entry_key, load, member_id, members, split_key,
)
from tests.instruments._runner import Program, run_legs
from tests.test_ir_wasm_parity import (
    _capture_stdout,
    _has_wasm_tools,
    _has_wasmtime_py,
    _parse_and_analyze,
    _run_cir,
    _run_python,
    _run_wasm,
)


_CORPUS = Path(__file__).resolve().parent / "stdlib_characterization"

#: Programs whose stdout must be byte-identical on all three backends.
_AGREEING: tuple[str, ...] = (
    "list_methods.capa",
    "range_methods.capa",
    "string_methods.capa",
    "map_methods.capa",
    "set_methods.capa",
    "option_methods.capa",
    "result_methods.capa",
    "json_methods.capa",
    "ordering_operators.capa",
    "float_sorted_by.capa",
)

#: Programs whose Wasm behaviour DIFFERS from the two Python paths today.
#: Each is a measured, pre-existing defect (design section 9; contest F2;
#: the NaN member found by the qa gate), recorded in the instrument
#: register with the exact vector of every leg; the list is DERIVED from
#: the register so the inventory and the pins cannot disagree.
_STDLIB_INSTRUMENT = "stdlib_characterization"
_THREE_BACKENDS = "three_backends"
_REGISTER: dict = load(PUBLIC_REGISTER)
_KNOWN_DIVERGENT: tuple[str, ...] = tuple(members(_REGISTER, _STDLIB_INSTRUMENT))


def _registered_entry(filename: str) -> tuple[str, dict]:
    """The register key and entry of a known-divergent program; the key
    carries the program's hash, so an edited program has no entry."""
    key = entry_key(_STDLIB_INSTRUMENT, member_id(filename, _source(filename)), _THREE_BACKENDS)
    if key not in _REGISTER:
        raise AssertionError(
            f"{filename} is in the corpus but its text no longer matches its "
            f"register entry (the member identity carries the program hash); "
            f"re-measure and re-register it: {key}"
        )
    return key, _REGISTER[key]


def _source(filename: str) -> str:
    return (_CORPUS / filename).read_text(encoding="utf-8")


def _declared_pairs() -> set[tuple[str, str]]:
    """Every ``(owner, method)`` declared on a non-capability owner.
    Capability surfaces are security decisions, not a completeness
    question, and their methods need fixtures or the network, so they
    are outside this corpus by construction."""
    return {
        (owner, name)
        for owner in METHODS
        if owner not in CAPABILITY_NAMES
        for name in declared_methods(owner)
    }


def _called_methods(src: str) -> set[tuple[str, str]]:
    """Every ``(owner, method)`` a program calls, read from the analysed
    AST: the owner is the receiver's checked type, so a call through a
    chained receiver or a literal is attributed the same way the
    analyzer dispatches it."""
    module, result = _parse_and_analyze(src)
    called: set[tuple[str, str]] = set()
    for node in A.walk(module):
        if isinstance(node, A.MethodCall):
            ty = result.types.get(id(node.receiver))
            if isinstance(ty, TyName):
                called.add((ty.name, node.method))
    return called


def _three_backend_outputs(src: str) -> tuple[str, str, str]:
    py = _capture_stdout(lambda: _run_python(src))
    cir = _capture_stdout(lambda: _run_cir(src))
    wasm = _capture_stdout(lambda: _run_wasm(src))
    return py, cir, wasm


class TestCorpusInventory(unittest.TestCase):
    def test_every_corpus_file_is_listed_exactly_once(self):
        on_disk = sorted(p.name for p in _CORPUS.glob("*.capa"))
        listed = sorted(_AGREEING + _KNOWN_DIVERGENT)
        self.assertEqual(
            on_disk, listed,
            "tests/stdlib_characterization/ and the _AGREEING / "
            "_KNOWN_DIVERGENT lists disagree; a program must be in exactly "
            "one list so it is either diffed or pinned as divergent",
        )

    def test_no_program_is_both_agreeing_and_divergent(self):
        self.assertEqual(set(_AGREEING) & set(_KNOWN_DIVERGENT), set())


class TestCorpusCoverage(unittest.TestCase):
    def test_corpus_calls_every_declared_non_capability_method(self):
        called: set[tuple[str, str]] = set()
        for filename in _AGREEING + _KNOWN_DIVERGENT:
            called |= _called_methods(_source(filename))
        missing = sorted(_declared_pairs() - called)
        self.assertEqual(
            missing, [],
            "capa.builtins.METHODS declares methods the characterization "
            "corpus never calls; add a call to the owner's program under "
            "tests/stdlib_characterization/ so the three backends are "
            f"diffed on it: {missing}",
        )

    def test_corpus_calls_no_capability_method_other_than_stdio(self):
        # The corpus must stay deterministic and fixture-free: Stdio is
        # the only capability a program may touch.
        for filename in _AGREEING + _KNOWN_DIVERGENT:
            with self.subTest(program=filename):
                owners = {o for (o, _m) in _called_methods(_source(filename))}
                self.assertEqual(owners & CAPABILITY_NAMES, {"Stdio"})


class TestLegacyVsCir(unittest.TestCase):
    """The two Python paths agree on every program, divergent ones
    included: the recorded divergences are Wasm-only. Needs no Wasm
    toolchain, so it also runs on the no-wasm CI job."""

    def test_legacy_and_cir_agree_on_every_program(self):
        for filename in _AGREEING + _KNOWN_DIVERGENT:
            with self.subTest(program=filename):
                src = _source(filename)
                py = _capture_stdout(lambda: _run_python(src))
                cir = _capture_stdout(lambda: _run_cir(src))
                self.assertNotEqual(py, "", "program printed nothing")
                self.assertEqual(
                    py, cir,
                    f"legacy/--ir divergence for {filename}.\n"
                    f"--- legacy ---\n{py}\n--- --ir ---\n{cir}",
                )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestThreeBackendAgreement(unittest.TestCase):
    def test_every_agreeing_program_is_byte_identical(self):
        for filename in _AGREEING:
            with self.subTest(program=filename):
                py, cir, wasm = _three_backend_outputs(_source(filename))
                self.assertNotEqual(py, "", "program printed nothing")
                self.assertEqual(
                    py, cir,
                    f"legacy/--ir divergence for {filename}.\n"
                    f"--- legacy ---\n{py}\n--- --ir ---\n{cir}",
                )
                self.assertEqual(
                    py, wasm,
                    f"Python/Wasm divergence for {filename}.\n"
                    f"--- python ---\n{py}\n--- wasm ---\n{wasm}",
                )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestKnownDivergent(unittest.TestCase):
    """Pre-existing cross-backend defects, RECORDED here so nobody
    mistakes them for correct behaviour. The register entry of each
    program pins today's exact per-leg vectors; the generic test below
    re-measures them through the bounded runner. When it goes red because
    the backends now AGREE, the defect has been fixed: delete the entry
    (which promotes the program to ``_AGREEING``), do not re-pin the new
    output. The structural assertions stay as hand-written tests."""

    LEGS = ("run", "ir", "wasm")

    @classmethod
    def setUpClass(cls):
        programs = [Program(name, _CORPUS / name) for name in _KNOWN_DIVERGENT]
        work = Path(tempfile.mkdtemp(prefix="capa_stdlib_"))
        try:
            cls.rows = run_legs(_CORPUS.parent.parent, cls.LEGS, programs, workdir=work) if programs else {}
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _vectors(self, filename: str) -> dict:
        out = {}
        for leg in self.LEGS:
            row = self.rows[(filename, leg)]
            out[leg] = [row["outcome"], norm_text(row["stdout"])]
        return out

    def test_every_registered_divergence_holds_on_every_leg(self):
        for filename in _KNOWN_DIVERGENT:
            with self.subTest(program=filename):
                key, entry = _registered_entry(filename)
                observed = self._vectors(filename)
                self.assertEqual(
                    wrong(composite_vector(observed)), entry["outcome"],
                    f"{filename}: a leg no longer produces its registered vector.\n"
                    f"registered: {entry.get('vectors')}\nobserved:   {observed}\n"
                    "If the three legs now agree the divergence is fixed: delete "
                    f"the entry {key} (the program joins _AGREEING). If one leg "
                    "changed its answer, re-measure and record the new defect; "
                    "never re-pin silently.",
                )
                distinct = {observed[leg][0] + observed[leg][1] for leg in self.LEGS}
                self.assertGreater(len(distinct), 1, f"{filename}: the legs agree; the entry is FIXED")

    def test_sorted_by_nan_non_nan_subsequence_lost_its_order(self):
        # FIVE elements, not four, and the count is load-bearing. At
        # four the outputs differ only in where NaN sits, which reads as
        # a cosmetic ordering question and is what let this defect be
        # discussed as one. At five the real damage shows: on the Python
        # paths the CLEAN elements come out 2.0, 1.0, 3.0, 4.0, which is
        # not sorted. That is the defect this program records.
        py = self._vectors("known_divergent_sorted_by_nan.capa")["run"][1]
        clean = [part for part in py.strip().split("|") if part not in ("", "nan")]
        self.assertNotEqual(
            clean, sorted(clean, key=float),
            "the Python paths no longer corrupt the order of the non-NaN "
            "elements. That is the defect this program records, so if it "
            "is gone the comparator or the sort has been fixed: re-measure "
            "and promote, do not re-pin",
        )

    def test_generic_closure_param_failure_names_the_callee(self):
        # .claude/STDLIB_CONTEST_1.md F2: a generic function with a
        # closure-typed parameter runs on both Python paths but the Wasm
        # backend emits a module that references the never-emitted
        # specialisation, so assembly fails naming the callee.
        row = self.rows[("known_divergent_generic_closure_param.capa", "wasm")]
        self.assertNotEqual(row["outcome"], "OK")
        self.assertIn(
            "sort_any", row["exc"],
            "the Wasm failure no longer names the un-emitted generic "
            "callee; if the program now runs, the defect is fixed: delete "
            "its register entry",
        )


class TestKnownDivergentIsPinned(unittest.TestCase):
    """Pentest finding F5, the UNPINNED direction.

    An entry of the register IS the pin (it has no shape without an
    outcome), so a program cannot be listed as divergent without its
    divergence being asserted. What can still drift is the structural
    assertion an entry points at: every ``pins`` name must be a test of
    ``TestKnownDivergent`` whose source names the member, and every
    structural test must be pointed at by an entry. Whether a member is
    pinned is a property of the module, not of the host, so this runs
    without the Wasm toolchain.
    """

    GENERIC_PIN = "test_every_registered_divergence_holds_on_every_leg"

    def test_every_pin_an_entry_points_at_exists_and_names_the_member(self):
        for filename in _KNOWN_DIVERGENT:
            key, entry = _registered_entry(filename)
            for pin in entry.get("pins", []):
                with self.subTest(program=filename, pin=pin):
                    method = getattr(TestKnownDivergent, pin, None)
                    self.assertIsNotNone(method, f"{key} points at a test that does not exist: {pin}")
                    self.assertIn(filename, inspect.getsource(method), f"{pin} does not name {filename}")

    def test_every_structural_test_is_pointed_at_by_an_entry(self):
        pointed = set()
        for filename in _KNOWN_DIVERGENT:
            pointed |= set(_registered_entry(filename)[1].get("pins", []))
        structural = {
            name for name in dir(TestKnownDivergent)
            if name.startswith("test_") and name != self.GENERIC_PIN
        }
        self.assertEqual(
            sorted(structural - pointed), [],
            "a structural pin names no register entry; either point an "
            "entry at it or delete it with the defect it recorded",
        )

    def test_every_register_entry_is_a_corpus_file(self):
        on_disk = {p.name for p in _CORPUS.glob("*.capa")}
        for filename in _KNOWN_DIVERGENT:
            self.assertIn(filename, on_disk)
        for key in _REGISTER:
            if split_key(key)[0] == _STDLIB_INSTRUMENT:
                self.assertEqual(split_key(key)[2], _THREE_BACKENDS)


class TestCapabilitySurface(unittest.TestCase):
    """Contest correction 6: what a collection method must never do is
    widen the CAPABILITY or OBLIGATION surface. The manifest's ``calls``
    list is derived from the AST and legitimately names collection
    methods, so this asserts the surface, not the absence of names."""

    def test_manifest_surface_is_exactly_stdio_with_no_obligations(self):
        for filename in _AGREEING + _KNOWN_DIVERGENT:
            with self.subTest(program=filename):
                module, result = _parse_and_analyze(_source(filename))
                manifest = build_manifest(
                    module, filename=filename,
                    bindings=result.bindings,
                    expr_labels=result.expr_labels,
                )
                self.assertEqual(manifest["user_defined_capabilities"], [])
                for fn in manifest["functions"]:
                    with self.subTest(program=filename, function=fn["name"]):
                        self.assertLessEqual(
                            set(fn["declared_capabilities"]), {"Stdio"},
                        )
                        self.assertLessEqual(
                            set(fn["transitively_reachable_capabilities"]),
                            {"Stdio"},
                        )
                        self.assertEqual(
                            fn["linear_obligations"],
                            {"consumes": [], "produces_linear": False},
                        )


if __name__ == "__main__":
    unittest.main()

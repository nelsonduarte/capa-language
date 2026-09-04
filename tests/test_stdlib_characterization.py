"""Three-backend characterization of the built-in method surface.

Step 0 of the standard-library design (.claude/STDLIB_DESIGN.md, section
10): land BEFORE any change to the surface, because the behaviour it pins
was previously unguarded. The parity harness in tests/test_ir_wasm_parity.py
runs examples/wasm/ and left several declared methods with no cross-backend
test at all (List find_index / sorted_by / reverse / enumerate / zip /
flat_map, the whole Set algebra, most Option / Result methods): a Python-
runtime semantic change to any of them survived every existing test.

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
- ``TestKnownDivergent``: the two programs in ``_KNOWN_DIVERGENT`` are
  RECORDED as defects, never blessed as correct. Each test pins the exact
  divergence measured today and says what to do when it goes red because
  the backends now agree (promote the program to ``_AGREEING``).
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

import unittest
from pathlib import Path

from capa import capa_ast as A
from capa.builtins import METHODS
from capa.manifest import build_manifest
from capa.typesys import CAPABILITY_NAMES, TyName

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
#: Each is a measured, pre-existing defect (design section 9; contest F2),
#: pinned exactly by a dedicated test in ``TestKnownDivergent`` so the
#: suite records the defect instead of locking it in as correct.
_KNOWN_DIVERGENT: tuple[str, ...] = (
    "known_divergent_sorted_by_inconsistent.capa",
    "known_divergent_generic_closure_param.capa",
)


def _source(filename: str) -> str:
    return (_CORPUS / filename).read_text(encoding="utf-8")


def _declared_methods() -> set[tuple[str, str]]:
    """Every ``(owner, method)`` declared on a non-capability owner.
    Capability surfaces are security decisions, not a completeness
    question, and their methods need fixtures or the network, so they
    are outside this corpus by construction."""
    return {
        (owner, name)
        for owner, entries in METHODS.items()
        if owner not in CAPABILITY_NAMES
        for (name, _ty, _params) in entries
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
        missing = sorted(_declared_methods() - called)
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
    mistakes them for correct behaviour. Each test pins today's exact
    outputs. When one goes red because the backends now AGREE, the
    defect has been fixed: move the program to ``_AGREEING`` and delete
    the pin, do not re-pin the new output."""

    def test_sorted_by_inconsistent_comparator_is_recorded_not_blessed(self):
        # .claude/STDLIB_DESIGN.md section 9, decision 2: the byte-identity
        # promise of sorted_by holds only for a consistent total order.
        # Python's Timsort and the Wasm bottom-up merge sort visit
        # different comparison sequences, so an inconsistent comparator
        # settles on different permutations.
        src = _source("known_divergent_sorted_by_inconsistent.capa")
        py, cir, wasm = _three_backend_outputs(src)
        self.assertEqual(py, "1|2|3|4|5|6|\n")
        self.assertEqual(cir, py)
        self.assertEqual(
            wasm, "6|5|4|3|2|1|\n",
            "the Wasm sorted_by output for an inconsistent comparator "
            "changed; if it now equals the Python output the divergence is "
            "fixed: promote the program to _AGREEING",
        )

    def test_generic_closure_param_is_recorded_not_blessed(self):
        # .claude/STDLIB_CONTEST_1.md F2: a generic function with a
        # closure-typed parameter runs on both Python paths but the Wasm
        # backend emits a module that references the never-emitted
        # specialisation, so assembly fails naming the callee.
        src = _source("known_divergent_generic_closure_param.capa")
        py = _capture_stdout(lambda: _run_python(src))
        cir = _capture_stdout(lambda: _run_cir(src))
        self.assertEqual(py, "1 a\n")
        self.assertEqual(cir, py)
        with self.assertRaises(Exception) as caught:
            _capture_stdout(lambda: _run_wasm(src))
        self.assertIn(
            "sort_any", str(caught.exception),
            "the Wasm failure no longer names the un-emitted generic "
            "callee; if the program now runs, the defect is fixed: promote "
            "it to _AGREEING",
        )


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

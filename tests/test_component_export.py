"""Tests for the ``@export`` attribute and the Wasm Component Model
export surface (embeddable-component increment, scalar-first).

Four blocks:

  - analyzer: ``@export`` is a recognized attribute, and it is a hard
    error to place it where it cannot become a component export
    (``main``, an impl method).
  - WIT emission: an ``@export`` scalar function becomes an extra
    ``world`` export alongside ``main``; a deferred name / type shape
    (String, aggregate, non-WIT-identifier name) is refused fail-loud
    with ``ComponentExportUnsupported``; a program with no ``@export``
    emits an unchanged world (no extra export line).
  - component build: the multi-export component embeds + promotes with
    the real ``wasm-tools`` and passes ``wasm-tools validate``.
  - host round-trip: a Component Model host (the ``wasmtime`` CLI)
    calls the exported ``add`` and reads back the scalar. This is the
    honest go/no-go for the seam; it is gated on the toolchain being
    present.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.ir import (
    lower, emit_wit, compile_wasm, compile_wit,
    ComponentExportUnsupported,
)
from capa.cli import _wrap_as_component


def _parse(src: str):
    tokens = Lexer(src).lex()
    return Parser(tokens, source=src).parse_module()


def _analyze_errors(src: str) -> list[str]:
    module = _parse(src)
    return [e.message for e in analyze(module, source=src).errors]


def _lower_ok(src: str):
    module = _parse(src)
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return lower(module, types=result.types)


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_cli() -> bool:
    return shutil.which("wasmtime") is not None


# A canonical scalar export: the smallest thing that proves the seam.
_ADD_SRC = (
    "@export()\n"
    "fun add(a: Int, b: Int) -> Int\n"
    "    return a + b\n"
    "\n"
    "fun main()\n"
    "    return\n"
)


# =============================================================
# Analyzer: recognition + placement
# =============================================================

class TestExportAnalyzer(unittest.TestCase):
    def test_export_is_a_recognized_attribute(self):
        # No "unknown attribute" diagnostic: ``@export`` is threaded
        # through the same allow-list as the other v1 attributes.
        errs = _analyze_errors(_ADD_SRC)
        self.assertEqual(errs, [])

    def test_export_independent_of_pub(self):
        # ``@export`` is an ABI-surface axis, orthogonal to ``pub``:
        # a non-``pub`` function may still be exported.
        errs = _analyze_errors(_ADD_SRC)
        self.assertEqual(errs, [])
        errs_pub = _analyze_errors(
            "@export()\n"
            "pub fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        self.assertEqual(errs_pub, [])

    def test_export_on_main_is_rejected(self):
        # ``main`` is exported unconditionally; a redundant ``@export``
        # would emit a duplicate world export, so it is a hard error.
        errs = _analyze_errors(
            "@export()\n"
            "fun main()\n"
            "    return\n"
        )
        self.assertTrue(
            any("main is exported automatically" in e for e in errs),
            errs,
        )

    def test_export_on_impl_method_is_rejected(self):
        # The WIT world only advertises top-level functions; marking an
        # impl method would silently drop, so reject it up front.
        errs = _analyze_errors(
            "type P { x: Int }\n"
            "impl P\n"
            "    @export()\n"
            "    fun get(self) -> Int\n"
            "        return self.x\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        self.assertTrue(
            any("only valid on a top-level function" in e for e in errs),
            errs,
        )


# =============================================================
# WIT emission
# =============================================================

class TestExportWit(unittest.TestCase):
    def test_scalar_export_appears_alongside_main(self):
        ir_mod = _lower_ok(_ADD_SRC)
        wit = emit_wit(ir_mod)
        self.assertIn("world program {", wit)
        self.assertIn("export main: func();", wit)
        self.assertIn("export add: func(a: s64, b: s64) -> s64;", wit)

    def test_bool_and_float_and_unit_scalars(self):
        src = (
            "@export()\n"
            "fun flag(x: Bool) -> Bool\n"
            "    return x\n"
            "\n"
            "@export()\n"
            "fun half(x: Float) -> Float\n"
            "    return x\n"
            "\n"
            "@export()\n"
            "fun noop(x: Int)\n"
            "    return\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        wit = emit_wit(_lower_ok(src))
        self.assertIn("export flag: func(x: bool) -> bool;", wit)
        self.assertIn("export half: func(x: f64) -> f64;", wit)
        # A Unit/absent return carries no result clause.
        self.assertIn("export noop: func(x: s64);", wit)

    def test_no_export_program_has_no_extra_export_line(self):
        # No-regression / byte-identity floor: a program with no
        # ``@export`` emits exactly one world export (``main``); the
        # ``@export`` machinery contributes nothing.
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        wit = emit_wit(_lower_ok(src))
        export_lines = [
            ln for ln in wit.splitlines() if ln.strip().startswith("export ")
        ]
        self.assertEqual(export_lines, ["  export main: func();"])

    def test_string_return_is_refused(self):
        src = (
            "@export()\n"
            "fun greet(a: Int) -> String\n"
            "    return \"hi\"\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        with self.assertRaises(ComponentExportUnsupported) as ctx:
            emit_wit(_lower_ok(src))
        self.assertIn("String", str(ctx.exception))
        self.assertIn("greet", str(ctx.exception))

    def test_string_param_is_refused(self):
        src = (
            "@export()\n"
            "fun f(s: String) -> Int\n"
            "    return 1\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        with self.assertRaises(ComponentExportUnsupported) as ctx:
            emit_wit(_lower_ok(src))
        self.assertIn("parameter", str(ctx.exception))
        self.assertIn("String", str(ctx.exception))

    def test_aggregate_param_is_refused(self):
        src = (
            "@export()\n"
            "fun f(xs: List<Int>) -> Int\n"
            "    return 1\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        with self.assertRaises(ComponentExportUnsupported):
            emit_wit(_lower_ok(src))

    def test_non_wit_identifier_name_is_refused(self):
        # The world export name must byte-match the core
        # ``(export "add_two")``; WIT identifiers admit no underscore,
        # so this cannot be a component export in the scalar increment.
        src = (
            "@export()\n"
            "fun add_two(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
            "\n"
            "fun main()\n"
            "    return\n"
        )
        with self.assertRaises(ComponentExportUnsupported) as ctx:
            emit_wit(_lower_ok(src))
        self.assertIn("valid WIT identifier", str(ctx.exception))


# =============================================================
# Component build (wasm-tools)
# =============================================================

@unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
class TestExportComponentBuilds(unittest.TestCase):
    def _build_component(self, src: str) -> bytes:
        module = _parse(src)
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        core = compile_wasm(module, types=result.types)
        wit = compile_wit(module, types=result.types)
        return _wrap_as_component(core, wit)

    def test_multi_export_component_validates(self):
        blob = self._build_component(_ADD_SRC)
        with tempfile.TemporaryDirectory() as td:
            comp = Path(td) / "component.wasm"
            comp.write_bytes(blob)
            validate = subprocess.run(
                ["wasm-tools", "validate", str(comp)],
                capture_output=True, check=False,
            )
            self.assertEqual(
                validate.returncode, 0,
                validate.stderr.decode("utf-8", "replace"),
            )
            # The promoted component's WIT advertises both exports.
            dump = subprocess.run(
                ["wasm-tools", "component", "wit", str(comp)],
                capture_output=True, check=False,
            )
            self.assertEqual(dump.returncode, 0, dump.stderr)
            text = dump.stdout.decode("utf-8", "replace")
            self.assertIn("export main:", text)
            self.assertIn("export add:", text)


# =============================================================
# Host round-trip (wasm-tools + wasmtime CLI)
# =============================================================

@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_cli(),
    "wasm-tools and/or wasmtime CLI not installed",
)
class TestExportHostRoundTrip(unittest.TestCase):
    """The crux go/no-go: a real Component Model host calls the
    exported scalar function and reads back the result."""

    def test_host_calls_exported_add(self):
        module = _parse(_ADD_SRC)
        result = analyze(module, source=_ADD_SRC)
        self.assertTrue(result.ok, result.errors)
        core = compile_wasm(module, types=result.types)
        wit = compile_wit(module, types=result.types)
        blob = _wrap_as_component(core, wit)
        with tempfile.TemporaryDirectory() as td:
            comp = Path(td) / "component.wasm"
            comp.write_bytes(blob)
            run = subprocess.run(
                ["wasmtime", "run", "--invoke", "add(2, 3)", str(comp)],
                capture_output=True, check=False,
            )
            self.assertEqual(
                run.returncode, 0,
                run.stderr.decode("utf-8", "replace"),
            )
            self.assertEqual(run.stdout.decode("utf-8", "replace").strip(), "5")

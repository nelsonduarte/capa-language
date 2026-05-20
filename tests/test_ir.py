"""Tests for the Capa IR layer (Phase 1).

The IR is the future-proofing layer that decouples lowered semantics
from backend-specific emission. Phase 1 covers a small language
subset (literal expressions, identifiers, binary ops, calls, method
calls, let / return / expression statements) and emits Python source
through a dedicated emitter that mirrors the legacy transpiler for
that subset.

These tests pin three things:

1. The lowering pass walks the supported subset without raising.
2. The Python emitter produces source that ``ast.parse`` accepts and
   that ``exec``-runs to the expected output for a few canonical
   programs.
3. Constructs outside the supported subset raise
   ``UnsupportedInIR`` so the caller can fall back to the legacy
   transpiler. This is the explicit contract the IR makes with its
   caller while the lowering coverage grows incrementally.
"""

from __future__ import annotations

import ast as pyast
import unittest

from capa import Lexer, Parser, analyze
from capa.ir import (
    Lowerer, UnsupportedInIR, PythonEmitter, lower, emit_python, compile,
)
from capa.ir import _nodes as N


def _parse_and_check(src: str):
    """Lex + parse + analyze, returning the typed AST module and the
    analyzer's type map. Bails the test if analysis fails."""
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result.types


class TestIRLowering(unittest.TestCase):
    def test_lowers_arithmetic_function(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.functions), 1)
        fn = ir_mod.functions[0]
        self.assertEqual(fn.name, "add")
        self.assertEqual([p.name for p in fn.params], ["a", "b"])
        self.assertEqual(fn.return_type, "Int")
        # Body shape: a BinOp computing a fresh local, then Return
        # using that local.
        self.assertEqual(len(fn.body), 2)
        self.assertIsInstance(fn.body[0], N.BinOp)
        self.assertEqual(fn.body[0].op, "+")
        self.assertIsInstance(fn.body[1], N.Return)
        assert fn.body[1].value is not None
        self.assertEqual(fn.body[1].value.kind, "local")
        self.assertEqual(fn.body[1].value.name, fn.body[0].dst)

    def test_lowers_let_binding(self):
        src = (
            "fun simple() -> Int\n"
            "    let x = 1\n"
            "    let y = 2\n"
            "    return x + y\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        # Two AssignConst (let x, let y) + one BinOp + one Return.
        kinds = [type(instr).__name__ for instr in fn.body]
        self.assertEqual(kinds, ["AssignConst", "AssignConst", "BinOp", "Return"])
        # ``x`` and ``y`` are recorded as locals with type Int.
        self.assertIn("x", fn.locals)
        self.assertIn("y", fn.locals)
        self.assertEqual(fn.locals["x"], "Int")

    def test_lowers_method_call_on_capability_param(self):
        src = (
            "fun greet(stdio: Stdio)\n"
            "    stdio.println(\"hello\")\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        # Param ``stdio`` is flagged as capability.
        self.assertEqual(len(fn.params), 1)
        self.assertTrue(fn.params[0].is_capability)
        self.assertEqual(fn.params[0].ty, "Stdio")
        self.assertEqual(fn.declared_caps, ["Stdio"])
        # The MethodCall instruction records ``cap_used="Stdio"`` and
        # has its dst dropped because the expression was used as a
        # statement (ExprStmt path).
        mc = [i for i in fn.body if isinstance(i, N.MethodCall)]
        self.assertEqual(len(mc), 1)
        self.assertEqual(mc[0].method, "println")
        self.assertEqual(mc[0].cap_used, "Stdio")
        self.assertIsNone(mc[0].dst)


class TestPythonEmission(unittest.TestCase):
    def test_emits_parseable_python_for_arithmetic(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        # The emitted Python is parseable.
        pyast.parse(py)
        # Both the parameter names and the operator are present.
        self.assertIn("def add(a, b):", py)
        self.assertIn("+", py)
        self.assertIn("return", py)

    def test_emitted_python_executes_with_expected_result(self):
        src = (
            "fun sum_three(a: Int, b: Int, c: Int) -> Int\n"
            "    let ab = a + b\n"
            "    return ab + c\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        # Run the emitted Python in a fresh namespace and call the
        # function; the result must match the source's intent.
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["sum_three"](1, 2, 3), 6)


class TestUnsupportedSurfaces(unittest.TestCase):
    """The IR explicitly raises ``UnsupportedInIR`` for constructs the
    Phase 1 lowering does not yet handle, so callers (typically the
    compilation pipeline) can fall back to the legacy transpiler
    without surprises. These tests pin the contract; as coverage
    grows, the corresponding entry moves out of this class and into
    a positive test in ``TestIRLowering``."""

    def _try_lower(self, src: str):
        module, types = _parse_and_check(src)
        return lower(module, types=types)

    def test_match_expression_is_unsupported(self):
        src = (
            "fun classify(n: Int) -> Int\n"
            "    return match n\n"
            "        0 -> 100\n"
            "        _ -> 200\n"
        )
        with self.assertRaises(UnsupportedInIR):
            self._try_lower(src)

    def test_if_statement_is_unsupported(self):
        src = (
            "fun pick(b: Bool) -> Int\n"
            "    if b\n"
            "        return 1\n"
            "    return 2\n"
        )
        with self.assertRaises(UnsupportedInIR):
            self._try_lower(src)

    def test_lambda_expression_is_unsupported(self):
        src = (
            "fun build() -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + 1\n"
        )
        with self.assertRaises(UnsupportedInIR):
            self._try_lower(src)


if __name__ == "__main__":
    unittest.main()

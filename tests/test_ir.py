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
    compile_program,
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


class TestControlFlow(unittest.TestCase):
    """Phase 2: lowering and emission for ``var`` / ``if`` / ``while``
    and the bare ``=`` assignment form. Each test verifies both the
    IR shape and the runtime behaviour of the emitted Python."""

    def test_var_then_reassign(self):
        src = (
            "fun main()\n"
            "    var x = 1\n"
            "    x = 2\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        kinds = [type(i).__name__ for i in fn.body]
        self.assertEqual(kinds, ["AssignConst", "Reassign"])
        py = compile(module, types=types)
        # Both statements compile to plain Python assignments.
        self.assertIn("x = 1", py)
        self.assertIn("x = 2", py)

    def test_if_else_emits_and_runs(self):
        src = (
            "fun pick(b: Bool) -> Int\n"
            "    if b\n"
            "        return 1\n"
            "    return 2\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        # The body should be one If followed by a Return.
        self.assertIsInstance(fn.body[0], N.If)
        self.assertIsInstance(fn.body[-1], N.Return)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["pick"](True), 1)
        self.assertEqual(ns["pick"](False), 2)

    def test_if_elif_else_chains_nest(self):
        src = (
            "fun grade(n: Int) -> Int\n"
            "    if n >= 90\n"
            "        return 4\n"
            "    elif n >= 75\n"
            "        return 3\n"
            "    elif n >= 50\n"
            "        return 2\n"
            "    return 1\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["grade"](95), 4)
        self.assertEqual(ns["grade"](80), 3)
        self.assertEqual(ns["grade"](60), 2)
        self.assertEqual(ns["grade"](20), 1)

    def test_while_loop_counts_down(self):
        src = (
            "fun count_down(n: Int) -> Int\n"
            "    var x = n\n"
            "    var steps = 0\n"
            "    while x > 0\n"
            "        x = x - 1\n"
            "        steps = steps + 1\n"
            "    return steps\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        # Find the While instruction.
        whiles = [i for i in fn.body if isinstance(i, N.While)]
        self.assertEqual(len(whiles), 1)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["count_down"](5), 5)
        self.assertEqual(ns["count_down"](0), 0)

    def test_while_with_break(self):
        src = (
            "fun first_positive(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    var result = 0\n"
            "    while x < b\n"
            "        if x > 0\n"
            "            result = x\n"
            "            break\n"
            "        x = x + 1\n"
            "    return result\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["first_positive"](-3, 10), 1)
        self.assertEqual(ns["first_positive"](-5, -2), 0)


class TestDataAndIteration(unittest.TestCase):
    """Phase 2B: struct / list / tuple literals, field / index access,
    string interpolation, and for-loop iteration."""

    def test_struct_literal_and_field_access(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun build() -> Int\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    return p.x + p.y\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.functions), 1)
        fn = ir_mod.functions[0]
        instr_kinds = [type(i).__name__ for i in fn.body]
        self.assertIn("MakeStruct", instr_kinds)
        self.assertIn("FieldAccess", instr_kinds)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["build"](), 7)

    def test_list_literal_and_index(self):
        src = (
            "fun pick(i: Int) -> Int\n"
            "    let xs = [10, 20, 30]\n"
            "    return xs[i]\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        py = compile(module, types=types)
        # List literals lower to ``CapaList([...])`` so methods like
        # ``length()`` / ``map()`` resolve; supply the wrapper in the
        # exec namespace because the minimal ``compile()`` emitter
        # does not introduce runtime imports.
        from capa.runtime import CapaList
        ns: dict = {"CapaList": CapaList}
        exec(py, ns)
        self.assertEqual(ns["pick"](0), 10)
        self.assertEqual(ns["pick"](2), 30)

    def test_tuple_literal_two_elements(self):
        src = (
            "fun pair() -> (Int, Int)\n"
            "    return (1, 2)\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["pair"](), (1, 2))

    def test_interpolated_string_emits_fstring(self):
        src = (
            "fun greet(name: String) -> String\n"
            "    return \"hello, ${name}!\"\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        # The emitter uses Python f-strings.
        self.assertIn("f'hello, {", py)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["greet"]("Ana"), "hello, Ana!")

    def test_for_loop_over_list(self):
        src = (
            "fun sum_all(xs: List<Int>) -> Int\n"
            "    var total = 0\n"
            "    for x in xs\n"
            "        total = total + x\n"
            "    return total\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        # The function takes a list parameter; the caller passes a
        # plain Python list (CapaList inherits from list so either
        # shape iterates identically).
        self.assertEqual(ns["sum_all"]([1, 2, 3, 4]), 10)
        self.assertEqual(ns["sum_all"]([]), 0)


class TestTryOperator(unittest.TestCase):
    """Phase 2C: the ``?`` operator. In the three-address IR every
    ``?`` lowers to a single TryUnwrap instruction; the legacy
    expression-position-vs-statement-position distinction does not
    survive ANF flattening. The Python emitter expands TryUnwrap
    inline (no _capa_try / _CapaTryEarlyReturn exception)."""

    def _runtime_ns(self) -> dict:
        """Pre-load Err / Ok / Some / None_ so emitted Python that
        uses TryUnwrap can run in a bare exec namespace."""
        from capa.runtime import Err, Ok, Some, None_
        return {"Err": Err, "Ok": Ok, "Some": Some, "None_": None_}

    def test_question_mark_on_result_lowers_to_try_unwrap(self):
        src = (
            "fun produce(b: Bool) -> Result<Int, String>\n"
            "    if b\n"
            "        return Err(\"boom\")\n"
            "    return Ok(42)\n"
            "fun via(b: Bool) -> Result<Int, String>\n"
            "    let x = produce(b)?\n"
            "    return Ok(x + 1)\n"
        )
        module, types = _parse_and_check(src)
        # Lower only the ``via`` function (the ``produce`` function
        # uses ``Err("boom")`` / ``Ok(42)`` constructors that look
        # like calls -- supported -- but the IR's top-level walk
        # accepts FunDecl items so the whole module lowers cleanly).
        try:
            ir_mod = lower(module, types=types)
        except UnsupportedInIR:
            from capa.ir._lower import Lowerer
            lowerer = Lowerer(types=types)
            from capa import capa_ast as A
            ir_funs = [
                lowerer.lower_function(it)
                for it in module.items
                if isinstance(it, A.FunDecl)
            ]
            ir_mod = type(ir_mod := None) if False else None  # unreachable
        # The ``via`` function's IR body contains a TryUnwrap.
        via_fn = next(f for f in ir_mod.functions if f.name == "via")
        kinds = [type(i).__name__ for i in via_fn.body]
        self.assertIn("TryUnwrap", kinds)

    def test_question_mark_runtime_ok_path(self):
        src = (
            "fun produce(b: Bool) -> Result<Int, String>\n"
            "    if b\n"
            "        return Err(\"boom\")\n"
            "    return Ok(42)\n"
            "fun via(b: Bool) -> Result<Int, String>\n"
            "    let x = produce(b)?\n"
            "    return Ok(x + 1)\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns = self._runtime_ns()
        exec(py, ns)
        # Ok path: produce(false) -> Ok(42); via unwraps to 42 and
        # returns Ok(43).
        result_ok = ns["via"](False)
        from capa.runtime import Ok as RuntimeOk
        self.assertIsInstance(result_ok, RuntimeOk)
        self.assertEqual(result_ok.value, 43)

    def test_question_mark_runtime_err_path(self):
        src = (
            "fun produce(b: Bool) -> Result<Int, String>\n"
            "    if b\n"
            "        return Err(\"boom\")\n"
            "    return Ok(42)\n"
            "fun via(b: Bool) -> Result<Int, String>\n"
            "    let x = produce(b)?\n"
            "    return Ok(x + 1)\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns = self._runtime_ns()
        exec(py, ns)
        # Err path: produce(true) -> Err("boom"); via early-returns
        # the Err unchanged.
        result_err = ns["via"](True)
        from capa.runtime import Err as RuntimeErr
        self.assertIsInstance(result_err, RuntimeErr)
        self.assertEqual(result_err.error, "boom")


class TestMatch(unittest.TestCase):
    """Phase 2D: statement-form ``match``. The expression-position
    ``let x = match ...`` form is still deferred (it would need the
    lowerer to thread a destination through each arm body). Patterns
    supported here: wildcard, ident binding, literal (int / str / bool
    / unit), and variant with payloads. The Python emitter targets
    3.10+ ``match`` / ``case`` syntax."""

    def _runtime_ns(self) -> dict:
        from capa.runtime import Err, Ok, Some, None_
        from capa.runtime._result import _NoneType
        return {
            "Err": Err, "Ok": Ok, "Some": Some,
            "None_": None_, "_NoneType": _NoneType,
        }

    def test_variant_match_with_payload_binding(self):
        src = (
            "fun describe(r: Result<Int, String>) -> String\n"
            "    match r\n"
            "        Ok(n) ->\n"
            "            return \"ok:${n}\"\n"
            "        Err(e) ->\n"
            "            return \"err:${e}\"\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        # Body should contain a Match instruction.
        matches = [i for i in fn.body if isinstance(i, N.Match)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0].arms), 2)
        # Run the emitted Python end to end.
        py = compile(module, types=types)
        ns = self._runtime_ns()
        exec(py, ns)
        self.assertEqual(ns["describe"](ns["Ok"](7)), "ok:7")
        self.assertEqual(ns["describe"](ns["Err"]("nope")), "err:nope")

    def test_wildcard_catch_all_arm(self):
        src = (
            "fun bucket(n: Int) -> String\n"
            "    match n\n"
            "        0 ->\n"
            "            return \"zero\"\n"
            "        1 ->\n"
            "            return \"one\"\n"
            "        _ ->\n"
            "            return \"many\"\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["bucket"](0), "zero")
        self.assertEqual(ns["bucket"](1), "one")
        self.assertEqual(ns["bucket"](42), "many")

    def test_option_none_variant_pattern(self):
        # Capa's ``None`` (Option's singleton) is rendered as ``None_``
        # in Python; the emitter rewrites the variant name.
        src = (
            "fun length(o: Option<String>) -> Int\n"
            "    match o\n"
            "        Some(s) ->\n"
            "            return 1\n"
            "        None ->\n"
            "            return 0\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        # Capa's source-level ``None`` pattern reaches the emitter as a
        # PatVariant whose name is "None"; the emitter rewrites this
        # to ``_NoneType()`` because the runtime's ``None_`` is a
        # singleton instance, not a class, and Python's case-pattern
        # syntax requires a class on the left of ``(...)``.
        self.assertIn("_NoneType()", py)
        ns = self._runtime_ns()
        exec(py, ns)
        self.assertEqual(ns["length"](ns["Some"]("hi")), 1)
        self.assertEqual(ns["length"](ns["None_"]), 0)

    def test_expression_position_match_returns_value(self):
        # Phase 5A: ``return match n ...`` is the dominant idiom in
        # examples. Each arm body is an expression; the lowerer
        # threads a result local through the arms so the match
        # itself carries a Value.
        src = (
            "fun classify(n: Int) -> Int\n"
            "    return match n\n"
            "        0 -> 100\n"
            "        1 -> 200\n"
            "        _ -> 300\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        matches = [i for i in fn.body if isinstance(i, N.Match)]
        self.assertEqual(len(matches), 1)
        self.assertIsNotNone(matches[0].result_dst)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["classify"](0), 100)
        self.assertEqual(ns["classify"](1), 200)
        self.assertEqual(ns["classify"](42), 300)

    def test_expression_match_on_variant_payload(self):
        src = (
            "fun pluck(r: Result<Int, String>) -> Int\n"
            "    return match r\n"
            "        Ok(n) -> n\n"
            "        Err(_) -> -1\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns = self._runtime_ns()
        exec(py, ns)
        self.assertEqual(ns["pluck"](ns["Ok"](42)), 42)
        self.assertEqual(ns["pluck"](ns["Err"]("nope")), -1)

    def test_block_bodied_arm_in_expr_match_runs(self):
        # Block bodies in expression-position match lower with an
        # implicit ``Unit`` value at the tail of the case body. The
        # source contract: if the block needs to produce a non-Unit
        # value it must ``return`` out of the function.
        src = (
            "fun pick(n: Int) -> Int\n"
            "    return match n\n"
            "        0 ->\n"
            "            let y = 100\n"
            "            return y\n"
            "        _ -> 0\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["pick"](0), 100)
        self.assertEqual(ns["pick"](5), 0)

    def test_match_arm_with_trivial_guard_runs(self):
        # Guard ``x > 0`` lowers to a single BinOp with no prelude;
        # the Python emitter renders ``case x if (x > 0):`` directly.
        # Locked in 2026-05-24 along with the non-trivial-prelude
        # case below; previously the IR rejected every guard with
        # any prelude.
        src = (
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        x if x > 0 -> \"pos\"\n"
            "        _ -> \"nonpos\"\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["classify"](5), "pos")
        self.assertEqual(ns["classify"](0), "nonpos")
        self.assertEqual(ns["classify"](-3), "nonpos")

    def test_match_arm_with_non_trivial_guard_runs(self):
        # ``not t.done`` is a UnaryOp on a FieldAccess; the lowerer
        # captures the FieldAccess + UnaryOp pair as guard_setup and
        # the Python emitter inlines them back into the case clause
        # as ``case High() if (not t.done):``. End-to-end coverage
        # of the example/tasks.capa pattern via CIR.
        src = (
            "type Priority =\n"
            "    High\n"
            "    Low\n"
            "type Task { priority: Priority, done: Bool }\n"
            "fun classify(t: Task) -> String\n"
            "    return match t.priority\n"
            "        High if not t.done -> \"urgent\"\n"
            "        High -> \"done\"\n"
            "        Low -> \"later\"\n"
        )
        module, types = _parse_and_check(src)
        # IR layer: the arm carries guard_setup with the prelude
        # the ANF lowering produced.
        ir_mod = lower(module, types=types)
        fn = next(f for f in ir_mod.functions if f.name == "classify")
        match_instr = next(i for i in fn.body if isinstance(i, N.Match))
        guarded = [a for a in match_instr.arms if a.guard is not None]
        self.assertEqual(len(guarded), 1)
        self.assertTrue(
            guarded[0].guard_setup,
            "expected guard_setup to carry the FieldAccess + UnaryOp "
            "prelude that lowering produced for `not t.done`",
        )
        # End-to-end: emitted Python runs and produces the right
        # verdicts. We can't exec without instantiating Task/Priority,
        # so verify the emitted source contains the inlined guard.
        py = compile(module, types=types)
        self.assertIn("case High() if (not t.done):", py)

    def test_match_arm_guard_with_chained_binops_inlines(self):
        # Two chained BinOps in the guard: lowering produces a
        # prelude with one BinOp computing ``n + 1``, the emitter
        # inlines it back into the case clause as a single
        # composite expression. Locks the inline-chain code path.
        #
        # The inlined Int ``+`` routes through ``_capa_iadd`` exactly
        # like the instruction stream (and like the legacy transpiler's
        # guard emission), so a guard that overflows i64 traps on the
        # CIR path at the same input the legacy and Wasm backends trap
        # on. A bare ``(x + 1)`` here would silently diverge at
        # ``x == i64::MAX`` (Python bignum, no trap).
        src = (
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        x if (x + 1) > 5 -> \"big\"\n"
            "        _ -> \"small\"\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        self.assertIn("if (_capa_iadd(x, 1) > 5):", py)
        # The emitted module imports ``_capa_iadd`` itself (the guard's
        # Int ``+`` toggles the safety-helper import), so exec is
        # self-contained.
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["classify"](5), "big")
        self.assertEqual(ns["classify"](2), "small")

    def test_match_arm_guard_with_call_emit_raises_unsupported(self):
        # A guard whose lowered prelude includes a free-function
        # ``Call`` is not safely inlineable (purity unknown), so
        # emission raises UnsupportedInIR. The CLI's ``--ir`` path
        # catches this and falls back to the legacy transpiler;
        # the test enforces the emitter-side refusal.
        src = (
            "fun positive(n: Int) -> Bool\n"
            "    return n > 0\n"
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        x if positive(x) -> \"pos\"\n"
            "        _ -> \"nonpos\"\n"
        )
        module, types = _parse_and_check(src)
        # IR lowering must succeed (the lowerer no longer rejects
        # any guard); the emitter is the layer that refuses.
        ir_mod = lower(module, types=types)
        from capa.ir import emit_python
        with self.assertRaises(UnsupportedInIR):
            emit_python(ir_mod)


class TestTopLevelTypes(unittest.TestCase):
    """Phase 3A: top-level ``type`` declarations. Structs lower to a
    ``StructDecl`` IR item, sums to a ``SumDecl`` with one ``SumVariant``
    per arm. The Python emitter renders both as ``@dataclass`` classes
    (nullary variants stay as bare classes; sum-type aliases use
    ``|``)."""

    def test_struct_decl_emits_dataclass_and_runs(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun origin() -> Point\n"
            "    return Point { x: 0, y: 0 }\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.types), 1)
        self.assertEqual(ir_mod.types[0].name, "Point")
        self.assertEqual(
            [(f.name, f.ty) for f in ir_mod.types[0].fields],
            [("x", "Int"), ("y", "Int")],
        )
        py = compile(module, types=types)
        self.assertIn("@dataclass", py)
        self.assertIn("class Point:", py)
        ns: dict = {}
        exec(py, ns)
        origin = ns["origin"]()
        self.assertEqual(origin.x, 0)
        self.assertEqual(origin.y, 0)

    def test_sum_decl_with_mixed_variants_runs(self):
        src = (
            "type Shape =\n"
            "    Circle(Int)\n"
            "    Rect(Int, Int)\n"
            "    Unit\n"
            "fun area(s: Shape) -> Int\n"
            "    match s\n"
            "        Circle(r) ->\n"
            "            return r * r * 3\n"
            "        Rect(w, h) ->\n"
            "            return w * h\n"
            "        Unit ->\n"
            "            return 0\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        sums = [t for t in ir_mod.types if isinstance(t, N.SumDecl)]
        self.assertEqual(len(sums), 1)
        self.assertEqual([v.name for v in sums[0].variants], ["Circle", "Rect", "Unit"])
        py = compile(module, types=types)
        # Sum-type alias should appear.
        self.assertIn("Shape = Circle | Rect | Unit", py)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["area"](ns["Circle"](2)), 12)
        # Two-payload variant uses ``f0`` / ``f1`` positional fields.
        self.assertEqual(ns["area"](ns["Rect"](3, 4)), 12)
        self.assertEqual(ns["area"](ns["Unit"]()), 0)

    def test_empty_struct_emits_pass_body(self):
        src = (
            "type Empty {}\n"
            "fun make() -> Empty\n"
            "    return Empty {}\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        self.assertIn("class Empty:", py)
        self.assertIn("pass", py)
        ns: dict = {}
        exec(py, ns)
        self.assertIsInstance(ns["make"](), ns["Empty"])


class TestConstAndImport(unittest.TestCase):
    """Phase 3D: top-level ``const`` declarations and ``import``
    statements. Constants emit as module-level assignments with their
    initialiser prelude inlined. Imports always emit a breadcrumb
    comment (defence in depth): the analyzer rejects them in v1, but
    if the IR ever sees one, the emitted source must not contain a
    real Python import."""

    def test_simple_int_const(self):
        src = (
            "const MAX_RETRIES: Int = 3\n"
            "fun budget() -> Int\n"
            "    return MAX_RETRIES + 1\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.consts), 1)
        self.assertEqual(ir_mod.consts[0].name, "MAX_RETRIES")
        py = compile(module, types=types)
        self.assertIn("MAX_RETRIES = 3", py)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["budget"](), 4)

    def test_const_with_computed_value(self):
        src = (
            "const HALF: Int = 100 / 2\n"
            "fun read() -> Int\n"
            "    return HALF\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["read"](), 50)


class TestTraitsAndCapabilities(unittest.TestCase):
    """Phase 3C: ``trait`` and user-defined ``capability`` declarations.
    Both lower to an IR ``TraitDecl`` (distinguished by
    ``is_capability``); the Python emitter renders both alike as a
    shell class with stub methods plus a name alias. The substantive
    work happens in the analyzer's static trait-impl check; at the
    Python level the class only needs the attribute names to exist."""

    def test_trait_decl_emits_shell_class_and_alias(self):
        src = (
            "trait Greeter\n"
            "    fun greet(self) -> String\n"
            "type Robot {}\n"
            "impl Greeter for Robot\n"
            "    fun greet(self) -> String\n"
            "        return \"beep\"\n"
            "fun main() -> String\n"
            "    let r = Robot {}\n"
            "    return r.greet()\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.traits), 1)
        self.assertEqual(ir_mod.traits[0].name, "Greeter")
        self.assertFalse(ir_mod.traits[0].is_capability)
        py = compile(module, types=types)
        self.assertIn("class _Trait_Greeter:", py)
        self.assertIn("Greeter = _Trait_Greeter", py)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["main"](), "beep")

    def test_user_defined_capability_lowers_with_flag_set(self):
        # User-defined capabilities use the ``capability`` keyword and
        # produce a TraitDecl with ``is_capability=True``. The Python
        # emission is structurally identical to a plain trait.
        src = (
            "capability Auditable\n"
            "    fun audit(self) -> String\n"
            "type Job {\n"
            "    name: String\n"
            "}\n"
            "impl Auditable for Job\n"
            "    fun audit(self) -> String\n"
            "        return self.name\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.traits), 1)
        self.assertTrue(ir_mod.traits[0].is_capability)
        # Compile to keep the round-trip honest.
        py = compile(module, types=types)
        self.assertIn("class _Trait_Auditable:", py)


class TestImplBlocks(unittest.TestCase):
    """Phase 3B: ``impl`` blocks. The IR carries an ImplBlock per
    source impl, with methods lowered as ordinary Functions (their
    ``self`` is a regular Param). The Python emitter renders each
    method as a free function and then attaches it to the target
    class; for sum types, it attaches to every variant class because
    the union alias is not patchable."""

    def test_inherent_impl_on_struct(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "impl Point\n"
            "    fun magnitude_sq(self) -> Int\n"
            "        return self.x * self.x + self.y * self.y\n"
            "fun make() -> Int\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    return p.magnitude_sq()\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        self.assertEqual(len(ir_mod.impls), 1)
        self.assertEqual(ir_mod.impls[0].type_name, "Point")
        self.assertIsNone(ir_mod.impls[0].trait_name)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["make"](), 25)

    def test_impl_on_sum_attaches_to_each_variant(self):
        src = (
            "type Shape =\n"
            "    Circle(Int)\n"
            "    Square(Int)\n"
            "impl Shape\n"
            "    fun area(self) -> Int\n"
            "        match self\n"
            "            Circle(r) ->\n"
            "                return r * r * 3\n"
            "            Square(s) ->\n"
            "                return s * s\n"
            "fun total(a: Shape, b: Shape) -> Int\n"
            "    return a.area() + b.area()\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        # Method should be attached to both variant classes.
        self.assertIn("Circle.area = _Shape_area", py)
        self.assertIn("Square.area = _Shape_area", py)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["total"](ns["Circle"](2), ns["Square"](5)), 37)


class TestLambda(unittest.TestCase):
    """Phase 2E: lambdas. Both expression-body and block-body forms
    lower to a ``MakeLambda`` instruction; the Python emitter renders
    each as a nested ``def`` (a Python ``lambda`` expression cannot
    host the statement-level instructions ANF lowering produces, so
    we use the same ``def`` form for both source shapes)."""

    def test_expression_body_lambda_lowers_and_runs(self):
        src = (
            "fun build() -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + 1\n"
        )
        module, types = _parse_and_check(src)
        ir_mod = lower(module, types=types)
        fn = ir_mod.functions[0]
        kinds = [type(i).__name__ for i in fn.body]
        self.assertIn("MakeLambda", kinds)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        inc = ns["build"]()
        self.assertEqual(inc(41), 42)

    def test_higher_order_call_with_inline_lambda(self):
        src = (
            "fun apply(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main() -> Int\n"
            "    return apply(fun (x: Int) -> Int => x * x, 7)\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["main"](), 49)

    def test_block_body_lambda_runs(self):
        src = (
            "fun build() -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int =>\n"
            "        let y = x + 1\n"
            "        return y * 2\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        f = ns["build"]()
        self.assertEqual(f(3), 8)

    def test_lambda_captures_outer_local(self):
        # Python closures capture by reference; the IR relies on that
        # rather than emitting an explicit capture record.
        src = (
            "fun make_adder(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + n\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        add3 = ns["make_adder"](3)
        self.assertEqual(add3(4), 7)


class TestLegacyIREquivalence(unittest.TestCase):
    """Phase 4C: for a curated corpus of examples, the IR pipeline
    (compile_program) and the legacy direct transpiler must produce
    Python whose execution yields identical observable output. This
    is the load-bearing test that justifies the IR's existence: if
    these two paths ever diverge, the IR has a bug.

    Examples are picked for purity (no network, no env reads beyond
    what's necessary, no LLM calls) and IR support (they don't hit
    the still-unsupported constructs: MatchExpr, TuplePat, CharLit,
    compound assignment, identifier reference to payload-less
    variants used as values)."""

    # Curated subset: examples whose IR-emitted Python produces the
    # same observable output as the legacy transpiler's. The subset
    # excludes programs that use String / Set / Map methods whose
    # legacy dispatch (e.g. ``s.contains(x)`` -> ``(x in s)``,
    # ``set.length()`` -> ``len(set)``) has no IR counterpart yet;
    # the IR currently emits those calls verbatim, which fails on
    # Python primitives. Closing that gap is a separate Phase 4D
    # work item; for Phase 4C the goal is to pin equivalence on the
    # subset where the two paths already agree.
    _CORPUS = [
        "hello.capa",
        "closures.capa",
        "generics.capa",
        "stdlib_list.capa",
        "stdlib_map_set.capa",
        "fs_env_attenuation.capa",
        "user_capabilities.capa",
        "manifest_demo.capa",
        "demo_event_stream.capa",
        "net_attenuation.capa",
        "documented_demo.capa",
        "clock_attenuation.capa",
        "json.capa",
        "vex_demo.capa",
        "spdx_license_expr.capa",
        "spdx_parser.capa",
        "cyclonedx_parser.capa",
        "interactive.capa",
        "provenance_demo.capa",
        "sbom_diff.capa",
        "empirical_config.capa",
        "python_interop.capa",
        "cve_pickle.capa",
        "cve_pyyaml.capa",
        "cve_lxml_xxe.capa",
        "cve_jinja2_ssti.capa",
        "cve_torchtriton.capa",
        "cve_ua_parser_js.capa",
        "cve_eslint_scope.capa",
        "cve_xz_utils.capa",
        "cve_node_ipc.capa",
    ]

    def _compile_legacy(self, source: str, filename: str) -> str:
        from capa import transpile
        tokens = Lexer(source, filename=filename).lex()
        from capa import Parser as P
        module = P(tokens, source=source, filename=filename).parse_module()
        result = analyze(module, source=source, filename=filename)
        self.assertTrue(result.ok, msg=f"analyzer errors: {result.errors}")
        return transpile(
            module, filename=filename,
            types=result.types, bindings=result.bindings,
        )

    def _compile_ir(self, source: str, filename: str) -> str:
        tokens = Lexer(source, filename=filename).lex()
        from capa import Parser as P
        module = P(tokens, source=source, filename=filename).parse_module()
        result = analyze(module, source=source, filename=filename)
        self.assertTrue(result.ok, msg=f"analyzer errors: {result.errors}")
        return compile_program(module, filename=filename, types=result.types)

    def _exec_capture(self, code: str) -> str:
        import io, sys, contextlib
        run_globals: dict = {"__name__": "__main__", "__file__": "<eq>"}
        out = io.StringIO()
        saved_argv = sys.argv
        sys.argv = ["<eq>"]
        try:
            with contextlib.redirect_stdout(out):
                exec(__builtins__["compile"](code, "<eq>", "exec"), run_globals)
        except SystemExit as e:
            if isinstance(e.code, int) and e.code != 0:
                raise AssertionError(f"program exited with code {e.code}")
        finally:
            sys.argv = saved_argv
        return out.getvalue()

    def test_examples_match_legacy_output(self):
        import os
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        examples_dir = os.path.join(repo_root, "examples")
        diverged: list[tuple[str, str, str]] = []
        for name in self._CORPUS:
            path = os.path.join(examples_dir, name)
            with open(path, encoding="utf-8") as f:
                source = f.read()
            legacy_code = self._compile_legacy(source, path)
            ir_code = self._compile_ir(source, path)
            legacy_out = self._exec_capture(legacy_code)
            ir_out = self._exec_capture(ir_code)
            if legacy_out != ir_out:
                diverged.append((name, legacy_out, ir_out))
        if diverged:
            details = "\n\n".join(
                f"--- {name} ---\nlegacy:\n{lo}\nir:\n{io_}"
                for name, lo, io_ in diverged
            )
            self.fail(
                f"{len(diverged)} example(s) diverged between legacy and IR:\n"
                f"{details}"
            )


class TestCompleteProgramEmission(unittest.TestCase):
    """Phase 4A: end-to-end ``compile_program`` runs through prelude
    (runtime imports) + IR body + ``main`` bootstrap. The result must
    exec in a fresh namespace and the bootstrap must call ``main`` with
    each capability instantiated."""

    def _exec_program(self, source: str, argv=None) -> tuple[int, str, str]:
        """Compile a Capa source through the IR program pipeline and
        exec it in a fresh process-like namespace. Returns
        ``(exit_code, stdout, stderr)`` so tests can assert the
        program's observable behaviour."""
        import io, sys, contextlib
        tokens = Lexer(source).lex()
        from capa import Parser as P
        module = P(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        self.assertTrue(result.ok, msg=f"analyzer errors: {result.errors}")
        code = compile_program(module, filename="<test>", types=result.types)
        run_globals: dict = {"__name__": "__main__", "__file__": "<test>"}
        out, err = io.StringIO(), io.StringIO()
        saved_argv = sys.argv
        sys.argv = ["<test>", *(argv or [])]
        rc = 0
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                exec(__builtins__["compile"](code, "<test>", "exec"), run_globals)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
        finally:
            sys.argv = saved_argv
        return rc, out.getvalue(), err.getvalue()

    def test_hello_world_runs(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        rc, out, _ = self._exec_program(src)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "hi")

    def test_compile_program_includes_prelude_and_bootstrap(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        from capa import Parser as P
        module = P(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        code = compile_program(module, types=result.types)
        # Runtime import line and main bootstrap should both appear.
        self.assertIn("from capa.runtime import", code)
        self.assertIn('if __name__ == "__main__":', code)
        self.assertIn("main(Stdio())", code)

    def test_program_with_struct_runs(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    stdio.println(\"${p.x},${p.y}\")\n"
        )
        rc, out, _ = self._exec_program(src)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "3,4")


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
        # Both the parameter names and the addition are present.
        # Audit fix C2: Int ``+`` now routes through ``_capa_iadd`` so
        # the Python backend raises ``OverflowError`` at the same input
        # the Wasm backend traps on; asserting the literal ``+`` token
        # would regress to silent wraparound.
        self.assertIn("def add(a, b):", py)
        self.assertIn("_capa_iadd", py)
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

    def test_compound_assignment_runs(self):
        # Phase 5C: ``x += y`` rewrites to ``x = x + y`` at IR level.
        src = (
            "fun bump() -> Int\n"
            "    var x = 0\n"
            "    x += 1\n"
            "    x += 2\n"
            "    return x\n"
        )
        module, types = _parse_and_check(src)
        py = compile(module, types=types)
        ns: dict = {}
        exec(py, ns)
        self.assertEqual(ns["bump"](), 3)


if __name__ == "__main__":
    unittest.main()

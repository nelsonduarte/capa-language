"""Tests for the CIR -> WebAssembly backend (Phase 6).

Phase 6A coverage: Int / Bool arithmetic, comparisons, locals,
``if`` / ``while`` / ``break`` / ``continue`` / ``return``. We
exercise three levels of the pipeline:

1. **WAT shape**: the emitter produces valid WAT for a given Capa
   source. Pinning a few canonical snippets keeps regressions in
   the textual form visible.
2. **wasm-tools parse**: the WAT assembles to binary ``.wasm``
   without error. This proves we are speaking the actual textual
   grammar, not just something that looks like it.
3. **wasmtime-py execution**: the assembled module loads in a
   real Wasm runtime and the exported functions return the
   expected results when called from Python. This is the
   load-bearing check; everything else is plumbing.

Tests that need an external toolchain (``wasm-tools`` for parsing,
``wasmtime-py`` for execution) skip themselves cleanly if the
toolchain is missing, so the rest of the suite stays runnable on
machines without the Wasm side-stack installed.
"""

from __future__ import annotations

import shutil
import unittest

from capa import Lexer, Parser, analyze
from capa.ir import (
    lower, emit_wat, emit_wit, compile_wat, compile_wasm, compile_wit,
    collect_used_capabilities, WasmEmissionError,
    UnsupportedCapabilityMethod,
)


def _parse_lower(src: str):
    """Lex + parse + analyze + lower; returns (ir_module, types_map).
    Aborts the test if analysis fails so we get a clear message."""
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    ir_mod = lower(module, types=result.types)
    return ir_mod, result.types, module


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_py() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


class TestWasmEmissionShape(unittest.TestCase):
    """Pin the textual WAT shape for canonical CIR fragments. These
    tests never shell out, so they run on any machine."""

    def test_arithmetic_function_emits_module_and_func(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        ir_mod, types, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        # The shape we expect: a top-level (module ...) with an
        # exported (func $add ...) inside.
        self.assertIn("(module", wat)
        self.assertIn('(func $add (export "add") (param $a i64) (param $b i64) (result i64)', wat)
        self.assertIn("i64.add", wat)
        self.assertIn("return", wat)

    def test_bool_comparison_emits_i32_result(self):
        src = (
            "fun is_pos(n: Int) -> Bool\n"
            "    return n > 0\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn('(func $is_pos (export "is_pos") (param $n i64) (result i32)', wat)
        self.assertIn("i64.gt_s", wat)

    def test_unsupported_phase_construct_raises(self):
        # A string literal returning function is outside Phase 6A.
        src = (
            "fun greet() -> String\n"
            "    return \"hi\"\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)


@unittest.skipUnless(_has_wasm_tools(), "wasm-tools CLI not installed")
class TestWasmAssembles(unittest.TestCase):
    """Send the emitted WAT through ``wasm-tools parse``. If the
    grammar is wrong, the parser tells us; the test asserts a
    non-empty binary came back."""

    def test_arithmetic_function_assembles(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        # Wasm binaries start with the magic bytes ``\x00asm`` and a
        # version field. The component model wraps this in additional
        # layers; Phase 6A emits core wasm so the magic must be
        # right at the start.
        self.assertTrue(blob.startswith(b"\x00asm"))
        self.assertGreater(len(blob), 8)

    def test_while_loop_assembles(self):
        src = (
            "fun count(n: Int) -> Int\n"
            "    var x = 0\n"
            "    while x < n\n"
            "        x = x + 1\n"
            "    return x\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        self.assertTrue(blob.startswith(b"\x00asm"))


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmExecutes(unittest.TestCase):
    """Load the assembled binary in wasmtime and call the exported
    functions from Python. The contract: identical numeric output
    to what a hand-written Capa-to-Python transpile would produce."""

    def _exec(self, src: str, fn_name: str, *args):
        """Compile a Capa source to Wasm bytes, instantiate in
        wasmtime, call ``fn_name`` with ``args``, return the
        result. Each call gets a fresh Store so per-test state is
        isolated."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        mod = wasmtime.Module(engine, blob)
        instance = wasmtime.Instance(store, mod, [])
        fn = instance.exports(store)[fn_name]
        return fn(store, *args)

    def test_add(self):
        src = "fun add(a: Int, b: Int) -> Int\n    return a + b\n"
        self.assertEqual(self._exec(src, "add", 3, 4), 7)
        self.assertEqual(self._exec(src, "add", -10, 5), -5)
        self.assertEqual(self._exec(src, "add", 0, 0), 0)

    def test_arithmetic_ops(self):
        src = (
            "fun arith(a: Int, b: Int) -> Int\n"
            "    let s = a + b\n"
            "    let d = s * 2\n"
            "    return d - 1\n"
        )
        # (3 + 4) * 2 - 1 = 13
        self.assertEqual(self._exec(src, "arith", 3, 4), 13)

    def test_int_division_and_modulo(self):
        src = (
            "fun divmod(a: Int, b: Int) -> Int\n"
            "    let q = a / b\n"
            "    let r = a % b\n"
            "    return q * 1000 + r\n"
        )
        # 17 / 5 = 3, 17 % 5 = 2 -> 3002
        self.assertEqual(self._exec(src, "divmod", 17, 5), 3002)

    def test_comparison_returns_bool(self):
        src = "fun is_pos(n: Int) -> Bool\n    return n > 0\n"
        # Wasm returns i32 0/1; wasmtime maps that to Python int.
        self.assertEqual(self._exec(src, "is_pos", 5), 1)
        self.assertEqual(self._exec(src, "is_pos", -3), 0)
        self.assertEqual(self._exec(src, "is_pos", 0), 0)

    def test_if_else(self):
        src = (
            "fun pick(b: Bool) -> Int\n"
            "    if b\n"
            "        return 100\n"
            "    return 200\n"
        )
        self.assertEqual(self._exec(src, "pick", 1), 100)
        self.assertEqual(self._exec(src, "pick", 0), 200)

    def test_while_loop_counts(self):
        src = (
            "fun count(n: Int) -> Int\n"
            "    var x = 0\n"
            "    while x < n\n"
            "        x = x + 1\n"
            "    return x\n"
        )
        self.assertEqual(self._exec(src, "count", 5), 5)
        self.assertEqual(self._exec(src, "count", 0), 0)
        self.assertEqual(self._exec(src, "count", 100), 100)

    def test_while_with_break(self):
        src = (
            "fun first_match(n: Int) -> Int\n"
            "    var i = 0\n"
            "    while i < 1000\n"
            "        if i >= n\n"
            "            break\n"
            "        i = i + 1\n"
            "    return i\n"
        )
        self.assertEqual(self._exec(src, "first_match", 7), 7)
        self.assertEqual(self._exec(src, "first_match", 2000), 1000)

    def test_unary_negation(self):
        src = "fun neg(n: Int) -> Int\n    return -n\n"
        self.assertEqual(self._exec(src, "neg", 5), -5)
        self.assertEqual(self._exec(src, "neg", -5), 5)
        self.assertEqual(self._exec(src, "neg", 0), 0)

    def test_short_circuit_and(self):
        # The IR rewrites ``and`` to a short-circuit ``if``; the
        # right operand never evaluates when the left is false.
        # We can't observe that directly through a pure-Int test,
        # but we can verify the boolean result is correct.
        src = (
            "fun both_pos(a: Int, b: Int) -> Bool\n"
            "    return a > 0 and b > 0\n"
        )
        self.assertEqual(self._exec(src, "both_pos", 1, 2), 1)
        self.assertEqual(self._exec(src, "both_pos", 1, -1), 0)
        self.assertEqual(self._exec(src, "both_pos", -1, 5), 0)


class TestWitGeneration(unittest.TestCase):
    """Phase 6B: WIT file generation from CIR. Tests the structural
    output (interface declarations + world) for canonical programs.
    Does not shell out to wasm-tools; just checks the textual form."""

    def test_program_with_stdio_emits_stdio_interface(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("package capa:generated;", wit)
        self.assertIn("interface stdio {", wit)
        self.assertIn("println: func(msg: string);", wit)
        self.assertIn("world program {", wit)
        self.assertIn("import stdio;", wit)

    def test_program_using_multiple_stdio_methods(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"a\")\n"
            "    stdio.println(\"b\")\n"
            "    stdio.eprintln(\"err\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        # All three methods must show up. Order is deterministic
        # (we sort by name) but using substring search across
        # "print:" / "println:" is brittle because "print" is a
        # prefix of "println"; check on full lines instead.
        self.assertIn("print: func(msg: string);", wit)
        self.assertIn("println: func(msg: string);", wit)
        self.assertIn("eprintln: func(msg: string);", wit)

    def test_program_without_capabilities_has_no_imports(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        # The world is still emitted (caller may want to package it
        # as a component) but with no imports.
        self.assertIn("world program {", wit)
        self.assertNotIn("interface", wit)
        self.assertNotIn("import", wit)

    def test_collect_used_capabilities_groups_by_capability(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\")\n"
            "    stdio.eprintln(\"b\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        used = collect_used_capabilities(ir_mod)
        self.assertEqual(used, {"Stdio": {"println", "eprintln"}})

    def test_unsupported_cap_method_raises_at_wit_gen(self):
        # ``read_line`` is a real Stdio method but Phase 6B does not
        # yet have a WIT signature for it (returns Result<String, IoError>
        # which needs Phase 6C+ to encode). The WIT generator must
        # surface the gap as a precise error rather than emit a
        # half-defined interface.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let line = stdio.read_line()\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(UnsupportedCapabilityMethod):
            emit_wit(ir_mod)


class TestWasmStdioEmission(unittest.TestCase):
    """Phase 6B Wasm-side emission of capability method calls.
    Pure shape tests (no toolchain shell-out)."""

    def test_emits_stdio_import(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn(
            '(import "capa:stdio" "println" '
            '(func $Stdio_println (param i32) (param i32))',
            wat,
        )

    def test_main_export_drops_capability_param(self):
        # ``main(stdio: Stdio)`` has no Wasm-level parameters because
        # the capability is provided via imports, not as a value.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn('(func $main (export "main")', wat)
        self.assertNotIn("$stdio", wat)

    def test_string_literal_lowers_to_data_segment(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn('(memory (export "memory") 1)', wat)
        self.assertIn('(data (i32.const 0) "hi")', wat)

    def test_non_string_method_call_raises(self):
        # No String type for non-capability method calls yet.
        src = (
            "fun greet(name: String) -> String\n"
            "    return name.to_upper()\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStdioExecutes(unittest.TestCase):
    """End-to-end: Capa -> CIR -> WAT -> .wasm -> wasmtime with
    a Python host bridge providing the ``capa:stdio`` interface."""

    def _run_capturing_stdout(self, src: str) -> tuple[str, str]:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            host.run_main(blob)
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        return out.getvalue(), err.getvalue()

    def test_hello_world(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hello from wasm\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hello from wasm\n")

    def test_print_does_not_append_newline(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"no newline\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "no newline")

    def test_multiple_prints_in_order(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"line one\")\n"
            "    stdio.println(\"line two\")\n"
            "    stdio.println(\"line three\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "line one\nline two\nline three\n")

    def test_eprintln_goes_to_stderr(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(\"warn\")\n"
        )
        out, err = self._run_capturing_stdout(src)
        self.assertEqual(out, "")
        self.assertEqual(err, "warn\n")

    def test_utf8_in_string_literal(self):
        # Non-ASCII characters survive UTF-8 encoding through the
        # data segment + host decode round-trip.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"olá, mundo\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "olá, mundo\n")

    def test_user_function_call_with_capability_arg(self):
        # ``greet`` takes a Stdio param and a Bool. The Wasm signature
        # drops Stdio; the call site at ``main`` passes only the Bool.
        # The capability flows through the module-level import.
        src = (
            "fun greet(stdio: Stdio, friendly: Bool)\n"
            "    if friendly\n"
            "        stdio.println(\"hi\")\n"
            "    else\n"
            "        stdio.println(\"bye\")\n"
            "fun main(stdio: Stdio)\n"
            "    greet(stdio, true)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hi\n")

    def test_string_literals_are_pooled(self):
        # Two identical literals should share a single data-segment
        # entry (verified indirectly: the emitted WAT only mentions
        # the literal once).
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
            "    stdio.println(\"hi\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertEqual(wat.count('(data (i32.const 0) "hi")'), 1)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmSumAndStruct(unittest.TestCase):
    """Phase 6C: sum types, structs, and pattern matching compile
    to a heap-allocator-backed memory layout and execute on
    wasmtime end-to-end.

    Layout invariants the tests rely on:
    - A sum type lays out a 4-byte discriminant at offset 0, then
      per-variant payloads starting at offset 8 (i64 alignment).
    - A struct lays out fields in declaration order with natural
      alignment; the resulting size is rounded up to 8 bytes.
    - All values larger than a single primitive are referenced by
      i32 pointer; Python sees opaque integers and can pass them
      back to subsequent calls."""

    def _exec(self, src: str, fn_name: str, *args):
        """Compile a Capa source to Wasm, instantiate without any
        host imports (Phase 6C tests don't use Stdio), call
        ``fn_name`` with ``args`` and return the result. Each call
        uses a fresh Store + Linker so per-test heap state is
        isolated."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return instance.exports(store)[fn_name](store, *args)

    def _make_and_call(self, src: str, ctor: str, ctor_args, op: str, op_args=()):
        """Two-call helper: first instantiate the module once,
        invoke the constructor to get a pointer, then invoke the
        operator with that pointer. Pinning the same Store across
        calls is required because the heap pointer in the wasm
        module is per-instance state."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        exp = instance.exports(store)
        ptr = exp[ctor](store, *ctor_args)
        return exp[op](store, ptr, *op_args)

    def test_struct_make_and_field_access(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun make(a: Int, b: Int) -> Point\n"
            "    return Point { x: a, y: b }\n"
            "fun get_x(p: Point) -> Int\n"
            "    return p.x\n"
            "fun get_y(p: Point) -> Int\n"
            "    return p.y\n"
        )
        # Construct once, read both fields back, confirm they round-trip.
        self.assertEqual(self._make_and_call(src, "make", (10, 20), "get_x"), 10)
        self.assertEqual(self._make_and_call(src, "make", (10, 20), "get_y"), 20)

    def test_struct_magnitude_sq(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun make(a: Int, b: Int) -> Point\n"
            "    return Point { x: a, y: b }\n"
            "fun mag_sq(p: Point) -> Int\n"
            "    return p.x * p.x + p.y * p.y\n"
        )
        self.assertEqual(self._make_and_call(src, "make", (3, 4), "mag_sq"), 25)
        self.assertEqual(self._make_and_call(src, "make", (5, 12), "mag_sq"), 169)

    def test_sum_two_variants_with_payload(self):
        src = (
            "type Shape =\n"
            "    Circle(Int)\n"
            "    Rect(Int, Int)\n"
            "fun area(s: Shape) -> Int\n"
            "    match s\n"
            "        Circle(r) -> return r * r * 3\n"
            "        Rect(w, h) -> return w * h\n"
            "fun mk_circle(r: Int) -> Shape\n"
            "    return Circle(r)\n"
            "fun mk_rect(w: Int, h: Int) -> Shape\n"
            "    return Rect(w, h)\n"
        )
        # Approximation of pi=3; pinning the value as 5*5*3 = 75.
        self.assertEqual(self._make_and_call(src, "mk_circle", (5,), "area"), 75)
        self.assertEqual(self._make_and_call(src, "mk_rect", (3, 4), "area"), 12)
        self.assertEqual(self._make_and_call(src, "mk_rect", (7, 6), "area"), 42)

    def test_sum_wildcard_arm_matches(self):
        src = (
            "type Choice =\n"
            "    Left(Int)\n"
            "    Right(Int)\n"
            "    Neither\n"
            "fun extract(c: Choice) -> Int\n"
            "    match c\n"
            "        Left(n) -> return n\n"
            "        _ -> return 0\n"
            "fun mk_left(n: Int) -> Choice\n"
            "    return Left(n)\n"
            "fun mk_right(n: Int) -> Choice\n"
            "    return Right(n)\n"
            "fun mk_neither() -> Choice\n"
            "    return Neither\n"
        )
        self.assertEqual(self._make_and_call(src, "mk_left", (42,), "extract"), 42)
        self.assertEqual(self._make_and_call(src, "mk_right", (7,), "extract"), 0)
        self.assertEqual(self._make_and_call(src, "mk_neither", (), "extract"), 0)

    def test_struct_allocator_advances_heap(self):
        # Build two structs and confirm they receive distinct
        # pointers (allocator is monotonic; same-Store calls share
        # the heap).
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun mk(a: Int, b: Int) -> Point\n"
            "    return Point { x: a, y: b }\n"
            "fun diff(p: Point, q: Point) -> Int\n"
            "    return p.x - q.x\n"
        )
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        exp = instance.exports(store)
        p = exp["mk"](store, 100, 200)
        q = exp["mk"](store, 1, 2)
        self.assertNotEqual(p, q, "allocator must hand out distinct pointers")
        self.assertEqual(exp["diff"](store, p, q), 99)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringLocals(unittest.TestCase):
    """Phase 6D-1: String values backed by a (ptr, len) i32 pair.
    A String local declares two Wasm locals (``$name_ptr`` /
    ``$name_len``); String params expand to two i32 params at the
    function signature. String literals and locals can be passed
    interchangeably to capability methods and user functions."""

    def _run_capturing_stdout(self, src: str) -> tuple[str, str]:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            host.run_main(blob)
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        return out.getvalue(), err.getvalue()

    def test_string_local_used_in_println(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let msg = \"hello from a local\"\n"
            "    stdio.println(msg)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hello from a local\n")

    def test_string_param_in_user_function(self):
        src = (
            "fun say(stdio: Stdio, msg: String)\n"
            "    stdio.println(msg)\n"
            "fun main(stdio: Stdio)\n"
            "    say(stdio, \"forwarded literal\")\n"
            "    let s = \"forwarded local\"\n"
            "    say(stdio, s)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(
            out,
            "forwarded literal\nforwarded local\n",
        )

    def test_string_reassign_to_local(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    var msg = \"first\"\n"
            "    stdio.println(msg)\n"
            "    msg = \"second\"\n"
            "    stdio.println(msg)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "first\nsecond\n")


if __name__ == "__main__":
    unittest.main()

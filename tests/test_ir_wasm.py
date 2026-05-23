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
        # Set methods land in a later 6D sub-phase; pin the gap.
        src = (
            "fun has(s: Set<Int>, n: Int) -> Bool\n"
            "    return s.contains(n)\n"
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
        self.assertIn("package capa:host;", wit)
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
            '(import "capa:host/stdio" "println" '
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

    def test_unsupported_method_raises(self):
        # ``replace`` still raises (Phase 6D-4 deferred);
        # ``split`` itself works as of Phase 6H.
        src = (
            "fun cleaned(s: String) -> String\n"
            "    return s.replace(\",\", \";\")\n"
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


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmListInt(unittest.TestCase):
    """Phase 6D-2: List<Int> backed by a 16-byte header + grow-
    able element array. Methods covered: length, is_empty, push
    (with realloc via memory.copy), iteration via ``for``,
    indexing via ``xs[i]``."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def test_literal_length_and_iteration(self):
        src = (
            "fun sum_list(xs: List<Int>) -> Int\n"
            "    var total = 0\n"
            "    for x in xs\n"
            "        total = total + x\n"
            "    return total\n"
            "fun build() -> List<Int>\n"
            "    let xs = [10, 20, 30, 40]\n"
            "    return xs\n"
        )
        store, exp = self._instantiate(src)
        xs = exp["build"](store)
        self.assertEqual(exp["sum_list"](store, xs), 100)

    def test_push_then_iterate(self):
        src = (
            "fun build_and_sum() -> Int\n"
            "    let xs: List<Int> = []\n"
            "    xs.push(7)\n"
            "    xs.push(14)\n"
            "    xs.push(21)\n"
            "    xs.push(28)\n"
            "    var total = 0\n"
            "    for x in xs\n"
            "        total = total + x\n"
            "    return total\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["build_and_sum"](store), 70)

    def test_length_and_is_empty(self):
        src = (
            "fun len_of() -> Int\n"
            "    let xs = [1, 2, 3, 4, 5]\n"
            "    return xs.length()\n"
            "fun empty_check() -> Bool\n"
            "    let xs: List<Int> = []\n"
            "    return xs.is_empty()\n"
            "fun nonempty_check() -> Bool\n"
            "    let xs = [1]\n"
            "    return xs.is_empty()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["len_of"](store), 5)
        self.assertEqual(exp["empty_check"](store), 1)
        self.assertEqual(exp["nonempty_check"](store), 0)

    def test_indexing_by_position(self):
        src = (
            "fun pick(i: Int) -> Int\n"
            "    let xs = [100, 200, 300, 400]\n"
            "    return xs[i]\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["pick"](store, 0), 100)
        self.assertEqual(exp["pick"](store, 2), 300)
        self.assertEqual(exp["pick"](store, 3), 400)

    def test_push_grows_beyond_initial_capacity(self):
        # Initial cap is 8 for empty literals; pushing more than 8
        # forces the data array to grow via memory.copy. This pins
        # the grow path against accidentally clobbering elements.
        src = (
            "fun build_big() -> Int\n"
            "    let xs: List<Int> = []\n"
            "    var i = 0\n"
            "    while i < 50\n"
            "        xs.push(i)\n"
            "        i = i + 1\n"
            "    var total = 0\n"
            "    for x in xs\n"
            "        total = total + x\n"
            "    return total\n"
        )
        store, exp = self._instantiate(src)
        # 0 + 1 + ... + 49 = 1225
        self.assertEqual(exp["build_big"](store), 1225)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmMapStringInt(unittest.TestCase):
    """Phase 6D-3: Map<String, Int> backed by a 16-byte header
    (len, cap, data_ptr, padding) + a linear array of 16-byte
    (key_ptr, key_len, value) triples. Methods covered: set
    (with grow + key-overwrite), get (returning Option<Int>),
    contains_key, length, is_empty.

    Strings are compared via the inline ``$str_eq`` helper that
    the emitter writes alongside ``$alloc`` whenever the module
    touches a Map. Phase 6D-3 only supports String keys; richer
    key types wait until the pair slot layout becomes
    configurable in a later phase."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def test_set_and_length_distinct_keys(self):
        src = (
            "fun build() -> Int\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 10)\n"
            "    m.set(\"b\", 20)\n"
            "    m.set(\"c\", 30)\n"
            "    return m.length()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["build"](store), 3)

    def test_set_overwrite_does_not_grow_length(self):
        src = (
            "fun build() -> Int\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    m.set(\"a\", 99)\n"
            "    m.set(\"a\", 7)\n"
            "    return m.length()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["build"](store), 1)

    def test_get_returns_some_on_hit(self):
        src = (
            "fun apples() -> Int\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"apples\", 5)\n"
            "    m.set(\"oranges\", 3)\n"
            "    match m.get(\"apples\")\n"
            "        Some(n) -> return n\n"
            "        None -> return -1\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["apples"](store), 5)

    def test_get_returns_none_on_miss(self):
        src = (
            "fun bananas() -> Int\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"apples\", 5)\n"
            "    match m.get(\"bananas\")\n"
            "        Some(n) -> return n\n"
            "        None -> return -1\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["bananas"](store), -1)

    def test_overwrite_then_get_returns_new_value(self):
        src = (
            "fun overwrite() -> Int\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    m.set(\"a\", 99)\n"
            "    match m.get(\"a\")\n"
            "        Some(n) -> return n\n"
            "        None -> return 0\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["overwrite"](store), 99)

    def test_contains_key_hit_and_miss(self):
        src = (
            "fun has_a() -> Bool\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    return m.contains_key(\"a\")\n"
            "fun has_z() -> Bool\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    return m.contains_key(\"z\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["has_a"](store), 1)
        self.assertEqual(exp["has_z"](store), 0)

    def test_is_empty_before_and_after_insert(self):
        src = (
            "fun empty_at_start() -> Bool\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    return m.is_empty()\n"
            "fun empty_after_insert() -> Bool\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"k\", 1)\n"
            "    return m.is_empty()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["empty_at_start"](store), 1)
        self.assertEqual(exp["empty_after_insert"](store), 0)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringMethods(unittest.TestCase):
    """Phase 6D-4: String methods backed by (ptr, len) pair
    semantics. Read-only methods (length, contains, starts_with,
    ends_with, is_empty) compute over the receiver bytes without
    allocating. Transforming methods (substring, to_upper,
    to_lower, trim) allocate fresh buffers via ``$alloc`` and
    return new (ptr, len) pairs. String returns use Wasm 2.0
    multi-value ``(result i32 i32)``."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def _read_string(self, store, exports, name: str) -> str:
        """Call a no-arg function returning String (multi-value
        i32 ptr, i32 len) and decode the result via the module's
        exported memory. wasmtime maps multi-value to a tuple."""
        result = exports[name](store)
        ptr, length = result
        data = exports["memory"].read(store, ptr, ptr + length)
        return bytes(data).decode("utf-8")

    def test_length_and_is_empty(self):
        src = (
            "fun len_hello() -> Int\n"
            "    return \"hello\".length()\n"
            "fun empty1() -> Bool\n"
            "    return \"\".is_empty()\n"
            "fun empty2() -> Bool\n"
            "    return \"x\".is_empty()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["len_hello"](store), 5)
        self.assertEqual(exp["empty1"](store), 1)
        self.assertEqual(exp["empty2"](store), 0)

    def test_starts_with(self):
        src = (
            "fun yes() -> Bool\n"
            "    return \"hello world\".starts_with(\"hello\")\n"
            "fun no_mismatch() -> Bool\n"
            "    return \"hello world\".starts_with(\"world\")\n"
            "fun no_longer_than_self() -> Bool\n"
            "    return \"hi\".starts_with(\"hello\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["yes"](store), 1)
        self.assertEqual(exp["no_mismatch"](store), 0)
        self.assertEqual(exp["no_longer_than_self"](store), 0)

    def test_ends_with(self):
        src = (
            "fun yes() -> Bool\n"
            "    return \"hello world\".ends_with(\"world\")\n"
            "fun no_mismatch() -> Bool\n"
            "    return \"hello world\".ends_with(\"hello\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["yes"](store), 1)
        self.assertEqual(exp["no_mismatch"](store), 0)

    def test_contains(self):
        src = (
            "fun mid() -> Bool\n"
            "    return \"hello world\".contains(\"o w\")\n"
            "fun start() -> Bool\n"
            "    return \"hello world\".contains(\"hello\")\n"
            "fun end() -> Bool\n"
            "    return \"hello world\".contains(\"world\")\n"
            "fun missing() -> Bool\n"
            "    return \"hello world\".contains(\"xyz\")\n"
            "fun empty_needle() -> Bool\n"
            "    return \"hello\".contains(\"\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["mid"](store), 1)
        self.assertEqual(exp["start"](store), 1)
        self.assertEqual(exp["end"](store), 1)
        self.assertEqual(exp["missing"](store), 0)
        self.assertEqual(exp["empty_needle"](store), 1)

    def test_substring(self):
        src = (
            "fun mid() -> String\n"
            "    return \"hello world\".substring(6, 11)\n"
            "fun empty() -> String\n"
            "    return \"hello\".substring(2, 2)\n"
            "fun whole() -> String\n"
            "    return \"abc\".substring(0, 3)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "mid"), "world")
        self.assertEqual(self._read_string(store, exp, "empty"), "")
        self.assertEqual(self._read_string(store, exp, "whole"), "abc")

    def test_to_upper_and_to_lower(self):
        src = (
            "fun upper() -> String\n"
            "    return \"hello world\".to_upper()\n"
            "fun lower() -> String\n"
            "    return \"HELLO WORLD\".to_lower()\n"
            "fun mixed() -> String\n"
            "    return \"Hello, World!\".to_upper()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "upper"), "HELLO WORLD")
        self.assertEqual(self._read_string(store, exp, "lower"), "hello world")
        self.assertEqual(self._read_string(store, exp, "mixed"), "HELLO, WORLD!")

    def test_trim_variants(self):
        src = (
            "fun both() -> String\n"
            "    return \"  spaced  \".trim()\n"
            "fun left() -> String\n"
            "    return \"  spaced  \".trim_start()\n"
            "fun right() -> String\n"
            "    return \"  spaced  \".trim_end()\n"
            "fun mixed_ws() -> String\n"
            "    return \"\\t\\n  hi  \\r\\n\".trim()\n"
            "fun no_trim_needed() -> String\n"
            "    return \"abc\".trim()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "both"), "spaced")
        self.assertEqual(self._read_string(store, exp, "left"), "spaced  ")
        self.assertEqual(self._read_string(store, exp, "right"), "  spaced")
        self.assertEqual(self._read_string(store, exp, "mixed_ws"), "hi")
        self.assertEqual(self._read_string(store, exp, "no_trim_needed"), "abc")

    def test_string_method_chaining(self):
        # Verify that the result of one string method can be the
        # receiver of another. Locals carry the (ptr, len) pair so
        # this works without explicit temp variables.
        src = (
            "fun pipeline() -> String\n"
            "    let s = \"  Hello, World!  \"\n"
            "    let t = s.trim()\n"
            "    return t.to_upper()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(
            self._read_string(store, exp, "pipeline"),
            "HELLO, WORLD!",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFloatAndClock(unittest.TestCase):
    """Phase 7A: Capa ``Float`` lowers to Wasm ``f64``; arithmetic
    and comparison ops dispatch on operand type. ``Clock.now_secs``
    / ``now_monotonic`` are imported as capability methods
    returning ``f64`` and bound to Python's ``time`` module via
    the WasmHost bridge."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def test_float_arithmetic_round_trip(self):
        src = (
            "fun three_quarters() -> Float\n"
            "    return 0.5 + 0.25\n"
            "fun divide() -> Float\n"
            "    return 1.0 / 4.0\n"
            "fun multiply() -> Float\n"
            "    return 1.5 * 2.0\n"
            "fun subtract() -> Float\n"
            "    return 1.0 - 0.25\n"
        )
        store, exp = self._instantiate(src)
        self.assertAlmostEqual(exp["three_quarters"](store), 0.75)
        self.assertAlmostEqual(exp["divide"](store), 0.25)
        self.assertAlmostEqual(exp["multiply"](store), 3.0)
        self.assertAlmostEqual(exp["subtract"](store), 0.75)

    def test_float_comparison_returns_bool(self):
        src = (
            "fun positive(f: Float) -> Bool\n"
            "    return f > 0.0\n"
            "fun negative(f: Float) -> Bool\n"
            "    return f < 0.0\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["positive"](store, 5.0), 1)
        self.assertEqual(exp["positive"](store, -3.0), 0)
        self.assertEqual(exp["negative"](store, -3.0), 1)
        self.assertEqual(exp["negative"](store, 5.0), 0)

    def test_clock_capability_via_host(self):
        # Compile with a Clock parameter. The Wasm signature drops
        # the capability param itself; the methods are imported via
        # capa:host/clock and resolved by the WasmHost.
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun now_positive(clock: Clock) -> Bool\n"
            "    let t = clock.now_secs()\n"
            "    return t > 0.0\n"
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if now_positive(clock)\n"
            "        stdio.println(\"clock OK\")\n"
            "    else\n"
            "        stdio.println(\"clock NOT OK\")\n"
        )
        import io, sys
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "clock OK\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmEnv(unittest.TestCase):
    """Phase 7B: Env.get returns Option<String>, with the host
    bridge allocating both the Option container and the string
    payload bytes via the module's exported \\$alloc. String
    payloads are packed into the 8-byte Option slot as
    (ptr low, len high); the match emitter unpacks at the
    Some-binding site."""

    def test_env_get_hit_and_miss(self):
        import os
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun lookup(stdio: Stdio, env: Env, key: String)\n"
            "    match env.get(key)\n"
            "        Some(v) -> stdio.println(\"hit: ${v}\")\n"
            "        None -> stdio.println(\"miss\")\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    lookup(stdio, env, \"CAPA_WASM_TEST_HIT\")\n"
            "    lookup(stdio, env, \"DEFINITELY_NOT_SET_XYZ\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        os.environ["CAPA_WASM_TEST_HIT"] = "found-value"
        os.environ.pop("DEFINITELY_NOT_SET_XYZ", None)
        try:
            import io, sys
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            lines = out.getvalue().strip().split("\n")
            self.assertEqual(lines, ["hit: found-value", "miss"])
        finally:
            os.environ.pop("CAPA_WASM_TEST_HIT", None)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFs(unittest.TestCase):
    """Phase 7C: Fs.read / Fs.write return Result<T, IoError>. The
    host bridge constructs Result + IoError records in wasm
    memory via the module's exported \\$alloc. Pattern matching
    on Ok / Err works through the existing match emitter, with
    String payloads unpacked from the i64 slot and IoError
    pointer payloads i32-wrapped at the bind site."""

    def test_fs_round_trip(self):
        import os
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "out.txt").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                "    match fs.write(\"" + target + "\", \"hello-fs\")\n"
                "        Ok(_) -> stdio.println(\"wrote\")\n"
                "        Err(_) -> stdio.eprintln(\"write failed\")\n"
                "    match fs.read(\"" + target + "\")\n"
                "        Ok(text) -> stdio.println(\"read: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"read failed\")\n"
            )
            _, types, ast_mod = _parse_lower(src)
            blob = compile_wasm(ast_mod, types=types)
            import io, sys
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            self.assertEqual(out.getvalue(), "wrote\nread: hello-fs\n")

    def test_fs_read_missing_returns_err(self):
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"/does/not/exist/xyz\")\n"
            "        Ok(_) -> stdio.println(\"BUG\")\n"
            "        Err(_) -> stdio.println(\"missing\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        import io, sys
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "missing\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmClosures(unittest.TestCase):
    """Phase 6E: closure conversion in the Wasm backend. Lambdas
    lift to top-level functions with an env_ptr first parameter;
    captured locals are read from a heap-allocated env record;
    the closure value packs (fn_idx << 32) | env_ptr into an i64.

    Tests pin: no-capture apply pattern, Int capture, List<Int>
    map/filter/fold via call_indirect."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def test_apply_pattern_no_capture(self):
        src = (
            "fun apply(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main() -> Int\n"
            "    return apply(fun (x: Int) -> Int => x * 2, 5)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 10)

    def test_int_capture(self):
        src = (
            "fun make_adder(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + n\n"
            "fun main() -> Int\n"
            "    let add7 = make_adder(7)\n"
            "    return add7(3)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 10)

    def test_list_map_int(self):
        src = (
            "fun main() -> Int\n"
            "    let xs = [1, 2, 3, 4]\n"
            "    let ys = xs.map(fun (x: Int) -> Int => x * x)\n"
            "    return ys[3]\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 16)

    def test_list_filter_int(self):
        src = (
            "fun main() -> Int\n"
            "    let xs = [1, 2, 3, 4, 5, 6]\n"
            "    let evens = xs.filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    return evens[2]\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 6)

    def test_list_fold_int(self):
        src = (
            "fun main() -> Int\n"
            "    let xs = [1, 2, 3, 4, 5]\n"
            "    return xs.fold(0, fun (acc: Int, x: Int) -> Int => acc + x)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 15)

    def test_capture_in_hof(self):
        src = (
            "fun main() -> Int\n"
            "    let factor = 10\n"
            "    let xs = [1, 2, 3]\n"
            "    let scaled = xs.map(fun (x: Int) -> Int => x * factor)\n"
            "    return scaled[2]\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 30)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmJson(unittest.TestCase):
    """Phase 6G end-to-end JsonValue support: variant constructors,
    method dispatch (as_X / is_null), and the parse_json / to_json
    host bridge.

    Each test drives a small main() through the WasmHost so the
    full pipeline (CIR -> WAT -> wasm -> host imports) is
    exercised. Output is checked against the expected stdout."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_jstr_construct_and_match(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("hello")\n'
            '    match j\n'
            '        JStr(s) -> stdio.println(s)\n'
            '        _ -> stdio.println("other")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "hello\n")

    def test_jnum_construct_and_match(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(3.5)\n'
            '    match j\n'
            '        JNum(v) -> stdio.println("got ${v}")\n'
            '        _       -> stdio.println("other")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "got 3.500000\n",
        )

    def test_jnull_via_parse(self):
        # JNull as a bare identifier hits a gap in the IR lowerer
        # (it only registers user-declared payloadless variants);
        # exercise the same code path via parse_json("null") which
        # produces a JNull, then is_null() projects it back to Bool.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_json("null")\n'
            '        Ok(jv) ->\n'
            '            if jv.is_null()\n'
            '                stdio.println("null")\n'
            '            else\n'
            '                stdio.println("not null")\n'
            '        Err(_) -> stdio.println("parse err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "null\n")

    def test_as_string_some_on_jstr(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("abc")\n'
            '    match j.as_string()\n'
            '        Some(s) -> stdio.println("got ${s}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got abc\n")

    def test_as_string_none_on_other_variant(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(1.0)\n'
            '    match j.as_string()\n'
            '        Some(_) -> stdio.println("got string")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "none\n")

    def test_parse_json_array(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let txt = "[1, 2, 3]"\n'
            '    match parse_json(txt)\n'
            '        Ok(jv) ->\n'
            '            match jv.as_array()\n'
            '                Some(arr) -> stdio.println("len=${arr.length()}")\n'
            '                None      -> stdio.println("not array")\n'
            '        Err(_) -> stdio.println("parse error")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "len=3\n")

    def test_parse_json_object_key_lookup(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let txt = "{\\"name\\": \\"alice\\"}"\n'
            '    match parse_json(txt)\n'
            '        Ok(jv) ->\n'
            '            match jv.as_object()\n'
            '                Some(obj) ->\n'
            '                    match obj.get("name")\n'
            '                        Some(jname) ->\n'
            '                            match jname.as_string()\n'
            '                                Some(s) -> stdio.println(s)\n'
            '                                None    -> stdio.println("not string")\n'
            '                        None -> stdio.println("no key")\n'
            '                None -> stdio.println("not object")\n'
            '        Err(_) -> stdio.println("parse error")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alice\n")

    def test_parse_json_malformed_returns_err(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_json("not json")\n'
            '        Ok(_) -> stdio.println("unexpected ok")\n'
            '        Err(_) -> stdio.println("got err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got err\n")

    def test_to_json_array_round_trip(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let built = JArr([JStr("a"), JNum(1.5), JBool(true)])\n'
            '    stdio.println(to_json(built))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), '["a", 1.5, true]\n',
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringSplit(unittest.TestCase):
    """Phase 6H: String.split(sep) -> List<String> via single-char
    separator. Also exercises the new List<String> baseline
    (literal + index + iter) that the same change unlocks."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_list_string_literal_and_index(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = ["alpha", "beta", "gamma"]\n'
            '    stdio.println(xs[0])\n'
            '    stdio.println(xs[2])\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alpha\ngamma\n")

    def test_list_string_for_iteration(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = ["one", "two", "three"]\n'
            '    for s in xs\n'
            '        stdio.println(s)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "one\ntwo\nthree\n",
        )

    def test_split_simple(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,b,c".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println(parts[0])\n'
            '    stdio.println(parts[1])\n'
            '    stdio.println(parts[2])\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\na\nb\nc\n",
        )

    def test_split_no_separator_found(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "abc".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println(parts[0])\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=1\nabc\n",
        )

    def test_split_trailing_separator(self):
        # "a,,c" produces 3 elements with the middle one empty.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,,c".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println("mid_empty=${parts[1].is_empty()}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\nmid_empty=true\n",
        )

    def test_split_dotted_path(self):
        # policy-eval pattern: a.b.c -> ["a", "b", "c"]
        src = (
            'fun main(stdio: Stdio)\n'
            '    let segs = "config.encryption.enabled".split(".")\n'
            '    for s in segs\n'
            '        stdio.println(s)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "config\nencryption\nenabled\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmOptionResult(unittest.TestCase):
    """Phase 6I: Option<T> and Result<T, E> method dispatch.
    Covers is_some / is_none / is_ok / is_err (tag check returning
    Bool) and unwrap_or(default) for the four payload shapes
    policy-eval exercises (Int / Bool / Float / String)."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_option_is_some_is_none(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s: Option<Int> = Some(7)\n'
            '    let n: Option<Int> = None\n'
            '    stdio.println("s_is_some=${s.is_some()}")\n'
            '    stdio.println("s_is_none=${s.is_none()}")\n'
            '    stdio.println("n_is_some=${n.is_some()}")\n'
            '    stdio.println("n_is_none=${n.is_none()}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "s_is_some=true\ns_is_none=false\n"
            "n_is_some=false\nn_is_none=true\n",
        )

    def test_option_unwrap_or_int(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s: Option<Int> = Some(42)\n'
            '    let n: Option<Int> = None\n'
            '    stdio.println("${s.unwrap_or(0)}")\n'
            '    stdio.println("${n.unwrap_or(99)}")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "42\n99\n")

    def test_option_unwrap_or_bool(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s: Option<Bool> = Some(true)\n'
            '    let n: Option<Bool> = None\n'
            '    stdio.println("${s.unwrap_or(false)}")\n'
            '    stdio.println("${n.unwrap_or(false)}")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "true\nfalse\n")

    def test_option_unwrap_or_float(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s: Option<Float> = Some(3.14)\n'
            '    let n: Option<Float> = None\n'
            '    stdio.println("${s.unwrap_or(0.0)}")\n'
            '    stdio.println("${n.unwrap_or(0.0)}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "3.140000\n0.000000\n",
        )

    def test_option_unwrap_or_string(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s: Option<String> = Some("hi")\n'
            '    let n: Option<String> = None\n'
            '    let dflt = "fallback"\n'
            '    stdio.println(s.unwrap_or(dflt))\n'
            '    stdio.println(n.unwrap_or(dflt))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hi\nfallback\n",
        )

    def test_result_is_ok_is_err(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let o: Result<Int, String> = Ok(7)\n'
            '    let msg = "boom"\n'
            '    let e: Result<Int, String> = Err(msg)\n'
            '    stdio.println("o_is_ok=${o.is_ok()}")\n'
            '    stdio.println("e_is_err=${e.is_err()}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "o_is_ok=true\ne_is_err=true\n",
        )

    def test_result_unwrap_or(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let o: Result<Int, String> = Ok(11)\n'
            '    let msg = "x"\n'
            '    let e: Result<Int, String> = Err(msg)\n'
            '    stdio.println("${o.unwrap_or(0)}")\n'
            '    stdio.println("${e.unwrap_or(0)}")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "11\n0\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTraitDispatch(unittest.TestCase):
    """Phase 6J: user-defined trait + capability dispatch via
    monomorphisation (unique impl per trait). Covers both the
    trait-typed receiver (param of type Greeter) and the concrete-
    impl-typed self call inside an impl body."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io, sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_user_capability_with_unique_impl(self):
        src = (
            'pub capability Greeter\n'
            '    fun greet(self, name: String) -> Unit\n'
            'pub type StdioGreeter {\n'
            '    stdio: Stdio,\n'
            '    prefix: String,\n'
            '}\n'
            'pub fun make_greeter(stdio: Stdio, prefix: String) -> StdioGreeter\n'
            '    return StdioGreeter { stdio: stdio, prefix: prefix }\n'
            'impl Greeter for StdioGreeter\n'
            '    fun greet(self, name: String) -> Unit\n'
            '        self.stdio.println("${self.prefix}, ${name}!")\n'
            'fun say_hi(g: Greeter, name: String) -> Unit\n'
            '    g.greet(name)\n'
            'fun main(stdio: Stdio)\n'
            '    let g = make_greeter(stdio, "Hi")\n'
            '    say_hi(g, "Capa")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "Hi, Capa!\n")

    def test_nested_variant_pattern(self):
        # Two-level destructuring: Result<T, ArgError> with
        # variant patterns inside Err. Each arm combines the
        # outer + inner tag checks into a single AND-bool.
        src = (
            'pub type ArgError =\n'
            '    Missing(String)\n'
            '    Unknown(String)\n'
            'fun classify(r: Result<Int, ArgError>) -> String\n'
            '    match r\n'
            '        Ok(_)             -> return "ok"\n'
            '        Err(Missing(n))   -> return "missing ${n}"\n'
            '        Err(Unknown(a))   -> return "unknown ${a}"\n'
            'fun main(stdio: Stdio)\n'
            '    let m: Result<Int, ArgError> = Err(Missing("name"))\n'
            '    let u: Result<Int, ArgError> = Err(Unknown("flag"))\n'
            '    let o: Result<Int, ArgError> = Ok(7)\n'
            '    stdio.println(classify(m))\n'
            '    stdio.println(classify(u))\n'
            '    stdio.println(classify(o))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "missing name\nunknown flag\nok\n",
        )

    def test_self_method_call_inside_impl(self):
        # Impl method delegates to another method on self via the
        # concrete-impl-type entry in _method_table.
        src = (
            'pub capability Logger\n'
            '    fun log(self, msg: String) -> Unit\n'
            '    fun info(self, msg: String) -> Unit\n'
            'pub type StdioLogger { stdio: Stdio }\n'
            'pub fun make_logger(stdio: Stdio) -> StdioLogger\n'
            '    return StdioLogger { stdio: stdio }\n'
            'impl Logger for StdioLogger\n'
            '    fun log(self, msg: String) -> Unit\n'
            '        self.stdio.println("[LOG] ${msg}")\n'
            '    fun info(self, msg: String) -> Unit\n'
            '        self.log(msg)\n'
            'fun main(stdio: Stdio)\n'
            '    let log = make_logger(stdio)\n'
            '    log.info("boot")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "[LOG] boot\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmComponentHost(unittest.TestCase):
    """End-to-end coverage for the Component Model runtime host
    (``capa.runtime._wasm_component_host``). The CLI's
    ``--wasm --component --run`` path wraps a core module in a
    CM component via ``wasm-tools component embed/new`` and
    dispatches through ``WasmComponentHost`` (which speaks lifted
    WIT values instead of raw pointers). These tests exercise
    that runtime directly.

    Coverage motivation: before this class landed,
    ``_wasm_component_host.py`` had 0% test coverage; the only
    real user was the CLI path, never invoked from the test
    suite. Adding even one end-to-end run lifts the file to ~70%
    and catches any future regression that breaks the CM
    runtime."""

    def _wrap_as_component(self, core_blob: bytes, wit_text: str) -> bytes:
        """Re-export of capa.cli._wrap_as_component. Couples this
        test file to the CLI's private helper; acceptable because
        the shape (core wasm + WIT text -> CM component bytes) is
        the only contract that matters and is stable across
        wasm-tools versions."""
        from capa.cli import _wrap_as_component
        return _wrap_as_component(core_blob, wit_text)

    def _run_capturing_stdout(self, src: str, args=()) -> str:
        import io, sys
        from capa.runtime._wasm_component_host import WasmComponentHost
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        wit = compile_wit(ast_mod, types=types)
        component_blob = self._wrap_as_component(core_blob, wit)
        host = WasmComponentHost(args=list(args))
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(component_blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_hello_under_component_host(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hello from component")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "hello from component\n",
        )

    def test_stdio_with_string_interpolation(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let name = "capa"\n'
            '    stdio.println("hi ${name}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hi capa\n",
        )

    def test_env_args_round_trip(self):
        # Component-host argv lifting: Env.args() should return
        # the list passed at construction time, length-and-order
        # preserved. The print-each-arg pattern catches both
        # truncation and reordering bugs.
        src = (
            'fun main(stdio: Stdio, env: Env)\n'
            '    for a in env.args()\n'
            '        stdio.println(a)\n'
        )
        out = self._run_capturing_stdout(src, args=["alpha", "beta", "gamma"])
        self.assertEqual(out, "alpha\nbeta\ngamma\n")

    def test_clock_now_secs_returns_positive_float(self):
        # Component-host Clock bridge. Exact value depends on
        # wall-clock so we only assert shape + sign.
        src = (
            'fun main(stdio: Stdio, clock: Clock)\n'
            '    let t = clock.now_secs()\n'
            '    if t > 0.0\n'
            '        stdio.println("positive")\n'
            '    else\n'
            '        stdio.println("non-positive")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "positive\n",
        )


if __name__ == "__main__":
    unittest.main()

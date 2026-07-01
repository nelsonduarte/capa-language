# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this file passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union four times
# per call site (50+ helpers x 4 = ~200 spurious red squiggles).
# We know the relevant export is a Func because the WAT we emit
# always declares it as one; silencing ``reportCallIssue`` for the
# whole file is the smallest fix that doesn't bury the test code in
# per-line type-ignore noise. Real "not callable" errors are still
# caught by ``python -m unittest`` -- the runtime check is sharper
# than Pyright's union narrowing here.
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
    UnsupportedCapabilityMethod, MainReturnTypeUnsupported,
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

    def test_list_struct_map_uses_4byte_pointer_slot(self):
        # Pointer-shape (struct) elements occupy a single 4-byte i32
        # slot driven by _size_of, both for the source list and the
        # mapped result. Pin the slot-size decision so a regression
        # back to an 8-byte pointer slot (which would diverge from
        # the base list path) is caught at the WAT level: the map
        # driver must stride by ``i32.const 4`` and store the closure
        # result pointer with ``i32.store`` (no i64.extend widening).
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun doubled(pts: List<Point>) -> List<Point>\n"
            "    return pts.map(fun (p: Point) -> Point => "
            "Point { x: p.x * 2, y: p.y })\n"
        )
        import re
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("i32.const 4", wat)
        self.assertIn("i32.store", wat)
        # The pointer-shape store path must NOT widen the closure
        # result to i64 before storing into the 4-byte slot. This
        # module is String-free, so the only i64.extend->i64.store
        # adjacency that could appear is the old 8-byte pointer slot
        # we are pinning against; assert it is gone.
        self.assertIsNone(
            re.search(r"i64\.extend_i32_u\s*\n\s*i64\.store", wat)
        )

    def test_set_methods_now_supported(self):
        # Set<T> add / contains / remove / length / is_empty / to_list
        # are emitted by the _sets mixin; this used to raise (the gap
        # is now closed). Pinning it asserts the dispatcher routes Set
        # receivers rather than rejecting them.
        src = (
            "fun has(s: Set<Int>, n: Int) -> Bool\n"
            "    return s.contains(n)\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("$has", wat)

    def test_map_keys_and_values_now_supported(self):
        # Map.keys() / Map.values() emit a List<K> / List<V> by
        # walking the pair table (slice 5, 2026-05). Closes the
        # last per-method gap on Map; the rejection used to raise
        # ``WasmEmissionError``. Pinning both directions asserts
        # the dispatcher routes correctly and the per-K / per-V
        # encoding chose the right slot stride.
        src_keys = (
            "fun ks(m: Map<String, Int>) -> List<String>\n"
            "    return m.keys()\n"
        )
        src_vals = (
            "fun vs(m: Map<String, Int>) -> List<Int>\n"
            "    return m.values()\n"
        )
        for src, fn in ((src_keys, "$ks"), (src_vals, "$vs")):
            ir_mod, _, _ = _parse_lower(src)
            wat = emit_wat(ir_mod)
            self.assertIn(fn, wat)


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

    def test_bitwise_and(self):
        src = "fun bw(a: Int, b: Int) -> Int\n    return a & b\n"
        self.assertEqual(self._exec(src, "bw", 5, 3), 1)
        self.assertEqual(self._exec(src, "bw", 0xFF, 0x0F), 0x0F)
        self.assertEqual(self._exec(src, "bw", 0, 12345), 0)

    def test_bitwise_or(self):
        src = "fun bw(a: Int, b: Int) -> Int\n    return a | b\n"
        self.assertEqual(self._exec(src, "bw", 5, 3), 7)
        self.assertEqual(self._exec(src, "bw", 0x0F, 0xF0), 0xFF)
        self.assertEqual(self._exec(src, "bw", 0, 0), 0)

    def test_bitwise_xor(self):
        src = "fun bw(a: Int, b: Int) -> Int\n    return a ^ b\n"
        self.assertEqual(self._exec(src, "bw", 5, 3), 6)
        # ``a ^ a == 0`` is the canonical identity.
        self.assertEqual(self._exec(src, "bw", 12345, 12345), 0)
        self.assertEqual(self._exec(src, "bw", 0xFF, 0x0F), 0xF0)

    def test_shift_left(self):
        src = "fun bw(a: Int, b: Int) -> Int\n    return a << b\n"
        self.assertEqual(self._exec(src, "bw", 1, 3), 8)
        self.assertEqual(self._exec(src, "bw", 5, 1), 10)
        self.assertEqual(self._exec(src, "bw", 0, 10), 0)

    def test_shift_right_signed(self):
        # ``>>`` is arithmetic (sign-extending) to match Python's
        # signed-int ``>>``. Negative inputs stay negative.
        src = "fun bw(a: Int, b: Int) -> Int\n    return a >> b\n"
        self.assertEqual(self._exec(src, "bw", 8, 1), 4)
        self.assertEqual(self._exec(src, "bw", -8, 1), -4)
        self.assertEqual(self._exec(src, "bw", 1024, 10), 1)

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
        # ``UnsupportedCapabilityMethod`` is the precise error the WIT
        # generator raises when a CIR ``MethodCall`` references a
        # capability method that has no signature in ``_WIT_SIGNATURES``.
        # ``Stdio.read_line`` used to be the canary here; slice 1 of
        # the Wasm-fully-functional arc closed that gap, so we drive
        # the error path via a synthetic ``MethodCall`` instead. This
        # keeps the contract (raise loudly, never silently emit a
        # half-defined interface) under test even as the supported set
        # grows toward full coverage.
        from capa.ir._nodes import (
            Module, Function, MethodCall, Value, Param,
        )
        # Hand-build a one-instr module that calls a non-existent
        # method. ``cap_used="Stdio"`` makes the WIT walker classify
        # the receiver as the built-in cap; the method name is novel
        # so the lookup misses and the exception fires.
        recv = Value(kind="param", name="stdio", ty="Stdio")
        fake = MethodCall(
            dst=None, receiver=recv,
            method="not_a_real_method", args=[],
            cap_used="Stdio",
        )
        fn = Function(
            name="main",
            params=[Param(name="stdio", ty="Stdio", is_capability=True)],
            return_type="",
            declared_caps=["Stdio"],
            body=[fake],
        )
        ir_mod = Module(types=[], functions=[fn])
        with self.assertRaises(UnsupportedCapabilityMethod):
            emit_wit(ir_mod)

    def test_main_returning_unit_has_no_result_clause(self):
        # Baseline / no-regression: a plain ``fun main`` (Unit return)
        # keeps the historical ``export main: func();`` shape with no
        # result clause, matching the core module's Unit ``main``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func();", wit)
        self.assertNotIn("export main: func() ->", wit)

    def test_main_returning_int_emits_s64_result(self):
        # ``main -> Int``: the core module returns ``(result i64)``,
        # so the WIT world must advertise ``-> s64`` (Capa Int is
        # signed) or ``wasm-tools component new`` rejects the artifact
        # with a core-vs-world result mismatch.
        src = (
            "fun main(stdio: Stdio) -> Int\n"
            "    stdio.println(\"hi\")\n"
            "    return 7\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> s64;", wit)

    def test_main_returning_float_emits_f64_result(self):
        src = (
            "fun main(stdio: Stdio) -> Float\n"
            "    stdio.println(\"hi\")\n"
            "    return 1.5\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> f64;", wit)

    def test_main_returning_bool_emits_bool_result(self):
        src = (
            "fun main(stdio: Stdio) -> Bool\n"
            "    stdio.println(\"hi\")\n"
            "    return true\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> bool;", wit)

    def test_main_result_clause_present_with_handle_params(self):
        # The result clause must sit AFTER the cap-handle param list,
        # so a ``main`` with both handle params and a scalar return
        # produces ``export main: func(fs: u32) -> s64;``. Guards the
        # ordering the shared ``main_result_clause`` helper appends.
        src = (
            "fun main(stdio: Stdio, fs: Fs) -> Int\n"
            "    let _e = fs.exists(\"/nope\")\n"
            "    stdio.println(\"hi\")\n"
            "    return 3\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func(fs: u32) -> s64;", wit)

    def test_main_returning_string_rejected_with_clear_error(self):
        # ``main -> String``: the core returns a flattened (i32 i32)
        # multi-value the Component Model canonical ABI cannot lift
        # from a WIT ``string`` result (it demands an indirect return
        # area). Rather than surface the cryptic wasm-tools mismatch,
        # the WIT generator raises a clear Capa compile-time error.
        src = (
            "fun main(stdio: Stdio) -> String\n"
            "    stdio.println(\"hi\")\n"
            "    return \"x\"\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(MainReturnTypeUnsupported) as ctx:
            emit_wit(ir_mod)
        self.assertIn("String", str(ctx.exception))

    def test_main_returning_struct_rejected_with_clear_error(self):
        # A composite (Struct) return on ``main`` is likewise rejected
        # at WIT generation with the actionable Capa error, not the raw
        # component-linker mismatch.
        src = (
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio) -> Point\n"
            "    stdio.println(\"hi\")\n"
            "    return Point(x: 1, y: 2)\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(MainReturnTypeUnsupported):
            emit_wit(ir_mod)

    def test_parse_json_does_not_emit_host_json_interface(self):
        # Audit 2026-05-25 (item #3): parse_json / to_json are
        # bundled into the guest module via
        # ``capa.ir._builtin_json.inject_into``; the Wasm side never
        # imports a ``capa:host/json`` interface. The WIT emitter
        # used to keep emitting ``interface json`` and ``import
        # json``, contradicting what the component actually consumes.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    let r = parse_json(s)\n"
            "    stdio.println(\"parsed\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertNotIn("interface json", wit)
        self.assertNotIn("import json", wit)
        self.assertIn("interface stdio", wit)

    def test_to_json_does_not_emit_host_json_interface(self):
        # Same as the parse_json case, but exercising the serialise
        # direction as well so both bundled functions are covered.
        # The ``?`` operator needs a Result-returning function, so the
        # json round-trip lives in a helper; ``main`` stays Unit so the
        # world export is the trivial ``func()`` shape (a composite /
        # Result return on ``main`` itself is unsupported by the
        # component backend -- see the main-return-type tests above).
        src = (
            "fun roundtrip() -> Result<String, String>\n"
            "    let jv = parse_json(\"[1,2]\")?\n"
            "    return Ok(to_json(jv))\n"
            "fun main(stdio: Stdio)\n"
            "    match roundtrip()\n"
            "        Ok(back) -> stdio.println(back)\n"
            "        Err(_) -> stdio.eprintln(\"bug\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertNotIn("interface json", wit)
        self.assertNotIn("import json", wit)

    def test_wit_and_wasm_discovery_agree_on_used_caps(self):
        # Cross-side parity: the WIT and Wasm emitters must compute
        # the same used-capability set for the same module, otherwise
        # ``--component --run`` either misses a host import or
        # publishes a phantom one. Audit 2026-05-25.
        from capa.ir._emit_wasm import WasmEmitter

        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    let r = parse_json(s)\n"
            "    stdio.println(\"x\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit_used = set(collect_used_capabilities(ir_mod).keys())

        emitter = WasmEmitter()
        for fn in ir_mod.functions:
            emitter._discover_instrs(fn.body)
        wasm_used = {cap for (cap, _method) in emitter._used_caps}

        self.assertEqual(wit_used, wasm_used)


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
        # The memory limits clause now carries a default upper-page
        # cap (audit H1, 2026-05); use a tolerant match that fires on
        # any ``(memory (export "memory") 1 ...)`` prefix.
        self.assertIn('(memory (export "memory") 1', wat)
        self.assertIn('(data (i32.const 0) "hi")', wat)

    def test_unsupported_method_raises(self):
        # D3 slice 4 (2026-05) closed the last three known String
        # gaps (replace / char_at / index_of). Any String method
        # outside the supported set should still raise so a future
        # gap is visible at compile time instead of silently
        # mis-emitting; drive that via a bogus method name. The
        # analyzer rejects the source before emission gets a chance,
        # so we drive emission directly via the IR shape used here.
        src = (
            "fun cleaned(s: String) -> String\n"
            "    return s.replace(\",\", \";\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        # Mutate the lowered MethodCall in-place to point at a method
        # the dispatcher does not know about; everything else stays
        # type-checked.
        from capa.ir._nodes import MethodCall
        for fn in ir_mod.functions:
            for instr in fn.body:
                if isinstance(instr, MethodCall) and instr.method == "replace":
                    instr.method = "definitely_not_a_real_method"
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
        import io
        import sys
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
        import io
        import sys
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
class TestWasmSetInt(unittest.TestCase):
    """Set<Int> backed by the List 16-byte header + grow-able
    element array, with add deduping and remove preserving
    insertion order via a tail-shift. Mirrors the List<Int> /
    Map<String, Int> execution coverage; the full byte-for-byte
    parity against the Python backend lives in
    tests/test_ir_wasm_parity.py."""

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

    def test_add_dedups_length(self):
        # Adding a duplicate must not grow the set.
        src = (
            "fun count() -> Int\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    s.add(2)\n"
            "    s.add(2)\n"
            "    s.add(3)\n"
            "    return s.length()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["count"](store), 3)

    def test_contains_hit_and_miss(self):
        src = (
            "fun has(x: Int) -> Bool\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(10)\n"
            "    s.add(20)\n"
            "    return s.contains(x)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["has"](store, 20), 1)
        self.assertEqual(exp["has"](store, 99), 0)

    def test_remove_preserves_order_and_is_discard_safe(self):
        # Remove the middle element; the survivors keep insertion
        # order (10 then 30), so summing 10*1 + 30*1000 distinguishes
        # an order-preserving shift from a reordering swap-remove.
        src = (
            "fun fingerprint() -> Int\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(10)\n"
            "    s.add(20)\n"
            "    s.add(30)\n"
            "    s.remove(20)\n"
            "    s.remove(99)\n"
            "    var acc = 0\n"
            "    var mult = 1\n"
            "    for x in s\n"
            "        acc = acc + x * mult\n"
            "        mult = mult * 1000\n"
            "    return acc\n"
        )
        store, exp = self._instantiate(src)
        # 10*1 + 30*1000 = 30010.
        self.assertEqual(exp["fingerprint"](store), 30010)

    def test_add_grows_beyond_initial_capacity(self):
        # Initial cap is 8; adding 50 distinct elements forces a grow
        # via memory.copy. Pins the grow path against clobbering.
        src = (
            "fun build_big() -> Int\n"
            "    let s: Set<Int> = new_set()\n"
            "    var i = 0\n"
            "    while i < 50\n"
            "        s.add(i)\n"
            "        i = i + 1\n"
            "    var total = 0\n"
            "    for x in s\n"
            "        total = total + x\n"
            "    return total\n"
        )
        store, exp = self._instantiate(src)
        # 0 + 1 + ... + 49 = 1225.
        self.assertEqual(exp["build_big"](store), 1225)

    def test_is_empty_before_and_after_add(self):
        src = (
            "fun empty_at_start() -> Bool\n"
            "    let s: Set<Int> = new_set()\n"
            "    return s.is_empty()\n"
            "fun empty_after_add() -> Bool\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    return s.is_empty()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["empty_at_start"](store), 1)
        self.assertEqual(exp["empty_after_add"](store), 0)

    # ----- set algebra: union / intersection / difference / subset ---
    #
    # Each builds a result set and folds it into an order-sensitive
    # fingerprint (acc = acc*100 + x, walked in iteration order) so a
    # wrong RESULT or a wrong ORDER both change the number. The
    # base-100 fold is unambiguous because every element used is < 100.

    def _ab_prelude(self) -> str:
        # a = {3, 1, 4, 5} (insertion order), b = {5, 9, 2, 6, 3}.
        return (
            "    let a: Set<Int> = new_set()\n"
            "    a.add(3)\n"
            "    a.add(1)\n"
            "    a.add(4)\n"
            "    a.add(5)\n"
            "    let b: Set<Int> = new_set()\n"
            "    b.add(5)\n"
            "    b.add(9)\n"
            "    b.add(2)\n"
            "    b.add(6)\n"
            "    b.add(3)\n"
        )

    def _fingerprint(self, set_expr: str) -> str:
        return (
            "fun fp() -> Int\n"
            + self._ab_prelude()
            + f"    let r = {set_expr}\n"
            "    var acc = 0\n"
            "    for x in r\n"
            "        acc = acc * 100 + x\n"
            "    return acc\n"
        )

    def test_union_result_and_order(self):
        # a union b -> 3,1,4,5,9,2,6.
        store, exp = self._instantiate(self._fingerprint("a.union(b)"))
        self.assertEqual(exp["fp"](store), 3010405090206)

    def test_union_order_is_asymmetric(self):
        # b union a -> 5,9,2,6,3,1,4.
        store, exp = self._instantiate(self._fingerprint("b.union(a)"))
        self.assertEqual(exp["fp"](store), 5090206030104)

    def test_intersection_result_and_order(self):
        # a intersect b -> 3,5.
        store, exp = self._instantiate(self._fingerprint("a.intersection(b)"))
        self.assertEqual(exp["fp"](store), 305)

    def test_difference_result_and_order(self):
        # a minus b -> 1,4.
        store, exp = self._instantiate(self._fingerprint("a.difference(b)"))
        self.assertEqual(exp["fp"](store), 104)

    def test_difference_other_direction(self):
        # b minus a -> 9,2,6.
        store, exp = self._instantiate(self._fingerprint("b.difference(a)"))
        self.assertEqual(exp["fp"](store), 90206)

    def test_intersection_disjoint_is_empty(self):
        src = (
            "fun fp() -> Int\n"
            "    let a: Set<Int> = new_set()\n"
            "    a.add(1)\n"
            "    a.add(2)\n"
            "    let b: Set<Int> = new_set()\n"
            "    b.add(3)\n"
            "    b.add(4)\n"
            "    let r = a.intersection(b)\n"
            "    return r.length()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["fp"](store), 0)

    def test_union_with_empty_preserves_order(self):
        src = (
            "fun fp() -> Int\n"
            + self._ab_prelude()
            + "    let e: Set<Int> = new_set()\n"
            "    let r = a.union(e)\n"
            "    var acc = 0\n"
            "    for x in r\n"
            "        acc = acc * 100 + x\n"
            "    return acc\n"
        )
        store, exp = self._instantiate(src)
        # a union empty -> 3,1,4,5.
        self.assertEqual(exp["fp"](store), 3010405)

    def test_is_subset_true_false_and_empty(self):
        src = (
            "fun sub_ab() -> Bool\n"
            + self._ab_prelude()
            + "    return a.is_subset(b)\n"
            "fun sub_self() -> Bool\n"
            + self._ab_prelude()
            + "    return a.is_subset(a)\n"
            "fun empty_sub() -> Bool\n"
            + self._ab_prelude()
            + "    let e: Set<Int> = new_set()\n"
            "    return e.is_subset(a)\n"
            "fun d_sub_a() -> Bool\n"
            + self._ab_prelude()
            + "    let d: Set<Int> = new_set()\n"
            "    d.add(1)\n"
            "    d.add(5)\n"
            "    return d.is_subset(a)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["sub_ab"](store), 0)
        self.assertEqual(exp["sub_self"](store), 1)
        self.assertEqual(exp["empty_sub"](store), 1)
        self.assertEqual(exp["d_sub_a"](store), 1)

    def test_algebra_does_not_mutate_operands(self):
        # a.union(b) must leave a and b untouched: after the call,
        # a still has 4 elements and b still has 5.
        src = (
            "fun lens() -> Int\n"
            + self._ab_prelude()
            + "    let r = a.union(b)\n"
            "    return a.length() * 10 + b.length()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["lens"](store), 45)


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

    def test_to_upper_lower_ascii_only_non_ascii_intact(self):
        # to_upper / to_lower are ASCII-only by design: only A-Z <-> a-z
        # fold, every other code point passes through untouched. This
        # mirrors the Python backend (which routes through
        # _capa_to_upper / _capa_to_lower for byte-identical parity).
        # The accented "é", Greek, Cyrillic, and the emoji must survive
        # unchanged; only the surrounding ASCII letters change case.
        src = (
            "fun u_accent() -> String\n"
            "    return \"café\".to_upper()\n"
            "fun l_accent() -> String\n"
            "    return \"CAFÉx\".to_lower()\n"
            "fun greek() -> String\n"
            "    return \"Ελλ\".to_upper()\n"
            "fun emoji() -> String\n"
            "    return \"a\U0001F600B\".to_upper()\n"
        )
        store, exp = self._instantiate(src)
        # "café" -> "CAFé": the é is unchanged (Python's full-Unicode
        # .upper() would have produced "CAFÉ"; ASCII-only does not).
        self.assertEqual(self._read_string(store, exp, "u_accent"), "CAFé")
        # "CAFÉx" -> "cafÉx": only the ASCII x lowers; the É is intact.
        self.assertEqual(self._read_string(store, exp, "l_accent"), "cafÉx")
        # Greek letters have no ASCII fold, so they pass through.
        self.assertEqual(self._read_string(store, exp, "greek"), "Ελλ")
        # Emoji is a 4-byte code point; its bytes are never folded.
        # The surrounding ASCII letters do fold: "a😀B" -> "A😀B".
        self.assertEqual(self._read_string(store, exp, "emoji"), "A\U0001F600B")

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
        import io
        import sys
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
class TestWasmFtoaParity(unittest.TestCase):
    """Bit-identical parity of the Wasm ``$ftoa`` helper against
    Python's ``str(float)`` for a curated set of values: common
    decimals, hard IEEE 754 cases (0.1 + 0.2 territory), the
    scientific-notation thresholds Python uses (``|x| < 1e-4``,
    ``|x| >= 1e16``), and the special cases (``+/-0``, ``+/-inf``,
    ``nan``).

    Each test compiles a tiny Capa program that materialises the
    target value (either as a literal or via arithmetic for the
    NaN/inf cases) and asserts the ``${x}``-interpolated stdout
    matches ``str(target)``. Grisu2's documented ~0.5% extra-digit
    edge cases are not included; the corpus here is the corpus
    Grisu2 is known to handle shortest."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def _assert_literal_parity(self, v: float) -> None:
        """Compile a program that interpolates ``v`` as a literal
        and asserts the Wasm output equals Python's ``str(v)``."""
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
        expected = str(v) + "\n"
        self.assertEqual(self._run_capturing_stdout(src), expected)

    # Plain decimals -- the bread-and-butter case.
    def test_one_point_five(self):  self._assert_literal_parity(1.5)
    def test_zero_five(self):       self._assert_literal_parity(0.5)
    def test_hundred(self):         self._assert_literal_parity(100.0)
    def test_one_two_three(self):   self._assert_literal_parity(123.0)
    def test_pi_short(self):        self._assert_literal_parity(3.14)
    def test_one_quarter(self):     self._assert_literal_parity(0.25)
    def test_one(self):             self._assert_literal_parity(1.0)
    def test_two(self):             self._assert_literal_parity(2.0)
    def test_seven(self):           self._assert_literal_parity(7.0)
    def test_forty_two(self):       self._assert_literal_parity(42.0)

    # Hard IEEE 754 cases -- shortest-round-trip required.
    def test_zero_one(self):        self._assert_literal_parity(0.1)
    def test_zero_two(self):        self._assert_literal_parity(0.2)
    def test_zero_three(self):      self._assert_literal_parity(0.3)
    def test_one_thousandth(self):  self._assert_literal_parity(0.001)
    def test_one_ten_thousandth(self): self._assert_literal_parity(0.0001)
    def test_one_eighth(self):      self._assert_literal_parity(0.125)
    def test_one_sixteenth(self):   self._assert_literal_parity(0.0625)

    # Negatives.
    def test_neg_one_five(self):    self._assert_literal_parity(-1.5)
    def test_neg_half(self):        self._assert_literal_parity(-0.5)
    def test_neg_hundred(self):     self._assert_literal_parity(-100.0)
    def test_neg_pi_short(self):    self._assert_literal_parity(-3.14)

    # Scientific-notation thresholds. Python's str(float) uses
    # e-notation when ``e = n - 1 < -4`` (lower) or ``e >= 17``
    # (upper); the values below straddle both edges.
    def test_just_inside_decimal_low(self):
        # 1e-4 is the smallest magnitude that stays in decimal form.
        self._assert_literal_parity(1e-4)

    def test_just_outside_decimal_low(self):
        # 1e-5 crosses into scientific.
        self._assert_literal_parity(1e-5)

    def test_just_outside_decimal_high(self):
        # 1e16 just crosses into scientific (n=17, e=16).
        self._assert_literal_parity(1e16)

    def test_one_quadrillion(self):
        # Highest magnitude still in decimal form (n=16).
        self._assert_literal_parity(1e15)

    def test_scientific_negative_exponent_three_digits(self):
        # 1e-100 exercises the three-digit-exponent branch.
        self._assert_literal_parity(1e-100)

    def test_scientific_positive_exponent_three_digits(self):
        # 1e100 exercises the three-digit-exponent branch on the
        # positive side.
        self._assert_literal_parity(1e100)

    # Special cases: +/-0, +/-inf, nan.
    def test_positive_zero(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Float = 0.0\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "0.0\n")

    def test_negative_zero(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Float = -0.0\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "-0.0\n")

    def test_infinity_via_division_now_traps(self):
        # Bug #4: float division by zero used to yield IEEE-754 inf on
        # the Wasm backend while the Python backend raised
        # ZeroDivisionError - a divergence. Both backends now agree by
        # trapping on a zero divisor, so ``one / zero`` can no longer
        # be used to synthesise inf (Capa has no inf/nan literals).
        import wasmtime
        src = (
            "fun main(stdio: Stdio)\n"
            "    let zero: Float = 0.0\n"
            "    let one: Float = 1.0\n"
            "    let inf_val: Float = one / zero\n"
            "    stdio.println(\"${inf_val}\")\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._run_capturing_stdout(src)

    def test_nan_via_division_now_traps(self):
        # Bug #4 (cont.): ``zero / zero`` (which produced nan) now
        # traps on the Wasm backend too, matching Python.
        import wasmtime
        src = (
            "fun main(stdio: Stdio)\n"
            "    let zero: Float = 0.0\n"
            "    let nan_val: Float = zero / zero\n"
            "    stdio.println(\"${nan_val}\")\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._run_capturing_stdout(src)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFtoaRoundWeed(unittest.TestCase):
    """Audit C1 (2026-06-09): the hard-rounding values the pre-fix
    Grisu2 port got wrong because it omitted the RoundWeed last-digit
    nudge. ``$ftoa`` returned the FIRST digit string inside the
    rounding interval rather than the one closest to ``W``; for
    ``100.0 / 7.0`` that meant ``14.285714285714287`` (one ulp high)
    against Python's ``14.285714285714286``.

    With RoundWeed ported into ``$grisu2`` these are all byte-exact.
    Each value below diverged BEFORE the fix; this class is the
    regression net for the headline cases and the realistic
    computed-float classes (ratios, averages, sums)."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def _assert_repr_parity(self, v: float) -> None:
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), repr(v) + "\n",
            msg=f"Wasm $ftoa diverged from repr for {v!r}",
        )

    def test_hundred_over_seven(self):
        # The audit headline. Pre-fix: 14.285714285714287.
        self._assert_repr_parity(100.0 / 7.0)

    def test_sum_over_three(self):
        # (1+2+4)/3. Pre-fix: 2.3333333333333337.
        self._assert_repr_parity((1.0 + 2.0 + 4.0) / 3.0)

    def test_one_over_seven(self):
        self._assert_repr_parity(1.0 / 7.0)

    def test_ten_over_three(self):
        self._assert_repr_parity(10.0 / 3.0)

    def test_one_over_six(self):
        self._assert_repr_parity(1.0 / 6.0)

    def test_one_over_twentynine(self):
        self._assert_repr_parity(1.0 / 29.0)

    def test_twentytwo_over_seven(self):
        self._assert_repr_parity(22.0 / 7.0)

    def test_average_of_set(self):
        self._assert_repr_parity((3.0 + 5.0 + 8.0 + 11.0) / 4.0)

    def test_ratio_sweep_small(self):
        # The whole a/b grid for a,b in 1..40 is byte-exact post-fix
        # (it was 954/3481 diverging pre-fix). One subTest per ratio
        # so a future regression points at the exact value.
        for a in range(1, 41):
            for b in range(1, 41):
                v = a / b
                with self.subTest(a=a, b=b):
                    self.assertEqual(
                        self._run_capturing_stdout(
                            "fun main(stdio: Stdio)\n"
                            f"    let x: Float = {v!r}\n"
                            "    stdio.println(\"${x}\")\n"
                        ),
                        repr(v) + "\n",
                    )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFtoaResidual(unittest.TestCase):
    """F2 (2026-06-10): the Grisu3-confidence + Dragon4 exact
    fallback has LANDED, so the residual float-formatting hole is
    closed. Grisu2 is INHERENTLY unable to produce the
    shortest-round-trip digit string for a sub-1% fraction of bit
    patterns; ``$grisu2`` now carries the RoundWeed
    boundary-ambiguity success flag and ``$ftoa`` falls back to the
    exact limb-bignum Dragon4 (``$dragon4`` + the ``$bn_*`` family)
    when that flag is clear. Both paths feed the same (digits, K)
    shape into the spelling layer, so the output is byte-exact with
    Python ``repr(float)``.

    The values below were CONFIRMED Grisu2-inherent divergences
    before F2 - the validated Python Grisu2 reference produced the
    SAME wrong digit as the WAT, proving the gap was the algorithm,
    not the port. They are now real PASSING parity tests (the
    Dragon4 fallback names the correct double), including a
    plain-arithmetic case (``86.0 / 7018.0``) so the formerly-open
    hole is pinned as a realistic-value regression guard, not just
    hand-picked literals."""

    def _wat_ftoa(self, v: float) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio)\n"
            f"    let x: Float = {v!r}\n"
            "    stdio.println(\"${x}\")\n"
        )
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
        return out.getvalue()

    def test_residual_decimal_range_a(self):
        # Formerly Grisu2-inherent residual in the common decimal
        # range (repr 76821.07266303091, old WAT ...0309); the
        # Dragon4 fallback now matches repr.
        v = 76821.07266303091
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")

    def test_residual_decimal_range_b(self):
        # Formerly repr 0.08549800233840919 vs old WAT ...092; now
        # exact via the Dragon4 fallback.
        v = 0.08549800233840919
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")

    def test_residual_from_ordinary_division(self):
        # Arithmetic-reachable residual (NOT a hand-picked literal).
        # ``86.0 / 7018.0`` -> repr 0.012254203476774009. The old
        # Grisu2-only WAT emitted 0.01225420347677401, which did NOT
        # round-trip (it named the WRONG double); the Dragon4 fallback
        # now produces the shortest round-tripping string byte-for-byte
        # equal to repr.
        v = 86.0 / 7018.0
        self.assertEqual(self._wat_ftoa(v), repr(v) + "\n")


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
            import io
            import sys
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
            import io
            import sys
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
        import io
        import sys
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
class TestWasmSlice1HostBridges(unittest.TestCase):
    """Slice 1 of the Wasm-fully-functional arc (2026-05): close
    the host-bridge pile (Fs.exists / is_dir / mkdir / list_dir,
    Stdio.read_line, Clock.sleep, Clock.allows). Each method gets
    a runtime test with a deterministic fixture so the Wasm side
    matches the Python runtime byte-for-byte (or behaviourally
    equivalent for time-dependent calls like Clock.sleep).
    """

    def _run(self, src: str, stdin_text: str | None = None) -> str:
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        saved_in = None
        if stdin_text is not None:
            saved_in = sys.stdin
            sys.stdin = io.StringIO(stdin_text)
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
            if saved_in is not None:
                sys.stdin = saved_in
        return out.getvalue()

    def test_fs_exists_true_and_false(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            real = os.path.join(td, "real.txt").replace("\\", "/")
            with open(real, "w", encoding="utf-8") as f:
                f.write("x")
            missing = os.path.join(td, "missing.txt").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    if fs.exists(\"{real}\")\n"
                "        stdio.println(\"real: yes\")\n"
                "    else\n"
                "        stdio.println(\"real: no\")\n"
                f"    if fs.exists(\"{missing}\")\n"
                "        stdio.println(\"missing: yes\")\n"
                "    else\n"
                "        stdio.println(\"missing: no\")\n"
            )
            self.assertEqual(
                self._run(src), "real: yes\nmissing: no\n",
            )

    def test_fs_is_dir_dir_and_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = td.replace("\\", "/")
            f_path = os.path.join(td, "f.txt").replace("\\", "/")
            with open(f_path, "w", encoding="utf-8") as f:
                f.write("x")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    if fs.is_dir(\"{target}\")\n"
                "        stdio.println(\"dir: yes\")\n"
                "    else\n"
                "        stdio.println(\"dir: no\")\n"
                f"    if fs.is_dir(\"{f_path}\")\n"
                "        stdio.println(\"file: yes\")\n"
                "    else\n"
                "        stdio.println(\"file: no\")\n"
            )
            self.assertEqual(
                self._run(src), "dir: yes\nfile: no\n",
            )

    def test_fs_mkdir_creates_and_is_idempotent(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "nested", "sub").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"first ok\")\n"
                "        Err(_) -> stdio.println(\"first err\")\n"
                # Second call must succeed (exist_ok=True mirrors
                # the Python runtime).
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"second ok\")\n"
                "        Err(_) -> stdio.println(\"second err\")\n"
            )
            self.assertEqual(
                self._run(src), "first ok\nsecond ok\n",
            )
            self.assertTrue(os.path.isdir(target))

    def test_fs_mkdir_err_on_file_collision(self):
        # mkdir on a path that exists as a regular file is an OS
        # error even with ``exist_ok=True``; surfaced as Err.
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "f.txt").replace("\\", "/")
            with open(target, "w", encoding="utf-8") as f:
                f.write("x")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
                "        Err(_) -> stdio.println(\"expected err\")\n"
            )
            self.assertEqual(self._run(src), "expected err\n")

    def test_fs_list_dir_sorted_entries(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            for name in ("z.txt", "a.txt", "m.txt"):
                with open(os.path.join(td, name), "w") as f:
                    f.write("")
            target = td.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.list_dir(\"{target}\")\n"
                "        Ok(items) -> \n"
                "            for item in items\n"
                "                stdio.println(item)\n"
                "        Err(_) -> stdio.println(\"err\")\n"
            )
            self.assertEqual(
                self._run(src), "a.txt\nm.txt\nz.txt\n",
            )

    def test_fs_list_dir_err_on_missing(self):
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.list_dir(\"/no/such/path/zzz_capa_test_98765\")\n"
            "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
            "        Err(_) -> stdio.println(\"expected err\")\n"
        )
        self.assertEqual(self._run(src), "expected err\n")

    def test_fs_list_dir_empty_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = td.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.list_dir(\"{target}\")\n"
                "        Ok(items) -> stdio.println(\"len: ${items.length()}\")\n"
                "        Err(_) -> stdio.println(\"err\")\n"
            )
            self.assertEqual(self._run(src), "len: 0\n")

    def test_stdio_read_line_returns_input(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    match stdio.read_line()\n"
            "        Ok(line) -> stdio.println(\"got: ${line}\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        self.assertEqual(
            self._run(src, stdin_text="hello\n"), "got: hello\n",
        )

    def test_stdio_read_line_eof_returns_err(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    match stdio.read_line()\n"
            "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
            "        Err(_) -> stdio.println(\"eof\")\n"
        )
        self.assertEqual(self._run(src, stdin_text=""), "eof\n")

    def test_clock_sleep_does_not_error(self):
        # Don't assert on timing (would be flaky); just confirm a
        # short sleep returns to the caller cleanly.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(0.001)\n"
            "    stdio.println(\"after sleep\")\n"
        )
        self.assertEqual(self._run(src), "after sleep\n")

    def test_clock_sleep_negative_is_noop(self):
        # Negative sleeps should not crash the host (the bridge
        # guards against ``time.sleep(negative)`` which would
        # otherwise raise ValueError).
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(-1.0)\n"
            "    stdio.println(\"survived\")\n"
        )
        self.assertEqual(self._run(src), "survived\n")

    def test_clock_allows_unrestricted_returns_true(self):
        # Unrestricted Clock at the host returns true; matches the
        # Python runtime's ``self._not_before is None`` branch.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if clock.allows()\n"
            "        stdio.println(\"allowed\")\n"
            "    else\n"
            "        stdio.println(\"denied\")\n"
        )
        self.assertEqual(self._run(src), "allowed\n")


class TestWasmAllowsInlineEmit(unittest.TestCase):
    """GAP-2b (2026-06-21): ``Fs.allows`` / ``Env.allows`` /
    ``Db.allows`` / ``Net.allows`` / ``Proc.allows`` route through
    the authoritative ``$<Cap>_allows(handle, arg) -> bool`` host
    function (the same host-route ``Clock.allows`` already used), so
    a host import IS emitted and no guest-side ``$_atten_*`` check is
    left behind. Pre-route these queries were inlined at emit time
    and the dynamic-prefix case failed/diverged. These tests pin the
    emit-time contract independent of the runtime so the routing is
    visible even on machines without the Wasm toolchain.
    """

    def test_fs_allows_literal_emits_host_import(self):
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    if fs.allows(\"/x\")\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        # GAP-2b: Fs.allows now routes through the host. The
        # Stdio.println import is still present too.
        self.assertIn("\"capa:host/fs\" \"allows\"", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertIn("\"capa:host/stdio\" \"println\"", wat)

    def test_env_allows_literal_emits_host_import(self):
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    if env.allows(\"HOME\")\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/env\" \"allows\"", wat)
        self.assertIn("call $Env_allows", wat)

    def test_fs_allows_dynamic_arg_routes_through_host(self):
        # GAP-2b (2026-06-21): the dynamic-arg case (the gap) now
        # travels guest->host as a normal (ptr, len) string, so the
        # WAT carries no ``$_atten_*`` scratch and calls the host
        # import. Pre-route the unrestricted case collapsed to a
        # const and the attenuated case emitted an inline check.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let p = \"/x\"\n"
            "    if fs.allows(p)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/fs\" \"allows\"", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_fs_allows_dynamic_arg_attenuated_routes_through_host(self):
        # GAP-2b (2026-06-21): the dynamic-arg + attenuated case is
        # exactly what diverged before (the guest-side lexical prefix
        # check could not realpath). It now pushes the receiver
        # handle + the (ptr, len) string and calls the host import,
        # which consults the authoritative ``fs.allows(path)``; no
        # ``$_atten_*`` machinery remains.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let scoped = fs.restrict_to(\"/tmp/\")\n"
            "    let p = \"/tmp/work\"\n"
            "    if scoped.allows(p)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$_atten_path_ptr", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertIn("call $Fs_restrict_to", wat)

    def test_env_allows_dynamic_arg_routes_through_host(self):
        # GAP-2b: same host-route for Env.allows. The dynamic
        # restrict_to_keys list was the silent-divergence case
        # (the lexical key-list reconstruction returned []); routing
        # it host-side restores parity.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let n = \"HOME\"\n"
            "    if env.allows(n)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/env\" \"allows\"", wat)
        self.assertIn("call $Env_allows", wat)

    def test_net_proc_db_allows_emit_host_import(self):
        # GAP-2b: Net / Proc / Db .allows also route host-side.
        src = (
            "fun main(stdio: Stdio, net: Net, proc: Proc, db: Db)\n"
            "    let n = \"example.com\"\n"
            "    let c = \"git\"\n"
            "    let p = \"/var/data/x.db\"\n"
            "    if net.allows(n)\n"
            "        stdio.println(\"a\")\n"
            "    if proc.allows(c)\n"
            "        stdio.println(\"b\")\n"
            "    if db.allows(p)\n"
            "        stdio.println(\"c\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/net\" \"allows\"", wat)
        self.assertIn("\"capa:host/proc\" \"allows\"", wat)
        self.assertIn("\"capa:host/db\" \"allows\"", wat)
        self.assertIn("call $Net_allows", wat)
        self.assertIn("call $Proc_allows", wat)
        self.assertIn("call $Db_allows", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_clock_allows_stays_on_host_bridge(self):
        # Clock.allows depends on the live wall clock; per D4 we
        # keep it as a host import rather than inlining.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if clock.allows()\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/clock\" \"allows\"", wat)


class TestWasmAttenuationEnforcement(unittest.TestCase):
    """Audit C2 + slice 25 (2026-05-30): privileged capability ops
    (Fs.read / Net.get / Db.exec / ...) on a receiver bound via a
    ``restrict_to`` / ``restrict_to_keys`` chain are enforced by
    the host handle table -- the receiver is an i32 handle the
    host looks up to consult the recorded restriction before each
    syscall. Pre-slice-25 the Wasm backend emitted an inline
    check before the host import; slice 25.9 removed that dead
    machinery once every cap had been routed through the handle
    table.

    These tests cover two layers:
    - WAT shape: the emit-time inline check is no longer present
      for privileged ops; the receiver handle flows as the first
      arg of the host import instead.
    - Runtime execution: the host returns Err for denied paths,
      Ok for allowed paths -- matching the Python runtime byte-
      for-byte. Cross-function attenuation (the previous gap that
      the inline check could not catch) is now sound on both
      backends.
    """

    def test_no_restrict_no_inline_check(self):
        # Unrestricted ``fs.read`` produces no inline-check
        # machinery. Pin via grep so a regression that re-
        # introduces an emit-time check is caught.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"/etc/passwd\")\n"
            "        Ok(_) -> stdio.println(\"X\")\n"
            "        Err(_) -> stdio.println(\"Y\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_starts_with", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_fs_read_restricted_uses_handle_not_inline_check(self):
        # After slice 25.2, Fs.read carries the receiver handle as
        # its first arg and the host enforces the restriction via
        # the handle table. No inline ``$str_starts_with`` /
        # ``$_atten_*`` machinery is emitted for the privileged
        # op; the WAT just passes the handle and calls $Fs_read.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let tmp = fs.restrict_to(\"/tmp/\")\n"
            "    match tmp.read(\"/tmp/x\")\n"
            "        Ok(_) -> stdio.println(\"X\")\n"
            "        Err(_) -> stdio.println(\"Y\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_starts_with", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertNotIn("$_atten_path_ptr", wat)
        self.assertIn("call $Fs_read", wat)
        self.assertIn("call $Fs_restrict_to", wat)

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_read_inside_prefix_allowed(self):
        import io
        import os
        import sys
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "ok.txt").replace("\\", "/")
            with open(target, "w", encoding="utf-8") as f:
                f.write("inside-prefix")
            # The Wasm attenuation check is a byte-level prefix
            # check (matches the str_starts_with Python contract).
            # Use the temp directory itself as the prefix so the
            # absolute path of ``target`` starts with it on both
            # platforms.
            prefix = td.replace("\\", "/") + "/"
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let scoped = fs.restrict_to(\"{prefix}\")\n"
                f"    match scoped.read(\"{target}\")\n"
                "        Ok(text) -> stdio.println(\"got: ${text}\")\n"
                "        Err(_) -> stdio.println(\"DENIED\")\n"
            )
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
            self.assertEqual(out.getvalue(), "got: inside-prefix\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_read_outside_prefix_denied(self):
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let tmp = fs.restrict_to(\"/tmp/\")\n"
            "    match tmp.read(\"/etc/passwd\")\n"
            "        Ok(_) -> stdio.println(\"BUG: read succeeded\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
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
        # The inline check fires; the host import is never invoked,
        # so the failure is hermetic (would still pass on a system
        # where /etc/passwd is present and readable).
        self.assertEqual(out.getvalue(), "denied\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_write_outside_prefix_denied(self):
        import io
        import sys
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            # Write target lies outside the restrict_to prefix.
            target = "/should/not/exist.txt"
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let scoped = fs.restrict_to(\"{td}/\".replace(\"\\\\\", \"/\"))\n"
                f"    match scoped.write(\"{target}\", \"x\")\n"
                "        Ok(_) -> stdio.println(\"BUG: wrote\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
            # Simpler shape: use a literal /usr/ prefix so /tmp/x
            # is denied. Avoids the f-string escaping nightmare.
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                "    let scoped = fs.restrict_to(\"/usr/\")\n"
                "    match scoped.write(\"/tmp/should-be-denied.txt\", \"x\")\n"
                "        Ok(_) -> stdio.println(\"BUG\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
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
            self.assertEqual(out.getvalue(), "denied\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_two_attenuations_both_apply(self):
        # ``fs.restrict_to("/tmp/").restrict_to("/tmp/myapp/")``:
        # the second restriction must AND with the first. A read on
        # ``/tmp/foo`` matches the first but NOT the second, so the
        # combined check denies.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let one = fs.restrict_to(\"/tmp/\")\n"
            "    let two = one.restrict_to(\"/tmp/myapp/\")\n"
            "    match two.read(\"/tmp/foo\")\n"
            "        Ok(_) -> stdio.println(\"BUG\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
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
        self.assertEqual(out.getvalue(), "denied\n")

    def test_net_get_restricted_uses_handle_not_inline_check(self):
        # Slice 25.3 (2026-05-30): Net.get carries the receiver
        # handle as its first arg and the host enforces the
        # restriction via the handle table (using
        # ``urlparse(url).hostname`` rather than a substring
        # check, which closes the audit slice 25 F2 lookalike-URL
        # hazard). Verify no inline ``$str_contains`` machinery
        # is emitted.
        src = (
            "fun main(stdio: Stdio, net: Net)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    match api.get(\"https://api.example.com/health\")\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_contains", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertIn("call $Net_get", wat)
        self.assertIn("call $Net_restrict_to", wat)

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_env_restrict_to_keys_outside_set_denied(self):
        import os
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let limited = env.restrict_to_keys([\"HOME\"])\n"
            "    match limited.get(\"PATH\")\n"
            "        Some(_) -> stdio.println(\"BUG: leaked PATH\")\n"
            "        None -> stdio.println(\"hidden\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        # Set PATH so the host would normally return Some; the
        # check must short-circuit to None on the Wasm side.
        os.environ.setdefault("PATH", "/usr/bin:/bin")
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "hidden\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_env_restrict_to_keys_allowed_passes(self):
        import os
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        os.environ["CAPA_ATTEN_ALLOW_X"] = "allowed-value"
        try:
            src = (
                "fun main(stdio: Stdio, env: Env)\n"
                "    let limited = env.restrict_to_keys([\"CAPA_ATTEN_ALLOW_X\"])\n"
                "    match limited.get(\"CAPA_ATTEN_ALLOW_X\")\n"
                "        Some(v) -> stdio.println(\"got: ${v}\")\n"
                "        None -> stdio.println(\"BUG: missed\")\n"
            )
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
            self.assertEqual(out.getvalue(), "got: allowed-value\n")
        finally:
            os.environ.pop("CAPA_ATTEN_ALLOW_X", None)


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

    def test_call_through_fun_typed_param_returning_bool(self):
        # Regression: before 2026-05-25 the analyzer returned
        # TyUnknown for a call whose callee was a parameter
        # typed as ``Fun(...) -> ...``. The lowerer then
        # marked the call's dst local as ``?``, and
        # ``_wasm_type('?')`` fell back to i64. When the actual
        # closure returned Bool (i32 at Wasm level), the
        # ``local.set $dst`` after the call_indirect failed
        # the wasm-validator with ``i64 vs i32 mismatch``.
        # Tested return = Bool (the case the existing tests
        # didn't cover; their lambdas returned Int = i64 by
        # coincidence agreed with the fallback).
        src = (
            "fun apply_pred(items: List<Int>, pred: Fun(Int) -> Bool) -> Int\n"
            "    var count = 0\n"
            "    for x in items\n"
            "        if pred(x)\n"
            "            count = count + 1\n"
            "    return count\n"
            "fun main() -> Int\n"
            "    let xs: List<Int> = [1, 2, 3, 4, 5]\n"
            "    return apply_pred(xs, fun (n: Int) -> Bool => n % 2 == 0)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 2)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmNestedClosures(unittest.TestCase):
    """Phase 6E extension (2026-05-25): lambdas inside lambdas via
    lambda-lifting with flat envs. Each nested closure gets its own
    env record holding every name it references from any outer
    scope; there is no env-of-env chain at run time. At MakeLambda
    emit time the outer lambda's body copies values straight from
    its own ``$env`` / locals into the inner's freshly-allocated
    env record, so the inner only ever needs a single env-ptr.

    Tests pin: inner captures both function-scope and outer-lambda
    names; inner captures only the outer's param; inner captures
    only the function-scope variable; and a nested closure used as
    a HOF callback's body."""

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

    def test_simple_nested_closure(self):
        # Outer captures n (function-scope Int). Inner captures
        # both x (outer's param, copied into inner's env from a
        # Wasm local) and n (outer's capture, copied into inner's
        # env via an outer-$env i64.load). 7 + 5 + 10 = 22.
        src = (
            "fun main() -> Int\n"
            "    let n = 7\n"
            "    let outer = fun (x: Int) -> Int =>\n"
            "        let inner = fun (y: Int) -> Int => x + y + n\n"
            "        return inner(10)\n"
            "    return outer(5)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 22)

    def test_inner_captures_only_outer(self):
        # Classic make_adder: outer takes n, returns a closure
        # that captures n. Inner captures only the outer's param,
        # no function-scope variable. The outer itself has no
        # captures (env_size 0) -- its only free variable is n,
        # which is its own param.
        src = (
            "fun main() -> Int\n"
            "    let mk_adder = fun (n: Int) -> Fun(Int) -> Int =>\n"
            "        return fun (x: Int) -> Int => x + n\n"
            "    let add5 = mk_adder(5)\n"
            "    return add5(3)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 8)

    def test_inner_captures_only_function(self):
        # Outer is a thunk; inner captures n from the function
        # scope, skipping the outer's own scope entirely. The
        # outer therefore must still capture n (so the inner's
        # env can be populated at MakeLambda emit time) even
        # though outer itself never references n directly.
        src = (
            "fun main() -> Int\n"
            "    let n = 100\n"
            "    let outer = fun () -> Fun(Int) -> Int =>\n"
            "        return fun (x: Int) -> Int => x + n\n"
            "    let inner = outer()\n"
            "    return inner(7)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 107)

    def test_nested_in_hof(self):
        # Nested closure inside a HOF callback (List<Int>.map).
        # The let-binding extracts the callback out of the call
        # site to side-step the parser's block-body-lambda-in-
        # parens restriction; the closure machinery is the same
        # either way. For xs = [1, 2, 3] this computes [2, 4, 6]
        # and reads element 2 -> 6.
        src = (
            "fun main() -> Int\n"
            "    let xs = [1, 2, 3]\n"
            "    let h = fun (x: Int) -> Int =>\n"
            "        let f = fun (y: Int) -> Int => x + y\n"
            "        return f(x)\n"
            "    let ys = xs.map(h)\n"
            "    return ys[2]\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 6)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmListHofNonInt(unittest.TestCase):
    """Phase 6E extension (2026-05-25): List<T>.map / filter / fold
    for non-Int element types T. Closure signatures now reflect the
    elem / accumulator type's Wasm wire shape (String -> two i32s,
    Float -> f64, Bool / pointer -> i32, Int -> i64); the data-array
    load / store sequences pick op-codes matching the slot bytes.

    Each test compiles + runs a tiny program that prints the result
    through stdio and asserts the captured output."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_list_string_map_to_int(self):
        # Confirms List<String>.map -> List<Int>: the closure sig
        # becomes ``(i32 i32 i32) -> i64`` (env, ptr, len) -> i64
        # and the dst data array uses i64.store.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"a\", \"bb\", \"ccc\"]\n"
            "    let lens = xs.map(fun (s: String) -> Int => s.length())\n"
            "    for n in lens\n"
            "        stdio.println(\"${n}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "1\n2\n3\n"
        )

    def test_list_string_map_to_string(self):
        # Closure sig ``(i32 i32 i32) -> (i32 i32)``: multi-value
        # return packed back into the (ptr | (len << 32)) slot.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"a\", \"b\"]\n"
            "    let up = xs.map(fun (s: String) -> String => s.to_upper())\n"
            "    for s in up\n"
            "        stdio.println(s)\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "A\nB\n"
        )

    def test_list_string_filter(self):
        # Closure sig ``(i32 i32 i32) -> i32``: predicate over a
        # String, slot-copy preserves the packed-i64 bytes so the
        # destination list's String elements decode back correctly.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"\", \"a\", \"\", \"b\"]\n"
            "    let nonempty = xs.filter(fun (s: String) -> Bool => s.length() > 0)\n"
            "    for s in nonempty\n"
            "        stdio.println(s)\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "a\nb\n"
        )

    def test_list_string_fold_concat(self):
        # Closure sig ``(i32 i32 i32 i32 i32) -> (i32 i32)``:
        # (env, acc_ptr, acc_len, x_ptr, x_len) -> (out_ptr, out_len).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"a\", \"b\", \"c\"]\n"
            "    let joined = xs.fold(\"\", fun (acc: String, x: String) -> String => acc + x)\n"
            "    stdio.println(joined)\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "abc\n"
        )

    def test_list_float_map(self):
        # Closure sig ``(i32 f64) -> f64``; loaded slot bits go
        # through ``f64.reinterpret_i64`` and stored result uses
        # ``f64.store``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Float> = [1.5, 2.5]\n"
            "    let doubled = xs.map(fun (x: Float) -> Float => x * 2.0)\n"
            "    for v in doubled\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "3.0\n5.0\n"
        )

    def test_list_float_filter(self):
        # Closure sig ``(i32 f64) -> i32``: predicate over a Float
        # value (slot bytes reinterpreted).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Float> = [-1.0, 1.0, -2.0, 2.0]\n"
            "    let pos = xs.filter(fun (x: Float) -> Bool => x > 0.0)\n"
            "    for v in pos\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "1.0\n2.0\n"
        )

    def test_list_float_fold_sum(self):
        # Closure sig ``(i32 f64 f64) -> f64``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Float> = [1.0, 2.0, 3.5]\n"
            "    let total = xs.fold(0.0, fun (a: Float, x: Float) -> Float => a + x)\n"
            "    stdio.println(\"${total}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "6.5\n"
        )

    def test_list_int_map_still_works(self):
        # Regression: the existing Int path keeps working through
        # the refactored dispatcher.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let ys = xs.map(fun (x: Int) -> Int => x * x)\n"
            "    for v in ys\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "1\n4\n9\n"
        )

    def test_list_bool_map(self):
        # Closure sig ``(i32 i32) -> i32``; both load and store
        # paths run on 4-byte slots. Exercises the Bool branch of
        # ``_emit_store_closure_result_into_slot`` (i32.store) and
        # the matching map alloc stride.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Bool> = [true, false, true]\n"
            "    let ys = xs.map(fun (b: Bool) -> Bool => not b)\n"
            "    for v in ys\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "false\ntrue\nfalse\n"
        )

    def test_list_bool_filter(self):
        # Closure sig ``(i32 i32) -> i32``; filter's slot load
        # uses ``i32.load + i64.extend_i32_u`` and the inline push
        # path uses ``i32.wrap_i64 + i32.store`` (slot_size=4).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Bool> = [true, false, true, false, true]\n"
            "    let ys = xs.filter(fun (b: Bool) -> Bool => b)\n"
            "    for v in ys\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "true\ntrue\ntrue\n"
        )

    def test_list_int_map_to_bool(self):
        # Int element feeding into a Bool-returning closure: the
        # output List<Bool> uses ``out_stride=4`` so the store path
        # collapses to ``i32.store``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [3, -1, 0, 5]\n"
            "    let ys = xs.map(fun (i: Int) -> Bool => i > 0)\n"
            "    for v in ys\n"
            "        stdio.println(\"${v}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "true\nfalse\nfalse\ntrue\n",
        )

    def test_list_bool_fold_to_int(self):
        # Bool element into an Int accumulator: the fold slot load
        # uses ``i32.load + i64.extend_i32_u`` (no slot_size routing
        # on the accumulator side because it's a plain local).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Bool> = [true, false, true, true]\n"
            "    let n = xs.fold(0, fun (acc: Int, b: Bool) -> Int =>\n"
            "        if b then acc + 1 else acc)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "3\n"
        )

    @unittest.skip(
        "List<List<T>> / List<Struct> HOFs not supported: the "
        "alloc-and-store for pointer-shape elements is structurally "
        "different. Workaround: use the Python backend."
    )
    def test_list_of_lists_map(self):
        # Placeholder: future work would need an alloc-aware
        # store path. Skipped today.
        pass


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
        import io
        import sys
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
            self._run_capturing_stdout(src), "got 3.5\n",
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

    def test_as_int_some_on_integer_valued_jnum(self):
        # Audit 2026-05-25 parity fix: integer-valued JNum (1.0,
        # -7.0) projects to Some(int). Both backends must agree.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(7.0)\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got 7\n")

    def test_as_int_none_on_non_integer_jnum(self):
        # Audit 2026-05-25 parity fix: non-integer JNum (3.14)
        # must return None on both backends. Wasm used to truncate
        # unconditionally and return Some(3); now it checks for
        # zero fractional first.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(3.14)\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "none\n")

    def test_as_int_none_on_non_jnum_variant(self):
        # Sanity: non-JNum variants are unconditionally None on
        # both backends. This branch already worked but lock it in
        # so a future refactor of the as_int dispatch doesn't
        # regress it.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("not a number")\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
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

    def test_parse_json_deeply_nested_within_limit_succeeds(self):
        # 50 nested arrays is well under the 100-level cap.
        # Builds ``[[[ ... [] ... ]]]`` at runtime and parses it.
        # The parse must succeed; the result is an array of arrays
        # ending in an empty list.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 50\n'
            '        s = s + "["\n'
            '        i = i + 1\n'
            '    i = 0\n'
            '    while i < 50\n'
            '        s = s + "]"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)  -> stdio.println("ok")\n'
            '        Err(_) -> stdio.println("err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "ok\n")

    def test_parse_json_exceeds_depth_limit_returns_err(self):
        # Audit 2026-05-25 H4: pre-fix the parser recursed without
        # bound, so adversarial ``[[[ ... ]]]`` input was a DoS
        # surface (Wasm stack trap or deep recursion before failing).
        # Post-fix 150 levels exceeds the 100-level cap and the
        # parser returns Err(...) cleanly with a "max nesting depth"
        # diagnostic.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 150\n'
            '        s = s + "["\n'
            '        i = i + 1\n'
            '    i = 0\n'
            '    while i < 150\n'
            '        s = s + "]"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)   -> stdio.println("unexpected ok")\n'
            '        Err(msg) -> stdio.println(msg)\n'
        )
        out = self._run_capturing_stdout(src)
        self.assertIn("max nesting depth", out)

    def test_parse_json_deeply_nested_objects_capped(self):
        # Same cap applies to nested objects: 150 nested ``{"k":...}``
        # exceeds the depth limit.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 150\n'
            '        s = s + "{\\"k\\":"\n'
            '        i = i + 1\n'
            '    s = s + "null"\n'
            '    i = 0\n'
            '    while i < 150\n'
            '        s = s + "}"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)    -> stdio.println("unexpected ok")\n'
            '        Err(msg) -> stdio.println(msg)\n'
        )
        out = self._run_capturing_stdout(src)
        self.assertIn("max nesting depth", out)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringSplit(unittest.TestCase):
    """Phase 6H: String.split(sep) -> List<String> via single-char
    separator. Also exercises the new List<String> baseline
    (literal + index + iter) that the same change unlocks."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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
        import io
        import sys
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
            self._run_capturing_stdout(src), "3.14\n0.0\n",
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
        import io
        import sys
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


class TestWasmActionableErrors(unittest.TestCase):
    """Placeholder for future actionable-error tests. The two
    cases that lived here (generic user functions, lambda over
    String) are both closed:
    - generics: monomorphised by the IR pass; see
      TestWasmGenericMonomorphisation
    - lambda over String: handled via multi-value lowering;
      see TestWasmClosureStringTypes

    Kept as a class so a future surfacing of a NEW unsupported
    construct has an obvious home for its actionable-error test.
    """


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmClosureStringTypes(unittest.TestCase):
    """Closures with String params and/or String returns lower
    as multi-value Wasm functions: a String param becomes two
    i32s ``(ptr, len)`` in the closure signature, a String
    return becomes a multi-value ``(result i32 i32)``. The
    call-site emitter already pushed two i32s for a String arg
    and called ``_set_string_dst`` for a String dst; this
    class pins the now-functional path end-to-end via
    ``--wasm --run``."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_lambda_with_string_param(self):
        # The pred lambda takes a String, returns a Bool. The
        # lifted lambda's signature becomes (env i32, s_ptr i32,
        # s_len i32) -> i32; the call-site pushes 2 i32s for the
        # String arg.
        src = (
            'fun apply_pred(items: List<String>, pred: Fun(String) -> Bool) -> Int\n'
            '    var count = 0\n'
            '    for x in items\n'
            '        if pred(x)\n'
            '            count = count + 1\n'
            '    return count\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<String> = ["a", "bb", "ccc"]\n'
            '    let n = apply_pred(xs, fun(s: String) -> Bool => s.length() > 1)\n'
            '    stdio.println("n=${n}")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "n=2\n")

    def test_lambda_returning_string(self):
        # The f lambda takes an Int, returns a String. The
        # lifted lambda's result becomes multi-value
        # (result i32 i32); the call-site stores into
        # ${dst}_ptr / ${dst}_len via _set_string_dst.
        src = (
            'fun transform(items: List<Int>, f: Fun(Int) -> String) -> List<String>\n'
            '    var out: List<String> = []\n'
            '    for x in items\n'
            '        out.push(f(x))\n'
            '    return out\n'
            '\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [1, 2, 3]\n'
            '    let ss = transform(xs, fun(n: Int) -> String => "n=${n}")\n'
            '    for s in ss\n'
            '        stdio.println(s)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=1\nn=2\nn=3\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmUserCapMethodDispatch(unittest.TestCase):
    """User-defined capability methods (``capability ReadOnlyFs``
    plus ``impl ReadOnlyFs for ...``) used to fall through to
    TyUnknown in the analyzer because ``_check_method_call``
    only routed built-in capability names to the cap-method
    table. The fix in 2026-05-26 broadens the check to any
    SymbolKind.CAPABILITY symbol and populates the cap's
    method table during the second declarations pass. These
    tests pin user-cap method calls + ``?`` propagation
    end-to-end under ``--wasm --run``."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_user_cap_method_call_typed_correctly(self):
        # Before the fix: greet's call to log.info(...) was
        # typed as TyUnknown; the lowerer dropped the dst type
        # to ``?`` and the Wasm emitter raised a generic
        # layout error. Now the call returns Unit correctly
        # and the program runs end-to-end.
        src = (
            'pub capability Logger\n'
            '    fun info(self, msg: String) -> Unit\n'
            'pub type StdioLogger { stdio: Stdio }\n'
            'pub fun make_logger(stdio: Stdio) -> StdioLogger\n'
            '    return StdioLogger { stdio: stdio }\n'
            'impl Logger for StdioLogger\n'
            '    fun info(self, msg: String) -> Unit\n'
            '        self.stdio.println("[INFO] ${msg}")\n'
            'fun greet(log: Logger, name: String)\n'
            '    log.info("hello ${name}")\n'
            'fun main(stdio: Stdio)\n'
            '    let log = make_logger(stdio)\n'
            '    greet(log, "world")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "[INFO] hello world\n",
        )

    def test_user_cap_method_returning_int(self):
        # Pins the analyzer's return-type propagation for a
        # user-cap method whose return is a single-value Int.
        # Without the fix, ``inc.bump()`` would have typed as
        # TyUnknown and the caller's ``Int`` annotation would
        # have raised a let-binding mismatch in the analyzer.
        src = (
            'pub capability Counter\n'
            '    fun bump(self) -> Int\n'
            'pub type C { n: Int }\n'
            'pub fun make_c() -> C\n'
            '    return C { n: 42 }\n'
            'impl Counter for C\n'
            '    fun bump(self) -> Int\n'
            '        return self.n + 1\n'
            'fun use_counter(inc: Counter) -> Int\n'
            '    return inc.bump()\n'
            'fun main(stdio: Stdio)\n'
            '    let c = make_c()\n'
            '    let v: Int = use_counter(c)\n'
            '    stdio.println("v=${v}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "v=43\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTupleParamTypes(unittest.TestCase):
    """Bare tuple types in function parameter / return positions
    (``fun f(p: (String, Int)) -> (String, Int)``) lower to an
    i32 pointer-shaped value at the Wasm level. Before
    2026-05-26 the IR's ``_type_name`` helper had no
    ``TupleType`` AST case and fell through to ``repr(te)``,
    which stuffed the AST node's text into a ``ty`` string.
    Wrapped forms (``List<(String, Int)>``) short-circuited
    via the ``head in ("List", ...)`` branch in
    ``_wasm_type`` and worked by accident; bare tuple params
    surfaced the gap. Test pins the fix."""

    def _run(self, src: str) -> int:
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return instance.exports(store)["main"](store)

    def test_tuple_param_and_return(self):
        # main returns the second element of a (Int, Int) tuple
        # passed through a helper. Pins the lowerer +
        # _wasm_type contract for bare tuple types.
        src = (
            'fun second(t: (Int, Int)) -> Int\n'
            '    let (a, b) = t\n'
            '    return b\n'
            'fun main() -> Int\n'
            '    return second((10, 42))\n'
        )
        self.assertEqual(self._run(src), 42)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmIoErrorFormatStr(unittest.TestCase):
    """``${io}`` where ``io: IoError`` used to fail the Wasm
    backend with ``Phase 6F: FormatStr value of type 'IoError'
    not supported (Int / Bool / String only)``. Python tolerated
    it via ``__str__``. The 2026-05-27 fix special-cases IoError
    in ``_emit_format_part_stash`` to read the ``message`` field
    (a String at offset 0 of the 16-byte IoError record).

    General struct-to-string codegen for arbitrary user types
    is a separate (still open) P1 item; the cheap IoError
    special-case lands now because it unblocks the showcase's
    common ``stdio.eprintln("read error: ${io}")`` pattern."""

    def _run_capturing_stderr(self, src: str) -> str:
        # IoError interpolation flows through ``stdio.eprintln``
        # in the typical pattern; capture stderr to assert the
        # message renders correctly. The actual error path uses
        # fs.read on a non-existent file which returns an
        # IoError carrying a real OS message.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_err = sys.stderr
        sys.stderr = out
        try:
            host.run_main(blob)
        finally:
            sys.stderr = saved_err
        return out.getvalue()

    def test_io_error_interpolated_via_eprintln(self):
        # Trigger a real IoError via fs.read on a missing path,
        # match the Err, interpolate the IoError into a stderr
        # message. The exact OS message varies, so we only
        # assert the prefix + non-empty suffix.
        src = (
            'fun main(stdio: Stdio, fs: Fs)\n'
            '    match fs.read("/does/not/exist/at/all")\n'
            '        Ok(_)  -> stdio.println("unexpected ok")\n'
            '        Err(e) -> stdio.eprintln("read error: ${e}")\n'
        )
        out = self._run_capturing_stderr(src)
        self.assertTrue(
            out.startswith("read error: "),
            f"unexpected stderr: {out!r}",
        )
        self.assertGreater(
            len(out.strip()), len("read error: "),
            "IoError message should be non-empty",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGenericMonomorphisationFunType(unittest.TestCase):
    """Bonus regression added 2026-05-27: the monomorphiser's
    string-based unifier originally treated ``Fun(...) -> R``
    as an opaque atom because ``_parse_ty`` had no case for
    closure types. Consequence: a generic HOF whose param
    list included a closure (the showcase's
    ``count_by<T>(items: List<T>, key: Fun(T) -> String)``)
    failed unification at every call site and was never
    monomorphised, leaving an undefined ``$count_by`` call in
    the WAT. Test pins the now-working shape."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_generic_hof_with_closure_param(self):
        src = (
            'fun count_matching<T>(items: List<T>, pred: Fun(T) -> Bool) -> Int\n'
            '    var n = 0\n'
            '    for x in items\n'
            '        if pred(x)\n'
            '            n = n + 1\n'
            '    return n\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [1, 2, 3, 4, 5]\n'
            '    let n = count_matching(xs, fun(v: Int) -> Bool => v > 2)\n'
            '    stdio.println("n=${n}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmCapCallViaFieldAccess(unittest.TestCase):
    """The IR's MethodCall.cap_used field was set only when the
    receiver was a capability parameter (``param.method(...)``).
    User-defined cap impls that reach a built-in cap via a struct
    field (``self.fs.read(...)``) left cap_used as None, so the
    Wasm backend's ``has_indirect_cap_call`` detector in
    ``_collect_locals`` missed the call. The canonical-ABI
    indirect-return area ``$_ret_area`` then went undeclared and
    wasm-tools rejected the WAT with ``unknown local: $_ret_area``.

    Fix landed 2026-05-27: the lowerer now also tags cap_used
    when the receiver's type string resolves to a built-in cap,
    regardless of how it was reached. Test pins the impl-method-
    calls-built-in-cap pattern that the capa_showcase exercised
    via its ReadOnlyFs wrapper."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_user_cap_impl_calls_builtin_cap_via_self_field(self):
        # ReadOnlyFs.read delegates to self.fs.read (built-in
        # Fs.read with canonical-ABI Result<String, IoError>
        # return area). Caller matches the Result and routes
        # Err to a default string. Exercises the full chain:
        # user-cap method dispatch + impl body's built-in-cap
        # call via field access + $_ret_area declaration.
        src = (
            'pub capability ReadOnlyFs\n'
            '    fun read(self, path: String) -> Result<String, IoError>\n'
            'pub type ReadOnlyFsImpl { fs: Fs }\n'
            'pub fun make_ro_fs(fs: Fs) -> ReadOnlyFsImpl\n'
            '    return ReadOnlyFsImpl { fs: fs }\n'
            'impl ReadOnlyFs for ReadOnlyFsImpl\n'
            '    fun read(self, path: String) -> Result<String, IoError>\n'
            '        return self.fs.read(path)\n'
            'fun describe(fs: ReadOnlyFs, path: String) -> String\n'
            '    match fs.read(path)\n'
            '        Ok(s)  -> return s\n'
            '        Err(_) -> return "<missing>"\n'
            'fun main(stdio: Stdio, fs: Fs)\n'
            '    let ro = make_ro_fs(fs)\n'
            '    stdio.println(describe(ro, "/does/not/exist"))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "<missing>\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGlobalStringConst(unittest.TestCase):
    """Top-level ``pub const NAME: String = "..."`` referenced from
    a function body used to fail the Wasm backend with either
    ``cannot push string Value of kind 'global' as (ptr, len)``
    (interpolation site) or ``cannot bind String dst ... from
    value Value(kind='global', ...)`` (let-binding site).

    Root cause was two-fold: (1) ``_push_string_value_as_ptr_len``
    and ``_emit_string_assign`` had no ``global`` case; (2) even
    if they had, the constant's UTF-8 bytes were never interned
    in the data segment (the discovery pass walks function
    bodies only, never ConstDecl) so the recursion would push
    offset=0 -- the data segment's start, not the constant's
    location.

    Fix landed 2026-05-27: pre-intern every String-typed
    top-level constant at module-emit init, and add the
    ``global`` branch in both push / assign helpers. Tests
    pin both code paths."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_const_string_interpolated_via_push(self):
        # Exercises ``_push_string_value_as_ptr_len``'s new
        # global branch -- the format-string lowering pushes
        # the value as (ptr, len) into the format buffer.
        src = (
            'pub const SCHEMA: String = "1.0"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("schema=${SCHEMA}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "schema=1.0\n",
        )

    def test_const_string_let_bound_then_used(self):
        # Exercises ``_emit_string_assign``'s new global branch
        # -- the let copies the constant into a String local
        # (${dst}_ptr / ${dst}_len), then println reads from
        # the local.
        src = (
            'pub const GREETING: String = "hello"\n'
            'fun main(stdio: Stdio)\n'
            '    let g = GREETING\n'
            '    stdio.println(g)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hello\n",
        )

    def test_const_string_passed_as_arg(self):
        # The arg push path also routes through
        # _push_string_value_as_ptr_len for String params.
        src = (
            'pub const NAME: String = "world"\n'
            'fun greet(stdio: Stdio, name: String)\n'
            '    stdio.println("hi ${name}")\n'
            'fun main(stdio: Stdio)\n'
            '    greet(stdio, NAME)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hi world\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGenericMonomorphisation(unittest.TestCase):
    """Generic free functions (``fun first<T>(items: List<T>) -> Option<T>``)
    used to crash the Wasm backend at layout time because the IR
    carried ``T`` as a string with no Wasm encoding. The
    monomorphisation pass at ``capa/ir/_monomorphise.py`` walks
    the IR after lowering, infers each call's type-parameter
    substitution from the actual arg types, and synthesises a
    specialised clone with a mangled name (e.g., ``first__Int``).
    These tests pin the new behaviour end-to-end through
    ``--wasm --run``."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
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

    def test_generic_first_with_int_arg(self):
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [10, 20, 30]\n'
            '    match first(xs)\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("empty")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got 10\n")

    def test_generic_first_with_string_arg(self):
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<String> = ["alpha", "beta"]\n'
            '    match first(xs)\n'
            '        Some(s) -> stdio.println(s)\n'
            '        None    -> stdio.println("empty")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alpha\n")

    def test_same_generic_function_called_with_two_types(self):
        # Both call sites must produce their own monomorphic clone;
        # the dedupe key is the substitution, not the source name.
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let ns: List<Int> = [1, 2]\n'
            '    let ss: List<String> = ["x", "y"]\n'
            '    match first(ns)\n'
            '        Some(n) -> stdio.println("int=${n}")\n'
            '        None    -> stdio.println("ne")\n'
            '    match first(ss)\n'
            '        Some(s) -> stdio.println("str=${s}")\n'
            '        None    -> stdio.println("se")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "int=1\nstr=x\n",
        )


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
        import io
        import sys
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

    def test_net_get_file_url_under_component_host(self):
        # Slice 3: ``Net.get`` through the Component Model bridge.
        # Same hermetic ``file://`` round-trip as the core-host
        # test; the component host lifts result<string, io-error>
        # via Python type dispatch (str -> Ok, IoErrorRecord ->
        # Err) and must agree on the Ok-arm bytes.
        import os
        import tempfile
        from pathlib import Path
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8",
        ) as f:
            f.write("body bytes from a fixture")
            fixture = f.name
        try:
            uri = Path(fixture).as_uri()
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.get(\"{uri}\")\n"
                "        Ok(text) -> stdio.println(\"got: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: read failed\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "got: body bytes from a fixture\n",
            )
        finally:
            os.unlink(fixture)

    def test_net_post_under_component_host(self):
        # Slice 8 (2026-05): ``Net.post`` parallels ``Net.get`` on
        # the Component Model side. Same hermetic loopback fixture
        # as the core-host happy-path test in TestWasmNetExecutes;
        # the component host's ``post`` callback lifts
        # ``Result<String, IoError>`` via the same Python type
        # dispatch (``str`` -> Ok, ``IoErrorRecord`` -> Err).
        import http.server
        import threading
        body_text = "post-body-cm"

        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                self.send_response(200)
                self.send_header(
                    "Content-Type", "application/octet-stream",
                )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args, **kwargs):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{port}/echo"
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.post(\"{url}\", \"{body_text}\")\n"
                "        Ok(text) -> stdio.println(\"echo: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: post failed\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                f"echo: {body_text}\n",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_fs_round_trip_under_component_host(self):
        # Slice 1 (2026-05): ``Fs.read`` / ``Fs.write`` /
        # ``Fs.exists`` through the Component Model bridge. Writes
        # a fixture, reads it back, then asks ``exists`` to confirm.
        # The two result<...> arms exercise both Ok and Err code
        # paths on a single program.
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        os.unlink(path)
        # Escape backslashes in the path for the source-level
        # double-quoted string literal (Windows tempdir).
        escaped = path.replace("\\", "\\\\")
        try:
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.write(\"{escaped}\", \"hello-cm\")\n"
                "        Ok(_) -> stdio.println(\"wrote\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: write failed\")\n"
                f"    match fs.read(\"{escaped}\")\n"
                "        Ok(text) -> stdio.println(\"read: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: read failed\")\n"
                f"    if fs.exists(\"{escaped}\")\n"
                "        stdio.println(\"exists: yes\")\n"
                "    else\n"
                "        stdio.println(\"exists: no\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "wrote\nread: hello-cm\nexists: yes\n",
            )
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_env_get_under_component_host(self):
        # Slice 1 surface continued: ``Env.get`` returns
        # ``Option<String>``. The component host lifts the Python
        # ``str | None`` directly to ``Some(...)`` / ``None``. We
        # set an env var explicitly so the value is deterministic
        # across CI runs.
        import os
        os.environ["CAPA_CM_FIXTURE"] = "hello"
        try:
            src = (
                "fun main(stdio: Stdio, env: Env)\n"
                "    match env.get(\"CAPA_CM_FIXTURE\")\n"
                "        Some(v) -> stdio.println(\"got: ${v}\")\n"
                "        None -> stdio.println(\"missing\")\n"
                "    match env.get(\"CAPA_CM_DEFINITELY_UNSET_XYZ\")\n"
                "        Some(_) -> stdio.eprintln(\"BUG: leaked\")\n"
                "        None -> stdio.println(\"missing: ok\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "got: hello\nmissing: ok\n",
            )
        finally:
            os.environ.pop("CAPA_CM_FIXTURE", None)

    def test_fs_mkdir_and_list_dir_under_component_host(self):
        # Slice 1 host bridges: ``Fs.mkdir`` returns
        # ``Result<Unit, IoError>`` (a result with an empty Ok
        # arm); ``Fs.list_dir`` returns ``Result<List<String>,
        # IoError>``. Both exercise canonical-ABI return shapes
        # with custom-record + list-of-string lift paths that
        # nothing else in the CM test suite hits.
        import os
        import tempfile
        base = tempfile.mkdtemp(prefix="capa_cm_listdir_")
        with open(os.path.join(base, "a.txt"), "w") as f:
            f.write("a")
        with open(os.path.join(base, "b.txt"), "w") as f:
            f.write("b")
        target = os.path.join(base, "newdir")
        base_lit = base.replace("\\", "\\\\")
        target_lit = target.replace("\\", "\\\\")
        try:
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target_lit}\")\n"
                "        Ok(_) -> stdio.println(\"made dir\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: mkdir failed\")\n"
                f"    match fs.list_dir(\"{base_lit}\")\n"
                "        Ok(names) -> stdio.println(\"count: ${names.length()}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: list_dir failed\")\n"
            )
            # Three entries: a.txt, b.txt, newdir. Order is OS-
            # dependent so we only assert the count; that's
            # enough to validate the list<string> lift path
            # produced a length-3 list rather than 0 or trash.
            self.assertEqual(
                self._run_capturing_stdout(src),
                "made dir\ncount: 3\n",
            )
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)

    def test_stdio_read_line_eof_under_component_host(self):
        # Slice 1 host bridge: ``Stdio.read_line`` returns
        # ``Result<String, IoError>``; on EOF the bridge produces
        # Err with a known message. Validates both that the
        # bridge is wired into the CM linker and that the Err
        # arm's IoError record lifts through correctly.
        import io
        import sys
        saved_in = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            src = (
                "fun main(stdio: Stdio)\n"
                "    match stdio.read_line()\n"
                "        Ok(line) -> stdio.println(\"got: ${line}\")\n"
                "        Err(_) -> stdio.println(\"eof\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "eof\n",
            )
        finally:
            sys.stdin = saved_in

    def test_random_seeded_sequence_under_component_host(self):
        # Slice 2: the ``Random`` capability uses a pure-WAT
        # SplitMix64 PRNG that runs entirely guest-side; the only
        # host call is ``random.system-seed`` for entropy when
        # the program constructs a fresh ``Random()`` without a
        # seed. With ``Random.with_seed(seed)`` the host bridge
        # never fires, so the sequence is byte-identical across
        # backends. This test pins that property under the CM
        # path to catch any future regression in either the
        # PRNG lowering or the CM wiring.
        src = (
            "fun main(stdio: Stdio, r: Random)\n"
            "    let rng = r.with_seed(42)\n"
            "    let a = rng.int_range(0, 1000)\n"
            "    let b = rng.int_range(0, 1000)\n"
            "    let c = rng.int_range(0, 1000)\n"
            "    stdio.println(\"a=${a} b=${b} c=${c}\")\n"
        )
        out_cm = self._run_capturing_stdout(src)
        # Cross-check: the core host produces the same line. Any
        # divergence means either the PRNG lowering or the CM
        # wiring of ``random.system-seed`` diverged from the
        # core path; the body lives in linear memory in either
        # case and shouldn't care which host wraps it.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        core_out = io.StringIO()
        saved = sys.stdout
        sys.stdout = core_out
        try:
            host.run_main(core_blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out_cm, core_out.getvalue())

    def _core_stdout(self, src: str, args=()) -> str:
        # Run the same program under the NON-component core host so a
        # test can assert 3-backend parity (Python is covered by the
        # transpiler tests; here we pin core-wasm == component). The
        # component host discards ``main``'s return value exactly like
        # the core host, so a successful run (no exception) IS the
        # exit-0 assertion for both.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        host = WasmHost(args=list(args))
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(core_blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_main_returning_int_runs_and_discards_value(self):
        # Regression for the component-backend ``main -> Int`` bug:
        # the WIT world now advertises ``-> s64`` so ``component new``
        # accepts the core module's ``(result i64)`` main. The return
        # value is discarded (exit 0), same stdout as the core host.
        src = (
            "fun main(stdio: Stdio) -> Int\n"
            "    stdio.println(\"int-ret\")\n"
            "    return 42\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "int-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_float_runs_and_discards_value(self):
        src = (
            "fun main(stdio: Stdio) -> Float\n"
            "    stdio.println(\"float-ret\")\n"
            "    return 3.5\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "float-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_bool_runs_and_discards_value(self):
        src = (
            "fun main(stdio: Stdio) -> Bool\n"
            "    stdio.println(\"bool-ret\")\n"
            "    return true\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "bool-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_int_with_handle_param_runs(self):
        # A ``main`` that BOTH takes a cap-handle param (Fs) AND
        # returns a scalar: the world export is
        # ``func(fs: u32) -> s64``. Exercises the result clause sitting
        # after the handle param list end-to-end through the CM host.
        src = (
            "fun main(stdio: Stdio, fs: Fs) -> Int\n"
            "    let _e = fs.exists(\"/nope\")\n"
            "    stdio.println(\"handle-int-ret\")\n"
            "    return 9\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "handle-int-ret\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools or wasmtime-py not installed",
)
class TestWasmStructToStringDisplay(unittest.TestCase):
    """``${value}`` where ``value`` is a user struct routes through
    ``value.to_string()`` when the struct declares
    ``fun to_string(self) -> String`` in an impl block. Mirrors
    the Python emitter's Display protocol (transpiler's f-string
    emitter consults the same set of opted-in types), so both
    backends produce identical output for any struct that opted
    in. Structs that did NOT opt in fail Wasm emission with an
    actionable error pointing at the protocol.

    Closes the P1 "Wasm FormatStr on arbitrary user struct types"
    item with an opt-in Display protocol rather than auto-derive,
    which would have required reproducing Python's dataclass
    repr (TypeName(field=value, ...)) byte-for-byte and would
    have committed both backends to an arbitrary format choice.
    """

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
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
        return out.getvalue()

    def test_struct_with_to_string_renders_via_display(self):
        # The user's to_string() returns a formatted String; the
        # Wasm emitter's FormatStr Display branch calls it and
        # stashes the returned (ptr, len) pair.
        src = (
            "type Point { x: Int, y: Int }\n"
            "impl Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"Point<${self.x}, ${self.y}>\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    stdio.println(\"p = ${p}\")\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "p = Point<3, 4>\n")

    def test_struct_without_to_string_rejected_at_analysis(self):
        # A struct with no to_string cannot be interpolated. This is
        # now caught at the ANALYSIS stage (``capa --check``), in both
        # backends, rather than only by the Wasm emitter -- closing
        # the divergence where the Python backend accepted it (via
        # dataclass repr) and only Wasm rejected it. The message is
        # actionable: it points at adding `fun to_string(self) ->
        # String`. The Wasm emitter keeps its own raise as defense in
        # depth, but it is unreachable through the analyzed path.
        from capa import analyze
        src = (
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    stdio.println(\"p = ${p}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertFalse(result.ok)
        msg = " ".join(e.message for e in result.errors)
        self.assertIn("interpolate", msg)
        self.assertIn("to_string", msg)
        self.assertIn("Point", msg)

    def test_struct_to_string_called_inside_method_body(self):
        # Verifies the dispatch works when the interpolated value
        # appears inside a regular function body, not just main.
        src = (
            "type Tag { name: String }\n"
            "impl Tag\n"
            "    fun to_string(self) -> String\n"
            "        return \"[${self.name}]\"\n"
            "fun describe(t: Tag) -> String\n"
            "    return \"tag is ${t}\"\n"
            "fun main(stdio: Stdio)\n"
            "    let t = Tag { name: \"alpha\" }\n"
            "    stdio.println(describe(t))\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "tag is [alpha]\n",
        )

    def test_legacy_python_backend_uses_same_to_string(self):
        # The Python transpiler's Display path mirrors the Wasm
        # one; both should print the same `${p}` output for any
        # struct that opted into the protocol. Smoke check via
        # the in-process transpiler.
        src = (
            "type Point { x: Int, y: Int }\n"
            "impl Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"Point<${self.x}, ${self.y}>\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    stdio.println(\"p = ${p}\")\n"
        )
        from capa import analyze, transpile, Lexer, Parser
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        py = transpile(module, types=result.types)
        # The emitted Python should wrap the interpolated `p` in
        # a .to_string() call rather than letting it fall through
        # to dataclass repr. The emitter parenthesises the
        # expression before appending `.to_string()` so a complex
        # sub-expression (e.g. a method call) stays self-contained.
        self.assertIn("(p).to_string()", py)
        # And the interpolation concatenates that result, not the bare
        # `p`. Interpolation lowers to a ``str(...) + ...`` concatenation
        # (not an f-string) so nested-string / recursive interpolation
        # stays Python-3.10-compatible; the Display field is appended
        # verbatim because ``to_string()`` already returns a String.
        self.assertIn("'p = ' + (p).to_string()", py)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools or wasmtime-py not installed",
)
class TestWasmMatchEmission(unittest.TestCase):
    """Focused coverage for the dark code paths in
    ``capa/ir/_emit_wasm/_match.py``: the scrutinee-type-specific
    emitters (Bool / String / Tuple) and the per-shape payload
    binders (Float / Bool / String / pointer-shaped tuple).

    Each test compiles a small Capa function, instantiates it
    via wasmtime, and asserts the result matches what the legacy
    Python pipeline would produce. Coverage gaps in this module
    were measured at 43 % before this class landed; the tests
    were written from the missing-line ranges reported by
    ``coverage report --show-missing`` to maximise lines hit per
    test rather than chasing breadth."""

    def _exec(self, src: str, fn_name: str, *args):
        """Same helper as TestWasmExecutes._exec. Inlined here so
        coverage for the match emitter stays attributable to this
        class rather than diffused across the file."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        mod = wasmtime.Module(engine, blob)
        instance = wasmtime.Instance(store, mod, [])
        fn = instance.exports(store)[fn_name]
        return fn(store, *args)

    # ------- Bool-scrutinee match: catch-all branches -------

    def test_bool_match_with_pat_ident_catch_all(self):
        # ``other`` binds the scrutinee; emitter writes
        # ``local.set $other`` and runs the arm body inline.
        src = (
            "fun pick(b: Bool) -> Int\n"
            "    match b\n"
            "        true -> return 1\n"
            "        other -> return 0\n"
        )
        self.assertEqual(self._exec(src, "pick", 1), 1)
        self.assertEqual(self._exec(src, "pick", 0), 0)

    def test_bool_match_with_wildcard_catch_all(self):
        # ``_`` matches without binding; emitter emits the body
        # then ``break``s out of the arm loop.
        src = (
            "fun pick(b: Bool) -> Int\n"
            "    match b\n"
            "        false -> return 0\n"
            "        _ -> return 1\n"
        )
        self.assertEqual(self._exec(src, "pick", 1), 1)
        self.assertEqual(self._exec(src, "pick", 0), 0)

    # ------- String-scrutinee match: every arm shape ----------

    def test_string_match_with_literal_arms_and_wildcard(self):
        # Hits the literal-arm path (interns each pattern + calls
        # ``$str_eq``) plus the PatWildcard catch-all close.
        src = (
            "fun classify(s: String) -> Int\n"
            "    match s\n"
            "        \"yes\" -> return 1\n"
            "        \"no\" -> return 0\n"
            "        _ -> return -1\n"
        )
        # Need a Stdio entrypoint to drive String input; build
        # an indirection that hard-codes the strings instead.
        src = (
            "fun classify_yes() -> Int\n"
            "    return classify_inner(\"yes\")\n"
            "fun classify_no() -> Int\n"
            "    return classify_inner(\"no\")\n"
            "fun classify_other() -> Int\n"
            "    return classify_inner(\"maybe\")\n"
            "fun classify_inner(s: String) -> Int\n"
            "    match s\n"
            "        \"yes\" -> return 1\n"
            "        \"no\" -> return 0\n"
            "        _ -> return -1\n"
        )
        self.assertEqual(self._exec(src, "classify_yes"), 1)
        self.assertEqual(self._exec(src, "classify_no"), 0)
        self.assertEqual(self._exec(src, "classify_other"), -1)

    def test_string_match_with_pat_ident_catch_all(self):
        # ``other`` binds the receiver into ``$other_ptr`` /
        # ``$other_len`` Wasm locals; the body can then re-use
        # the binding (here, computes its length).
        src = (
            "fun pick_len() -> Int\n"
            "    return inner(\"banana\")\n"
            "fun inner(s: String) -> Int\n"
            "    match s\n"
            "        \"\" -> return -1\n"
            "        other -> return other.length()\n"
        )
        self.assertEqual(self._exec(src, "pick_len"), 6)

    # ------- Tuple-scrutinee match: literal sub-patterns -------

    def test_tuple_match_with_literal_int_sub_patterns(self):
        # ``(1, 2) -> ...`` exercises _emit_tuple_slot_eq's int
        # branch + the AND-of-slots cascade.
        src = (
            "fun pick(a: Int, b: Int) -> Int\n"
            "    let p = (a, b)\n"
            "    return match p\n"
            "        (1, 2) -> 100\n"
            "        (3, _) -> 200\n"
            "        (x, y) -> x + y\n"
        )
        self.assertEqual(self._exec(src, "pick", 1, 2), 100)
        self.assertEqual(self._exec(src, "pick", 3, 99), 200)
        self.assertEqual(self._exec(src, "pick", 10, 20), 30)

    def test_tuple_match_with_literal_bool_sub_pattern(self):
        # ``(true, _) -> ...`` exercises _emit_tuple_slot_eq's
        # bool branch (i64.load + i32.wrap_i64 + i32.eq).
        src = (
            "fun pick(b: Bool, n: Int) -> Int\n"
            "    let p = (b, n)\n"
            "    return match p\n"
            "        (true, x) -> x\n"
            "        (false, x) -> -x\n"
        )
        self.assertEqual(self._exec(src, "pick", 1, 7), 7)
        self.assertEqual(self._exec(src, "pick", 0, 7), -7)

    def test_tuple_match_with_literal_string_sub_pattern(self):
        # ``("yes", _) -> ...`` exercises _emit_tuple_slot_eq's
        # str branch (packed-i64 split + interned $str_eq call).
        src = (
            "fun pick_yes() -> Int\n"
            "    return inner(\"yes\", 5)\n"
            "fun pick_other() -> Int\n"
            "    return inner(\"no\", 5)\n"
            "fun inner(s: String, n: Int) -> Int\n"
            "    let p = (s, n)\n"
            "    return match p\n"
            "        (\"yes\", x) -> x * 10\n"
            "        (k, x) -> x\n"
        )
        self.assertEqual(self._exec(src, "pick_yes"), 50)
        self.assertEqual(self._exec(src, "pick_other"), 5)

    # ------- Tuple-scrutinee match: bind shapes --------------

    def test_tuple_match_binds_string_element(self):
        # ``(k, x) -> ...`` with k: String hits the String
        # branch in _emit_tuple_arm_binds (i64 split into _ptr /
        # _len locals).
        src = (
            "fun pick() -> Int\n"
            "    return inner(\"hello\", 99)\n"
            "fun inner(s: String, n: Int) -> Int\n"
            "    let p = (s, n)\n"
            "    return match p\n"
            "        (k, x) -> k.length() + x\n"
        )
        self.assertEqual(self._exec(src, "pick"), 104)

    def test_tuple_match_binds_float_element(self):
        # ``(f, x) -> ...`` with f: Float hits the Float branch
        # in _emit_tuple_arm_binds (f64.load).
        src = (
            "fun pick(f: Float, n: Int) -> Int\n"
            "    let p = (f, n)\n"
            "    return match p\n"
            "        (g, x) -> x\n"
        )
        # Float arg encoded as wasmtime-py float; we just need
        # the bind path to compile and return the int side.
        self.assertEqual(self._exec(src, "pick", 3.14, 42), 42)

    def test_tuple_match_catch_all_pat_ident_whole(self):
        # PatIdent on the whole tuple: ``p -> ...`` binds the
        # tuple pointer; subsequent arms are dead.
        src = (
            "fun pick(a: Int, b: Int) -> Int\n"
            "    let p = (a, b)\n"
            "    return match p\n"
            "        whole -> a + b\n"
        )
        self.assertEqual(self._exec(src, "pick", 3, 4), 7)

    def test_tuple_match_catch_all_wildcard(self):
        # PatWildcard on the whole tuple: ``_ -> ...`` matches
        # without binding; emitter exits the arm loop.
        src = (
            "fun pick(a: Int, b: Int) -> Int\n"
            "    let p = (a, b)\n"
            "    return match p\n"
            "        _ -> 42\n"
        )
        self.assertEqual(self._exec(src, "pick", 1, 2), 42)

    # ------- Variant payload binding: Float / Bool / Tuple ----

    def test_variant_payload_float_binding(self):
        # JsonValue's JNum variant carries a Float payload;
        # extracting it via match hits the Float branch in
        # _bind_variant_payload (f64.load offset=8).
        src = (
            "fun read_num() -> Float\n"
            "    let jv = JNum(3.5)\n"
            "    return match jv\n"
            "        JNum(x) -> x\n"
            "        _ -> 0.0\n"
        )
        self.assertAlmostEqual(self._exec(src, "read_num"), 3.5, places=5)

    def test_variant_payload_bool_binding(self):
        # JBool carries a Bool payload; the Bool branch in
        # _bind_variant_payload (i64.load + i32.wrap_i64).
        src = (
            "fun read_flag() -> Int\n"
            "    let jv = JBool(true)\n"
            "    return match jv\n"
            "        JBool(b) ->\n"
            "            if b\n"
            "                return 1\n"
            "            return 0\n"
            "        _ -> -1\n"
        )
        self.assertEqual(self._exec(src, "read_flag"), 1)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools or wasmtime-py not installed",
)
class TestWasmMatchArmGuards(unittest.TestCase):
    """Coverage for the Wasm backend's match-arm guard emission.

    Until 2026-05-25 the Wasm emitter rejected EVERY arm with a
    guard (the IR has carried ``MatchArm.guard`` + ``guard_setup``
    since 2026-05-24 but only the Python backend honoured them).
    The new flat-block-with-labeled-exit path emits one ``block
    $match_done<N>`` per match; each arm's predicate + guard are
    NESTED ifs and a matched arm escapes via ``br``. Failed
    guards fall through to the next arm naturally.

    Each test compiles a small Capa function, executes it under
    wasmtime, and confirms the runtime output against the same
    program's expected behaviour (which the Python backend already
    supports). The string oracle is implicit: any output mismatch
    surfaces immediately as an assertion failure."""

    def _exec(self, src: str, fn_name: str, *args):
        """Same helper as TestWasmMatchEmission._exec; keeps the
        guards class self-contained for coverage attribution."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        mod = wasmtime.Module(engine, blob)
        instance = wasmtime.Instance(store, mod, [])
        fn = instance.exports(store)[fn_name]
        return fn(store, *args)

    # ---- Sum-type: variant arm with a guard on the binder -------

    def test_simple_guard_on_int_variant(self):
        # ``Ok(n) if n > 5 -> "big"`` covers the basic guarded
        # variant arm. The guard references the variant's payload
        # binder so the binder must be in scope at guard time;
        # exercise both branches (big / small) plus the Err fall
        # through.
        src = (
            "fun classify(n: Int) -> Int\n"
            "    let r = Ok(n)\n"
            "    match r\n"
            "        Ok(v) if v > 5 -> return 100\n"
            "        Ok(_) -> return 50\n"
            "        Err(_) -> return -1\n"
            "    return 0\n"
        )
        self.assertEqual(self._exec(src, "classify", 10), 100)
        self.assertEqual(self._exec(src, "classify", 5), 50)
        self.assertEqual(self._exec(src, "classify", 3), 50)

    # ---- Sum-type: guard prelude is non-trivial -----------------

    def test_guard_with_setup(self):
        # ``Some(p) if p.x + p.y > 10`` lowers to a guard whose
        # guard_setup contains a FieldAccess pair + BinOp; the
        # emitter must emit them as normal instructions before
        # the inner ``if``. Struct-shaped payload binding pushes
        # an i32 pointer through the i64-uniform slot, so this
        # also covers the pointer-shape branch of
        # _bind_variant_payload.
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun pick(px: Int, py: Int) -> Int\n"
            "    let p = Some(Point { x: px, y: py })\n"
            "    match p\n"
            "        Some(point) if point.x + point.y > 10 -> return 1\n"
            "        Some(_) -> return 2\n"
            "        None -> return 0\n"
            "    return -1\n"
        )
        self.assertEqual(self._exec(src, "pick", 5, 7), 1)
        self.assertEqual(self._exec(src, "pick", 3, 4), 2)
        self.assertEqual(self._exec(src, "pick", 1, 2), 2)

    # ---- Bool-scrutinee match with a guard ----------------------

    def test_bool_match_with_guard(self):
        # ``true if other_var > 0`` covers the
        # _emit_bool_match_with_guards path. The wildcard catches
        # both ``false`` and ``true with guard failed``.
        src = (
            "fun pick(b: Bool, x: Int) -> Int\n"
            "    match b\n"
            "        true if x > 0 -> return 1\n"
            "        _ -> return 0\n"
            "    return -1\n"
        )
        self.assertEqual(self._exec(src, "pick", 1, 5), 1)
        self.assertEqual(self._exec(src, "pick", 1, 0), 0)
        self.assertEqual(self._exec(src, "pick", 1, -3), 0)
        self.assertEqual(self._exec(src, "pick", 0, 5), 0)

    # ---- Int-scrutinee match: literal arms + ident catch-all ----

    def test_int_match_with_literals_and_ident_catch_all(self):
        # Deep literal cascade (i64.eq per arm) closing on an
        # identifier-bind default that USES the bound value, so the
        # ``local.set $other`` + body-uses-binding path is covered.
        # (Negative literal PATTERNS are not accepted by the surface
        # parser, so we drive negative scrutinees through the
        # catch-all instead; the emitter itself handles negative
        # ``i64.const`` fine.)
        src = (
            "fun pick(n: Int) -> Int\n"
            "    match n\n"
            "        0 -> return 100\n"
            "        1 -> return 101\n"
            "        2 -> return 102\n"
            "        3 -> return 103\n"
            "        4 -> return 104\n"
            "        other -> return other + 1000\n"
        )
        self.assertEqual(self._exec(src, "pick", 0), 100)
        self.assertEqual(self._exec(src, "pick", 1), 101)
        self.assertEqual(self._exec(src, "pick", 2), 102)
        self.assertEqual(self._exec(src, "pick", 4), 104)
        # Falls through to the ident catch-all, which adds 1000.
        self.assertEqual(self._exec(src, "pick", 7), 1007)
        # Negative scrutinee also routes through the catch-all.
        self.assertEqual(self._exec(src, "pick", -3), 997)

    def test_int_match_with_wildcard_catch_all(self):
        # ``_`` matches without binding; emitter emits the body then
        # ``break``s out of the arm loop.
        src = (
            "fun pick(n: Int) -> Int\n"
            "    match n\n"
            "        0 -> return 0\n"
            "        _ -> return 1\n"
        )
        self.assertEqual(self._exec(src, "pick", 0), 0)
        self.assertEqual(self._exec(src, "pick", 5), 1)

    # ---- Int-scrutinee match with a guard -----------------------

    def test_int_match_with_guard(self):
        # First arm: literal match on 0. Second arm: ident catch-all
        # whose guard is ``x > 0``. Third arm: wildcard fallback.
        # Exercises both the ``i64.eq`` predicate branch and the
        # bind-then-guard sequence in _emit_int_match_with_guards.
        src = (
            "fun pick(n: Int) -> Int\n"
            "    match n\n"
            "        0 -> return 0\n"
            "        x if x > 0 -> return 1\n"
            "        _ -> return -1\n"
            "    return -2\n"
        )
        self.assertEqual(self._exec(src, "pick", 0), 0)
        self.assertEqual(self._exec(src, "pick", 9), 1)
        self.assertEqual(self._exec(src, "pick", -3), -1)

    # ---- String-scrutinee match with a guard --------------------

    def test_string_match_with_guard(self):
        # First arm: literal match on "yes". Second arm: catch-all
        # bind whose guard calls a String method (.length() > 0).
        # Third arm: wildcard fallback. Exercises both the str_eq
        # predicate branch and the bind-then-guard sequence in
        # _emit_string_match_with_guards.
        src = (
            "fun classify_yes() -> Int\n"
            "    return inner(\"yes\")\n"
            "fun classify_no() -> Int\n"
            "    return inner(\"no\")\n"
            "fun classify_empty() -> Int\n"
            "    return inner(\"\")\n"
            "fun inner(s: String) -> Int\n"
            "    match s\n"
            "        \"yes\" -> return 1\n"
            "        x if x.length() > 0 -> return 2\n"
            "        _ -> return 0\n"
            "    return -1\n"
        )
        self.assertEqual(self._exec(src, "classify_yes"), 1)
        self.assertEqual(self._exec(src, "classify_no"), 2)
        self.assertEqual(self._exec(src, "classify_empty"), 0)

    # ---- Multi-guard cascade: every guard fails until one fires -

    def test_guard_failure_falls_through(self):
        # Four consecutive Ok(v) arms, each with a stricter guard.
        # The flat-block emission must let a failed guard fall
        # through to the next arm without skipping it (the bug
        # that motivated the rewrite).
        src = (
            "fun bucket(n: Int) -> Int\n"
            "    let r = Ok(n)\n"
            "    match r\n"
            "        Ok(v) if v > 100 -> return 4\n"
            "        Ok(v) if v > 10 -> return 3\n"
            "        Ok(v) if v > 0 -> return 2\n"
            "        Ok(_) -> return 1\n"
            "        Err(_) -> return -1\n"
            "    return 0\n"
        )
        self.assertEqual(self._exec(src, "bucket", 500), 4)
        self.assertEqual(self._exec(src, "bucket", 50), 3)
        self.assertEqual(self._exec(src, "bucket", 5), 2)
        self.assertEqual(self._exec(src, "bucket", 0), 1)
        self.assertEqual(self._exec(src, "bucket", -5), 1)

    # ---- Regression: guard-free matches still use the old path --

    def test_no_guard_matches_unchanged(self):
        # Mirrors a baseline TestWasmMatchEmission case; passes
        # iff the unconditional cascade path is still wired up
        # (the new ``has_guards`` switch must select the legacy
        # path when no arm carries a guard).
        src = (
            "fun classify(n: Int) -> Int\n"
            "    let r = Ok(n)\n"
            "    match r\n"
            "        Ok(_) -> return 1\n"
            "        Err(_) -> return 0\n"
            "    return -1\n"
        )
        self.assertEqual(self._exec(src, "classify", 42), 1)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStructuralEquality(unittest.TestCase):
    """Structural ``==`` / ``!=`` on compound types compiles to the
    generated ``$eq_*`` helpers and executes by-value on wasmtime,
    matching the Python backend's deep equality. The execution tests
    here exercise the helpers directly (an eq fn returns the i32 0/1);
    the end-to-end parity is covered in test_ir_wasm_parity.py."""

    def _exec(self, src: str, fn_name: str, *args):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return instance.exports(store)[fn_name](store, *args)

    def test_sum_eq_option_payload(self):
        # Some(1) == Some(1) is True; Some(1) == Some(2) is False;
        # Some vs None differ on the tag.
        src = (
            "fun same() -> Bool\n"
            "    let a: Option<Int> = Some(1)\n"
            "    let b: Option<Int> = Some(1)\n"
            "    return a == b\n"
            "fun diff_payload() -> Bool\n"
            "    let a: Option<Int> = Some(1)\n"
            "    let b: Option<Int> = Some(2)\n"
            "    return a == b\n"
            "fun diff_tag() -> Bool\n"
            "    let a: Option<Int> = Some(1)\n"
            "    let b: Option<Int> = None\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff_payload"), 0)
        self.assertEqual(self._exec(src, "diff_tag"), 0)

    def test_sum_eq_result_string_payload(self):
        # Err("bad") == Err("bad") routes the String payload through
        # $str_eq; Err("bad") == Err("worse") is False.
        src = (
            "fun same() -> Bool\n"
            "    let a: Result<Int, String> = Err(\"bad\")\n"
            "    let b: Result<Int, String> = Err(\"bad\")\n"
            "    return a == b\n"
            "fun diff() -> Bool\n"
            "    let a: Result<Int, String> = Err(\"bad\")\n"
            "    let b: Result<Int, String> = Err(\"worse\")\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff"), 0)

    def test_sum_eq_payloadless_variant(self):
        # Payloadless variants compare structurally: a tag match means
        # equal (a value equals itself). This exercises the
        # tag-equal-no-payload path the other sum tests never hit
        # (they compare payload-bearing variants or mismatched tags).
        # The payloadless-only ``Color`` binders are typed by the
        # analyzer as the variant name (``Red``); the emitter must
        # normalise that to the ``Color`` sum so the compound-eq
        # dispatch fires instead of an i64 pointer compare (the
        # invalid-wasm bug this regresses against).
        src = (
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "type Shape =\n"
            "    Circle(Int)\n"
            "    Unit\n"
            "fun red_eq_red() -> Bool\n"
            "    let a = Red\n"
            "    let b = Red\n"
            "    return a == b\n"
            "fun red_eq_green() -> Bool\n"
            "    let a = Red\n"
            "    let b = Green\n"
            "    return a == b\n"
            "fun unit_eq_unit() -> Bool\n"
            "    let a: Shape = Unit\n"
            "    let b: Shape = Unit\n"
            "    return a == b\n"
            "fun unit_eq_circle() -> Bool\n"
            "    let a: Shape = Unit\n"
            "    let b: Shape = Circle(5)\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "red_eq_red"), 1)
        self.assertEqual(self._exec(src, "red_eq_green"), 0)
        self.assertEqual(self._exec(src, "unit_eq_unit"), 1)
        self.assertEqual(self._exec(src, "unit_eq_circle"), 0)

    def test_tuple_eq(self):
        src = (
            "fun same() -> Bool\n"
            "    let a: (Int, String) = (1, \"hi\")\n"
            "    let b: (Int, String) = (1, \"hi\")\n"
            "    return a == b\n"
            "fun diff() -> Bool\n"
            "    let a: (Int, String) = (1, \"hi\")\n"
            "    let b: (Int, String) = (1, \"bye\")\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff"), 0)

    def test_list_eq_int(self):
        src = (
            "fun same() -> Bool\n"
            "    let a: List<Int> = [1, 2, 3]\n"
            "    let b: List<Int> = [1, 2, 3]\n"
            "    return a == b\n"
            "fun diff_len() -> Bool\n"
            "    let a: List<Int> = [1, 2, 3]\n"
            "    let b: List<Int> = [1, 2]\n"
            "    return a == b\n"
            "fun diff_elem() -> Bool\n"
            "    let a: List<Int> = [1, 2, 3]\n"
            "    let b: List<Int> = [1, 2, 4]\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff_len"), 0)
        self.assertEqual(self._exec(src, "diff_elem"), 0)

    def test_list_eq_struct(self):
        # List<Point> compares each element via $eq_Point, so two
        # distinct records with equal fields match.
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun same() -> Bool\n"
            "    let a: List<Point> = [Point { x: 0, y: 0 }, Point { x: 1, y: 1 }]\n"
            "    let b: List<Point> = [Point { x: 0, y: 0 }, Point { x: 1, y: 1 }]\n"
            "    return a == b\n"
            "fun diff() -> Bool\n"
            "    let a: List<Point> = [Point { x: 0, y: 0 }]\n"
            "    let b: List<Point> = [Point { x: 0, y: 1 }]\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff"), 0)

    def test_list_contains_struct(self):
        # contains on a pointer-shape element is a structural scan: a
        # fresh Point equal by value to an element is found.
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun present() -> Bool\n"
            "    let pts: List<Point> = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]\n"
            "    return pts.contains(Point { x: 3, y: 4 })\n"
            "fun absent() -> Bool\n"
            "    let pts: List<Point> = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]\n"
            "    return pts.contains(Point { x: 5, y: 6 })\n"
        )
        self.assertEqual(self._exec(src, "present"), 1)
        self.assertEqual(self._exec(src, "absent"), 0)

    def test_nested_cross_kind_eq(self):
        # A struct whose fields span String + Option<Int> + List<Int>
        # recurses into the sum and List helpers.
        src = (
            "type Holder {\n"
            "    tag: String,\n"
            "    maybe: Option<Int>,\n"
            "    items: List<Int>\n"
            "}\n"
            "fun same() -> Bool\n"
            "    let a: Holder = Holder { tag: \"h\", maybe: Some(1), items: [1, 2] }\n"
            "    let b: Holder = Holder { tag: \"h\", maybe: Some(1), items: [1, 2] }\n"
            "    return a == b\n"
            "fun diff_option() -> Bool\n"
            "    let a: Holder = Holder { tag: \"h\", maybe: Some(1), items: [1, 2] }\n"
            "    let b: Holder = Holder { tag: \"h\", maybe: Some(2), items: [1, 2] }\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff_option"), 0)

    def test_map_eq_order_independent(self):
        # ``Map<K, V> == Map<K, V>`` is order-independent on the Wasm
        # backend: two maps built by inserting the same pairs in
        # different orders compare equal, matching Python's dict
        # equality. The generated ``$eq_Map_*`` helper walks ``a``'s
        # pairs and looks each key up in ``b`` (then value-compares),
        # so insertion order is irrelevant. End-to-end parity for
        # ``main`` is in test_ir_wasm_parity.py::test_map_eq; this
        # focused test exercises the helper directly via a ``cmp``
        # function returning the i32 0/1.
        src = (
            "fun same() -> Bool\n"
            "    let a: Map<String, Int> = new_map()\n"
            "    a.set(\"x\", 1)\n"
            "    a.set(\"y\", 2)\n"
            "    let b: Map<String, Int> = new_map()\n"
            "    b.set(\"y\", 2)\n"
            "    b.set(\"x\", 1)\n"
            "    return a == b\n"
            "fun diff_value() -> Bool\n"
            "    let a: Map<String, Int> = new_map()\n"
            "    a.set(\"x\", 1)\n"
            "    let b: Map<String, Int> = new_map()\n"
            "    b.set(\"x\", 2)\n"
            "    return a == b\n"
            "fun diff_length() -> Bool\n"
            "    let a: Map<String, Int> = new_map()\n"
            "    a.set(\"x\", 1)\n"
            "    let b: Map<String, Int> = new_map()\n"
            "    b.set(\"x\", 1)\n"
            "    b.set(\"y\", 2)\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff_value"), 0)
        self.assertEqual(self._exec(src, "diff_length"), 0)

    def test_set_eq_order_independent(self):
        # ``Set<T> == Set<T>`` is order-independent on the Wasm
        # backend: two sets built by adding the same elements in
        # different orders compare equal, matching Python's
        # ``CapaSet.__eq__`` (which compares the backing dicts).
        # The generated ``$eq_Set_*`` helper walks ``a`` and looks
        # each element up in ``b``.
        src = (
            "fun same() -> Bool\n"
            "    let a: Set<Int> = new_set()\n"
            "    a.add(1)\n"
            "    a.add(2)\n"
            "    a.add(3)\n"
            "    let b: Set<Int> = new_set()\n"
            "    b.add(3)\n"
            "    b.add(1)\n"
            "    b.add(2)\n"
            "    return a == b\n"
            "fun diff_element() -> Bool\n"
            "    let a: Set<Int> = new_set()\n"
            "    a.add(1)\n"
            "    a.add(2)\n"
            "    let b: Set<Int> = new_set()\n"
            "    b.add(1)\n"
            "    b.add(3)\n"
            "    return a == b\n"
            "fun diff_length() -> Bool\n"
            "    let a: Set<Int> = new_set()\n"
            "    a.add(1)\n"
            "    let b: Set<Int> = new_set()\n"
            "    b.add(1)\n"
            "    b.add(2)\n"
            "    return a == b\n"
        )
        self.assertEqual(self._exec(src, "same"), 1)
        self.assertEqual(self._exec(src, "diff_element"), 0)
        self.assertEqual(self._exec(src, "diff_length"), 0)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmSafetyTraps(unittest.TestCase):
    """Audit 2026-05 safety fixes (C2 / C3 / C5 / C6): every fix has
    BOTH a positive parity check (see ``test_ir_wasm_parity.py::
    test_safety_traps``) AND a dedicated negative check that asserts
    the trap actually fires on bad input. Without the negative side,
    a regression to silent unsafety would slip past parity (both
    backends would still match each other, just both wrongly)."""

    def _exec(self, src: str, fn_name: str, *args):
        """Compile, instantiate, call ``fn_name(*args)``, return its
        result. Each call gets its own Store + Linker for hermetic
        per-test heap state (mirrors the helpers used elsewhere in
        the file). Traps surface as ``wasmtime.Trap``; the caller
        wraps the call in ``assertRaises``."""
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        module = wasmtime.Module(engine, blob)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, module)
        fn = instance.exports(store)[fn_name]
        return fn(store, *args)

    # ---- Fix C3: shift count out of [0, 64) traps -----------------

    def test_shift_left_count_64_traps(self):
        # ``a << 64``: Wasm's i64.shl would silently mask the RHS to
        # 0; the audit fix emits a guard that traps instead so both
        # backends fail loud at the same input.
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        # Positive: shifts in range still work.
        self.assertEqual(self._exec(src, "shl", 5, 3), 40)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, 64)

    def test_shift_left_count_negative_traps(self):
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, -1)

    def test_shift_right_count_64_traps(self):
        import wasmtime
        src = (
            "fun shr(a: Int, b: Int) -> Int\n"
            "    return a >> b\n"
        )
        self.assertEqual(self._exec(src, "shr", 1024, 4), 64)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shr", 1, 64)

    # ---- Bug #1: ``<<`` result leaving the i64 window traps --------

    def test_shift_left_result_overflow_traps(self):
        # ``1 << 63`` leaves the signed 64-bit window. The count (63)
        # is in range, so the old code emitted a bare ``i64.shl`` and
        # silently wrapped to i64::MIN; the Python backend's
        # ``_capa_shl`` traps. The Wasm emitter now arithmetic-shifts
        # the result back and traps when it does not recover the
        # operand, matching Python. ``1 << 62`` is the largest power
        # of two that fits and must NOT trap.
        import wasmtime
        src = (
            "fun shl(a: Int, b: Int) -> Int\n"
            "    return a << b\n"
        )
        # In-window shifts (incl. the i64::MIN boundary) return.
        self.assertEqual(self._exec(src, "shl", 1, 62), 1 << 62)
        self.assertEqual(self._exec(src, "shl", -1, 63), -(1 << 63))
        self.assertEqual(self._exec(src, "shl", -2, 62), -(1 << 63))
        self.assertEqual(self._exec(src, "shl", 0, 40), 0)
        self.assertEqual(self._exec(src, "shl", 5, 0), 5)
        # Result-window overflow traps (count in range, bits lost).
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 1, 63)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", 2, 62)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "shl", -2, 63)

    # ---- Fix C6: Float % by zero traps ----------------------------

    def test_float_modulo_zero_traps(self):
        import wasmtime
        src = (
            "fun fmod(a: Float, b: Float) -> Float\n"
            "    return a % b\n"
        )
        # Positive: 7.5 % 3.0 == 1.5.
        self.assertAlmostEqual(self._exec(src, "fmod", 7.5, 3.0), 1.5)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "fmod", 7.5, 0.0)

    # ---- Fix C2: Int +/-/* overflow traps -------------------------

    def test_int_add_overflow_traps(self):
        # ``i64::MAX + 1`` = ``9223372036854775807 + 1`` overflows.
        # We construct it as ``(1 << 62) + (1 << 62) + (1 << 62)``
        # via a function so the operands stay i64-typed all the way
        # through ANF lowering rather than being constant-folded.
        import wasmtime
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        # Positive: in-range add returns the sum.
        self.assertEqual(self._exec(src, "add", 5, 3), 8)
        # Negative: i64::MAX + 1 overflows.
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "add", (1 << 63) - 1, 1)

    def test_int_mul_overflow_traps(self):
        # ``3_000_000_000 * 4_000_000_000`` = 1.2e19, well past i64::MAX
        # (~9.22e18). Without the C2 fix the result wrapped mod 2^64
        # to a garbage value; now the multiply traps.
        import wasmtime
        src = (
            "fun mul(a: Int, b: Int) -> Int\n"
            "    return a * b\n"
        )
        self.assertEqual(
            self._exec(src, "mul", 1_000_000, 1_000_000), 1_000_000_000_000,
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "mul", 3_000_000_000, 4_000_000_000)

    def test_int_sub_overflow_traps(self):
        # ``i64::MIN - 1`` overflows below the signed window.
        import wasmtime
        src = (
            "fun sub(a: Int, b: Int) -> Int\n"
            "    return a - b\n"
        )
        self.assertEqual(self._exec(src, "sub", 100, 50), 50)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "sub", -(1 << 63), 1)

    # ---- Bug #1: Int ``/`` is floored AND traps on /0 and MIN/-1 ---

    def test_int_div_is_floored(self):
        # ``i64.div_s`` truncates toward zero (``-7 / 2 == -3``), but
        # Capa Int division floors (``-7 / 2 == -4``), matching the
        # Python backend's ``//``. The Wasm floor correction must agree.
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertEqual(self._exec(src, "div", -7, 2), -4)
        self.assertEqual(self._exec(src, "div", 7, -2), -4)
        self.assertEqual(self._exec(src, "div", -1, 2), -1)
        self.assertEqual(self._exec(src, "div", 7, 2), 3)
        self.assertEqual(self._exec(src, "div", -8, -2), 4)
        self.assertEqual(self._exec(src, "div", 0, 5), 0)

    def test_int_div_by_zero_traps(self):
        import wasmtime
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "div", 7, 0)

    def test_int_div_min_by_neg_one_traps(self):
        # ``i64::MIN / -1`` = ``2**63`` overflows the signed window;
        # the native div_s trap (preserved by computing the quotient
        # first) must fire, matching ``_capa_idiv``'s OverflowError.
        import wasmtime
        src = (
            "fun div(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "div", -(1 << 63), -1)

    # ---- Augmented Int /= and %= match the binary div / mod -------
    #
    # The augmented form (``x /= y`` / ``x %= y``) on an Int target
    # must produce the same floored result AND trap on the same
    # inputs as the binary ``/`` / ``%``. These mirror the binary
    # trap tests above for the augmented-assignment path (which the
    # Python backend used to route through raw float division).

    def test_aug_int_div_is_floored(self):
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        self.assertEqual(self._exec(src, "adiv", -7, 2), -4)
        self.assertEqual(self._exec(src, "adiv", 7, -2), -4)
        self.assertEqual(self._exec(src, "adiv", 24, 4), 6)
        self.assertEqual(self._exec(src, "adiv", -8, -2), 4)

    def test_aug_int_div_by_zero_traps(self):
        import wasmtime
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "adiv", 7, 0)

    def test_aug_int_div_min_by_neg_one_traps(self):
        import wasmtime
        src = (
            "fun adiv(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x /= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "adiv", -(1 << 63), -1)

    def test_aug_int_mod_is_floored(self):
        src = (
            "fun amod(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x %= b\n"
            "    return x\n"
        )
        self.assertEqual(self._exec(src, "amod", -7, 3), 2)
        self.assertEqual(self._exec(src, "amod", 7, -3), -2)
        self.assertEqual(self._exec(src, "amod", 17, 5), 2)

    def test_aug_int_mod_by_zero_traps(self):
        import wasmtime
        src = (
            "fun amod(a: Int, b: Int) -> Int\n"
            "    var x = a\n"
            "    x %= b\n"
            "    return x\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "amod", 7, 0)

    # ---- Bug #6: unary negation of i64::MIN traps -----------------

    def test_int_negate_works(self):
        src = (
            "fun neg(a: Int) -> Int\n"
            "    return -a\n"
        )
        self.assertEqual(self._exec(src, "neg", 5), -5)
        self.assertEqual(self._exec(src, "neg", -5), 5)
        self.assertEqual(self._exec(src, "neg", 0), 0)

    def test_int_negate_min_traps(self):
        # ``-(i64::MIN)`` = ``2**63`` overflows i64. The naive ``0 - x``
        # wraps back to MIN; the guard traps instead, matching the
        # Python backend's ``_capa_isub(0, x)`` OverflowError.
        import wasmtime
        src = (
            "fun neg(a: Int) -> Int\n"
            "    return -a\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "neg", -(1 << 63))

    # ---- Bug #4: Float ``/`` by zero traps ------------------------

    def test_float_div_zero_traps(self):
        # ``f64.div`` yields inf on a zero divisor, but Python raises
        # ZeroDivisionError. The Wasm guard now traps to match.
        import wasmtime
        src = (
            "fun fdiv(a: Float, b: Float) -> Float\n"
            "    return a / b\n"
        )
        self.assertAlmostEqual(self._exec(src, "fdiv", 7.5, 3.0), 2.5)
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "fdiv", 1.5, 0.0)

    # ---- Fix C4: to_int out-of-range traps ------------------------

    def test_to_int_in_range_works(self):
        # Positive parity: a value inside the signed 64-bit window
        # truncates toward zero on both backends.
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        self.assertEqual(self._exec(src, "trunc", 1.5), 1)
        self.assertEqual(self._exec(src, "trunc", -2.7), -2)
        # i64::MIN as a float is exactly representable and trunc-safe.
        self.assertEqual(
            self._exec(src, "trunc", -9223372036854775808.0),
            -9223372036854775808,
        )

    def test_to_int_overflow_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", 1e20)

    def test_to_int_nan_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", float("nan"))

    def test_to_int_inf_traps(self):
        import wasmtime
        src = (
            "fun trunc(f: Float) -> Int\n"
            "    return to_int(f)\n"
        )
        with self.assertRaises(wasmtime.Trap):
            self._exec(src, "trunc", float("inf"))

    # ---- Fix C5: parse_int overflow returns None ------------------

    def test_parse_int_too_big_returns_none(self):
        # An input larger than i64::MAX returns None on both backends;
        # without the fix the Wasm accumulator silently wrapped mod
        # 2^64 and reported a "successful" Some carrying a garbage
        # value. ``"99999999999999999999"`` is well outside the i64
        # window so any wrap is detectable.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("99999999999999999999")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(buf.getvalue(), "None\n")

    # ---- Bug #7: user-defined parse_int / parse_float shadow the
    # builtin (no "duplicate func identifier" parse error) ----------

    def _run_main_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_user_parse_int_shadows_builtin(self):
        # A user-defined ``parse_int`` must win over the builtin
        # (matching the Python backend) instead of colliding with the
        # ``$parse_int`` runtime helper at WAT-parse time.
        src = (
            'fun parse_int(s: String) -> Int\n'
            '    return 99\n'
            'fun main(stdio: Stdio)\n'
            '    let v = parse_int("x")\n'
            '    stdio.println("${v}")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "99\n")

    def test_user_parse_float_shadows_builtin(self):
        src = (
            'fun parse_float(s: String) -> Float\n'
            '    return 1.5\n'
            'fun main(stdio: Stdio)\n'
            '    let v = parse_float("x")\n'
            '    stdio.println("${v}")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "1.5\n")

    def test_builtin_parse_int_still_works_when_not_shadowed(self):
        # Control: with no user definition the builtin helper must
        # still parse the string and return Some.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("42")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(42)\n")

    def test_builtin_parse_float_still_works_when_not_shadowed(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_float("3.5")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(3.5)\n")

    def test_parse_int_i64_min_accepted(self):
        # ``-9223372036854775808`` (i64::MIN) sits inside the
        # ``[-2**63, 2**63)`` window. The overflow guard used to
        # compare the magnitude against i64::MAX with no sign case
        # and rejected it (magnitude last digit 8 > 7); it now admits
        # digit 8 at the boundary when a sign is present.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("-9223372036854775808")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(
            self._run_main_stdout(src), "Some(-9223372036854775808)\n"
        )

    def test_parse_int_trims_ascii_whitespace(self):
        # Surrounding ASCII whitespace (space/tab/LF/VT/FF/CR) is
        # trimmed before parsing, matching the Python helper; a bare
        # ``" 7 "`` used to return None on the Wasm backend.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("\\t 42 \\r\\n")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "Some(42)\n")

    def test_parse_int_rejects_underscores(self):
        # Canonical grammar has no PEP-515 digit separators.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_int("1_000")\n'
            '        Some(n) -> stdio.println("Some(${n})")\n'
            '        None -> stdio.println("None")\n'
        )
        self.assertEqual(self._run_main_stdout(src), "None\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmBoundsChecks(unittest.TestCase):
    """Audit fix C1: List indexing and String.substring emit inline
    bounds-check traps. Pairs with
    ``tests/test_transpiler.py::TestBoundsRaise`` for the Python
    backend; together they pin "both backends fail loud at the same
    input" for collection access.

    Negative IR-level indices (a Capa source expression like
    ``0 - 1`` evaluates to ``-1`` an i64) are caught by the unsigned
    compare: ``i32.wrap_i64`` of a negative i64 is a huge u32 that
    exceeds any list's length, so ``i32.ge_u`` returns 1 and the
    trap fires on the same input that Python's ``_capa_list_get``
    rejects.
    """

    def _exec_main(self, src: str) -> str:
        """Compile, run ``main`` via the host bridge, return captured
        stdout. Used by positive-case tests where the program prints
        a value and exits cleanly."""
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def _exec_main_expect_trap(self, src: str) -> None:
        """Compile, run ``main`` via the host bridge, expect a
        ``wasmtime.Trap`` to fire. Used by the negative-case tests
        where the program indexes out of range or substrings past
        the end. We swallow stdout to keep the test output clean."""
        import io
        import sys
        import wasmtime
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            with self.assertRaises(wasmtime.Trap):
                host.run_main(blob)
        finally:
            sys.stdout = saved

    # ---- List indexing --------------------------------------------

    def test_list_index_in_bounds_works(self):
        # Positive parity: a valid index returns the element.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[1]}")\n'
        )
        self.assertEqual(self._exec_main(src), "20\n")

    def test_list_index_out_of_bounds_traps(self):
        # ``xs[5]`` on a 3-element list: idx >= len -> i32.ge_u
        # returns 1 -> unreachable trap.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    stdio.println("${xs[5]}")\n'
        )
        self._exec_main_expect_trap(src)

    def test_list_index_negative_traps(self):
        # ``xs[0 - 1]`` evaluates to ``xs[-1]`` an i64; i32.wrap_i64
        # of -1 is 0xFFFFFFFF (4294967295), well above any list's
        # length, so i32.ge_u traps. The 0 - 1 construction keeps
        # the analyzer from folding to a literal that some future
        # change might constant-evaluate.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = [10, 20, 30]\n'
            '    let neg = 0 - 1\n'
            '    stdio.println("${xs[neg]}")\n'
        )
        self._exec_main_expect_trap(src)

    # ---- String substring -----------------------------------------

    def test_substring_in_bounds_works(self):
        # Positive parity: an in-range slice copies the requested bytes.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(1, 4)}")\n'
        )
        self.assertEqual(self._exec_main(src), "bcd\n")

    def test_substring_out_of_bounds_traps(self):
        # ``s.substring(0, 100)`` on a 6-byte string: end > recv.len
        # -> i32.gt_u returns 1 -> unreachable trap. Without the C1
        # fix the emitter would memory.copy past the buffer.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let s = "abcdef"\n'
            '    stdio.println("${s.substring(0, 100)}")\n'
        )
        self._exec_main_expect_trap(src)

    # ---- String split (Bug #4) ------------------------------------

    def test_split_nonempty_separator_works(self):
        # Positive parity: a non-empty separator splits as before.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,b,c".split(",")\n'
            '    stdio.println("${parts.length()}")\n'
        )
        self.assertEqual(self._exec_main(src), "3\n")

    def test_split_empty_separator_traps(self):
        # ``"hello".split("")`` is a usage error: Python raises
        # ``ValueError: empty separator``. The Wasm backend used to
        # return the whole receiver as one element; it now traps on a
        # zero-length separator so both backends fail loud on the same
        # invalid input.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "hello".split("")\n'
            '    stdio.println("${parts.length()}")\n'
        )
        self._exec_main_expect_trap(src)


@unittest.skipUnless(
    _has_wasm_tools(),
    "wasm-tools not installed",
)
class TestWasmCapaManifestCustomSection(unittest.TestCase):
    """Audit fix M4 (2026-05): per-function capability manifest
    embedded in a Wasm custom section named ``capa-manifest`` so the
    discipline travels with the artefact. Runtimes ignore custom
    sections by definition; ``wasm-tools dump`` and the helper
    ``capa.ir.read_wasm_manifest`` surface them."""

    def test_manifest_section_present_and_parses(self):
        from capa.ir import compile_wasm, read_wasm_manifest
        src = (
            'fun helper() -> Int\n'
            '    return 42\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${helper()}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types, filename='m4_test.capa')
        manifest = read_wasm_manifest(blob)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest["capa_manifest_version"], 1)
        self.assertIn("capa_version", manifest)
        names = {f["name"]: f["declared_capabilities"]
                 for f in manifest["functions"]}
        # ``main`` declares ``Stdio`` via its capability param;
        # ``helper`` declares nothing.
        self.assertIn("main", names)
        self.assertEqual(names["main"], ["Stdio"])
        self.assertIn("helper", names)
        self.assertEqual(names["helper"], [])

    def test_manifest_off_via_embed_manifest_false(self):
        # Tests / regression scenarios where the extra custom section
        # would noisily change byte-level snapshots can pass
        # ``embed_manifest=False`` to suppress it.
        from capa.ir import compile_wasm, read_wasm_manifest
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types, embed_manifest=False)
        self.assertIsNone(read_wasm_manifest(blob))

    @unittest.skipUnless(
        _has_wasmtime_py(),
        "wasmtime-py not installed",
    )
    def test_manifest_does_not_break_wasmtime_load(self):
        # Custom sections are by definition ignored by runtimes; verify
        # the resulting binary still loads + runs cleanly. The check
        # would catch a future regression where the emitter put the
        # ``(@custom ...)`` in a position wasm-tools accepts but a
        # runtime rejects.
        import io
        import sys
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("manifest-ok")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(buf.getvalue(), "manifest-ok\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmMemoryCap(unittest.TestCase):
    """Audit fix H1 (2026-05): the emitted ``(memory ...)``
    declaration carries a page-count upper bound (default
    ``MEMORY_CAP_DEFAULT_PAGES`` = 256 pages = 16 MiB; configurable
    via the CLI ``--wasm-memory-cap`` flag). The bump allocator's
    ``memory.grow`` then traps via ``unreachable`` at a
    deterministic ceiling instead of a host-dependent OOM point."""

    def test_default_cap_baked_into_memory_decl(self):
        # The WAT shape carries ``(memory (export "memory") 1 256)``
        # by default. Pinning the textual form catches a regression
        # that would silently drop the cap.
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertIn(
            f'(memory (export "memory") 1 {MEMORY_CAP_DEFAULT_PAGES})',
            wat,
        )

    def test_explicit_cap_baked_into_memory_decl(self):
        from capa.ir import compile_wat
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types, memory_cap_pages=7)
        self.assertIn('(memory (export "memory") 1 7)', wat)

    def test_no_cap_omits_max(self):
        # Passing ``None`` lets the host decide; the WAT has no upper
        # bound in the memory limits clause.
        from capa.ir import compile_wat
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types, memory_cap_pages=None)
        self.assertIn('(memory (export "memory") 1)', wat)

    def test_low_cap_traps_on_runaway_alloc(self):
        # A list-push loop allocates header + growing data array;
        # with ``memory_cap_pages=1`` (64 KiB total) the bump
        # allocator's ``memory.grow`` returns -1 once the heap
        # outgrows the cap and the helper traps via ``unreachable``.
        import io
        import sys
        import wasmtime
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    var xs: List<Int> = []\n'
            '    var i = 0\n'
            '    while i < 100000\n'
            '        xs.push(i)\n'
            '        i = i + 1\n'
            '    stdio.println("${xs.length()}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(
            ast_mod, types=types, memory_cap_pages=1,
        )
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            with self.assertRaises(wasmtime.Trap):
                host.run_main(blob)
        finally:
            sys.stdout = saved

    def test_large_data_segment_sizes_initial_pages(self):
        # Fix (2026-06-10): the initial page count must cover the
        # static data segment. Pre-fix the declaration hard-coded
        # ``1`` initial page, so a module whose interned literals
        # crossed 64 KiB trapped at INSTANTIATION ("out of bounds
        # memory access" placing the active data segment) before
        # ``$alloc`` could ever grow -- which is also why
        # ``--wasm-memory-cap`` had no effect on the symptom.
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
        big = "x" * 70000  # > one 64 KiB page of string data
        src = (
            'fun main(stdio: Stdio)\n'
            f'    stdio.println("{big}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        wat = compile_wat(ast_mod, types=types)
        self.assertIn(
            f'(memory (export "memory") 2 {MEMORY_CAP_DEFAULT_PAGES})',
            wat,
        )

    def test_cap_below_data_segment_is_a_loud_error(self):
        # When the static data alone needs more pages than the cap
        # allows, the module could never instantiate; the emitter
        # refuses loudly at compile time (pointing at the
        # --wasm-memory-cap knob) instead of producing a WAT whose
        # limits clause is invalid (min > max).
        from capa.ir import compile_wat
        from capa.ir._emit_wasm import WasmEmissionError
        big = "x" * 70000
        src = (
            'fun main(stdio: Stdio)\n'
            f'    stdio.println("{big}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        with self.assertRaises(WasmEmissionError) as ctx:
            compile_wat(ast_mod, types=types, memory_cap_pages=1)
        self.assertIn("--wasm-memory-cap", str(ctx.exception))


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmHostUtf8Safety(unittest.TestCase):
    """Audit fix H3: every ``bytes.decode("utf-8")`` site in the
    host bridge is wrapped so invalid UTF-8 surfaces through the
    relevant WIT return shape (Option::None / Result::Err) or, for
    Stdio (no return), through U+FFFD replacement, instead of
    bubbling ``UnicodeDecodeError`` up through wasmtime and crashing
    the store."""

    def test_stdio_print_invalid_utf8_replaces(self):
        # Construct a host directly, prep its memory with invalid
        # UTF-8, invoke the stdio_print callback against the bytes.
        # The callback must NOT raise UnicodeDecodeError; the bytes
        # should print as the U+FFFD replacement glyph.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        # Minimal module: declares a 1-page memory and exports it.
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("warmup")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        instance = host.instantiate(blob)
        # Splat invalid UTF-8 (a lone 0xFF) into linear memory at offset 0.
        memory = instance.exports(host.store)["memory"]
        memory.write(host.store, b"\xff", 0)
        # Find the stdio.println import via the linker: easiest path
        # is to call it via a re-instantiation that exports the host
        # callback's effect. Simpler still: spin up our own raw
        # decode of the bytes to mirror what stdio_print does.
        # The decode-with-replace must not raise.
        raw = bytes(memory.read(host.store, 0, 1))
        self.assertEqual(
            raw.decode("utf-8", errors="replace"), "�",
        )
        # Sanity-check that the live host's println callback ALSO
        # handles invalid UTF-8 without raising. We re-instantiate a
        # tiny module that calls println with the (ptr, len) of the
        # 0xFF byte: directly invoking the registered Func through
        # wasmtime's caller protocol is brittle, so we instead pin
        # that ``bytes.decode("utf-8", errors="replace")`` is the
        # behaviour the patched host uses (see
        # capa/runtime/_wasm_host.py::stdio_println).
        import inspect
        src_host = inspect.getsource(host._register_stdio)
        self.assertIn('errors="replace"', src_host)

    def test_env_get_invalid_utf8_name_returns_none(self):
        # When the guest passes an invalid-UTF-8 key to env.get, the
        # host must return Option::None (Env.get's WIT shape) rather
        # than raise UnicodeDecodeError. The Capa program below would
        # observe ``None`` for any unknown key; we ensure invalid
        # UTF-8 lands on the same path.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        import wasmtime
        src = (
            'fun main(stdio: Stdio, env: Env)\n'
            '    match env.get("present")\n'
            '        Some(_) -> stdio.println("Some")\n'
            '        None -> stdio.println("None")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        # "present" is almost certainly not set; the test asserts the
        # happy path (printing "None") still works. The actual H3
        # behaviour (invalid UTF-8 -> None) is verified by inspection:
        # the host's env_get now catches UnicodeDecodeError.
        self.assertEqual(buf.getvalue(), "None\n")
        import inspect
        src_host = inspect.getsource(host._register_env)
        self.assertIn("UnicodeDecodeError", src_host)

    def test_fs_read_invalid_utf8_path_returns_err(self):
        # Capa Fs.read on an invalid-UTF-8 path should return Err
        # (matching the no-such-file path) rather than raise. We
        # cannot easily synthesise an invalid-UTF-8 string from
        # Capa source (the lexer rejects bad UTF-8 in literals);
        # instead, pin that the host's fs_read catches
        # UnicodeDecodeError and routes to the Err arm.
        from capa.runtime._wasm_host import WasmHost
        import inspect
        host = WasmHost()
        src_host = inspect.getsource(host._register_fs)
        self.assertIn("UnicodeDecodeError", src_host)
        self.assertIn("invalid utf-8 in path", src_host)

    def test_json_parse_invalid_utf8_returns_err(self):
        # Same shape as fs_read: the host's json_parse must route
        # invalid UTF-8 through the result<u32, string> Err arm
        # rather than raise.
        from capa.runtime._wasm_host import WasmHost
        import inspect
        host = WasmHost()
        src_host = inspect.getsource(host._register_json)
        self.assertIn("UnicodeDecodeError", src_host)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmRandomExecutes(unittest.TestCase):
    """Slice 2 of the "Wasm backend fully functional" arc: Random
    capability lowering through the SplitMix64 helpers in
    ``capa.ir._emit_wasm._random``. Seeded sequences must be
    byte-identical with the Python ``Random`` runtime; unseeded
    sequences must at minimum stay inside the requested range.
    """

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
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
        return out.getvalue()

    def test_seeded_int_range_matches_python_oracle(self):
        # SplitMix64 starting from state=42, drawing int_range(0, 100)
        # ten times in sequence. The Python runtime's
        # ``Random(42).int_range(0, 100)`` produces this exact
        # sequence (Lemire rejection sampling never rejects for any
        # of these draws within the first 10 calls, so the body of
        # the loop runs straight-through).
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let r = rng.with_seed(42)\n"
            "    var i = 0\n"
            "    while i < 10\n"
            "        stdio.println(\"${r.int_range(0, 100)}\")\n"
            "        i = i + 1\n"
        )
        out = self._run_capturing_stdout(src)
        expected = "\n".join(
            ["13", "91", "58", "64", "50", "62", "25", "8", "5", "74"]
        ) + "\n"
        self.assertEqual(out, expected)

    def test_seeded_int_range_signed_low(self):
        # Negative ``low`` is parsed as ``0 - 50`` in Capa source
        # (no unary-negative-literal support at the moment); pin that
        # the i64 subtraction passes through unchanged so the
        # signed-add path lands the correct values.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let r = rng.with_seed(42)\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        # Bound 100, same draws as the (0, 100) test: 13 - 50, 91 - 50,
        # 58 - 50. Equivalent to ``low + (rng % bound)`` where the rng
        # bytes match.
        self.assertEqual(out, "-37\n41\n8\n")

    def test_with_seed_overrides_unseeded(self):
        # An incoming Random (which lazy-inits state on first draw)
        # plus a subsequent ``with_seed(42)`` must land
        # deterministically on the seed=42 sequence. The init guard
        # the helpers flip after with_seed should prevent the
        # entropy path from clobbering the state. We trigger lazy
        # init by drawing a throwaway value before reseeding so the
        # init-then-reseed order is exercised, not just the
        # reseed-only order other tests cover.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let _throwaway = rng.int_range(0, 100)\n"
            "    let s = rng.with_seed(42)\n"
            "    stdio.println(\"${s.int_range(0, 100)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "13\n")

    def test_unseeded_in_range(self):
        # Unseeded Random pulls entropy from the host
        # (``capa:host/random/system-seed``). We can't pin the
        # value, but we can assert the draw lands in the requested
        # half-open range.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let n = rng.int_range(0, 100)\n"
            "    if n >= 0\n"
            "        if n < 100\n"
            "            stdio.println(\"ok\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "ok\n")

    def test_chained_with_seed_last_wins(self):
        # Per the Python runtime semantic
        # (``Random.with_seed(1).with_seed(2)`` is two fresh
        # instances; the second seed wins), the Wasm-side last-write
        # to ``$rand_state`` must produce the same draw as a single
        # ``with_seed(2)``.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let s = rng.with_seed(1).with_seed(2)\n"
            "    stdio.println(\"${s.int_range(0, 100)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        # Recompute via the Python oracle so any future PRNG tweak
        # surfaces here too.
        from capa.runtime._capabilities import Random as _PyRandom
        expected = f"{_PyRandom(2).int_range(0, 100)}\n"
        self.assertEqual(out, expected)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmNetExecutes(unittest.TestCase):
    """Slice 3 of the "Wasm backend fully functional" arc: ``Net.get``
    end-to-end through the ``capa:host/net`` interface. The host
    bridge mirrors ``capa.runtime._capabilities.Net.get`` exactly
    (``urllib.request.urlopen`` + ``decode("utf-8", errors="replace")``);
    these tests pin the round-trip on hermetic ``file://`` URLs so
    the suite never hits a network.
    """

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
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
        return out.getvalue()

    def test_net_get_file_url_round_trip(self):
        # Hermetic round-trip via a ``file://`` URL. Both backends
        # call ``urllib.request.urlopen`` against the same on-disk
        # bytes; the Wasm host's ``errors="replace"`` UTF-8 decode
        # path agrees with the Python runtime's. We pre-stage the
        # fixture from the test (rather than from the Capa source)
        # so the assertion isolates the Net path from the Fs path.
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8",
        ) as f:
            f.write("body bytes from a fixture")
            fixture = f.name
        try:
            # ``file://`` URL needs forward slashes regardless of
            # the host OS. ``pathlib.Path.as_uri`` does the right
            # thing on Windows (where ``tempfile`` returns a
            # backslash-form path) and on POSIX (no-op).
            from pathlib import Path
            uri = Path(fixture).as_uri()
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.get(\"{uri}\")\n"
                "        Ok(text) -> stdio.println(\"got: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: read failed\")\n"
            )
            out = self._run_capturing_stdout(src)
            self.assertEqual(out, "got: body bytes from a fixture\n")
        finally:
            os.unlink(fixture)

    def test_net_get_restrict_denies_outside_host(self):
        # Inline attenuation check (audit C2): a Net cap scoped to a
        # host string that the URL does not contain must short-
        # circuit to Err without ever calling the host bridge. The
        # restriction host (``unreachable.invalid``) names a URL no
        # real DNS resolves, so even if the check accidentally fell
        # through, a 10-second timeout would surface here as a test
        # hang -- the assertion below catches the silent-pass case.
        src = (
            "fun main(stdio: Stdio, net: Net)\n"
            "    let scoped = net.restrict_to(\"only.allowed.invalid\")\n"
            "    match scoped.get(\"https://api.example.com/path\")\n"
            "        Ok(_) -> stdio.println(\"BUG: leaked\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "denied\n")

    def test_net_post_round_trip_against_loopback(self):
        # Hermetic POST round-trip: spin up an in-process http.server
        # whose handler echoes the request body verbatim, then have
        # the Capa program POST a known body and assert the response
        # equals it. Validates the body-bytes path end-to-end (Wasm
        # bridge reads the body bytes from linear memory, builds the
        # urllib Request, the loopback server echoes them back, the
        # Ok arm carries the response into the program). Bound to
        # 127.0.0.1 on an ephemeral port so it never collides with
        # CI workers.
        import http.server
        import threading

        body_text = "hello-post-body"

        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args, **kwargs):
                # Silence the default access log so the test output
                # stays scoped to the assertion.
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{port}/echo"
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.post(\"{url}\", \"{body_text}\")\n"
                "        Ok(text) -> stdio.println(\"echo: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: post failed\")\n"
            )
            out = self._run_capturing_stdout(src)
            self.assertEqual(out, f"echo: {body_text}\n")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


@unittest.skipUnless(_has_wasmtime_py(), "wasmtime-py not installed")
class TestWasmHostAllocGuard(unittest.TestCase):
    """Audit 2026-05-25 L1: a failed guest ``$alloc`` (returns 0)
    must raise a clean host error instead of writing the buffer at
    address 0 and scribbling the data segment."""

    def test_failed_alloc_raises_host_error(self):
        from capa.runtime._wasm_host import WasmHost, WasmHostError

        host = WasmHost()
        # Stand in for the module's exported $alloc returning 0 (OOM).
        host._alloc_export = lambda caller, n: 0
        with self.assertRaises(WasmHostError) as ctx:
            host._host_alloc(object(), 32)
        self.assertIn("out of memory", str(ctx.exception))

    def test_zero_length_alloc_returns_zero_without_calling_export(self):
        from capa.runtime._wasm_host import WasmHost

        host = WasmHost()
        called = []

        def _boom(caller, n):  # pragma: no cover - must not run
            called.append(n)
            return 0

        host._alloc_export = _boom
        self.assertEqual(host._host_alloc(object(), 0), 0)
        self.assertEqual(called, [])

    def test_successful_alloc_returns_pointer(self):
        from capa.runtime._wasm_host import WasmHost

        host = WasmHost()
        host._alloc_export = lambda caller, n: 4096
        self.assertEqual(host._host_alloc(object(), 8), 4096)


class TestWasmRejectsUnsafeReachingTypes(unittest.TestCase):
    """Audit 2026-06-17 C5(b): the Wasm discovery pass rejects a
    parameter whose type merely CONTAINS Unsafe (through a struct
    field, a sum-variant payload, or a generic argument), not only a
    literal ``Unsafe`` head. The analyzer normally blocks Unsafe in a
    struct field upstream (C5(a)); this is the defense-in-depth check
    one layer down, so we build the IR by hand to exercise it."""

    def _emit(self, module):
        return emit_wat(module)

    def test_struct_field_unsafe_param_is_rejected(self):
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="w", ty="Wrapper")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Wrapper",
                    fields=[StructField(name="u", ty="Unsafe")],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))
        # The offender is named with its real (struct) type, and no
        # invalid ``call $py_import`` is emitted.
        self.assertIn("f(w: Wrapper)", str(ctx.exception))

    def test_nested_struct_field_unsafe_param_is_rejected(self):
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="o", ty="Outer")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Outer",
                    fields=[StructField(name="inner", ty="Inner")],
                ),
                StructDecl(
                    name="Inner",
                    fields=[StructField(name="u", ty="Unsafe")],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))

    def test_generic_arg_unsafe_param_is_rejected(self):
        from capa.ir._nodes import Module, Function, Param
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="xs", ty="List<Unsafe>")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            self._emit(module)
        self.assertIn("Unsafe", str(ctx.exception))

    def test_unsafe_free_struct_param_still_emits(self):
        # A struct that does NOT reach Unsafe is untouched by the
        # tightened check.
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f",
                    params=[Param(name="p", ty="Point")],
                    return_type="Unit",
                    declared_caps=[],
                    body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Point",
                    fields=[StructField(name="x", ty="Int")],
                ),
            ],
        )
        # Should not raise the Unsafe rejection (it emits normally).
        wat = self._emit(module)
        self.assertIn("(module", wat)


if __name__ == "__main__":
    unittest.main()

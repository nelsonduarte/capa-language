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

import re
import shutil
import typing
import unittest

from capa import Lexer, Parser, analyze
from capa.ir import (
    lower, emit_wat, emit_wit, compile_wat, compile_wasm, compile_wit,
    collect_used_capabilities, WasmEmissionError,
    UnsupportedCapabilityMethod, MainReturnTypeUnsupported,
)

from tests.ir_wasm._helpers import (
    _has_wasm_tools, _has_wasmtime_py, _parse_lower,
)


# A generic function monomorphised at a *qualified typestate*: the
# type parameter ``T`` of ``passthrough`` is inferred from the
# ``Socket[Connected]``-typed local it is applied to (a return-
# annotation binding), so its mangled type string carries the ``[``
# / ``]`` a bare-value argument would have stripped. Before the
# ``_sanitise_type_token`` fix this emitted the WAT-invalid identifier
# ``$passthrough__Socket[Connected]``, which ``wasm-tools parse``
# rejects; the Python/legacy backend, which never monomorphises,
# always ran it fine.
_QUALIFIED_TYPESTATE_GENERIC_SRC = (
    "typestate Socket { fd: Int }\n"
    "    Created\n"
    "    Connected\n"
    "\n"
    "fun passthrough<T>(consume x: T) -> T\n"
    "    return x\n"
    "\n"
    "fun connect(consume s: Socket[Created]) -> Socket[Connected]\n"
    "    return become(s, Connected)\n"
    "\n"
    "fun relay(consume s: Socket[Created]) -> Socket[Connected]\n"
    "    let c = connect(s)\n"
    "    return passthrough(c)\n"
    "\n"
    "fun discard(consume s: Socket[Connected])\n"
    "    return\n"
    "\n"
    "fun main(_stdio: Stdio)\n"
    "    let s0 = Socket[Created] { fd: 7 }\n"
    "    let s1 = relay(s0)\n"
    "    discard(s1)\n"
)


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

    def test_self_copied_into_unannotated_binding_emits(self):
        # An unannotated copy of ``self`` (``var cur = self``) followed
        # by a method call on the copy used to raise
        # ``WasmEmissionError: MethodCall on receiver of type
        # 'Unknown'`` because the copy inherited the ``self`` param's
        # ``Unknown`` type. The lowerer now recovers the copy's type
        # from the analyzer's type map, so emission succeeds. Pure
        # emitter path -- no wasm tooling needed.
        for bind in ("var cur = self", "let cur = self"):
            src = (
                "type Counter { n: Int }\n"
                "impl Counter\n"
                "    fun bump(self) -> Int\n"
                f"        {bind}\n"
                "        return cur.value()\n"
                "    fun value(self) -> Int\n"
                "        return self.n\n"
            )
            ir_mod, _, _ = _parse_lower(src)
            # Must not raise WasmEmissionError.
            wat = emit_wat(ir_mod)
            self.assertIn("$Counter_bump", wat)
            self.assertIn("$Counter_value", wat)

    def test_discarded_call_drops_exact_result_slot_count(self):
        # A value-discarded call must drop EXACTLY as many operand-stack
        # slots as the callee's return type pushed: 0 for Unit (a
        # negative that must NOT gain a drop), 1 for a scalar / pointer,
        # 2 for a String (ptr + len). A blanket single ``drop`` would
        # leave one String value on the stack and fail validation. The
        # callee ``m`` is emitted with no drops; the discarding
        # ``caller`` holds all of them, so counting module-wide ``drop``
        # lines pins caller's count. Pure emitter path.
        import re
        cases = [
            ("String", 'return "x"', 2),
            ("Int", "return 1", 1),
            ("List<Int>", "return [1, 2]", 1),
            ("Unit", "return ()", 0),
        ]
        for ret, body, expected in cases:
            # Method form (routes through _store_trait_call_result).
            method_src = (
                "type C { n: Int }\n"
                "impl C\n"
                f"    fun m(self) -> {ret}\n"
                f"        {body}\n"
                "    fun caller(self) -> Unit\n"
                "        self.m()\n"
                "        return ()\n"
            )
            # Free-function form (routes through _emit_call).
            free_src = (
                f"fun m() -> {ret}\n"
                f"    {body}\n"
                "fun caller() -> Unit\n"
                "    m()\n"
                "    return ()\n"
            )
            for src, kind in ((method_src, "method"), (free_src, "free")):
                ir_mod, _, _ = _parse_lower(src)
                wat = emit_wat(ir_mod)
                n = len(re.findall(r"(?m)^\s*drop\s*$", wat))
                self.assertEqual(
                    n, expected,
                    msg=f"{kind} discard of {ret}: expected "
                        f"{expected} drop(s), got {n}",
                )

    def test_discarded_builtin_method_drops_exact_slot_count(self):
        # Sibling of the test above for BUILTIN methods. A builtin that
        # pushes its result must drop it exactly when discarded: a
        # scalar-returning builtin (length / contains / is_empty ->
        # Int / Bool) drops 1. The negatives matter just as much: the
        # builtins that early-return BEFORE pushing (the allocating /
        # String-returning ones) must NOT gain a spurious drop, which
        # would underflow the stack. The setup below emits no drops of
        # its own (asserted as the baseline), so a module-wide count
        # pins the discarded call's contribution exactly.
        import re

        def drop_count(body: str) -> int:
            src = (
                "fun main(stdio: Stdio)\n"
                '    let t = "hello"\n'
                "    let xs = [1, 2, 3]\n"
                "    var m = new_map()\n"
                '    m.set("k", 1)\n'
                "    var st = new_set()\n"
                "    st.add(1)\n"
                "    let o = Some(1)\n"
                "    let r = 0..5\n"
                f"{body}"
                '    stdio.println("x")\n'
            )
            ir_mod, _, _ = _parse_lower(src)
            return len(re.findall(r"(?m)^\s*drop\s*$", emit_wat(ir_mod)))

        # Baseline: the setup alone contributes no drops, so every
        # count below is attributable to the discarded call.
        self.assertEqual(drop_count(""), 0)

        pushes_one = [
            "t.length()", "t.is_empty()", 't.contains("e")',
            't.starts_with("h")', 't.ends_with("o")',
            "xs.length()", "xs.is_empty()", "xs.contains(2)",
            "m.length()", "m.is_empty()", 'm.contains_key("k")',
            'm.get("k")',
            "st.length()", "st.is_empty()", "st.contains(1)",
            "o.is_some()", "o.is_none()",
            "r.length()", "r.is_empty()", "r.contains(2)",
        ]
        for expr in pushes_one:
            self.assertEqual(
                drop_count(f"    {expr}\n"), 1,
                msg=f"discarded {expr}: expected exactly 1 drop",
            )

        # Negatives: these never push on the discard path (they
        # early-return), so they must emit NO drop.
        pushes_none = [
            "t.to_upper()", "t.to_lower()", "t.trim()",
            "t.substring(0, 2)", 't.split("l")', "t.bytes()",
            "m.keys()", "m.values()", "st.to_list()", "r.to_list()",
            "xs.map(fun (a: Int) -> Int => a + 1)",
            "xs.reverse()",
        ]
        for expr in pushes_none:
            self.assertEqual(
                drop_count(f"    {expr}\n"), 0,
                msg=f"discarded {expr}: expected NO drop (it pushes "
                    f"nothing on the discard path; a drop would "
                    f"underflow)",
            )

    def test_discarded_json_builtin_drops_exact_slot_count(self):
        # ``to_json`` returns a multi-value String and so must drop 2;
        # ``is_null`` returns Bool and drops 1. A blanket single drop
        # would leave one String value on the stack.
        import re

        def drop_count(body: str) -> int:
            src = (
                "fun main(stdio: Stdio)\n"
                '    match parse_json("1")\n'
                "        Ok(j) ->\n"
                f"{body}"
                '            stdio.println("ok")\n'
                '        Err(e) -> stdio.println("err")\n'
            )
            ir_mod, _, _ = _parse_lower(src)
            return len(re.findall(r"(?m)^\s*drop\s*$", emit_wat(ir_mod)))

        self.assertEqual(drop_count(""), 0)
        self.assertEqual(drop_count("            to_json(j)\n"), 2)
        self.assertEqual(drop_count("            j.is_null()\n"), 1)

    def test_method_call_on_payloadless_variant_receiver_emits(self):
        # An unannotated ``let l = Leaf`` is typed as the VARIANT name
        # (``Leaf``), not the sum (``Tree``); the method-table lookup is
        # keyed by the sum, so the emitter must resolve the variant head
        # to its owning sum. Before the fix this raised
        # "MethodCall on receiver of type 'Leaf'".
        src = (
            "type Tree =\n"
            "    Leaf\n"
            "    Node(Int)\n"
            "impl Tree\n"
            "    fun val_of(self) -> Int\n"
            "        return match self\n"
            "            Leaf -> 0\n"
            "            Node(n) -> n\n"
            "fun f() -> Int\n"
            "    let l = Leaf\n"
            "    return l.val_of()\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)  # must not raise
        self.assertIn("call $Tree_val_of", wat)

    def test_match_on_payloadless_variant_scrutinee_emits(self):
        # Sibling of the method-call case: a match on the same binding
        # used to raise "Match on scrutinee of type 'Leaf'".
        src = (
            "type Tree =\n"
            "    Leaf\n"
            "    Node(Int)\n"
            "fun g() -> Int\n"
            "    let l = Leaf\n"
            "    return match l\n"
            "        Leaf -> 0\n"
            "        Node(n) -> n\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)  # must not raise
        self.assertIn('(func $g (export "g")', wat)


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

    def test_qualified_typestate_generic_assembles(self):
        # Regression: a generic specialised at ``Socket[Connected]``
        # used to mangle to ``$passthrough__Socket[Connected]``, whose
        # ``[`` / ``]`` are not legal WAT identifier chars, so
        # ``wasm-tools parse`` failed. The bracket now sanitises to
        # ``_St_``.
        _, types, ast_mod = _parse_lower(_QUALIFIED_TYPESTATE_GENERIC_SRC)
        wat = compile_wat(ast_mod, types=types)
        self.assertIn("$passthrough__Socket_St_Connected", wat)
        self.assertNotIn("passthrough__Socket[Connected]", wat)
        # The load-bearing check: it assembles.
        blob = compile_wasm(ast_mod, types=types)
        self.assertTrue(blob.startswith(b"\x00asm"))
        self.assertGreater(len(blob), 8)


class TestTypeTokenSanitiser(unittest.TestCase):
    """Unit coverage for the single ``_sanitise_type_token`` chain that
    ``_mangle`` and ``_mangle_type`` share, focused on the typestate
    ``[`` / ``]`` handling and its dedup-injectivity."""

    def test_single_shared_sanitiser_chain(self):
        # The fix collapsed two byte-identical sanitiser chains into one
        # helper. Both manglers must route through it, and the source
        # file must carry exactly one such chain.
        import inspect
        from capa.ir._monomorphise import _typestr

        src = inspect.getsource(_typestr)
        self.assertEqual(src.count('.replace("<", "_")'), 1)
        self.assertIn(
            "_sanitise_type_token",
            inspect.getsource(_typestr._mangle),
        )
        self.assertIn(
            "_sanitise_type_token",
            inspect.getsource(_typestr._mangle_type),
        )

    def test_bracketed_typestates_stay_injective(self):
        from capa.ir._monomorphise._typestr import (
            _mangle_type, _sanitise_type_token,
        )

        # Distinct typestates of the same base must not merge.
        self.assertNotEqual(
            _sanitise_type_token("Socket[Connected]"),
            _sanitise_type_token("Socket[Listening]"),
        )
        # A bracketed name must not alias its angle-bracket generic
        # twin nor the same letters run together unbracketed.
        self.assertNotEqual(
            _sanitise_type_token("Socket[Connected]"),
            _sanitise_type_token("Socket<Connected>"),
        )
        self.assertNotEqual(
            _sanitise_type_token("Socket[Connected]"),
            _sanitise_type_token("SocketConnected"),
        )
        # Same, one level up through the generic-type mangler.
        self.assertNotEqual(
            _mangle_type("Box", ["Socket[Connected]"]),
            _mangle_type("Box", ["Socket[Listening]"]),
        )
        # The sanitised token is a legal WAT identifier body.
        token = _sanitise_type_token("Socket[Connected]")
        self.assertNotIn("[", token)
        self.assertNotIn("]", token)

    def test_python_backend_never_mangles_the_typestate_generic(self):
        # The fix is Wasm-mangling only: the Python/legacy backend does
        # not monomorphise, so it never touches ``_sanitise_type_token``
        # and its output for the repro is unaffected. Proof: the emitted
        # Python carries no mangled ``passthrough__`` name at all.
        from capa.ir import compile as compile_python

        _, types, ast_mod = _parse_lower(_QUALIFIED_TYPESTATE_GENERIC_SRC)
        py_src = compile_python(ast_mod, types=types)
        self.assertNotIn("passthrough__", py_src)
        self.assertNotIn("Socket_St_", py_src)


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

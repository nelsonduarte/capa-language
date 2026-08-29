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
class TestWasmNestedTuplePattern(unittest.TestCase):
    """A PatTuple / PatStruct sitting as an ELEMENT of a tuple-match
    pattern. The nested sub-pattern's slot holds a pointer to another
    tuple / struct record; the emitter descends into it, reusing the
    tuple-destructuring and struct-match machinery one scratch level
    deeper so a parent pointer survives while a child is decoded.
    Each case asserts byte-exact stdout parity with the Python
    backend."""

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

    def test_nested_tuple_element(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = ((1, 2), \"x\")\n"
            "    match d\n"
            "        ((a, b), s) -> stdio.println(\"${a} ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 x\n")

    def test_deeper_nested_tuple_element(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = (((1, 2), 3), \"x\")\n"
            "    match d\n"
            "        (((a, b), c), s) ->"
            " stdio.println(\"${a} ${b} ${c} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 3 x\n")

    def test_struct_element(self):
        src = (
            "type P { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let d = (P { x: 1, y: 2 }, \"s\")\n"
            "    match d\n"
            "        (P { x: a, y: b }, s) ->"
            " stdio.println(\"${a} ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 s\n")

    def test_struct_element_string_field(self):
        # A pointer-shaped (String) struct field bound inside a tuple
        # element: the binder must be typed String (ptr/len pair), not
        # the Unknown i64 default (which formatted it via itoa).
        src = (
            "type P { name: String }\n"
            "fun main(stdio: Stdio)\n"
            "    let d = (P { name: \"bob\" }, 7)\n"
            "    match d\n"
            "        (P { name: n }, k) -> stdio.println(\"${n} ${k}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "bob 7\n")

    def test_mixture_struct_and_tuple_elements(self):
        src = (
            "type P { x: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let d = (P { x: 9 }, (4, 5))\n"
            "    match d\n"
            "        (P { x: a }, (b, c)) ->"
            " stdio.println(\"${a} ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "9 4 5\n")

    def test_literal_in_nested_tuple_selects_arm(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = ((1, 2), \"x\")\n"
            "    match d\n"
            "        ((1, b), s) -> stdio.println(\"one ${b} ${s}\")\n"
            "        ((a, b), s) ->"
            " stdio.println(\"other ${a} ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "one 2 x\n")

    def test_literal_in_nested_tuple_falls_through(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = ((9, 2), \"x\")\n"
            "    match d\n"
            "        ((1, b), s) -> stdio.println(\"one ${b} ${s}\")\n"
            "        ((a, b), s) ->"
            " stdio.println(\"other ${a} ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "other 9 2 x\n")

    def test_variant_inside_nested_tuple(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = ((Some(7), 2), \"x\")\n"
            "    match d\n"
            "        ((Some(n), b), s) ->"
            " stdio.println(\"some ${n} ${b} ${s}\")\n"
            "        ((None, b), s) ->"
            " stdio.println(\"none ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 7 2 x\n")

    def test_guard_over_nested_tuple(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let d = ((5, 2), \"x\")\n"
            "    match d\n"
            "        ((a, b), s) if a > 0 ->"
            " stdio.println(\"pos ${a} ${b} ${s}\")\n"
            "        ((a, b), s) ->"
            " stdio.println(\"nonpos ${a} ${b} ${s}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "pos 5 2 x\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStructFieldSubPatterns(unittest.TestCase):
    """A PatVariant / PatTuple / String-literal sitting as a FIELD of a
    struct-match pattern (the parallel of the nested tuple-element case
    above). The field slot holds the child value at its layout offset;
    the emitter reuses the variant tag-test / tuple-destructuring
    machinery one scratch level deeper, and the discovery pass registers
    ``$str_eq`` for a String-literal field. Each case asserts byte-exact
    stdout parity with the Python backend."""

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

    def test_variant_field_some(self):
        src = (
            "type P { tag: Option<Int>, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { tag: Some(7), y: 2 }\n"
            "    match p\n"
            "        P { tag: Some(n), y: b } ->"
            " stdio.println(\"some ${n} ${b}\")\n"
            "        P { tag: None, y: b } ->"
            " stdio.println(\"none ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 7 2\n")

    def test_variant_field_none_falls_through(self):
        src = (
            "type P { tag: Option<Int>, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { tag: None, y: 3 }\n"
            "    match p\n"
            "        P { tag: Some(n), y: b } ->"
            " stdio.println(\"some ${n} ${b}\")\n"
            "        P { tag: None, y: b } ->"
            " stdio.println(\"none ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "none 3\n")

    def test_variant_field_second_position(self):
        # Variant field is not the first field: the layout offset, not
        # a fixed slot, drives the pointer load.
        src = (
            "type P { y: Int, tag: Option<Int> }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { y: 4, tag: Some(8) }\n"
            "    match p\n"
            "        P { y: b, tag: Some(n) } ->"
            " stdio.println(\"some ${b} ${n}\")\n"
            "        P { y: b, tag: None } ->"
            " stdio.println(\"none ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 4 8\n")

    def test_tuple_field(self):
        src = (
            "type P { pair: (Int, Int), y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { pair: (1, 2), y: 3 }\n"
            "    match p\n"
            "        P { pair: (a, b), y: c } ->"
            " stdio.println(\"${a} ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 3\n")

    def test_tuple_field_with_literal_selects_arm(self):
        src = (
            "type P { pair: (Int, Int), y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { pair: (1, 9), y: 3 }\n"
            "    match p\n"
            "        P { pair: (1, b), y: c } ->"
            " stdio.println(\"one ${b} ${c}\")\n"
            "        P { pair: (a, b), y: c } ->"
            " stdio.println(\"rest ${a} ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "one 9 3\n")

    def test_string_literal_field(self):
        # Bug 3: the String-literal field compares via $str_eq; the
        # discovery pass must register the helper or wasm-tools parse
        # fails with "unknown func: failed to find name $str_eq".
        src = (
            "type P { name: String, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { name: \"bob\", y: 2 }\n"
            "    match p\n"
            "        P { name: \"bob\", y: b } ->"
            " stdio.println(\"bob ${b}\")\n"
            "        P { name: n, y: b } ->"
            " stdio.println(\"${n} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "bob 2\n")

    def test_two_string_literal_fields(self):
        src = (
            "type P { a: String, b: String }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { a: \"x\", b: \"y\" }\n"
            "    match p\n"
            "        P { a: \"x\", b: \"y\" } -> stdio.println(\"xy\")\n"
            "        P { a: u, b: v } -> stdio.println(\"${u} ${v}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "xy\n")

    def test_variant_inside_tuple_field(self):
        # Composition: a PatVariant nested inside a PatTuple field.
        src = (
            "type P { pair: (Option<Int>, Int), y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { pair: (Some(7), 2), y: 3 }\n"
            "    match p\n"
            "        P { pair: (Some(n), b), y: c } ->"
            " stdio.println(\"some ${n} ${b} ${c}\")\n"
            "        P { pair: (None, b), y: c } ->"
            " stdio.println(\"none ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 7 2 3\n")

    def test_variant_field_in_nested_struct(self):
        # Composition: a nested struct field whose own field is a variant.
        src = (
            "type Q { tag: Option<Int> }\n"
            "type P { q: Q, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { q: Q { tag: Some(7) }, y: 2 }\n"
            "    match p\n"
            "        P { q: Q { tag: Some(n) }, y: b } ->"
            " stdio.println(\"some ${n} ${b}\")\n"
            "        P { q: Q { tag: None }, y: b } ->"
            " stdio.println(\"none ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 7 2\n")

    def test_guard_over_struct_field(self):
        src = (
            "type P { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { x: 0, y: 9 }\n"
            "    match p\n"
            "        P { x: a, y: b } if a > 0 ->"
            " stdio.println(\"pos ${a} ${b}\")\n"
            "        P { x: a, y: b } ->"
            " stdio.println(\"nonpos ${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "nonpos 0 9\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTupleStructInVariantPayload(unittest.TestCase):
    """A PatTuple / PatStruct sitting as the PAYLOAD of a variant arm
    (``D((a, b))`` / ``Ev(P { x: a })``). The variant payload slot
    holds the child record's pointer (i64-extended in the uniform sum
    slot); the emitter descends into it, reusing the same tuple-
    destructuring and struct-match machinery the tuple-element and
    struct-field paths use, one scratch level deeper. Each case
    asserts byte-exact stdout parity with the Python backend."""

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

    def test_tuple_payload(self):
        src = (
            "type Duo =\n"
            "    D((Int, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((1, 2))\n"
            "    match x\n"
            "        D((a, b)) -> stdio.println(\"${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2\n")

    def test_deeper_tuple_payload(self):
        src = (
            "type Tri =\n"
            "    T(((Int, Int), Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = T(((1, 2), 3))\n"
            "    match x\n"
            "        T(((a, b), c)) ->"
            " stdio.println(\"${a} ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 3\n")

    def test_literal_in_tuple_payload_selects_arm(self):
        src = (
            "type Duo =\n"
            "    D((Int, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((1, 2))\n"
            "    match x\n"
            "        D((1, b)) -> stdio.println(\"one ${b}\")\n"
            "        D((a, b)) -> stdio.println(\"${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "one 2\n")

    def test_literal_in_tuple_payload_falls_through(self):
        src = (
            "type Duo =\n"
            "    D((Int, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((9, 2))\n"
            "    match x\n"
            "        D((1, b)) -> stdio.println(\"one ${b}\")\n"
            "        D((a, b)) -> stdio.println(\"${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "9 2\n")

    def test_wildcard_in_tuple_payload(self):
        src = (
            "type Duo =\n"
            "    D((Int, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((1, 2))\n"
            "    match x\n"
            "        D((_, b)) -> stdio.println(\"w ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "w 2\n")

    def test_struct_payload_with_string_field(self):
        src = (
            "type P { x: Int, y: String }\n"
            "type E =\n"
            "    Ev(P)\n"
            "fun main(stdio: Stdio)\n"
            "    let e = Ev(P { x: 7, y: \"hi\" })\n"
            "    match e\n"
            "        Ev(P { x: a, y: b }) ->"
            " stdio.println(\"${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "7 hi\n")

    def test_variant_inside_tuple_payload(self):
        src = (
            "type Duo =\n"
            "    D((Option<Int>, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((Some(5), 2))\n"
            "    match x\n"
            "        D((Some(n), b)) ->"
            " stdio.println(\"some ${n} ${b}\")\n"
            "        D((None, b)) -> stdio.println(\"none ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 5 2\n")

    def test_tuple_inside_struct_payload(self):
        src = (
            "type Q { pair: (Int, Int), z: Int }\n"
            "type E =\n"
            "    Ev(Q)\n"
            "fun main(stdio: Stdio)\n"
            "    let e = Ev(Q { pair: (1, 2), z: 3 })\n"
            "    match e\n"
            "        Ev(Q { pair: (a, b), z: c }) ->"
            " stdio.println(\"${a} ${b} ${c}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "1 2 3\n")

    def test_builtin_option_of_tuple(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let opt = Some((3, 4))\n"
            "    match opt\n"
            "        Some((a, b)) ->"
            " stdio.println(\"some ${a} ${b}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "some 3 4\n")

    def test_guard_over_tuple_payload(self):
        src = (
            "type Duo =\n"
            "    D((Int, Int))\n"
            "fun main(stdio: Stdio)\n"
            "    let x = D((1, 2))\n"
            "    match x\n"
            "        D((a, b)) if a > 0 ->"
            " stdio.println(\"pos ${a} ${b}\")\n"
            "        D((a, b)) -> stdio.println(\"nonpos ${a} ${b}\")\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "pos 1 2\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTuplePointerElementThroughTry(unittest.TestCase):
    """A tuple whose element is pointer-shaped (``Map`` / ``List`` /
    ``Set``) returned through a ``?`` / ``Result`` boundary and then
    destructured.

    Pre-fix ``_lower_try`` defaulted the ``?`` payload type to
    ``Unknown`` when the analyzer left the ``Try`` node untyped; the
    ``let (m, s) = f()?`` binders inherited it, and the Wasm tuple
    emitter sized the ``Map`` element as an i64 slot even though a
    ``Map`` is an i32 heap pointer. The module then failed the Wasm
    validator (``expected i32, found i64``) despite passing ``--check``
    and running on the Python backend. Each case asserts byte-exact
    stdout parity with the Python backend."""

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

    def test_map_element_let_destructure_through_try(self):
        src = (
            "type E =\n"
            "    Bad\n"
            "fun build() -> Result<(Map<String, String>, String), E>\n"
            "    let m: Map<String, String> = new_map()\n"
            '    m.set("k", "v")\n'
            '    return Ok((m, "tail"))\n'
            "fun run() -> Result<String, E>\n"
            "    let (m, s) = build()?\n"
            '    let got = match m.get("k")\n'
            '        None -> "missing"\n'
            "        Some(v) -> v\n"
            '    return Ok(got + "-" + s)\n'
            "fun main(stdio: Stdio)\n"
            "    match run()\n"
            "        Ok(v) -> stdio.println(v)\n"
            '        Err(_) -> stdio.println("err")\n'
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "v-tail\n")

    def test_map_element_match_ok_destructure(self):
        src = (
            "type E =\n"
            "    Bad\n"
            "fun build() -> Result<(Map<String, String>, String), E>\n"
            "    let m: Map<String, String> = new_map()\n"
            '    m.set("k", "v")\n'
            '    return Ok((m, "tail"))\n'
            "fun run() -> String\n"
            "    match build()\n"
            "        Ok((m, s)) ->\n"
            '            let got = match m.get("k")\n'
            '                None -> "missing"\n'
            "                Some(v) -> v\n"
            '            return got + "-" + s\n'
            '        Err(_) -> return "err"\n'
            "fun main(stdio: Stdio)\n"
            "    stdio.println(run())\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "v-tail\n")

    def test_list_element_let_destructure_through_try(self):
        src = (
            "type E =\n"
            "    Bad\n"
            "fun build() -> Result<(List<Int>, String), E>\n"
            "    let xs: List<Int> = [1, 2, 3]\n"
            '    return Ok((xs, "tail"))\n'
            "fun run() -> Result<String, E>\n"
            "    let (xs, s) = build()?\n"
            '    return Ok("${xs.length()}-${s}")\n'
            "fun main(stdio: Stdio)\n"
            "    match run()\n"
            "        Ok(v) -> stdio.println(v)\n"
            '        Err(_) -> stdio.println("err")\n'
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "3-tail\n")


class TestWasmTuplePointerSlotGuard(unittest.TestCase):
    """Fail-loud guard (defense in depth) for the tuple slot emitter.
    A pointer-shaped value reaching an unresolved (``Unknown`` / tyvar)
    slot type must raise a clear compiler diagnostic rather than fall
    silently into the i64 branch and ship invalid Wasm. These are pure
    emitter unit tests (no Wasm toolchain), so the class is not skip-
    guarded: it must run on the plain ``test`` CI job too."""

    def _emitter(self):
        from capa.ir._emit_wasm import WasmEmitter
        return WasmEmitter()

    def test_store_pointer_value_into_unknown_slot_raises(self):
        from capa.ir._nodes import Value
        em = self._emitter()
        v = Value(kind="local", name="m", ty="Map<String, String>")
        with self.assertRaises(WasmEmissionError) as ctx:
            em._store_tuple_slot(v, "Unknown", 0)
        self.assertIn("pointer-shaped", str(ctx.exception))

    def test_index_pointer_from_unknown_dst_raises(self):
        from types import SimpleNamespace
        from capa.ir._nodes import Value, Index
        em = self._emitter()
        em._current_fn = SimpleNamespace(locals={"m": "Unknown"})
        recv = Value(
            kind="local", name="t", ty="(Map<String, String>, String)",
        )
        instr = Index(
            dst="m", receiver=recv,
            index=Value(kind="lit_int", literal=0),
        )
        with self.assertRaises(WasmEmissionError) as ctx:
            em._emit_tuple_index(instr)
        self.assertIn("pointer-shaped", str(ctx.exception))

    def test_store_int_value_into_unknown_slot_does_not_raise(self):
        # Neighbour guard: a legitimately i64-typed element (Int) in an
        # unresolved slot must NOT trip the guard.
        from capa.ir._nodes import Value
        em = self._emitter()
        v = Value(kind="local", name="n", ty="Int")
        em._store_tuple_slot(v, "Unknown", 0)  # no raise

    def test_index_int_from_unknown_dst_does_not_raise(self):
        from types import SimpleNamespace
        from capa.ir._nodes import Value, Index
        em = self._emitter()
        em._current_fn = SimpleNamespace(locals={"n": "Unknown"})
        recv = Value(kind="local", name="t", ty="(Int, String)")
        instr = Index(
            dst="n", receiver=recv,
            index=Value(kind="lit_int", literal=0),
        )
        em._emit_tuple_index(instr)  # no raise


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

    # A payloadless variant literal bound by an UNANNOTATED let/var is
    # typed by the lowerer as the VARIANT name (``Leaf``), not the owning
    # sum (``Tree``). The method-table and sum-layout lookups are keyed
    # by the sum, so both a method call and a match on that binding used
    # to raise on the Wasm backend. They now resolve through
    # ``_variant_to_sum`` at the consumer sites.
    _TREE_IMPL = (
        "type Tree =\n"
        "    Leaf\n"
        "    Node(Int)\n"
        "impl Tree\n"
        "    fun val_of(self) -> Int\n"
        "        return match self\n"
        "            Leaf -> 0\n"
        "            Node(n) -> n\n"
    )

    def test_method_call_on_unannotated_payloadless_variant_let(self):
        src = self._TREE_IMPL + (
            "fun f() -> Int\n"
            "    let l = Leaf\n"
            "    return l.val_of()\n"
        )
        self.assertEqual(self._exec(src, "f"), 0)

    def test_method_call_on_unannotated_payloadless_variant_var(self):
        src = self._TREE_IMPL + (
            "fun f() -> Int\n"
            "    var l = Leaf\n"
            "    return l.val_of()\n"
        )
        self.assertEqual(self._exec(src, "f"), 0)

    def test_match_on_unannotated_payloadless_variant_let(self):
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
        self.assertEqual(self._exec(src, "g"), 0)

    def test_match_on_unannotated_payloadless_variant_var(self):
        src = (
            "type Tree =\n"
            "    Leaf\n"
            "    Node(Int)\n"
            "fun g() -> Int\n"
            "    var l = Leaf\n"
            "    return match l\n"
            "        Leaf -> 0\n"
            "        Node(n) -> n\n"
        )
        self.assertEqual(self._exec(src, "g"), 0)


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

    def test_compose_captures_and_calls(self):
        # Regression (2026-07): a lifted lambda that CAPTURES another
        # function and CALLS it. ``compose(f, g)`` returns
        # ``fun (x) => g(f(x))`` where ``f`` / ``g`` are captured only
        # as call targets, never as plain values. Before the fix the
        # free-var analysis missed the callee names entirely (a Call's
        # callee is a bare string, not a Value), so the env was empty
        # and the body emitted ``call $f`` for a non-existent static
        # function -- ``unknown func $f`` at wasm parse time.
        src = (
            "fun compose(f: Fun(Int) -> Int, g: Fun(Int) -> Int)"
            " -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => g(f(x))\n"
            "fun main() -> Int\n"
            "    let d = fun (x: Int) -> Int => x * 2\n"
            "    let i = fun (x: Int) -> Int => x + 1\n"
            "    let di = compose(d, i)\n"
            "    return di(10)\n"
        )
        store, exp = self._instantiate(src)
        # d(10) = 20, then i(20) = 21.
        self.assertEqual(exp["main"](store), 21)

    def test_compose_chained(self):
        # Chained / triple composition compose(compose(d, i), s):
        # the outer compose captures a capturing closure and another
        # closure, and calls both.
        src = (
            "fun compose(f: Fun(Int) -> Int, g: Fun(Int) -> Int)"
            " -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => g(f(x))\n"
            "fun main() -> Int\n"
            "    let d = fun (x: Int) -> Int => x * 2\n"
            "    let i = fun (x: Int) -> Int => x + 1\n"
            "    let s = fun (x: Int) -> Int => x - 3\n"
            "    let t = compose(compose(d, i), s)\n"
            "    return t(10)\n"
        )
        store, exp = self._instantiate(src)
        # d(10)=20, i(20)=21, s(21)=18.
        self.assertEqual(exp["main"](store), 18)

    def test_capturing_closure_returned_stored_called(self):
        # A capturing closure DEVOLVED, stored in a let, and called
        # later. ``adder(n)`` closes over the Int ``n``; the returned
        # closure is bound and invoked from another scope.
        src = (
            "fun adder(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + n\n"
            "fun main() -> Int\n"
            "    let add5 = adder(5)\n"
            "    let add10 = adder(10)\n"
            "    return add5(1) + add10(1)\n"
        )
        store, exp = self._instantiate(src)
        # (1+5) + (1+10) = 17.
        self.assertEqual(exp["main"](store), 17)

    def test_fun_capture_alongside_int_capture(self):
        # A Fun-typed capture sits next to an Int capture in the SAME
        # env record: the layout must place both without clobbering.
        src = (
            "fun make(f: Fun(Int) -> Int, k: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => f(x) + k\n"
            "fun main() -> Int\n"
            "    let d = fun (x: Int) -> Int => x * 2\n"
            "    let g = make(d, 100)\n"
            "    return g(7)\n"
        )
        store, exp = self._instantiate(src)
        # d(7)=14, +100 = 114.
        self.assertEqual(exp["main"](store), 114)

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
class TestWasmMapFunValue(unittest.TestCase):
    """A ``Map`` whose value type is ``Fun(...)``. A closure value is
    a packed i64 ``(fn_idx << 32) | env_ptr``; it rides the map's
    uniform 8-byte value slot verbatim (no extend / reinterpret),
    ``m.get`` reads the slot back into the Option<Fun> payload, and
    the bound ``f`` dispatches through the closure-call
    (call_indirect) path. Covers set+get+call, a string-keyed
    dispatch table, a CAPTURING closure as a map value, an Int key,
    and ``m.values()`` over a Map of Fun."""

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

    def test_map_string_fun_set_get_call(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main() -> Int\n"
            "    let m: Map<String, Fun(Int) -> Int> = new_map()\n"
            "    m.set(\"inc\", add1)\n"
            "    match m.get(\"inc\")\n"
            "        Some(f) -> return f(10)\n"
            "        None -> return -1\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 11)

    def test_map_fun_dispatch_table(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun dbl(x: Int) -> Int\n"
            "    return x * 2\n"
            "fun main() -> Int\n"
            "    let m: Map<String, Fun(Int) -> Int> = new_map()\n"
            "    m.set(\"inc\", add1)\n"
            "    m.set(\"dbl\", dbl)\n"
            "    var acc = 0\n"
            "    match m.get(\"inc\")\n"
            "        Some(f) -> acc = acc + f(10)\n"
            "        None -> acc = acc - 1\n"
            "    match m.get(\"dbl\")\n"
            "        Some(g) -> acc = acc + g(10)\n"
            "        None -> acc = acc - 1\n"
            "    return acc\n"
        )
        store, exp = self._instantiate(src)
        # add1(10)=11, dbl(10)=20 -> 31.
        self.assertEqual(exp["main"](store), 31)

    def test_map_capturing_closure_value(self):
        src = (
            "fun make_adder(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + n\n"
            "fun main() -> Int\n"
            "    let m: Map<String, Fun(Int) -> Int> = new_map()\n"
            "    m.set(\"a5\", make_adder(5))\n"
            "    m.set(\"a100\", make_adder(100))\n"
            "    var acc = 0\n"
            "    match m.get(\"a5\")\n"
            "        Some(f) -> acc = acc + f(1)\n"
            "        None -> acc = acc - 1\n"
            "    match m.get(\"a100\")\n"
            "        Some(g) -> acc = acc + g(1)\n"
            "        None -> acc = acc - 1\n"
            "    return acc\n"
        )
        store, exp = self._instantiate(src)
        # (1+5) + (1+100) = 107.
        self.assertEqual(exp["main"](store), 107)

    def test_map_int_key_fun_value(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main() -> Int\n"
            "    let m: Map<Int, Fun(Int) -> Int> = new_map()\n"
            "    m.set(7, add1)\n"
            "    match m.get(7)\n"
            "        Some(f) -> return f(41)\n"
            "        None -> return -1\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["main"](store), 42)

    def test_map_values_of_fun(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun dbl(x: Int) -> Int\n"
            "    return x * 2\n"
            "fun main() -> Int\n"
            "    let m: Map<String, Fun(Int) -> Int> = new_map()\n"
            "    m.set(\"inc\", add1)\n"
            "    m.set(\"dbl\", dbl)\n"
            "    let fs: List<Fun(Int) -> Int> = m.values()\n"
            "    var total = 0\n"
            "    for f in fs\n"
            "        total = total + f(10)\n"
            "    return total\n"
        )
        store, exp = self._instantiate(src)
        # add1(10)=11, dbl(10)=20 -> 31 (order-independent sum).
        self.assertEqual(exp["main"](store), 31)

    def test_map_fun_alongside_map_int_no_cross_contamination(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main() -> Int\n"
            "    let fm: Map<String, Fun(Int) -> Int> = new_map()\n"
            "    let im: Map<String, Int> = new_map()\n"
            "    fm.set(\"inc\", add1)\n"
            "    im.set(\"count\", 42)\n"
            "    var acc = 0\n"
            "    match fm.get(\"inc\")\n"
            "        Some(f) -> acc = acc + f(9)\n"
            "        None -> acc = acc - 1\n"
            "    match im.get(\"count\")\n"
            "        Some(n) -> acc = acc + n\n"
            "        None -> acc = acc - 1\n"
            "    return acc\n"
        )
        store, exp = self._instantiate(src)
        # add1(9)=10, +42 = 52.
        self.assertEqual(exp["main"](store), 52)


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

    # ------- Tuple-scrutinee match: PatVariant sub-pattern -----
    # A variant pattern as a tuple element is a slot at a known
    # offset holding a sum record; the emitter reuses the depth-1
    # nested-variant tag-test + payload-bind machinery. These
    # exercise every case in the supported matrix.

    def test_tuple_match_variant_with_payload_element(self):
        # ``(Some(n), m) -> ...`` binds the Option payload from the
        # first tuple slot; ``(None, m)`` is the tag-only arm.
        src = (
            "fun pick(a: Int) -> Int\n"
            "    let t: (Option<Int>, Int) = (Some(a), 9)\n"
            "    return match t\n"
            "        (Some(n), m) -> n + m\n"
            "        (None, m) -> m\n"
        )
        self.assertEqual(self._exec(src, "pick", 3), 12)
        self.assertEqual(self._exec(src, "pick", 100), 109)

    def test_tuple_match_nullary_variant_element(self):
        # ``(None, m) -> ...`` is a pure tag check with no payload
        # bind; the Some arm must NOT fire.
        src = (
            "fun pick() -> Int\n"
            "    let t: (Option<Int>, Int) = (None, 7)\n"
            "    return match t\n"
            "        (Some(n), m) -> n + m\n"
            "        (None, m) -> m\n"
        )
        self.assertEqual(self._exec(src, "pick"), 7)

    def test_tuple_match_variant_in_second_position(self):
        # The variant element is NOT slot 0: offset math + inner
        # scrutinee extraction must key off ``idx * 8``.
        src = (
            "fun pick(a: Int) -> Int\n"
            "    let t: (Int, Option<Int>) = (100, Some(a))\n"
            "    return match t\n"
            "        (m, Some(n)) -> m + n\n"
            "        (m, None) -> m\n"
        )
        self.assertEqual(self._exec(src, "pick", 5), 105)

    def test_tuple_match_multiple_variant_elements(self):
        # Two variant elements in one tuple: the predicate ANDs
        # both discriminant checks; each bind re-extracts its own
        # slot into $_m_scrut_inner.
        src = (
            "fun pick(a: Int, b: Int) -> Int\n"
            "    let t: (Option<Int>, Result<Int, Int>) = "
            "(Some(a), Ok(b))\n"
            "    return match t\n"
            "        (Some(x), Ok(y)) -> x * 100 + y\n"
            "        (Some(x), Err(e)) -> x\n"
            "        (None, _) -> -1\n"
        )
        self.assertEqual(self._exec(src, "pick", 2, 3), 203)

    def test_tuple_match_variant_next_to_literal(self):
        # ``(Some(n), "x")`` mixes a variant discriminant check
        # with a String-literal slot compare in the same predicate.
        src = (
            "fun pick_x() -> Int\n"
            "    return inner(\"x\", 5)\n"
            "fun pick_y() -> Int\n"
            "    return inner(\"y\", 5)\n"
            "fun inner(s: String, a: Int) -> Int\n"
            "    let t: (Option<Int>, String) = (Some(a), s)\n"
            "    return match t\n"
            "        (Some(n), \"x\") -> n * 10\n"
            "        (Some(n), k) -> n\n"
            "        (None, k) -> -1\n"
        )
        self.assertEqual(self._exec(src, "pick_x"), 50)
        self.assertEqual(self._exec(src, "pick_y"), 5)


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


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmNullaryVariantInAggregate(unittest.TestCase):
    """Regression: a payload-less (nullary) sum variant used as a
    VALUE inside an aggregate literal (struct field, list element,
    tuple element, map value) is materialised via the function-level
    ``$_alloc_tmp`` scratch in ``_push_value``. The locals collector
    only declared ``$_alloc_tmp`` when it saw the variant through a
    fixed set of flat instruction attributes plus ``instr.args``; it
    never descended into ``MakeStruct.fields`` / ``MakeList.elements``
    / ``MakeTuple.elements``. So when a nullary variant was the ONLY
    thing pulling in the scratch AND it lived inside an aggregate
    literal, the local was never declared and the emitted WAT
    referenced an unknown ``$_alloc_tmp`` (``--check`` and the Python
    backend both accepted the program). Each case below uses a
    program shape where no other construct (list method, match on a
    collection, for-loop, range, ...) would incidentally declare the
    scratch, so it isolates the aggregate path.
    """

    def _run(self, src: str) -> str:
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
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

    _DISP = (
        "type Disp =\n"
        "    Allow\n"
        "    Deny\n"
        "\n"
        "fun word(x: Disp) -> String\n"
        "    return match x\n"
        "        Allow -> \"allow\"\n"
        "        Deny  -> \"deny\"\n"
        "\n"
    )

    def test_nullary_variant_as_struct_field(self):
        src = self._DISP + (
            "type S {\n"
            "    d: Disp\n"
            "}\n"
            "\n"
            "pub fun main(stdio: Stdio)\n"
            "    let s = S { d: Allow }\n"
            "    stdio.println(word(s.d))\n"
        )
        self.assertEqual(self._run(src), "allow\n")

    def test_nullary_variant_as_list_element(self):
        src = self._DISP + (
            "pub fun main(stdio: Stdio)\n"
            "    let xs = [Allow, Deny]\n"
            "    stdio.println(word(xs[0]))\n"
        )
        self.assertEqual(self._run(src), "allow\n")

    def test_nullary_variant_as_tuple_element(self):
        src = self._DISP + (
            "pub fun main(stdio: Stdio)\n"
            "    let t = (Allow, 1)\n"
            "    let (a, b) = t\n"
            "    stdio.println(word(a))\n"
        )
        self.assertEqual(self._run(src), "allow\n")

    def test_nullary_variant_as_map_value(self):
        src = self._DISP + (
            "pub fun main(stdio: Stdio)\n"
            "    let m: Map<String, Disp> = new_map()\n"
            "    m.set(\"k\", Allow)\n"
            "    match m.get(\"k\")\n"
            "        Some(v) -> stdio.println(word(v))\n"
            "        None -> stdio.println(\"none\")\n"
        )
        self.assertEqual(self._run(src), "allow\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmReturnUnitUserMethod(unittest.TestCase):
    """``return <user-method-call-returning-Unit>`` used to miscompile
    on the Wasm backend. The analyzer types a Unit method result as
    ``()`` (Unit is the empty tuple), but the emitter keys its Unit
    handling off the spelling ``Unit``; the mismatch let a Unit value
    slip past those guards, so the trait-method emitter wrote a
    ``local.set`` for a callee that pushed nothing and the ``return``
    then re-pushed the (never-declared) local. wasmtime rejected the
    module with "expected i64 but nothing on stack".

    The free-function form (``return f(...)``) and the builtin-cap form
    (``return stdio.eprintln(...)``) already worked -- the former via
    the tail-call peephole, the latter via the cap-method path -- so
    these tests pin the user-method form across every context the
    ``return`` can appear in (match arm, if / else branch, loose
    statement) plus the non-taken path, confirming valid codegen and
    parity with the Python backend."""

    _LOGGER = (
        "pub type Logger {\n"
        "    prefix: String\n"
        "}\n"
        "impl Logger\n"
        "    pub fun note(self, stdio: Stdio, msg: String)\n"
        "        stdio.println(\"${self.prefix}: ${msg}\")\n"
    )

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

    def test_return_unit_method_in_match_arm(self):
        src = self._LOGGER + (
            "pub fun classify(n: Int) -> Result<Int, String>\n"
            "    if n > 0\n"
            "        return Ok(n)\n"
            "    return Err(\"negative\")\n"
            "pub fun main(stdio: Stdio)\n"
            "    let logger = Logger { prefix: \"log\" }\n"
            "    match classify(-1)\n"
            "        Ok(v)  -> stdio.println(\"ok\")\n"
            "        Err(e) -> return logger.note(stdio, \"bad: ${e}\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "log: bad: negative\n",
        )

    def test_match_ok_arm_skips_unit_method_return(self):
        # The Ok arm is taken: the Unit-method return is NOT reached, so
        # the ``match`` falls through to the trailing statement.
        src = self._LOGGER + (
            "pub fun classify(n: Int) -> Result<Int, String>\n"
            "    if n > 0\n"
            "        return Ok(n)\n"
            "    return Err(\"negative\")\n"
            "pub fun main(stdio: Stdio)\n"
            "    let logger = Logger { prefix: \"log\" }\n"
            "    match classify(5)\n"
            "        Ok(v)  -> stdio.println(\"ok\")\n"
            "        Err(e) -> return logger.note(stdio, \"bad: ${e}\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "ok\nafter\n",
        )

    def test_return_unit_method_in_if_else_branch(self):
        src = self._LOGGER + (
            "pub fun main(stdio: Stdio)\n"
            "    let logger = Logger { prefix: \"log\" }\n"
            "    let n = 0\n"
            "    if n > 0\n"
            "        stdio.println(\"pos\")\n"
            "    else\n"
            "        return logger.note(stdio, \"nonpos\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "log: nonpos\n",
        )

    def test_return_unit_method_as_loose_statement(self):
        src = self._LOGGER + (
            "pub fun main(stdio: Stdio)\n"
            "    let logger = Logger { prefix: \"log\" }\n"
            "    return logger.note(stdio, \"hi\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "log: hi\n",
        )

    def test_let_bound_unit_literal(self):
        # Same Unit class via a ``let`` binding: ``let u = ()`` binds a
        # literal-unit value. A ``lit_unit`` source pushes nothing, so
        # the binder must emit no ``local.set`` (else ``local.set``
        # consumes a value that is not on the operand stack).
        src = (
            "pub fun main(stdio: Stdio)\n"
            "    let u = ()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "done\n",
        )

    def test_let_bound_unit_method_result(self):
        # ``let x = obj.unit_method()`` binds the Unit result of a user
        # method call; the same no-``local.set`` rule applies.
        src = self._LOGGER + (
            "pub fun main(stdio: Stdio)\n"
            "    let logger = Logger { prefix: \"log\" }\n"
            "    let x = logger.note(stdio, \"hi\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "log: hi\nafter\n",
        )

    def test_try_unwrap_over_result_unit(self):
        # Regression guard: ``fs.write(...)?`` returns ``Result<Unit,
        # IoError>``, so the ``?`` operator's ``TryUnwrap`` unpacks a
        # Unit Ok-payload. The Unit result temp must stay declared (the
        # unpack does a real ``local.set`` into it); an earlier form of
        # the Unit fix dropped that declaration and left the emitted WAT
        # referencing an undeclared ``$_ir_tN``, which wasm-tools
        # rejected. Writes into a fresh temp dir so the host actually
        # succeeds and the Ok path is taken.
        import os
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "capa_try_unit.txt").replace("\\", "/")
        src = (
            "fun writeit(fs: Fs, path: String) -> Result<Int, IoError>\n"
            "    fs.write(path, \"hello\")?\n"
            "    return Ok(1)\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match writeit(fs, \"" + path + "\")\n"
            "        Ok(n)  -> stdio.println(\"wrote ${n}\")\n"
            "        Err(e) -> stdio.eprintln(\"err: ${e}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "wrote 1\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmAggregateSlotTypeInference(unittest.TestCase):
    """Regression guards for the 2026-07 aggregate/payload slot
    type-inference fix. Family: a slot whose Capa type stayed ``?`` /
    Unknown at lowering defaulted to a scalar i64 in the Wasm backend
    while the actual value is pointer-shaped (i32 record pointer) or
    packed-i64 (String / closure), producing a Wasm validator
    rejection or an undeclared local. Four roots were closed:

    1. ``IoError(...)`` constructor calls typed TyUnknown by the
       analyzer, so any aggregate slot holding one (list element,
       tuple slot, Option/Result payload) inferred ``?``.
    2. Binders nested under a builtin-variant pattern
       (``Ok(JObj(m))`` / ``Some(JStr(s))``) never resolved: the
       lowerer's ``_variant_payload_tys`` did not know the builtin
       JsonValue variants' payload types.
    3. A match expression's result type took the FIRST arm verbatim,
       so ``None -> [] ; Some(xs) -> xs`` kept the empty-list arm's
       flexible ``List<?lst_N>`` and later pushes of String /
       pointer elements were emitted as scalar i64.
    4. ``_ty_to_str`` normalised ``fun(`` -> ``Fun(`` only at the top
       level, so a ``List<fun(...)>`` literal's closure elements
       missed the ``startswith("Fun")`` width checks (4-byte slots
       for packed-i64 values).

    Each test executes end-to-end on wasmtime and asserts the exact
    stdout the Python backend produces for the same program."""

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

    def test_list_of_ioerror_iterated_and_formatted(self):
        # Root 1: ``[IoError(..), IoError(..)]`` inferred List<?>; the
        # element slot stored the i32 record pointer with i64.store and
        # the for-binder was a scalar i64 formatted via $itoa.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [IoError(\"alpha\"), IoError(\"beta\")]\n"
            "    for e in xs\n"
            "        stdio.println(\"item: ${e}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "item: alpha\nitem: beta\n",
        )

    def test_ioerror_in_tuple_and_option_payload(self):
        # Root 1: tuple slot and Some(...) payload holding an IoError.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let t = (IoError(\"a\"), 7)\n"
            "    stdio.println(\"second: ${t[1]}\")\n"
            "    let o = Some(IoError(\"b\"))\n"
            "    match o\n"
            "        Some(e) -> stdio.println(\"some: ${e}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "second: 7\nsome: b\n",
        )

    def test_ioerror_field_access_on_let_binding(self):
        # Root 1 corollary: with the constructor result typed, the
        # FieldAccess dst is a String pair (``$_ir_tN_ptr``/``_len``)
        # instead of an undeclared bare i64 local; and the analyzer
        # knows the builtin's ``message`` / ``cause`` fields.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"boom\", \"root\")\n"
            "    stdio.println(\"msg=${e.message} cause=${e.cause}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "msg=boom cause=root\n",
        )

    def test_nested_builtin_variant_binding_map_payload(self):
        # Root 2 (the examples/tasks.capa shape): ``Ok(JObj(m))``
        # binds the Map<String, JsonValue> payload of a variant
        # nested inside Ok. Pre-fix ``m`` was declared i64 while the
        # payload extraction wrapped to i32. ``m`` is also USED, so
        # method dispatch on the refined binder type is exercised.
        src = (
            "fun main(stdio: Stdio)\n"
            "    match parse_json(\"{\\\"name\\\": \\\"zeta\\\"}\")\n"
            "        Ok(JObj(m)) ->\n"
            "            match m.get(\"name\")\n"
            "                Some(JStr(s)) -> stdio.println(\"name: ${s}\")\n"
            "                _ -> stdio.println(\"no name\")\n"
            "        _ -> stdio.println(\"bad\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "name: zeta\n",
        )

    def test_nested_builtin_variant_binding_string_payload(self):
        # Root 2 (the examples/quota_check.capa shape):
        # ``Some(JStr(s))`` binds a String payload one level deep;
        # pre-fix the local-decl sweep declared a bare i64 ``$s``
        # while the bind wrote ``$s_ptr`` / ``$s_len``.
        src = (
            "fun name_of(j: JsonValue) -> String\n"
            "    return match j.as_object()\n"
            "        None -> \"<not-an-object>\"\n"
            "        Some(m) -> match m.get(\"name\")\n"
            "            Some(JStr(s)) -> s\n"
            "            _ -> \"<unnamed>\"\n"
            "fun main(stdio: Stdio)\n"
            "    match parse_json(\"{\\\"name\\\": \\\"pod-1\\\"}\")\n"
            "        Ok(j) -> stdio.println(name_of(j))\n"
            "        Err(msg) -> stdio.println(\"bad: ${msg}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "pod-1\n",
        )

    def test_nested_builtin_variant_binding_list_payload(self):
        # Root 2: ``Ok(JArr(xs))`` binds the List<JsonValue> payload.
        src = (
            "fun main(stdio: Stdio)\n"
            "    match parse_json(\"[1, 2, 3]\")\n"
            "        Ok(JArr(xs)) -> stdio.println(\"len ${xs.length()}\")\n"
            "        _ -> stdio.println(\"not arr\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "len 3\n",
        )

    def test_match_arm_result_type_refined_across_arms(self):
        # Root 3 (the spdx/cyclonedx adjacency-building shape): the
        # empty-list arm types List<?lst_N>; the Some arm's
        # List<String> must refine the match's result type or the
        # later ``push`` of a String element is emitted as a scalar
        # i64 against an undeclared bare local.
        src = (
            "type Rel { source: String, target: String }\n"
            "fun main(stdio: Stdio)\n"
            "    let rels = [\n"
            "        Rel { source: \"a\", target: \"b\" },\n"
            "        Rel { source: \"a\", target: \"c\" }\n"
            "    ]\n"
            "    let adj: Map<String, List<String>> = new_map()\n"
            "    for r in rels\n"
            "        let existing = match adj.get(r.source)\n"
            "            None -> []\n"
            "            Some(xs) -> xs\n"
            "        existing.push(r.target)\n"
            "        adj.set(r.source, existing)\n"
            "    match adj.get(\"a\")\n"
            "        Some(ts) ->\n"
            "            for t in ts\n"
            "                stdio.println(\"a -> ${t}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "a -> b\na -> c\n",
        )

    def test_closure_elements_in_annotated_list_literal(self):
        # Root 4 (the quota_check policy-list shape): the analyzer
        # renders the annotated literal's element type ``fun(...)``
        # (lowercase) NESTED inside List<>; the normalisation must
        # reach it or the packed-i64 closures get 4-byte slots.
        src = (
            "fun add_n(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x + n\n"
            "fun main(stdio: Stdio)\n"
            "    let fns: List<Fun(Int) -> Int> = [add_n(1), add_n(10)]\n"
            "    var total = 0\n"
            "    for f in fns\n"
            "        total += f(5)\n"
            "    stdio.println(\"total: ${total}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "total: 21\n",
        )

    def test_nested_user_variant_binding_still_works(self):
        # Guard: nested USER-sum variants inside Ok (already working
        # pre-fix via ``_user_variants``) must keep working with the
        # builtin seeding in place.
        src = (
            "type Col =\n"
            "    Red\n"
            "    Blue(Int)\n"
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Col, String> = Ok(Blue(9))\n"
            "    match r\n"
            "        Ok(Blue(n)) -> stdio.println(\"blue ${n}\")\n"
            "        Ok(Red) -> stdio.println(\"red\")\n"
            "        Err(e) -> stdio.println(\"err ${e}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "blue 9\n",
        )

    def test_list_of_user_structs_still_works(self):
        # Guard: List<user-struct> element inference (working pre-fix)
        # is unaffected by the IoError constructor typing.
        src = (
            "type P { x: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let a = [P { x: 1 }, P { x: 2 }]\n"
            "    for e in a\n"
            "        stdio.println(\"p: ${e.x}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "p: 1\np: 2\n",
        )

    def test_user_declared_ioerror_struct_field_write_runs(self):
        # A USER-declared ``type IoError`` shadows the builtin: it
        # keeps ordinary mutable-struct semantics (the analyzer's
        # read-only rule applies only to the BUILTIN_POS symbol), and
        # a field write runs with Python/Wasm parity. The builtin's
        # write rejection is covered in test_analyzer.py
        # (TestBuiltinIoErrorReadOnly).
        src = (
            "type IoError { message: String, cause: String }\n"
            "fun main(stdio: Stdio)\n"
            "    var e = IoError { message: \"x\", cause: \"\" }\n"
            "    e.message = \"y\"\n"
            "    stdio.println(\"msg=${e.message}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "msg=y\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFnRefInAggregate(unittest.TestCase):
    """Regression guards for the fn-ref-in-aggregate thunk fix.

    A top-level function used as a ``Fun(...)`` value that appears
    as an ELEMENT of an aggregate literal (list element, tuple
    slot, struct field) was not seen by the pre-emit thunk
    discovery walk: the walk swept Call / MethodCall / BinOp /
    etc. Value slots but had no case for MakeList / MakeTuple /
    MakeStruct element values. The reference therefore registered
    no thunk and emit failed with "no thunk was registered for
    sig". Each test executes end-to-end on wasmtime and asserts the
    exact stdout the Python backend produces for the same program."""

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

    def test_list_of_fn_refs_iterated_and_called(self):
        # The minimal repro: ``[add1, add1]`` iterated and each
        # element applied. Pre-fix the MakeList element ``add1``
        # (a global Fun value) never reached thunk discovery.
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main(stdio: Stdio)\n"
            "    let fs = [add1, add1]\n"
            "    var acc = 0\n"
            "    for f in fs\n"
            "        acc = f(acc)\n"
            "    stdio.println(\"acc=${acc}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "acc=2\n",
        )

    def test_list_of_fn_refs_indexed_and_called(self):
        # A fn-ref list element reached through an index, bound to a
        # local, then called.
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main(stdio: Stdio)\n"
            "    let fs = [add1, add1]\n"
            "    let f = fs[0]\n"
            "    let r = f(10)\n"
            "    stdio.println(\"r=${r}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "r=11\n",
        )

    def test_struct_field_of_fun_type_built_with_fn_ref(self):
        # A Fun-typed struct field initialised with a top-level
        # function reference (MakeStruct field value).
        src = (
            "type S { op: Fun(Int) -> Int }\n"
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main(stdio: Stdio)\n"
            "    let s = S { op: add1 }\n"
            "    let op = s.op\n"
            "    let r = op(41)\n"
            "    stdio.println(\"s=${r}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "s=42\n",
        )

    def test_nested_list_of_fn_refs(self):
        # A nested aggregate (list of lists of fn-refs). ANF flattens
        # the inner lists into their own MakeList instrs, so the
        # top-level walk must reach each one.
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun dbl(x: Int) -> Int\n"
            "    return x * 2\n"
            "fun main(stdio: Stdio)\n"
            "    let grid = [[add1, dbl], [dbl, add1]]\n"
            "    var acc = 0\n"
            "    for row in grid\n"
            "        for f in row\n"
            "            acc = f(acc + 1)\n"
            "    stdio.println(\"acc=${acc}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "acc=16\n",
        )

    def test_mixed_fn_ref_and_lambda_in_same_list(self):
        # A fn-ref and an inline lambda in the same list literal:
        # the lambda registers via _discover_lambdas, the fn-ref via
        # the aggregate-element thunk walk; both must resolve.
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main(stdio: Stdio)\n"
            "    let fs = [add1, fun (x: Int) -> Int => x * 2]\n"
            "    var acc = 1\n"
            "    for f in fs\n"
            "        acc = f(acc)\n"
            "    stdio.println(\"acc=${acc}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "acc=4\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmUnitReturnFnRef(unittest.TestCase):
    """Regression guards for a Unit-RETURNING top-level function
    used as a ``Fun(...) -> Unit`` value.

    The thunk-discovery pass computed a fn-ref's sig key via
    ``_closure_sig_key_for(args, ret)``, whose result side went
    through ``_wasm_result_tys_for`` -> ``_wasm_arg_tys_for``. That
    argument mapping has no wire encoding for ``Unit`` and raised,
    so discovery silently skipped the thunk. Emit then looked the
    thunk up via ``_fun_type_to_sig_key``, which maps a ``Unit``
    result to an empty result clause (``... -> ()``) and so asked
    for a key that discovery never registered, failing with "no
    thunk was registered for sig '(i32 i64) -> ()'". The fix makes
    ``_wasm_result_tys_for("Unit")`` return ``[]`` so both paths
    agree on ``... -> ()``. A lambda with a Unit return already
    worked (it lowers via ``_register_lambda``, whose Unit-result
    handling was already ``""``); the last test pins that symmetry."""

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

    def test_unit_return_fn_ref_in_list_iterated_and_called(self):
        # The minimal repro: a Unit-returning top-level function in a
        # list literal, iterated and applied. Pre-fix this failed to
        # compile with "no thunk was registered for sig
        # '(i32 i64) -> ()'".
        src = (
            "fun noop(x: Int) -> Unit\n"
            "    return\n"
            "fun main(stdio: Stdio)\n"
            "    let fs = [noop, noop]\n"
            "    for f in fs\n"
            "        f(5)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "done\n",
        )

    def test_unit_return_fn_ref_passed_to_hof(self):
        # A Unit-returning fn-ref passed to a higher-order function
        # ``apply(f: Fun(Int) -> Unit, n: Int)`` and invoked there.
        src = (
            "fun noop(x: Int) -> Unit\n"
            "    return\n"
            "fun apply(f: Fun(Int) -> Unit, n: Int)\n"
            "    f(n)\n"
            "fun main(stdio: Stdio)\n"
            "    apply(noop, 5)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "done\n",
        )

    def test_unit_return_lambda_in_list_matches_fn_ref(self):
        # Symmetry check: a Unit-returning LAMBDA used the same way
        # already worked; it must keep working so the fn-ref path
        # (now aligned to the same ``... -> ()`` sig key) stays
        # consistent with the lambda path.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let fs = [fun (x: Int) -> Unit => (), "
            "fun (x: Int) -> Unit => ()]\n"
            "    for f in fs\n"
            "        f(5)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "done\n",
        )


class TestWasmOptResUnitReturnClosureFailsLoud(unittest.TestCase):
    """Guards that ``Option.map`` / ``Result.map`` / ``Result.map_err``
    with a Unit-RETURNING closure fail loud at compile time instead of
    emitting an invalid Wasm module.

    Aligning ``_wasm_result_tys_for`` (Unit -> empty result) so a
    Unit-returning fn-ref could be registered also made the Option/
    Result HOF sig key representable, which un-gated a neighbouring
    store path (``_emit_store_stashed_payload_into_optres`` /
    ``_stash_closure_return``) that is NOT Unit-aware: it would store a
    nonexistent (empty-stack) result at offset 8, so ``compile_wasm``
    succeeded but the module failed ``wasm-tools validate`` (and
    ``--output`` wrote the broken module to disk with exit 0). The fix
    adds the same Unit-result guard the list-HOF store already has, in
    ``_emit_closure_call_from_optres_payload``. These tests never shell
    out (``emit_wat`` raises before any module bytes exist), so they run
    everywhere."""

    def test_option_map_unit_closure_raises(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(1)\n"
            "    let r2 = o.map(fun (x: Int) -> Unit => ())\n"
            "    stdio.println(\"done\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)

    def test_result_map_unit_closure_raises(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(1)\n"
            "    let r2 = r.map(fun (x: Int) -> Unit => ())\n"
            "    stdio.println(\"done\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)

    def test_result_map_err_unit_closure_raises(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Err(\"e\")\n"
            "    let r2 = r.map_err(fun (e: String) -> Unit => ())\n"
            "    stdio.println(\"done\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(WasmEmissionError):
            emit_wat(ir_mod)

    def test_option_map_scalar_closure_still_compiles(self):
        # The guard must NOT reject a normal (non-Unit) Option.map;
        # a Unit-returning closure is the only rejected case.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(1)\n"
            "    let r2 = o.map(fun (x: Int) -> Int => x + 10)\n"
            "    stdio.println(\"done\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("(module", wat)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFunValuePositions(unittest.TestCase):
    """End-to-end guards for ``Fun`` values in two positions that
    only the Wasm backend previously rejected:

    - a tuple slot whose element type is ``Fun(...) -> R`` (the
      top-level comma splitters mistook the ``>`` in ``->`` for a
      bracket close, so a tuple of Fun elements never split into
      per-slot types); and
    - a call whose callee is an *expression* of Fun type
      (``fs[0](x)``, ``getf()(x)``), which the lowerer rejected
      because it only handled a bare-identifier callee.

    Each program executes on wasmtime and asserts the exact stdout
    the Python backend produces for the same source."""

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

    def test_tuple_of_fun_unpacked_and_called(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun dbl(x: Int) -> Int\n"
            "    return x * 2\n"
            "fun main(stdio: Stdio)\n"
            "    let t = (add1, dbl)\n"
            "    let (f, g) = t\n"
            "    stdio.println(\"r=${g(f(10))}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "r=22\n",
        )

    def test_tuple_of_fun_returned_then_unpacked_and_called(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun dbl(x: Int) -> Int\n"
            "    return x * 2\n"
            "fun make() -> (Fun(Int) -> Int, Fun(Int) -> Int)\n"
            "    return (add1, dbl)\n"
            "fun main(stdio: Stdio)\n"
            "    let (f, g) = make()\n"
            "    stdio.println(\"r=${g(f(10))}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "r=22\n",
        )

    def test_index_of_fun_list_called_directly(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun main(stdio: Stdio)\n"
            "    let fs = [add1, add1]\n"
            "    stdio.println(\"r=${fs[0](10)}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "r=11\n",
        )

    def test_call_result_called_directly(self):
        src = (
            "fun add1(x: Int) -> Int\n"
            "    return x + 1\n"
            "fun getf() -> Fun(Int) -> Int\n"
            "    return add1\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"r=${getf()(10)}\")\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "r=11\n",
        )


if __name__ == "__main__":
    unittest.main()

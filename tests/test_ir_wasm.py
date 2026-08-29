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


if __name__ == "__main__":
    unittest.main()

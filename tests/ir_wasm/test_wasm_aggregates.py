# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this module passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union. We know the
# relevant export is a Func because the WAT we emit always declares it
# as one; silencing ``reportCallIssue`` for the whole module is the
# smallest fix that does not bury the test code in per-line type-ignore
# noise. Real "not callable" errors are still caught at runtime by
# ``python -m unittest``.
"""WebAssembly backend: aggregates (sums / structs, Option / Result,
struct-to-string, structural equality, and aggregate-slot / fn-ref-
slot typing).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention (the aggregate-slot facet is the named seam
toward a future test_wasm_aggregate_slots.py). The shared _parse_lower
/ skip gates live in tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa import Lexer, Parser, analyze
from capa.ir import compile_wasm


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

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
"""WebAssembly backend: pattern binding and match emission (nested
tuple / struct sub-patterns, tuple-pointer element access, and the
match-arm / guard emitters).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention (the match-arm facet is the named seam toward a
future test_wasm_match_arms.py). The shared _parse_lower / skip gates
live in tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm, WasmEmissionError


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

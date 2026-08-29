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
"""WebAssembly backend: closures and Fun values (capture, HOFs, nested
closures, non-Int HOFs, Fun-valued maps, and Fun-value call
positions).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import emit_wat, compile_wasm, WasmEmissionError


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

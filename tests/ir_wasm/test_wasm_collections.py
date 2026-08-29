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
"""WebAssembly backend: collections (List / Map / Set).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm


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

"""Analyzer tests: List/Map/Set builtin methods, collection helpers, and map-key type
restrictions.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


class TestListBuiltinMethods(unittest.TestCase):
    """List<T> has builtin methods: length, push, contains, map, filter,
    fold. Types are checked with substitution of T by the receiver's
    arg."""

    def test_length(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = [1, 2, 3].length()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_contains_with_correct_type(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let has = xs.contains(2)\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_contains_with_wrong_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let has = xs.contains(\"oops\")\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_map_changes_element_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let s = xs.map(fun (x: Int) -> String => \"x\")\n"
            "    stdio.println(\"${s.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        # s should have type List<String>
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "List<String>")

    def test_filter_predicate_must_return_bool(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs.filter(fun (x: Int) -> Int => x)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects fun(Int) -> Bool" in m for m in msgs)
        )

    def test_fold_with_different_acc_type(self):
        # fold may accumulate into a type different from the element.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let s = xs.fold(\"\", fun (acc: String, x: Int) -> String => acc)\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")


class TestMapBuiltinMethods(unittest.TestCase):
    """Map<K, V> has methods: length, get, set, contains_key, keys, values."""

    def test_basic_map_usage(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    let v = m.get(\"a\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_get_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let v = m.get(\"a\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_v = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_v.value)]), "Option<Int>")

    def test_set_wrong_value_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", \"oops\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_get_wrong_key_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let _v = m.get(42)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_keys_returns_list_of_keys(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let ks = m.keys()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_ks = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_ks.value)]), "List<String>")


class TestSetBuiltinMethods(unittest.TestCase):
    """Set<T> has methods: length, add, remove, contains, to_list,
    plus the algebra union / intersection / difference / is_subset."""

    def test_basic_set_usage(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    s.add(2)\n"
            "    let has = s.contains(1)\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_add_wrong_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(\"oops\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_algebra_returns_set_and_bool(self):
        # union / intersection / difference yield a Set<Int> (so
        # chaining a Set method on the result type-checks); is_subset
        # yields a Bool.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let a: Set<Int> = new_set()\n"
            "    let b: Set<Int> = new_set()\n"
            "    let u = a.union(b)\n"
            "    let n = u.length()\n"
            "    let i = a.intersection(b)\n"
            "    let d = a.difference(b)\n"
            "    let sub = a.is_subset(b)\n"
            "    let chained = a.union(b).intersection(a)\n"
            "    stdio.println(\"${n} ${sub}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_union_wrong_element_type_rejected(self):
        # The argument must be a Set<T> with the SAME element type.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let a: Set<Int> = new_set()\n"
            "    let b: Set<String> = new_set()\n"
            "    let u = a.union(b)\n"
        )
        self.assertTrue(msgs, "expected a type error for mismatched element types")


class TestCollectionHelpers(unittest.TestCase):
    """is_empty/first/last/get on List, is_empty on String/Map/Set."""

    def test_list_first_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let f = xs.first()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_f = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_f.value)]),
            "Option<Int>",
        )

    def test_list_get_returns_option(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"a\", \"b\", \"c\"]\n"
            "    match xs.get(0)\n"
            "        Some(s) -> stdio.println(s)\n"
            "        None -> stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_string_is_empty(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    if s.is_empty()\n"
            "        stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_empty_list_with_annotation(self):
        # `let xs: List<Int> = []` should compile.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = []\n"
            "    if xs.is_empty()\n"
            "        stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestMapKeyTypeRestrictions(unittest.TestCase):
    """Audit M4 (2026-05): the Wasm backend supports String / Int /
    Bool plus pointer-shape (struct / sum / tuple) Map keys. The
    analyzer rejects unsupported key types at the type-expression
    resolution site (declaration time) so the user sees the error
    at ``let m: Map<Float, ...>`` rather than at first method call.
    See ``_reject_unsupported_map_key`` in
    ``capa/analyzer/_declarations.py``."""

    def test_map_string_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_int_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<Int, Int> = new_map()\n"
            "    m.set(1, 2)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_bool_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<Bool, Int> = new_map()\n"
            "    m.set(true, 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_float_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Float, Int> = new_map()\n"
        )
        self.assertTrue(
            any("Float" in m and "Map keys" in m and "NaN" in m for m in msgs),
            msgs,
        )

    def test_map_list_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<List<Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_map_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Map<Int, Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_set_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Set<Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_struct_key_accepted(self):
        # Struct keys are accepted: the per-key dispatch reuses the
        # slice-3 ``$eq_<TypeName>`` helper, and H2 freezes Point so
        # ``p.x = 5`` is rejected wherever Point appears as a Map key.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun main()\n"
            "    let m: Map<Point, Int> = new_map()\n"
            "    m.set(Point{x: 1, y: 2}, 42)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_sum_key_accepted(self):
        # User sum keys are accepted alongside Option / Result. The
        # per-key dispatch reuses ``$eq_<SumName>``.
        r = check(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun main()\n"
            "    let m: Map<Color, Int> = new_map()\n"
            "    m.set(Red, 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_tuple_key_accepted(self):
        # Tuple keys are accepted; tuples are immutable from Capa
        # source so no extension to H2 is needed.
        r = check(
            "fun main()\n"
            "    let m: Map<(Int, Int), Int> = new_map()\n"
            "    m.set((1, 2), 3)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_function_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Fun(Int) -> Int, Int> = new_map()\n"
        )
        self.assertTrue(
            any("function types" in m for m in msgs), msgs,
        )

    def test_map_float_key_in_function_param_rejected(self):
        # The check fires regardless of where the Map<K, V> type
        # expression lives; function parameter type counts too.
        msgs = errors_of(
            "fun take(m: Map<Float, Int>)\n"
            "    return\n"
        )
        self.assertTrue(
            any("Float" in m and "NaN" in m for m in msgs), msgs,
        )

    def test_map_struct_key_in_return_type_accepted(self):
        # Struct keys are accepted wherever a Map<K, V> type
        # expression appears, including in function return types.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun make() -> Map<Point, Int>\n"
            "    return new_map()\n"
        )
        self.assertTrue(r.ok, r.errors)


if __name__ == "__main__":
    unittest.main()

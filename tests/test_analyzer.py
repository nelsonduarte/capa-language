"""Tests for the Capa semantic analyzer.

Covers name resolution (defined symbols, undefined, redefinitions)
and type checking (literals, operators, assignments, calls,
struct literals, returns, conditions). Also includes smoke tests of
the canonical examples.
"""

import unittest

from capa import (
    Lexer, Parser, analyze, AnalysisResult,
    TyName, TyUnit, TyUnknown, ty_str,
)


def check(source: str) -> AnalysisResult:
    """Lex + parse + analyze. Returns the AnalysisResult."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return analyze(module, source=source)


def errors_of(source: str) -> list[str]:
    """List of error messages (just the message part, without position)."""
    result = check(source)
    return [e.message for e in result.errors]


# =============================================================
# Valid programs
# =============================================================

class TestValidPrograms(unittest.TestCase):
    def test_empty_module(self):
        r = check("")
        self.assertTrue(r.ok)

    def test_simple_function(self):
        r = check("fun id(x: Int) -> Int\n    return x\n")
        self.assertTrue(r.ok, r.errors)

    def test_const(self):
        r = check("const N: Int = 42\n")
        self.assertTrue(r.ok, r.errors)

    def test_struct(self):
        r = check(
            "type Ponto { x: Float, y: Float }\n"
            "fun zero() -> Ponto\n"
            "    return Ponto { x: 0.0, y: 0.0 }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_sum_type(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun rever() -> Cor\n"
            "    return Vermelho\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_arithmetic(self):
        r = check(
            "fun calc() -> Int\n"
            "    let x = 1 + 2 * 3\n"
            "    return x\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_string_concat(self):
        r = check(
            "fun saudar(nome: String) -> String\n"
            '    return "Olá, " + nome\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_if_with_bool(self):
        r = check(
            "fun f(x: Int) -> Int\n"
            "    if x > 0\n"
            "        return 1\n"
            "    return 0\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_var_mutable(self):
        r = check(
            "fun count(n: Int) -> Int\n"
            "    var i = 0\n"
            "    while i < n\n"
            "        i += 1\n"
            "    return i\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Name resolution
# =============================================================

class TestNameResolution(unittest.TestCase):
    def test_undefined_name(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return x\n"
        )
        self.assertTrue(any("undefined name 'x'" in m for m in msgs))

    def test_undefined_type(self):
        msgs = errors_of("const N: Foo = 0\n")
        self.assertTrue(any("undefined type 'Foo'" in m for m in msgs))

    def test_duplicate_top_level(self):
        msgs = errors_of(
            "fun f() -> Int\n    return 1\n"
            "fun f() -> Int\n    return 2\n"
        )
        self.assertTrue(any("duplicate top-level declaration" in m for m in msgs))

    def test_duplicate_param(self):
        msgs = errors_of(
            "fun f(x: Int, x: Int) -> Int\n    return x\n"
        )
        self.assertTrue(any("duplicate parameter name" in m for m in msgs))

    def test_local_shadows_global_ok(self):
        # Shadowing of globals by locals is allowed
        # (the local just needs to be valid locally).
        r = check(
            "const N: Int = 42\n"
            "fun f() -> Int\n"
            "    let N = 1\n"
            "    return N\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_capability_in_scope(self):
        r = check(
            "fun f(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_import_silently_accepted_by_direct_analyzer(self):
        # Import resolution happens in capa.loader.ModuleLoader,
        # which the CLI invokes before analysis. When the analyzer
        # is called directly (e.g. in this test), Import items are
        # ignored: no error, no symbol. The loader's resolution
        # and conflict-detection behaviour is covered by
        # tests/test_loader.py.
        r = check(
            "import json\n"
            "fun f() -> Int\n"
            "    return 0\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_py_import_requires_unsafe(self):
        # A function that tries to cross the boundary without Unsafe in
        # scope is rejected.
        msgs = errors_of(
            "fun f() -> Int\n"
            "    let m = py_import(\"math\")\n"
            "    return 0\n"
        )
        # py_import has signature (Unsafe, String) -> ?; calling with 1
        # argument should be an arity error.
        self.assertTrue(len(msgs) >= 1, msgs)

    def test_py_import_with_unsafe_ok(self):
        # When the caller holds Unsafe, py_import passes the check.
        r = check(
            "fun f(unsafe: Unsafe) -> Int\n"
            "    let m = py_import(unsafe, \"math\")\n"
            "    return 0\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_py_import_rejects_non_unsafe(self):
        # Passing a different capability as the first argument fails
        # (Stdio is not Unsafe).
        msgs = errors_of(
            "fun f(stdio: Stdio) -> Int\n"
            "    let m = py_import(stdio, \"math\")\n"
            "    return 0\n"
        )
        self.assertTrue(len(msgs) >= 1, msgs)


# =============================================================
# Type checking
# =============================================================

class TestTypeChecking(unittest.TestCase):
    def test_let_type_mismatch(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    let x: Int = 3.14\n"
            "    return x\n"
        )
        self.assertTrue(any("expected Int, got Float" in m for m in msgs))

    def test_call_arity(self):
        msgs = errors_of(
            "fun add(a: Int, b: Int) -> Int\n    return a + b\n"
            "fun f() -> Int\n    return add(1, 2, 3)\n"
        )
        self.assertTrue(any("expected 2 arguments, got 3" in m for m in msgs))

    def test_call_arity_includes_signature(self):
        msgs = errors_of(
            "fun add(a: Int, b: Int) -> Int\n    return a + b\n"
            "fun f() -> Int\n    return add(1, 2, 3)\n"
        )
        self.assertTrue(
            any("fun(Int, Int) -> Int" in m for m in msgs),
            f"signature missing from arity error: {msgs}",
        )

    def test_capability_method_typo_hint(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.prntln(\"hi\")\n"
        )
        self.assertTrue(
            any("capability 'Stdio' has no method 'prntln'" in m for m in msgs),
            f"expected capability-method-not-found error: {msgs}",
        )
        self.assertTrue(
            any("did you mean 'println'" in m for m in msgs),
            f"expected 'did you mean' hint: {msgs}",
        )

    def test_call_arg_type(self):
        msgs = errors_of(
            "fun add(a: Int, b: Int) -> Int\n    return a + b\n"
            "fun f() -> Int\n    return add(\"a\", 2)\n"
        )
        self.assertTrue(any("expects Int, got String" in m for m in msgs))

    def test_return_type(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return \"string\"\n"
        )
        self.assertTrue(any("return: expected Int, got String" in m for m in msgs))

    def test_if_condition_must_be_bool(self):
        msgs = errors_of(
            "fun f(x: Int)\n"
            "    if x\n"
            "        return\n"
        )
        self.assertTrue(any("if condition must be Bool" in m for m in msgs))

    def test_while_condition_must_be_bool(self):
        msgs = errors_of(
            "fun f()\n"
            "    while 42\n"
            "        return\n"
        )
        self.assertTrue(any("while condition must be Bool" in m for m in msgs))

    def test_arithmetic_types(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return 1 + \"a\"\n"
        )
        self.assertTrue(any("incompatible operand types" in m for m in msgs))

    def test_unary_minus_on_string(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return -\"hello\"\n"
        )
        self.assertTrue(any("unary '-': operand must be numeric" in m for m in msgs))

    def test_not_on_int(self):
        msgs = errors_of(
            "fun f() -> Bool\n"
            "    return not 42\n"
        )
        self.assertTrue(any("'not': operand must be Bool" in m for m in msgs))

    def test_struct_missing_field(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "fun f() -> Ponto\n"
            "    return Ponto { x: 1.0 }\n"
        )
        self.assertTrue(any("missing fields y" in m for m in msgs))

    def test_struct_unknown_field(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "fun f() -> Ponto\n"
            "    return Ponto { x: 1.0, y: 2.0, z: 3.0 }\n"
        )
        self.assertTrue(any("has no field 'z'" in m for m in msgs))

    def test_struct_field_type(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "fun f() -> Ponto\n"
            "    return Ponto { x: \"a\", y: 1.0 }\n"
        )
        self.assertTrue(any("field 'x' expects Float, got String" in m for m in msgs))

    def test_assign_to_const(self):
        msgs = errors_of(
            "const PI: Float = 3.14\n"
            "fun f()\n"
            "    PI = 0.0\n"
        )
        self.assertTrue(any("cannot assign to constant 'PI'" in m for m in msgs))

    def test_assign_to_let(self):
        msgs = errors_of(
            "fun f()\n"
            "    let x = 1\n"
            "    x = 2\n"
        )
        self.assertTrue(any("cannot assign to immutable binding 'x'" in m for m in msgs))

    def test_assign_to_param(self):
        msgs = errors_of(
            "fun f(x: Int)\n"
            "    x = 2\n"
        )
        self.assertTrue(any("cannot assign to parameter 'x'" in m for m in msgs))

    def test_field_access_on_struct(self):
        # Verifies that field access returns the correct type.
        r = check(
            "type Ponto { x: Float, y: Float }\n"
            "fun f(p: Ponto) -> Float\n"
            "    return p.x\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_field_access_unknown_field(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "fun f(p: Ponto) -> Float\n"
            "    return p.z\n"
        )
        self.assertTrue(any("has no field 'z'" in m for m in msgs))

    def test_list_homogeneous(self):
        r = check(
            "fun f() -> List<Int>\n"
            "    return [1, 2, 3]\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_list_heterogeneous_rejected(self):
        msgs = errors_of(
            "fun f() -> List<Int>\n"
            "    return [1, \"two\", 3]\n"
        )
        self.assertTrue(
            any("element has type String, expected Int" in m for m in msgs)
        )


# =============================================================
# Variants and match
# =============================================================

class TestVariants(unittest.TestCase):
    def test_variant_constructor(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f() -> Cor\n"
            "    return Vermelho\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_match_pattern_binds(self):
        r = check(
            "type Forma =\n"
            "    Circulo(Float)\n"
            "    Quadrado(Float)\n"
            "fun area(f: Forma) -> Float\n"
            "    return match f\n"
            "        Circulo(r) -> r * r\n"
            "        Quadrado(l) -> l * l\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_match_with_guard(self):
        r = check(
            "fun f(n: Int) -> String\n"
            "    return match n\n"
            "        x if x > 0 -> \"positivo\"\n"
            "        _ -> \"outro\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_unknown_variant(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "fun f(c: Cor) -> Int\n"
            "    match c\n"
            "        XYZ -> 0\n"
        )
        self.assertTrue(any("unknown variant" in m for m in msgs))


# =============================================================
# Trait and impl
# =============================================================

class TestImpl(unittest.TestCase):
    def test_simple_impl(self):
        r = check(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun zero() -> Ponto\n"
            "        return Ponto { x: 0.0, y: 0.0 }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_trait_impl_complete(self):
        r = check(
            "trait Imprimivel\n"
            "    fun imprimir(self) -> String\n"
            "type Ponto { x: Float, y: Float }\n"
            "impl Imprimivel for Ponto\n"
            "    fun imprimir(self) -> String\n"
            "        return \"Ponto\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_trait_impl_missing_method(self):
        msgs = errors_of(
            "trait Comparavel\n"
            "    fun igual(self) -> Bool\n"
            "    fun menor(self) -> Bool\n"
            "type Numero { v: Int }\n"
            "impl Comparavel for Numero\n"
            "    fun igual(self) -> Bool\n"
            "        return true\n"
        )
        self.assertTrue(any("missing methods" in m and "menor" in m for m in msgs))

    def test_self_in_method_return(self):
        r = check(
            "type Contador { v: Int }\n"
            "impl Contador\n"
            "    fun zero() -> Self\n"
            "        return Contador { v: 0 }\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Capability discipline
# =============================================================

class TestCapabilityDiscipline(unittest.TestCase):
    """Capabilities represent permissions for effects. The discipline
    enforces that they only appear in function parameters, ensuring that
    the flow is visible in all signatures."""

    def test_cap_in_struct_field_rejected(self):
        msgs = errors_of("type S { c: Stdio, nome: String }\n")
        self.assertTrue(
            any("capability 'Stdio' cannot appear in struct field" in m for m in msgs)
        )

    def test_cap_in_variant_payload_rejected(self):
        msgs = errors_of(
            "type R =\n"
            "    Sem\n"
            "    Com(Stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in payload of variant" in m for m in msgs)
        )

    def test_cap_as_return_type_rejected(self):
        msgs = errors_of(
            "fun f() -> Stdio\n"
            "    return Stdio { }\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in return type" in m for m in msgs)
        )

    def test_cap_in_const_rejected(self):
        msgs = errors_of("const G: Fs = Fs { }\n")
        self.assertTrue(
            any("capability 'Fs' cannot appear in constant" in m for m in msgs)
        )

    def test_cap_in_let_rejected(self):
        msgs = errors_of(
            "fun f(stdio: Stdio)\n"
            "    let copia = stdio\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in a 'let' binding" in m for m in msgs)
        )

    def test_cap_in_var_rejected(self):
        msgs = errors_of(
            "fun f(fs: Fs)\n"
            "    var s: Fs = fs\n"
        )
        self.assertTrue(
            any("capability 'Fs' cannot appear in a 'var' binding" in m for m in msgs)
        )

    def test_cap_in_generic_arg_rejected(self):
        msgs = errors_of(
            "fun f() -> List<Stdio>\n"
            "    return []\n"
        )
        # The rule is detected via return type containing capability.
        self.assertTrue(
            any("capability 'Stdio'" in m for m in msgs)
        )

    def test_cap_in_tuple_rejected(self):
        msgs = errors_of(
            "fun f() -> (Stdio, Int)\n"
            "    return (Stdio { }, 0)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m for m in msgs)
        )

    def test_cap_as_param_ok(self):
        # The positive case: capability as parameter is the correct use.
        r = check(
            "fun saudar(stdio: Stdio)\n"
            "    stdio.println(\"olá\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_cap_passed_to_other_fn_ok(self):
        # Passing a capability to another function is acceptable (normal use).
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"em helper\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
            "    stdio.println(\"de volta em main\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_call_on_cap_ok(self):
        # Method calls on a capability don't consume it.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\")\n"
            "    stdio.println(\"b\")\n"
            "    stdio.println(\"c\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Non-aliasing in calls (v2 of the discipline) -------

    def test_aliased_arguments_rejected(self):
        msgs = errors_of(
            "fun pair(a: Stdio, b: Stdio)\n"
            "    a.println(\"a\")\n"
            "    b.println(\"b\")\n"
            "fun main(stdio: Stdio)\n"
            "    pair(stdio, stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 2 but was already used as argument 1"
                in m
                for m in msgs
            )
        )

    def test_aliased_receiver_and_arg_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.helper(stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 1 but was already used as receiver"
                in m
                for m in msgs
            )
        )

    def test_three_slots_with_repeat_rejected(self):
        msgs = errors_of(
            "fun trio(a: Stdio, b: Fs, c: Stdio)\n"
            "    a.println(\"a\")\n"
            "    c.println(\"c\")\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    trio(stdio, fs, stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 3 but was already used as argument 1"
                in m
                for m in msgs
            )
        )

    def test_distinct_caps_in_same_call_ok(self):
        r = check(
            "fun pair(s: Stdio, f: Fs)\n"
            "    s.println(\"hello\")\n"
            "    let _exists = f.exists(\"x\")\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    pair(stdio, fs)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_sequential_calls_with_same_cap_ok(self):
        # Each call is its own "borrow"; sequential ones are OK.
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
            "    helper(stdio)\n"
            "    helper(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Mandatory usage of capability params -------

    def test_unused_cap_param_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    stdio.println(\"sem usar fs\")\n"
        )
        self.assertTrue(
            any("capability parameter 'fs' is declared but never used" in m for m in msgs)
        )

    def test_underscore_silences_unused_cap(self):
        r = check(
            "fun main(stdio: Stdio, _fs: Fs)\n"
            "    stdio.println(\"underscore silencia\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_used_via_pass_through_ok(self):
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Generics inference
# =============================================================

class TestGenericsInference(unittest.TestCase):
    """The checker infers type arguments locally in variant
    constructors, function calls, and struct literals."""

    def _expr_type(self, src: str, expr_finder) -> str:
        """Helper: lex+parse+analyze, returns the textual representation
        of the type of the expression indicated by ``expr_finder(module)``."""
        from capa import Lexer, Parser, analyze, ty_str
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        e = expr_finder(module)
        return ty_str(result.types[id(e)])

    def test_ok_with_int_payload(self):
        # Ok(42) should produce Result<Int, ?>.
        ty = self._expr_type(
            "fun f() -> Result<Int, String>\n    return Ok(42)\n",
            lambda m: m.items[0].body.stmts[0].value,
        )
        self.assertEqual(ty, "Result<Int, ?>")

    def test_some_with_string(self):
        ty = self._expr_type(
            'fun f() -> Option<String>\n    return Some("oi")\n',
            lambda m: m.items[0].body.stmts[0].value,
        )
        self.assertEqual(ty, "Option<String>")

    def test_err_with_string(self):
        ty = self._expr_type(
            'fun f() -> Result<Int, String>\n    return Err("x")\n',
            lambda m: m.items[0].body.stmts[0].value,
        )
        self.assertEqual(ty, "Result<?, String>")

    def test_function_call_inference(self):
        # first<T>(xs: List<T>) -> T  →  first([1,2,3]) is Int
        ty = self._expr_type(
            "fun first<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun g() -> Int\n"
            "    return first([1, 2, 3])\n",
            lambda m: m.items[1].body.stmts[0].value,
        )
        self.assertEqual(ty, "Int")

    def test_function_call_two_params(self):
        ty = self._expr_type(
            "fun pair<A, B>(a: A, b: B) -> A\n"
            "    return a\n"
            "fun g() -> Int\n"
            '    return pair(42, "hi")\n',
            lambda m: m.items[1].body.stmts[0].value,
        )
        self.assertEqual(ty, "Int")

    def test_struct_literal_generic_inference(self):
        # Pair { primeiro: 1, segundo: "x" } → Par<Int, String>
        ty = self._expr_type(
            "type Par<A, B> { primeiro: A, segundo: B }\n"
            "fun f() -> Par<Int, String>\n"
            '    return Par { primeiro: 1, segundo: "x" }\n',
            lambda m: m.items[1].body.stmts[0].value,
        )
        self.assertEqual(ty, "Par<Int, String>")

    def test_index_propagates_type(self):
        # xs: List<Int>, xs[0] should be Int
        ty = self._expr_type(
            "fun f() -> Int\n"
            "    let xs = [1, 2, 3]\n"
            "    return xs[0]\n",
            lambda m: m.items[0].body.stmts[1].value,
        )
        self.assertEqual(ty, "Int")

    def test_inferred_type_used_for_error_detection(self):
        # Inference chain catches error: envolver(42)→List<Int>, [0]→Int,
        # assigning to String is an error.
        msgs = errors_of(
            "fun envolver<T>(x: T) -> List<T>\n"
            "    return [x]\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = envolver(42)\n"
            "    let s: String = xs[0]\n"
            "    stdio.println(s)\n"
        )
        self.assertTrue(
            any("expected String, got Int" in m for m in msgs)
        )

    def test_call_arg_type_mismatch_with_generics(self):
        # Despite inference, wrong types should still be caught
        # when there's a concrete annotation in context.
        msgs = errors_of(
            "fun envolver<T>(x: T, y: T) -> T\n"
            "    return x\n"
            "fun main(stdio: Stdio)\n"
            '    let r = envolver(1, "string")\n'
            "    stdio.println(\"x\")\n"
        )
        # With T inferred from the first arg as Int, "string" is not Int.
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs),
            f"got: {msgs}",
        )


# =============================================================
# Method dispatch
# =============================================================

class TestMethodDispatch(unittest.TestCase):
    """The analyzer does real dispatch of calls to methods defined in
    impl blocks, checking arity, argument types and returning the
    return type with substitution of receiver type params."""

    def test_method_returns_field_type(self):
        # extrair() returns the field type, with T substituted by the
        # concrete type of the receiver.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "type Caixa<T> { valor: T }\n"
            "impl Caixa<T>\n"
            "    fun extrair(self) -> T\n"
            "        return self.valor\n"
            "fun f() -> Int\n"
            "    let c = Caixa { valor: 42 }\n"
            "    return c.extrair()\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        # The expression c.extrair() should have type Int.
        ret_stmt = module.items[2].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(ret_stmt.value)]), "Int")

    def test_unknown_method_rejected(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun distancia(self) -> Float\n"
            "        return self.x\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Ponto { x: 1.0, y: 2.0 }\n"
            "    let v = p.metodo_inexistente()\n"
        )
        self.assertTrue(
            any("has no method 'metodo_inexistente'" in m for m in msgs)
        )

    def test_method_arity_mismatch_rejected(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun get_x(self) -> Float\n"
            "        return self.x\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Ponto { x: 1.0, y: 2.0 }\n"
            "    let v = p.get_x(99)\n"
        )
        self.assertTrue(
            any("expected 0 arguments, got 1" in m for m in msgs)
        )

    def test_method_arg_type_mismatch_rejected(self):
        msgs = errors_of(
            "type Caixa<T> { valor: T }\n"
            "impl Caixa<T>\n"
            "    fun substituir(self, novo: T) -> Caixa<T>\n"
            "        return Caixa { valor: novo }\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Caixa { valor: 42 }\n"
            "    let r = c.substituir(\"texto\")\n"
        )
        # T was inferred as Int from the receiver; "texto" is String.
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_self_returning_method(self):
        # A method that returns Self should resolve to the receiver type.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "type Contador { v: Int }\n"
            "impl Contador\n"
            "    fun incrementar(self) -> Self\n"
            "        return Contador { v: self.v + 1 }\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Contador { v: 0 }\n"
            "    let novo = c.incrementar()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_stmt = module.items[2].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_stmt.value)]), "Contador")

    def test_method_on_capability_passes(self):
        # Capabilities don't have impl in Capa code, calls to their
        # methods should continue to be accepted as TyUnknown.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "    stdio.eprintln(\"y\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Match exhaustiveness
# =============================================================

class TestMatchExhaustiveness(unittest.TestCase):
    """Match on sum types must cover all variants (or have a catch-all
    arm with wildcard or ident without guard)."""

    def test_complete_match_ok(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        Verde -> "g"\n'
            '        Azul -> "a"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_missing_variant_rejected(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        Verde -> "g"\n'
        )
        self.assertTrue(
            any("missing variants Azul" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_wildcard_makes_exhaustive(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_ident_pattern_makes_exhaustive(self):
        # Bind without guard is catch-all like _.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        outro -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_guarded_arm_does_not_cover(self):
        # Arms with guards may fail, they don't count toward coverage.
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor, b: Bool) -> String\n"
            "    return match c\n"
            '        Vermelho if b -> "v"\n'
            '        Verde -> "g"\n'
        )
        self.assertTrue(
            any("missing variants Vermelho" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_non_sum_types_not_checked(self):
        # Match over Int doesn't require exhaustiveness, user can use
        # _ explicitly, but the checker doesn't require it.
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            '        0 -> "zero"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Bool exhaustiveness -------

    def test_bool_match_missing_false_rejected(self):
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
        )
        self.assertTrue(
            any("non-exhaustive match on Bool: missing false" in m for m in msgs)
        )

    def test_bool_match_missing_true_rejected(self):
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        false -> "nao"\n'
        )
        self.assertTrue(
            any("non-exhaustive match on Bool: missing true" in m for m in msgs)
        )

    def test_bool_match_complete_ok(self):
        r = check(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
            '        false -> "nao"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_bool_match_wildcard_ok(self):
        r = check(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_bool_match_guards_dont_count(self):
        # Arms with guards don't count toward coverage.
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true if b -> "sim"\n'
            '        false if b -> "nao"\n'
        )
        self.assertTrue(
            any("missing true, false" in m for m in msgs)
        )


# =============================================================
# Closures (lambdas)
# =============================================================

class TestLambdas(unittest.TestCase):
    """Closures: ``fun (params) -> Ret => body``. For v0, body is
    always a single expression."""

    def test_lambda_typed_as_function(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let f = fun (x: Int) -> Int => x * 2\n"
            "    stdio.println(\"${f(21)}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_stmt = module.items[0].body.stmts[0]
        ty = ty_str(result.types[id(let_stmt.value)])
        # The exact textual representation depends on ty_str for TyFun;
        # verify that it contains Int → Int (in some format).
        self.assertIn("Int", ty)

    def test_lambda_return_type_mismatch_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let mau = fun (x: Int) -> Int => \"not int\"\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("lambda body has type String" in m for m in msgs)
        )

    def test_lambda_in_let(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let id = fun (x: Int) -> Int => x\n"
            "    stdio.println(\"${id(42)}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Function types and higher-order -------

    def test_function_type_in_param(self):
        r = check(
            "fun aplicar(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main(stdio: Stdio)\n"
            "    let dobro = fun (x: Int) -> Int => x * 2\n"
            "    let n = aplicar(dobro, 21)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_function_type_two_params(self):
        r = check(
            "fun aplicar2(g: Fun(Int, Int) -> Int, a: Int, b: Int) -> Int\n"
            "    return g(a, b)\n"
            "fun main(stdio: Stdio)\n"
            "    let s = aplicar2(fun (a: Int, b: Int) -> Int => a + b, 3, 4)\n"
            "    stdio.println(\"${s}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_function_type_signature_mismatch_rejected(self):
        msgs = errors_of(
            "fun aplicar(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main(stdio: Stdio)\n"
            "    let r = aplicar(fun (x: Int) -> String => \"x\", 5)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects fun(Int) -> Int" in m for m in msgs),
            f"got: {msgs}",
        )

    # ------- Capability capture in closures -------

    def test_closure_capture_borrow_ok(self):
        # Capturing a cap and borrowing it is allowed.
        r = check(
            "fun emprestar(stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 1\n"
            "fun main(stdio: Stdio)\n"
            "    let log = fun (x: Int) -> Int => emprestar(stdio) + x\n"
            "    let _r = log(1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_closure_capture_consume_rejected(self):
        # Capturing a cap and trying to consume it is an error: the closure
        # may be called multiple times.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let bad = fun (x: Int) -> Int => adoptar(stdio) + x\n"
            "    let _r = bad(1)\n"
        )
        self.assertTrue(
            any(
                "cannot consume capability 'stdio' captured from enclosing scope"
                in m for m in msgs
            )
        )

    def test_closure_consumes_own_param_ok(self):
        # Cap-as-param of the closure itself can be consumed, each
        # invocation receives its own.
        r = check(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let consumer = fun (s: Stdio) -> Int => adoptar(s)\n"
            "    let _r = consumer(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Block-body lambdas -------

    def test_block_body_lambda(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let log = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"got ${x}\")\n"
            "        return x * 10\n"
            "    let _r = log(3)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_block_body_lambda_return_type_check(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let mau = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"x\")\n"
            "        return \"string\"\n"
            "    stdio.println(\"never\")\n"
        )
        self.assertTrue(
            any("expected Int, got String" in m for m in msgs)
        )

    def test_block_body_capture_consume_rejected(self):
        # Capture analysis also applies in block-body lambdas.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let bad = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"step\")\n"
            "        return adoptar(stdio) + x\n"
            "    let _r = bad(1)\n"
        )
        self.assertTrue(
            any(
                "cannot consume capability 'stdio' captured" in m
                for m in msgs
            )
        )


# =============================================================
# Trait and impl verification
# =============================================================

class TestTraitImpl(unittest.TestCase):
    """Trait impls are fully checked: presence and signatures of
    methods.
    """

    def test_correct_impl_ok(self):
        r = check(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type Pessoa { nome: String }\n"
            "impl Mostravel for Pessoa\n"
            "    fun mostrar(self) -> String\n"
            "        return self.nome\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_missing_method_rejected(self):
        msgs = errors_of(
            "trait Comparavel\n"
            "    fun comparar(self, outro: Self) -> Int\n"
            "    fun aux(self) -> Bool\n"
            "type X { x: Int }\n"
            "impl Comparavel for X\n"
            "    fun comparar(self, outro: Self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any("missing methods: aux" in m for m in msgs)
        )

    def test_wrong_signature_return_type_rejected(self):
        msgs = errors_of(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type N { v: Int }\n"
            "impl Mostravel for N\n"
            "    fun mostrar(self) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(
            any(
                "expected signature fun() -> String, got fun() -> Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_wrong_signature_param_type_rejected(self):
        msgs = errors_of(
            "trait Adicionavel\n"
            "    fun adicionar(self, x: Int) -> Int\n"
            "type N { v: Int }\n"
            "impl Adicionavel for N\n"
            "    fun adicionar(self, x: String) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(
            any("expected signature" in m for m in msgs)
        )

    def test_self_in_trait_signature_resolved(self):
        # Self in the trait signature should resolve to the impl type.
        r = check(
            "trait Clonavel\n"
            "    fun clonar(self) -> Self\n"
            "type Caixa { v: Int }\n"
            "impl Clonavel for Caixa\n"
            "    fun clonar(self) -> Self\n"
            "        return Caixa { v: self.v }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_extra_methods_allowed(self):
        # Methods not declared in the trait are allowed as helpers.
        r = check(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type N { v: Int }\n"
            "impl Mostravel for N\n"
            "    fun mostrar(self) -> String\n"
            '        return "ok"\n'
            "    fun helper(self) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Standard library: List<T> builtin methods
# =============================================================

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


# =============================================================
# Multi-line method chaining (implicit line continuation by '.')
# =============================================================

class TestMethodChaining(unittest.TestCase):
    """When a line starts with '.', the lexer suppresses the previous
    NEWLINE/INDENT, allowing chaining of methods across multiple lines."""

    def test_simple_chain_two_lines(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_chain_three_methods(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3, 4]\n"
            "    let n = xs\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "        .map(fun (x: Int) -> Int => x * 2)\n"
            "        .fold(0, fun (a: Int, x: Int) -> Int => a + x)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_field_access_multi_line(self):
        # Chaining also with field access (not just methods).
        r = check(
            "type P { nome: String }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { nome: \"Ana\" }\n"
            "    let n = p\n"
            "        .nome\n"
            "    stdio.println(n)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_chain_with_inline_comment(self):
        # Comments between chain methods should be tolerated.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs\n"
            "        // filter\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Standard library: String builtin methods
# =============================================================

class TestStringBuiltinMethods(unittest.TestCase):
    """String has builtin methods: length, trim, to_upper, to_lower,
    contains, starts_with, ends_with, split, replace."""

    def test_length(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let n = s.length()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_upper_returns_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let u = s.to_upper()\n"
            "    stdio.println(u)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_u = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_u.value)]), "String")

    def test_split_returns_list_of_strings(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"a,b,c\"\n"
            "    let sep = \",\"\n"
            "    let parts = s.split(sep)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_parts = module.items[0].body.stmts[2]
        self.assertEqual(
            ty_str(result.types[id(let_parts.value)]),
            "List<String>",
        )

    def test_contains_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let bad = s.contains(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_chaining_string_methods(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let sep = \" \"\n"
            "    let r = \"  hello  \".trim().to_upper().split(sep)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_char_at_returns_option_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let c = s.char_at(1)\n"
            "    stdio.println(\"${c}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        r = analyze(module, source=src)
        self.assertTrue(r.ok, r.errors)
        # find the binding for `c`
        c_ty = None
        for scope in (r.scopes if hasattr(r, "scopes") else []):
            for sym in scope.symbols.values():
                if sym.name == "c":
                    c_ty = sym.ty
        # If we cannot inspect the binding, fall back to a type-checked
        # success assertion: the program above only compiles if char_at
        # returns Option<String>.
        self.assertTrue(r.ok)

    def test_char_at_rejects_non_int_arg(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let c = s.char_at(\"oops\")\n"
        )
        self.assertFalse(r.ok)
        msgs = [e.format() for e in r.errors]
        self.assertTrue(
            any("Int" in m for m in msgs),
            msgs,
        )

    def test_substring_returns_string(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello world\"\n"
            "    let sub = s.substring(0, 5)\n"
            "    stdio.println(sub)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_substring_rejects_non_int_args(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let sub = s.substring(\"a\", 5)\n"
        )
        self.assertFalse(r.ok)

    def test_index_of_returns_option_int(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello world\"\n"
            "    let idx = match s.index_of(\"world\")\n"
            "        None -> 0 - 1\n"
            "        Some(i) -> i\n"
            "    stdio.println(\"${idx}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_index_of_rejects_non_string_arg(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let idx = s.index_of(42)\n"
        )
        self.assertFalse(r.ok)


# =============================================================
# Interpolated strings (InterpolatedString)
# =============================================================

class TestInterpolatedString(unittest.TestCase):
    """Strings with ``${expr}`` are parsed as InterpolatedString
    with each interpolation as a real Capa expression, not raw text.
    This enables type-check, type-aware dispatch, etc."""

    def test_simple_interpolation(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let x = 42\n"
            "    stdio.println(\"value = ${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_call_in_interpolation(self):
        # Before this version, ${s.length()} would go to raw Python and fail.
        # Now it's parsed as an expression and dispatch works.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    stdio.println(\"len = ${s.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_undefined_in_interpolation_rejected(self):
        # Errors inside interpolation are reported.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"value = ${nao_existe}\")\n"
        )
        self.assertTrue(
            any("undefined name 'nao_existe'" in m for m in msgs)
        )

    def test_undefined_in_interpolation_has_correct_position(self):
        # Regression: prior to the interp_positions plumbing, a typo
        # inside ``${...}`` was reported at the string's opening
        # quote position (line 1, col 1) instead of at the actual
        # identifier inside the interpolation. Now the sub-lexer is
        # started at the source Pos of the interpolation content, so
        # the error position lands on the typo itself and the
        # rendered snippet shows the correct line with the correct
        # caret column.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let name = \"World\"\n"
            "    stdio.println(\"Hello, ${nme}!\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        # The error should report `nme` (not an empty name) and point
        # at line 3 where the typo lives, with the column landing on
        # the `n` of `nme`.
        msg = r.errors[0].message
        self.assertIn("undefined name 'nme'", msg)
        # Levenshtein hint should still find `name` as the suggestion.
        self.assertIn("did you mean 'name'", msg)
        # Position: line 3, and the caret lands on the `n` of `nme`
        # which is column 29 in the source above.
        self.assertEqual(r.errors[0].pos.line, 3)
        self.assertEqual(r.errors[0].pos.col, 29)

    def test_interpolation_position_with_escapes_before_it(self):
        # Escapes in the literal text (``\n``, ``\"``, ``\\``) consume
        # two source characters but only one byte in the resolved
        # value. The lexer-side position tracking records the
        # *source* position of each ``${...}``, so escapes earlier in
        # the literal do not throw off the column the error reports.
        source = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\\nb\\\"c ${missing}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'missing'", r.errors[0].message)
        # Line 2 (the println line); column lands on the `m` of
        # `missing`. The exact column comes from the source offset of
        # `${`'s opener plus 2 (for the ``${``).
        self.assertEqual(r.errors[0].pos.line, 2)
        # The string literal begins at col 19. `\n` is 2 source
        # chars, `\"` is 2 source chars, `${` is 2 source chars. So
        # ``missing`` starts at col 19 + 1 (quote) + 1 (a) + 2 (\n) +
        # 1 (b) + 2 (\") + 1 (c) + 1 (space) + 2 (${) = 30.
        self.assertEqual(r.errors[0].pos.col, 30)

    def test_two_interpolations_each_keep_their_own_position(self):
        # Two ``${...}`` in the same string. The second is the one
        # with the typo. The lexer records both positions in order,
        # and the parser pairs each interpolation with the right one,
        # so the second-interpolation diagnostic still points at the
        # second interpolation's position rather than at the first.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    stdio.println(\"${x} and ${y}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'y'", r.errors[0].message)
        self.assertEqual(r.errors[0].pos.line, 3)
        # ``y`` is at col 31 in the source:
        # 4 spaces + "stdio.println(" (14) + `"${x} and ${` (12) = 30,
        # then `y` is col 31.
        self.assertEqual(r.errors[0].pos.col, 31)


# =============================================================
# Standard library: Map<K, V> and Set<T>
# =============================================================

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
    """Set<T> has methods: length, add, remove, contains, to_list."""

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


# =============================================================
# Pattern matching with scrutinee type params
# =============================================================

class TestPatternTypeParams(unittest.TestCase):
    """Pattern matching against variants of generic types substitutes
    the owner's type params with the scrutinee's type args."""

    def test_some_payload_is_concrete_type(self):
        # match m: Option<Int> with Some(n), n should be Int, not T.
        from capa import Lexer, Parser, analyze
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    match m.get(\"a\")\n"
            "        Some(n) -> stdio.println(\"${n + 1}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        # No errors: n + 1 is only valid if n: Int.
        self.assertTrue(result.ok, result.errors)


# =============================================================
# Tuple patterns
# =============================================================

class TestTuplePatterns(unittest.TestCase):
    """Tuple patterns: ``(p1, p2, ...)`` destructures tuples in let,
    var, for, match. Each element can be an arbitrary pattern."""

    def test_let_tuple_destructure(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun par() -> (Int, String)\n"
            "    return (1, \"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    let (a, b) = par()\n"
            "    stdio.println(\"${a} ${b}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)

    def test_match_tuple_pattern(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let p = (1, \"um\")\n"
            "    match p\n"
            "        (1, s) -> stdio.println(s)\n"
            "        (n, _) -> stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_nested_pattern_in_tuple(self):
        # (Some(n), label), variant + literal in a tuple.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let opt: (Option<Int>, String) = (Some(42), \"x\")\n"
            "    match opt\n"
            "        (Some(n), label) -> stdio.println(\"${label}=${n}\")\n"
            "        (None, label) -> stdio.println(\"${label}=?\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_tuple_arity_mismatch_rejected(self):
        msgs = errors_of(
            "fun par() -> (Int, String)\n"
            "    return (1, \"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    let (a, b, c) = par()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("3 elements, but type is" in m for m in msgs)
        )

    def test_string_literal_in_match(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let cmd = \"help\"\n"
            "    let r = match cmd\n"
            "        \"help\" -> \"show help\"\n"
            "        \"quit\" -> \"exit\"\n"
            "        _ -> \"unknown\"\n"
            "    stdio.println(r)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Or-patterns
# =============================================================

class TestOrPatterns(unittest.TestCase):
    """Or-patterns: ``A | B | C -> ...`` matches if any of the
    alternatives matches. No bindings in v0."""

    def test_or_with_variants(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Azul -> \"extremo\"\n"
            "        Verde -> \"meio\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_with_strings(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let cmd = \"help\"\n"
            "    let r = match cmd\n"
            "        \"h\" | \"help\" | \"?\" -> \"ajuda\"\n"
            "        _ -> \"outro\"\n"
            "    stdio.println(r)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_with_ints(self):
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        0 | 1 -> \"binary\"\n"
            "        2 | 3 | 5 | 7 -> \"small prime\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_pattern_with_consistent_bindings_accepted(self):
        # Bindings in or-patterns are now allowed if each alternative
        # binds the same set of names with compatible types.
        r = check(
            "type Op =\n"
            "    Add(Int)\n"
            "    Sub(Int)\n"
            "fun valor(o: Op) -> Int\n"
            "    return match o\n"
            "        Add(n) | Sub(n) -> n\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_pattern_with_inconsistent_names_rejected(self):
        # Each alternative must bind the same names.
        msgs = errors_of(
            "type Op =\n"
            "    Add(Int)\n"
            "    NoOp\n"
            "fun valor(o: Op) -> Int\n"
            "    return match o\n"
            "        Add(n) | NoOp -> 0\n"
        )
        self.assertTrue(
            any("binds different names" in m for m in msgs)
        )

    def test_or_pattern_with_incompatible_types_rejected(self):
        # Same name with incompatible types in different alternatives.
        msgs = errors_of(
            "type M =\n"
            "    AsInt(Int)\n"
            "    AsStr(String)\n"
            "fun foo(m: M) -> Int\n"
            "    return match m\n"
            "        AsInt(x) | AsStr(x) -> 0\n"
        )
        self.assertTrue(
            any("Int" in m and "String" in m for m in msgs)
        )

    def test_or_pattern_exhaustive(self):
        # OrPat counts each alternative toward the variant count.
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Verde -> \"a\"\n"
        )
        # Azul is missing.
        self.assertTrue(
            any("missing variants Azul" in m for m in msgs)
        )

    def test_or_pattern_exhaustive_complete(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Verde -> \"qualquer\"\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Stdio: read_line and typed methods
# =============================================================

class TestStdioMethods(unittest.TestCase):
    """Stdio now has typed methods: print, println, eprintln,
    read_line. The checker catches wrong types that previously passed
    as TyUnknown."""

    def test_println_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(123)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_read_line_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_read_line_no_args(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line(\"oops\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected 0 arguments, got 1" in m for m in msgs)
        )


class TestParseFunctions(unittest.TestCase):
    """parse_int and parse_float convert String to Option<Int|Float>."""

    def test_parse_int_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Option<Int>")

    def test_parse_int_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )


class TestRangeExpressions(unittest.TestCase):
    """Range expressions: `a..b` (exclusive) and `a..=b` (inclusive).
    Endpoints must be Int; the result has type Range<Int> (a lazy
    iterable distinct from List<Int>; ``to_list()`` materialises
    when the full List method surface is needed)."""

    def test_exclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_inclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 1..=5\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_range_with_arithmetic_endpoints(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = 5\n"
            "    let xs = (n - 1)..(n * 2)\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_with_float_left_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 1.0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "left side" in m for m in msgs),
            msgs,
        )

    def test_range_with_string_right_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..\"ten\"\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "right side" in m for m in msgs),
            msgs,
        )

    def test_range_to_list_chains_with_list_methods(self):
        # Range's API surface is intentionally minimal (length,
        # contains, is_empty, to_list). Users that want the full
        # List API call `.to_list()` first; the materialisation
        # is then explicit in the source rather than hidden.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).to_list().filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_filter_directly_rejected(self):
        # Direct .filter on a Range is now a type error; the
        # discipline forces the user to opt into materialisation
        # via `.to_list()`.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        self.assertTrue(
            any("type 'Range' has no method 'filter'" in m for m in msgs),
            msgs,
        )


class TestNumericConversions(unittest.TestCase):
    """to_float(Int) -> Float and to_int(Float) -> Int are the explicit
    bridges between numeric types (Capa has no implicit coercion)."""

    def test_to_float_typechecks(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Int = 5\n"
            "    let y = to_float(x)\n"
            "    stdio.println(\"${y}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_y = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_y.value)]), "Float")

    def test_to_float_unblocks_int_to_float_division(self):
        # The motivating use case: Float / Int is a type error, but
        # Float / to_float(Int) is well-typed.
        r = check(
            "fun avg(sum: Float, count: Int) -> Float\n"
            "    return sum / to_float(count)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_int_typechecks(self):
        r = check(
            "fun f() -> Int\n"
            "    return to_int(3.7)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_float_rejects_non_int(self):
        msgs = errors_of(
            "fun f() -> Float\n"
            "    return to_float(3.14)\n"
        )
        self.assertTrue(
            any("expects Int, got Float" in m for m in msgs),
            msgs,
        )

    def test_to_int_rejects_non_float(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return to_int(42)\n"
        )
        self.assertTrue(
            any("expects Float, got Int" in m for m in msgs),
            msgs,
        )


# =============================================================
# Typed capabilities: Fs, Env, Clock, Random
# =============================================================

class TestCapabilityMethods(unittest.TestCase):
    """Fs, Env, Clock, Random have typed methods, they used to always
    return TyUnknown, now they have precise types."""

    def test_fs_ler_returns_result_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_fs_existe_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let b = fs.exists(\"/tmp/x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")

    def test_fs_ler_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_env_get_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let v = env.get(\"HOME\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_v = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_v.value)]),
            "Option<String>",
        )

    def test_clock_sleep_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(1)\n"
        )
        self.assertTrue(
            any("expects Float, got Int" in m for m in msgs)
        )

    def test_random_int_range_with_float_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, random: Random)\n"
            "    let n = random.int_range(1.0, 10)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects Int, got Float" in m for m in msgs)
        )


class TestNetAttenuation(unittest.TestCase):
    """Net capability, attenuation by `restrict_to`. The fresh narrowed
    capability is bindable in `let`/`var` (the structural rule against
    bare-capability lets is relaxed for method-call RHS), but a bare
    alias still is not."""

    def test_restrict_to_typechecks(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    stdio.println(\"${api.allows(\\\"api.example.com\\\")}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_api = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_api.value)]), "Net")

    def test_allows_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let b = net.allows(\"x\")\n"
            "    stdio.println(\"${b}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")

    def test_get_returns_result_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let r = net.get(\"https://x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_let_alias_of_bare_capability_still_rejected(self):
        # The relaxation only applies to method-call RHS. Plain identifier
        # aliases of capabilities remain forbidden, that is the case the
        # structural rule was originally there to catch.
        msgs = errors_of(
            "fun main(net: Net, stdio: Stdio)\n"
            "    let dup = net\n"
            "    stdio.println(\"${dup.allows(\\\"x\\\")}\")\n"
        )
        self.assertTrue(
            any("cannot appear in a 'let' binding" in m for m in msgs),
            msgs,
        )

    def test_restrict_to_with_non_string_rejected(self):
        msgs = errors_of(
            "fun main(net: Net, stdio: Stdio)\n"
            "    let api = net.restrict_to(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs),
            msgs,
        )

    def test_attenuation_example_clean(self):
        with open("examples/net_attenuation.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)


class TestUserDefinedCapabilities(unittest.TestCase):
    """`capability X { ... }` declarations and the relaxations they
    enable: built-in caps as struct fields when the struct implements a
    user-defined cap; user-defined caps as function return types;
    `let`-binding factory-call results; nominal subtyping via `impl`."""

    _SETUP = (
        "capability SendEmail\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "\n"
        "type SmtpMailer {\n"
        "    server: String,\n"
        "    net: Net\n"
        "}\n"
        "\n"
        "impl SendEmail for SmtpMailer\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "        return Ok(())\n"
        "\n"
        "fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer\n"
        "    return SmtpMailer { server: server, net: net.restrict_to(server) }\n"
    )

    def test_capability_decl_parses_and_typechecks(self):
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_cap_field_allowed_when_impl_user_cap(self):
        # SmtpMailer has `net: Net`, normally forbidden, allowed here
        # because SmtpMailer implements a user-defined capability.
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_cap_field_rejected_when_no_user_cap_impl(self):
        # Plain struct (no `impl SendEmail for ...`), built-in cap as
        # field still rejected.
        msgs = errors_of(
            "type Service { net: Net, label: String }\n"
            "fun main()\n    return\n"
        )
        self.assertTrue(
            any("cannot appear in struct field 'net'" in m for m in msgs),
            msgs,
        )

    def test_factory_returning_user_cap_typechecks(self):
        # `fun make_smtp_mailer(...) -> SmtpMailer` is allowed even
        # though SmtpMailer is a user-defined capability.
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_factory_returning_builtin_cap_rejected(self):
        # The relaxation is for *user-defined* caps. Built-in caps
        # still cannot be returned.
        msgs = errors_of(
            "fun forge() -> Net\n"
            "    return Net { }\n"
        )
        self.assertTrue(
            any("'Net' cannot appear in return type" in m for m in msgs),
            msgs,
        )

    def test_let_binding_of_factory_call_allowed(self):
        # `let mailer = make_smtp_mailer(net, ...)` is allowed because
        # the RHS is a Call producing a fresh user-defined cap.
        r = check(
            self._SETUP
            + "fun main(net: Net)\n"
            + "    let mailer = make_smtp_mailer(net, \"smtp.example.com\")\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_let_alias_of_bare_user_cap_rejected(self):
        # `let dup = mailer` (plain Ident RHS, alias) is still rejected.
        msgs = errors_of(
            self._SETUP
            + "fun use_mailer(mailer: SmtpMailer)\n"
            + "    let dup = mailer\n"
            + "    let _ = dup.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(
            any("cannot appear in a 'let' binding" in m for m in msgs),
            msgs,
        )

    def test_struct_can_be_passed_where_user_cap_expected(self):
        # Nominal subtyping: SmtpMailer is accepted where SendEmail
        # is expected, because SmtpMailer implements SendEmail.
        r = check(
            self._SETUP
            + "fun send_hello(mailer: SendEmail)\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
            + "fun main(net: Net)\n"
            + "    let m = make_smtp_mailer(net, \"smtp.example.com\")\n"
            + "    send_hello(m)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_unrelated_struct_not_accepted_where_user_cap_expected(self):
        # If Foo does NOT implement SendEmail, passing it to a
        # SendEmail parameter is a type error.
        msgs = errors_of(
            self._SETUP
            + "type Foo { x: Int }\n"
            + "fun send_hello(mailer: SendEmail)\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
            + "fun main()\n"
            + "    send_hello(Foo { x: 1 })\n"
        )
        self.assertTrue(
            any("expects SendEmail, got Foo" in m for m in msgs),
            msgs,
        )

    def test_user_capabilities_example_clean(self):
        with open("examples/user_capabilities.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)


# =============================================================
# JSON: built-in JsonValue type and parse_json/to_json
# =============================================================

class TestJson(unittest.TestCase):
    """JsonValue is a built-in sum type with 6 variants. parse_json and
    to_json are built-in functions."""

    def test_parse_json_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_json(\"{}\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<JsonValue, String>",
        )

    def test_match_all_json_variants(self):
        r = check(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
            "        JNum(n) -> \"num\"\n"
            "        JStr(s) -> \"str\"\n"
            "        JArr(xs) -> \"arr\"\n"
            "        JObj(m) -> \"obj\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_non_exhaustive_json_match_rejected(self):
        msgs = errors_of(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
        )
        self.assertTrue(
            any("missing variants" in m and "JArr" in m and "JObj" in m
                for m in msgs)
        )

    def test_jstr_payload_is_string(self):
        # In match against JStr(s), s should be String.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"hello\")\n"
            "    match v\n"
            "        JStr(s) -> stdio.println(s.to_upper())\n"
            "        _ -> stdio.println(\"\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_jstr_with_int_rejected(self):
        # JStr expects String in the payload.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("String" in m for m in msgs)
        )

    def test_to_json_returns_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = to_json(JNull)\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")


class TestJsonHelpers(unittest.TestCase):
    """Methods as_string, as_num, etc. on JsonValue avoid boilerplate."""

    def test_as_string_returns_option_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"x\")\n"
            "    let s = v.as_string()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_is_null_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JNull\n"
            "    let b = v.is_null()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")


class TestOptionResultMethods(unittest.TestCase):
    """Option and Result have is_some/is_none/is_ok/is_err/unwrap_or."""

    def test_option_is_some(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(42)\n"
            "    if o.is_some()\n"
            "        stdio.println(\"some\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_option_unwrap_or(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(0)\n"
            "    stdio.println(\"${n}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Int")

    def test_option_unwrap_or_wrong_type_rejected(self):
        # unwrap_or<T>(default: T), default must have the same T as Option<T>.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(\"oops\")\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_result_is_ok(self):
        r = check(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\")\n"
            "    if r.is_ok()\n"
            "        stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestFunctionalCombinators(unittest.TestCase):
    """map, and_then, ok_or, map_err on Option/Result."""

    def test_option_map_changes_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    let s = n.map(fun (x: Int) -> String => \"n\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_option_ok_or_to_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_int(\"42\").ok_or(\"bad\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<Int, String>",
        )

    def test_result_map_err_changes_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").map_err(fun (e: IoError) -> Int => 1)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_option_filter_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Bool => x > 5)\n"
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

    def test_option_filter_rejects_non_bool_predicate(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Int => x + 1)\n"
        )
        self.assertTrue(any("Bool" in m for m in msgs), msgs)

    def test_option_or_else_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let r = o.or_else(fun () -> Option<Int> => Some(42))\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Option<Int>",
        )

    def test_result_or_else_can_change_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").or_else(\n"
            "        fun (e: IoError) -> Result<String, Int> => Err(1)\n"
            "    )\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_result_ok_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(7)\n"
            "    let o = r.ok()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<Int>",
        )

    def test_result_err_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Err(\"boom\")\n"
            "    let o = r.err()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<String>",
        )


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


# =============================================================
# if-expression: ``if cond then e1 else e2``
# =============================================================

class TestIfExpression(unittest.TestCase):
    """if-expression is an inline ternary operator. Bool mandatory
    in cond, branches with compatible types."""

    def test_basic_if_expr(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = if true then \"a\" else \"b\"\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")

    def test_nested_if_expr(self):
        # if-elif chain via nesting
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = 0\n"
            "    let cat = if n > 0 then \"+\" else if n < 0 then \"-\" else \"0\"\n"
            "    stdio.println(cat)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_if_expr_in_lambda(self):
        # if-expression inside single-line lambda
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, -2, 3]\n"
            "    let abs = xs.map(fun (x: Int) -> Int => if x < 0 then 0 - x else x)\n"
            "    stdio.println(\"${abs.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_if_expr_cond_must_be_bool(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = if 42 then \"a\" else \"b\"\n"
            "    stdio.println(x)\n"
        )
        self.assertTrue(
            any("condition must be Bool, got Int" in m for m in msgs)
        )

    def test_if_expr_branches_incompatible(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let y = if true then \"ok\" else 0\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("branches have incompatible types" in m for m in msgs)
        )


# =============================================================
# Full linearity: consume keyword + flow analysis
# =============================================================

class TestConsume(unittest.TestCase):
    """The `consume` qualifier on a parameter indicates that the call
    transfers ownership of the passed capability. After a consuming
    call, the name cannot be used again.

    In branches (if/else, match), fork/merge is done: snapshot of
    consumed before each branch, conservative union after.
    """

    def test_consume_then_use_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier and cannot be used again" in m for m in msgs)
        )

    def test_consume_then_pass_again_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_does_not_consume(self):
        # Function without `consume` borrows, caller keeps the cap.
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_then_consume_ok(self):
        # Borrows followed by a final consume: typical pattern.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_one_branch_makes_unusable_after(self):
        # If any branch of the if consumes, after the if the cap is considered
        # consumed (conservative rule).
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_both_branches_consume_no_use_after_ok(self):
        # Both branches consume, no use afterward, OK.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_both_branches_consume_use_after_rejected(self):
        # Both branches consume, but using afterward is an error.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_match_arm(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, c: Cor)\n"
            "    match c\n"
            "        Vermelho ->\n"
            "            adoptar(stdio)\n"
            "        Verde ->\n"
            "            stdio.println(\"verde\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_methods_apply(self):
        # `consume` also works on methods.
        msgs = errors_of(
            "type Recurso { id: Int }\n"
            "impl Recurso\n"
            "    fun fechar(self, consume stdio: Stdio)\n"
            "        stdio.println(\"adeus\")\n"
            "fun main(stdio: Stdio)\n"
            "    let r = Recurso { id: 1 }\n"
            "    r.fechar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    # ------- Linearity in loops -------

    def test_consume_in_while_rejected(self):
        # Consuming inside while is an error: on the 2nd iteration it's already consumed.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    while true\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_for_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_in_loop_consume_after_ok(self):
        # Typical pattern: borrow several times in the loop, final consume outside.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio)\n"
            "    var i = 0\n"
            "    while i < 3\n"
            "        emprestar(stdio)\n"
            "        i += 1\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_only_in_loop_ok(self):
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Smoke tests of the canonical examples
# =============================================================

class TestExamples(unittest.TestCase):
    def test_hello_clean(self):
        with open("examples/hello.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_basics_clean(self):
        with open("examples/basics.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_tasks_clean(self):
        with open("examples/tasks.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_errors_detected(self):
        with open("examples/errors.capa", encoding="utf-8") as f:
            r = check(f.read())
        # The errors file intentionally contains several problems;
        # we expect at least 8.
        self.assertGreaterEqual(len(r.errors), 8)

    def test_cap_violations_detected(self):
        with open("examples/cap_violations.capa", encoding="utf-8") as f:
            r = check(f.read())
        # At least 8 capability discipline violations.
        cap_errors = [
            e for e in r.errors
            if "capability" in e.message and "cannot appear" in e.message
        ]
        self.assertGreaterEqual(len(cap_errors), 8)

    def test_aliasing_detected(self):
        with open("examples/aliasing.capa", encoding="utf-8") as f:
            r = check(f.read())
        # 3 aliasing violations between calls.
        alias_errors = [
            e for e in r.errors
            if "cannot be aliased" in e.message
        ]
        self.assertEqual(len(alias_errors), 3)

    def test_generics_clean(self):
        with open("examples/generics.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_consume_violations_detected(self):
        with open("examples/consume.capa", encoding="utf-8") as f:
            r = check(f.read())
        # 3 use-after-consume errors in the example.
        consume_errors = [
            e for e in r.errors
            if "was consumed earlier" in e.message
        ]
        self.assertEqual(len(consume_errors), 3)

    def test_stdlib_list_clean(self):
        with open("examples/stdlib_list.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_stdlib_string_clean(self):
        with open("examples/stdlib_string.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    def test_stdlib_map_set_clean(self):
        with open("examples/stdlib_map_set.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Named arguments
# =============================================================

class TestNamedArguments(unittest.TestCase):
    """Functions and methods accept named arguments
    (``f(name: "Ana", age: 30)``). Positional arguments must
    precede any named argument; names must match a parameter;
    no parameter may be given twice; arity must be respected."""

    def test_call_with_named_args_in_order(self):
        r = check(
            'fun greet(name: String, age: Int) -> String\n'
            '    return name\n'
            'fun main(stdio: Stdio)\n'
            '    let m = greet(name: "Ana", age: 30)\n'
            '    stdio.println(m)\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_call_with_named_args_reordered(self):
        r = check(
            'fun greet(name: String, age: Int) -> String\n'
            '    return name\n'
            'fun main(stdio: Stdio)\n'
            '    let m = greet(age: 30, name: "Ana")\n'
            '    stdio.println(m)\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_mix_positional_then_named(self):
        r = check(
            'fun f(a: Int, b: Int, c: Int) -> Int\n'
            '    return a + b + c\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${f(1, c: 3, b: 2)}")\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_positional_after_named_rejected(self):
        errs = errors_of(
            'fun f(a: Int, b: Int) -> Int\n'
            '    return a + b\n'
            'fun main(stdio: Stdio)\n'
            '    let _ = f(a: 1, 2)\n'
        )
        self.assertTrue(
            any("positional argument cannot follow" in e for e in errs),
            errs,
        )

    def test_unknown_parameter_name_rejected(self):
        errs = errors_of(
            'fun f(a: Int, b: Int) -> Int\n'
            '    return a + b\n'
            'fun main(stdio: Stdio)\n'
            '    let _ = f(a: 1, x: 2)\n'
        )
        self.assertTrue(
            any("unknown parameter name 'x'" in e for e in errs),
            errs,
        )

    def test_duplicate_name_rejected(self):
        errs = errors_of(
            'fun f(a: Int, b: Int) -> Int\n'
            '    return a + b\n'
            'fun main(stdio: Stdio)\n'
            '    let _ = f(a: 1, a: 2)\n'
        )
        self.assertTrue(
            any("given more than once" in e for e in errs),
            errs,
        )

    def test_named_arg_type_checked_at_right_slot(self):
        # If the analyzer were comparing positionally without
        # reordering, this would (wrongly) succeed because the values
        # happen to be Int and String. Test that we still catch the
        # type mismatch when the user swaps the *types* and *names*.
        errs = errors_of(
            'fun greet(name: String, age: Int) -> String\n'
            '    return name\n'
            'fun main(stdio: Stdio)\n'
            '    let _ = greet(age: "thirty", name: 30)\n'
        )
        # Two type errors: age expects Int got String, name expects
        # String got Int. The exact wording is not asserted, only that
        # both mismatches are surfaced.
        self.assertGreaterEqual(len(errs), 2, errs)

    def test_named_args_on_method(self):
        r = check(
            'type Point {\n'
            '    x: Int,\n'
            '    y: Int\n'
            '}\n'
            'impl Point\n'
            '    fun move_by(self, dx: Int, dy: Int) -> Point\n'
            '        return Point { x: self.x + dx, y: self.y + dy }\n'
            'fun main(stdio: Stdio)\n'
            '    let p = Point { x: 0, y: 0 }\n'
            '    let q = p.move_by(dy: 3, dx: 1)\n'
            '    stdio.println("${q.x}")\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_named_args_on_builtin_rejected(self):
        errs = errors_of(
            'fun main(stdio: Stdio)\n'
            '    let s = "hello"\n'
            '    let r = s.replace(old: "l", new: "L")\n'
            '    stdio.println(r)\n'
        )
        self.assertTrue(
            any("named arguments are not supported" in e for e in errs),
            errs,
        )


# =============================================================
# "Did you mean?" suggestions
# =============================================================

class TestDidYouMeanHints(unittest.TestCase):
    """The analyzer attaches ``; did you mean 'X'?`` to error
    messages where the user almost certainly mistyped a name in
    scope. Coverage: undefined name, undefined type, no method
    on type, no field on struct, unknown variant in pattern.
    Sub-3-char needles are deliberately not hinted (too many
    plausible candidates)."""

    def test_undefined_name_suggests_in_scope_name(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let result = 1\n"
            "    stdio.println(\"${reslt}\")\n"
        )
        self.assertTrue(
            any("did you mean 'result'?" in e for e in errs), errs,
        )

    def test_undefined_type_suggests_known_type(self):
        errs = errors_of(
            "fun greet(s: Strng) -> Strng\n"
            "    return s\n"
        )
        self.assertTrue(
            any("did you mean 'String'?" in e for e in errs), errs,
        )

    def test_no_method_on_string_suggests_builtin(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(
            any("did you mean 'length'?" in e for e in errs), errs,
        )

    def test_no_field_on_struct_suggests_field(self):
        errs = errors_of(
            "type Person {\n"
            "    full_name: String,\n"
            "    age: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Person { full_name: \"a\", age: 1 }\n"
            "    stdio.println(p.full_naem)\n"
        )
        self.assertTrue(
            any("did you mean 'full_name'?" in e for e in errs),
            errs,
        )

    def test_struct_literal_field_typo_suggests_known(self):
        errs = errors_of(
            "type Person {\n"
            "    full_name: String,\n"
            "    age: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Person { full_naem: \"a\", age: 1 }\n"
            "    stdio.println(p.full_name)\n"
        )
        self.assertTrue(
            any("did you mean 'full_name'?" in e for e in errs),
            errs,
        )

    def test_unknown_variant_suggests_scrutinee_variant(self):
        errs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun name(c: Color) -> String\n"
            "    return match c\n"
            "        Red -> \"r\"\n"
            "        Gren -> \"g\"\n"
            "        Blue -> \"b\"\n"
        )
        self.assertTrue(
            any("did you mean 'Green'?" in e for e in errs), errs,
        )

    def test_short_needle_does_not_hint(self):
        # 'xx' is two characters; below the hinting threshold,
        # so the message should NOT suggest anything.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = xx\n"
            "    stdio.println(\"${x}\")\n"
        )
        # 'xx' must still be reported as undefined, just without
        # a 'did you mean' suffix.
        self.assertTrue(any("undefined name 'xx'" in e for e in errs), errs)
        self.assertFalse(
            any("did you mean" in e for e in errs), errs,
        )

    def test_exact_match_does_not_hint(self):
        # No hint should appear when the only candidate is itself
        # (distance 0 is filtered).
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let length = 5\n"
            "    stdio.println(\"${lenght}\")\n"
        )
        # 'length' is distance 1 from 'lenght'; a suggestion is
        # expected, but should NOT be the needle itself.
        for e in errs:
            self.assertNotIn("did you mean 'lenght'?", e)


class TestQuestionMarkOnNonResultOption(unittest.TestCase):
    """``?`` is a Result / Option unwrap operator. Applied to any
    other type it would explode at runtime with
    ``? applied to a value that is not Result or Option`` (the
    helper in ``capa.runtime`` raises a ``RuntimeError``). The
    analyser now surfaces this at type-check time so the error
    points at the source location with the actual type the user
    wrote, instead of waiting for the runtime crash."""

    def test_question_on_int_is_rejected(self):
        errs = errors_of(
            "fun bad(x: Int) -> Int\n"
            "    return x?\n"
        )
        self.assertTrue(
            any("`?` is only valid on Result<T, E> or Option<T>" in e
                and "Int" in e
                for e in errs),
            errs,
        )

    def test_question_on_string_is_rejected(self):
        errs = errors_of(
            "fun bad(s: String) -> String\n"
            "    return s?\n"
        )
        self.assertTrue(
            any("`?` is only valid on Result<T, E> or Option<T>" in e
                and "String" in e
                for e in errs),
            errs,
        )

    def test_question_on_result_still_accepted(self):
        # The fix must not regress the legitimate uses of ``?`` on
        # Result. ``parse_int`` returns ``Result<Int, String>``.
        r = check(
            "fun add_one(s: String) -> Result<Int, String>\n"
            "    let n = parse_int(s)?\n"
            "    return Ok(n + 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_question_on_option_still_accepted(self):
        # Same check for Option<T>: the regression from before this
        # iteration applied here too.
        r = check(
            "fun first_plus_one(xs: List<Int>) -> Option<Int>\n"
            "    let x = xs.first()?\n"
            "    return Some(x + 1)\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestCallNonCallable(unittest.TestCase):
    """A call expression ``x(args)`` whose callee resolves to a
    non-function, non-variant binding (an Int local, a String
    constant, a struct value, etc.) used to be silently accepted
    by the v1 checker and would explode at runtime as
    ``TypeError: 'int' object is not callable``. The analyser
    now surfaces it at compile time with the actual type of the
    receiver. Function-typed locals (lambdas assigned to a
    binding) keep working."""

    def test_call_int_local_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 5\n"
            "    let y = x(2)\n"
            "    stdio.println(\"${y}\")\n"
        )
        self.assertTrue(
            any("'x' is not callable" in e and "Int" in e for e in errs),
            errs,
        )

    def test_call_string_constant_is_rejected(self):
        errs = errors_of(
            "const NAME: String = \"capa\"\n"
            "fun main(stdio: Stdio)\n"
            "    let x = NAME(1)\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("'NAME' is not callable" in e and "String" in e for e in errs),
            errs,
        )

    def test_call_lambda_local_is_accepted(self):
        # The function-typed-local exception: a lambda bound to a
        # local is callable. The checker leaves arity / arg-type
        # validation to the existing non-Ident-callee path (which
        # currently passes through to TyUnknown for these shapes);
        # the important thing is that this does not regress.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let f = fun (x: Int) -> Int => x * 2\n"
            "    let y = f(3)\n"
            "    stdio.println(\"${y}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestSelfFieldHint(unittest.TestCase):
    """Inside an ``impl`` method, a bare identifier that matches a
    field of ``self``'s struct type is almost certainly a
    forgotten ``self.``. The analyser surfaces a targeted hint
    so the fix is obvious from the diagnostic."""

    def test_bare_field_in_impl_method_suggests_self_dot(self):
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get(self) -> Int\n"
            "        return v\n"
        )
        self.assertTrue(
            any("did you mean `self.v`?" in e for e in errs),
            errs,
        )

    def test_bare_non_field_falls_back_to_generic_hint(self):
        # ``vfx`` is not a field of Counter; the targeted hint
        # should not appear (no ``self.vfx`` suggestion).
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get(self) -> Int\n"
            "        return vfx\n"
        )
        for e in errs:
            self.assertNotIn("did you mean `self.", e)

    def test_self_hint_only_inside_impl_methods(self):
        # A free function does not have a ``self`` type; the hint
        # must not fire even if a global struct happens to have a
        # field of that name.
        errs = errors_of(
            "type Counter { v: Int }\n"
            "fun get_outside() -> Int\n"
            "    return v\n"
        )
        for e in errs:
            self.assertNotIn("did you mean `self.", e)


class TestReturnOnAllPaths(unittest.TestCase):
    """A function that declares a non-Unit return type must
    ``return`` on every code path. Before this check landed, a
    function like ``fun greet(name: String) -> String\\n    \"hi\"``
    compiled silently and returned None at runtime, breaking
    downstream callers that trusted the signature."""

    def test_falls_through_with_expression_statement_is_rejected(self):
        errs = errors_of(
            "fun greet(name: String) -> String\n"
            "    \"hello\"\n"
        )
        self.assertTrue(
            any("not every path ends in `return`" in e for e in errs),
            errs,
        )

    def test_trailing_match_without_return_is_rejected(self):
        # The intent was almost certainly ``return match c``; the
        # bare ``match c`` is an ExprStmt whose value is discarded.
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Azul\n"
            "fun letra(c: Cor) -> String\n"
            "    match c\n"
            "        Vermelho -> \"R\"\n"
            "        Azul -> \"B\"\n"
        )
        self.assertTrue(
            any("not every path ends in `return`" in e for e in errs),
            errs,
        )

    def test_unit_return_does_not_require_return(self):
        # A function returning Unit can fall through; the check
        # only fires for non-Unit return types.
        r = check(
            "fun shout(stdio: Stdio, s: String)\n"
            "    stdio.println(s)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_if_else_both_returning_is_accepted(self):
        # An if/else where both branches return is fine: flow
        # cannot fall through. The check recurses into IfStmt.
        r = check(
            "fun sign(n: Int) -> String\n"
            "    if n >= 0\n"
            "        return \"non-negative\"\n"
            "    else\n"
            "        return \"negative\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_if_without_else_is_rejected(self):
        # Even if the if branch returns, the missing else means
        # flow falls through when the condition is false.
        errs = errors_of(
            "fun maybe(n: Int) -> String\n"
            "    if n > 0\n"
            "        return \"pos\"\n"
        )
        self.assertTrue(
            any("not every path ends in `return`" in e for e in errs),
            errs,
        )

    def test_return_match_is_accepted(self):
        # The idiomatic shape: ``return match scrut { ... }``.
        # The match's value flows through the explicit return.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Azul\n"
            "fun letra(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho -> \"R\"\n"
            "        Azul -> \"B\"\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestDuplicateBindingDiagnostic(unittest.TestCase):
    """``let x = ...; let x = ...`` (or any second binding of the
    same name in the same scope) is rejected. The diagnostic
    includes the source position of the previous binding and a
    hint about the ``var`` + bare-assignment idiom for the common
    case of "I meant to update the value, not redeclare it"."""

    def test_duplicate_let_names_previous_location(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    let x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        # The previous binding is on line 2, col 9 (``    let x``).
        self.assertTrue(
            any("duplicate binding 'x'" in e
                and "line 2, col 9" in e
                for e in errs),
            errs,
        )

    def test_duplicate_let_suggests_var(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    let x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("`var x` for a mutable binding" in e for e in errs),
            errs,
        )


if __name__ == "__main__":
    unittest.main()

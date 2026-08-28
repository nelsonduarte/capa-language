"""Analyzer tests: base typechecker and core constructs (valid programs, name
resolution, type checking, variants, impl blocks, if-expr,
return-on-all-paths, literal/index/tuple typing, char/string compat,
frozen structs, named args, for-loops, empty-container pinning, and the
canonical-examples smoke test).

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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

    def test_bitwise_int_int_ok(self):
        # All five bitwise ops on Int operands type-check to Int.
        # Covered in one function so a single failure surfaces every
        # offending op rather than the first one only.
        r = check(
            "fun bits(a: Int, b: Int) -> Int\n"
            "    let _and = a & b\n"
            "    let _or = a | b\n"
            "    let _xor = a ^ b\n"
            "    let _shl = a << b\n"
            "    let _shr = a >> b\n"
            "    return _and + _or + _xor + _shl + _shr\n"
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

    def test_block_shadow_of_outer_let_rejected(self):
        # Block-scope shadowing of a function-local cannot be
        # preserved by Python's function-scope semantics: the
        # inner ``let`` would assign to the same Python name as
        # the outer ``let`` and overwrite it for the rest of the
        # function. The analyzer rejects this with a precise
        # message rather than silently emit code whose runtime
        # value disagrees with the source.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    if true\n"
            "        let x = 2\n"
            "        stdio.println(\"${x}\")\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("would shadow an outer-scope local" in m for m in msgs),
            msgs,
        )

    def test_block_shadow_of_outer_var_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var x = 1\n"
            "    if true\n"
            "        let x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("would shadow an outer-scope local" in m for m in msgs),
            msgs,
        )

    def test_block_shadow_of_param_rejected(self):
        msgs = errors_of(
            "fun process(x: Int) -> Int\n"
            "    if x > 0\n"
            "        let x = x + 1\n"
            "        return x\n"
            "    return x\n"
        )
        self.assertTrue(
            any("would shadow an outer-scope local" in m for m in msgs),
            msgs,
        )

    def test_for_loop_binding_shadows_outer_rejected(self):
        # Same rule applies to ``for`` pattern bindings.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let i = 99\n"
            "    for i in 0..3\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(
            any("would shadow an outer-scope local" in m for m in msgs),
            msgs,
        )

    def test_sequential_blocks_same_name_ok(self):
        # Two non-overlapping blocks each declaring ``let x``: the
        # first ``x`` is out of scope before the second is
        # introduced, so there is no real shadow. The analyzer
        # pops each block's scope on exit; the lookup walk does
        # not find a stale outer ``x``.
        r = check(
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        let x = 1\n"
            "        stdio.println(\"${x}\")\n"
            "    if b\n"
            "        let x = 2\n"
            "        stdio.println(\"${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_lambda_body_shadows_outer_param_rejected(self):
        # A ``let`` inside a lambda body whose name collides with an
        # outer-function parameter is REJECTED: the two backends compile
        # it differently. The Python transpiler function-scopes the
        # redeclared name (``UnboundLocalError`` if the outer value is
        # read before the inner ``let``); the Wasm lowerer keeps the
        # inner closure's lexical capture and discloses the outer value.
        #
        # This case previously asserted ``.ok`` and NEVER ran the
        # program, so it masked a fully-silent Wasm miscompile where the
        # captured outer parameter is disclosed. It now asserts the
        # closure-shadow rejection so ``--check`` and both backends agree.
        msgs = errors_of(
            "fun outer(x: Int) -> Int\n"
            "    let f = fun () -> Int =>\n"
            "        let x = 99\n"
            "        return x\n"
            "    return f() + x\n"
        )
        self.assertTrue(
            any("may not shadow" in m for m in msgs),
            msgs,
        )

    def test_lambda_body_shadows_outer_let_rejected(self):
        # Same principle for an outer ``let``: a lambda-body ``let`` that
        # shadows an enclosing-scope local is rejected. Before the fix
        # this asserted ``.ok`` and was never executed, hiding the same
        # backend divergence (Python UnboundLocalError vs Wasm silent
        # disclosure of the outer ``y``).
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let y = 1\n"
            "    let f = fun () -> Int =>\n"
            "        let y = 2\n"
            "        return y\n"
            "    stdio.println(\"${f()} ${y}\")\n"
        )
        self.assertTrue(
            any("may not shadow" in m for m in msgs),
            msgs,
        )

    def test_lambda_body_intra_lambda_shadow_still_rejected(self):
        # Soundness anchor: shadowing within the SAME lambda
        # body must still be rejected. Both bindings end up in
        # the same Python function-local scope so the inner
        # ``let`` would overwrite the param.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let f = fun (z: Int) -> Int =>\n"
            "        if z > 0\n"
            "            let z = 99\n"
            "            return z\n"
            "        return z\n"
            "    stdio.println(\"${f(1)}\")\n"
        )
        self.assertTrue(
            any("would shadow an outer-scope local" in m for m in msgs),
            msgs,
        )

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

    def test_bitwise_float_rejected(self):
        # Bitwise on Float is rejected: the bit pattern of an IEEE-754
        # double is not a meaningful operand for ``& | ^``.
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return 1.5 & 2.0\n"
        )
        self.assertTrue(
            any("bitwise operators require Int operands" in m for m in msgs),
            msgs,
        )

    def test_shift_string_rejected(self):
        # Shift with a String operand should be rejected at the
        # analyzer; the error names the offending types.
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return 1 << \"two\"\n"
        )
        self.assertTrue(
            any("bitwise operators require Int operands" in m for m in msgs),
            msgs,
        )

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

    _SHAPE_PRELUDE = (
        "trait Shape\n"
        "    fun area(self) -> Int\n"
        "type Sq { s: Int }\n"
        "type Rec { w: Int, h: Int }\n"
        "impl Shape for Sq\n"
        "    fun area(self) -> Int\n"
        "        return self.s * self.s\n"
        "impl Shape for Rec\n"
        "    fun area(self) -> Int\n"
        "        return self.w * self.h\n"
    )

    def test_list_lit_trait_annotation_heterogeneous(self):
        # Bidirectional typing: a heterogeneous list literal of distinct
        # implementors of a common trait honours a ``List<Shape>``
        # annotation instead of inferring ``List<Sq>`` from the first
        # element and rejecting the rest.
        r = check(
            self._SHAPE_PRELUDE
            + "fun f() -> Int\n"
            "    let shapes: List<Shape> = [Sq { s: 2 }, Rec { w: 2, h: 3 }]\n"
            "    return shapes.length()\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_list_lit_trait_annotation_homogeneous(self):
        # A homogeneous annotated list still type-checks.
        r = check(
            self._SHAPE_PRELUDE
            + "fun f() -> Int\n"
            "    let shapes: List<Shape> = [Sq { s: 2 }, Sq { s: 3 }]\n"
            "    return shapes.length()\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_list_lit_trait_annotation_empty(self):
        # An empty annotated list keeps its declared element type.
        r = check(
            self._SHAPE_PRELUDE
            + "fun f() -> Int\n"
            "    let shapes: List<Shape> = []\n"
            "    return shapes.length()\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_list_lit_concrete_annotation_incompatible_still_rejected(self):
        # A list literal with a CONCRETE element annotation and an
        # incompatible element is still an error (no false acceptance).
        msgs = errors_of(
            "fun f() -> Int\n"
            "    let xs: List<Int> = [1, \"two\", 3]\n"
            "    return xs.length()\n"
        )
        self.assertTrue(
            any("element has type String, expected Int" in m for m in msgs)
        )

    def test_list_lit_unannotated_heterogeneous_still_rejected(self):
        # Without an annotation the element type is still inferred from
        # the first element, so an unannotated heterogeneous list still
        # errors (the threading is confined to the annotated path).
        msgs = errors_of(
            "type Sq { s: Int }\n"
            "type Rec { w: Int }\n"
            "fun f() -> Int\n"
            "    let xs = [Sq { s: 1 }, Rec { w: 2 }]\n"
            "    return xs.length()\n"
        )
        self.assertTrue(
            any("element has type Rec, expected Sq" in m for m in msgs)
        )


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

    def test_variant_with_multiple_payloads_ok(self):
        # Multi-payload declaration + matching constructor call type check.
        r = check(
            "type Pair =\n"
            "    P(Int, String)\n"
            "fun mk() -> Pair\n"
            "    return P(1, \"hi\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_variant_arity_mismatch_at_call(self):
        msgs = errors_of(
            "type Pair =\n"
            "    P(Int, String)\n"
            "fun f() -> Pair\n"
            "    return P(1)\n"
        )
        self.assertTrue(
            any("takes 2 arguments" in m for m in msgs),
            msgs,
        )

    def test_variant_arity_mismatch_at_pattern(self):
        msgs = errors_of(
            "type Pair =\n"
            "    P(Int, String)\n"
            "fun f(p: Pair) -> Int\n"
            "    return match p\n"
            "        P(a) -> a\n"
        )
        self.assertTrue(
            any("expects 2 sub-pattern" in m for m in msgs),
            msgs,
        )

    def test_variant_payload_type_mismatch(self):
        msgs = errors_of(
            "type Pair =\n"
            "    P(Int, String)\n"
            "fun f() -> Pair\n"
            "    return P(1, 2)\n"
        )
        self.assertTrue(
            any("argument 2" in m and "expected String" in m for m in msgs),
            msgs,
        )


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

    def test_impl_builtin_capability_rejected(self):
        # Audit slice 21 P2 (2026-05-29): built-in capabilities
        # are host-granted; user code must not be able to
        # inhabit them with arbitrary structs. Otherwise a
        # ``FakeStdio`` could appear in a Stdio-typed parameter
        # and downstream tooling that assumes values of cap
        # type Stdio are host-granted would be wrong.
        for cap in ("Stdio", "Fs", "Net", "Env", "Clock", "Random", "Unsafe"):
            msgs = errors_of(
                f"type Fake {{ junk: Int }}\n"
                f"impl {cap} for Fake\n"
                f"    fun ping(self)\n"
                f"        return ()\n"
            )
            self.assertTrue(
                any(
                    f"cannot impl built-in capability '{cap}'" in m
                    for m in msgs
                ),
                f"expected rejection for impl {cap}; got: {msgs}",
            )


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

    def test_named_args_on_first_class_local_lambda_rejected(self):
        # A function-typed VALUE carries no parameter names, so a NAMED
        # argument cannot bind soundly: the type checker binds positionally
        # while the Python transpiler emits kwargs, so a named-arg first-class
        # call diverges between the backends (and can reorder a @secret into an
        # un-sunk slot). Reject it. Positional first-class calls stay allowed.
        errs = errors_of(
            'fun app(a: String, b: String, stdio: Stdio)\n'
            '    stdio.println(b)\n'
            'fun main(stdio: Stdio)\n'
            '    let g: Fun(String, String) -> Unit = '
            'fun(a: String, b: String) -> Unit => app(a, b, stdio)\n'
            '    g(b: "y", a: "x")\n'
        )
        self.assertTrue(
            any("named arguments are not supported" in e for e in errs),
            errs,
        )

    def test_named_args_on_iife_rejected(self):
        # The immediately-invoked-lambda form of the same first-class call.
        errs = errors_of(
            'fun app(a: String, b: String, stdio: Stdio)\n'
            '    stdio.println(b)\n'
            'fun main(stdio: Stdio)\n'
            '    (fun(a: String, b: String) -> Unit => '
            'app(a, b, stdio))(b: "y", a: "x")\n'
        )
        self.assertTrue(
            any("named arguments are not supported" in e for e in errs),
            errs,
        )

    def test_named_args_on_fun_typed_parameter_rejected(self):
        # A ``Fun``-typed PARAMETER is a first-class value too: named args are
        # unsound there as well.
        errs = errors_of(
            'fun run(f: Fun(String, String) -> Unit)\n'
            '    f(b: "y", a: "x")\n'
        )
        self.assertTrue(
            any("named arguments are not supported" in e for e in errs),
            errs,
        )

    def test_positional_first_class_call_still_ok(self):
        # The sound path: positional arguments at a first-class call are
        # accepted and type-checked as before.
        r = check(
            'fun app(a: String, b: String, stdio: Stdio)\n'
            '    stdio.println(b)\n'
            'fun main(stdio: Stdio)\n'
            '    let g: Fun(String, String) -> Unit = '
            'fun(a: String, b: String) -> Unit => app(a, b, stdio)\n'
            '    g("x", "y")\n'
        )
        self.assertTrue(r.ok, r.errors)


class TestForLoopNonIterable(unittest.TestCase):
    """Iterating a primitive scalar (Int, Float, String, Char, Bool)
    is meaningless: Python would raise ``TypeError: 'X' object is
    not iterable`` at runtime. The analyser now catches it with the
    actual type name. List<T>, Range<T>, and TyUnknown remain
    accepted."""

    def test_for_int_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 5\n"
            "    for i in x\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(
            any("cannot iterate" in e and "Int" in e for e in errs),
            errs,
        )

    def test_for_string_is_accepted(self):
        # Python iterates strings character-by-character natively,
        # and ``examples/io.capa`` relies on this pattern to count
        # newlines. The check leaves String alone; only the genuinely
        # non-iterable primitives (Int, Float, Bool) are rejected.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    for c in s\n"
            "        stdio.println(\"${c}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_for_float_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 3.14\n"
            "    for i in x\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(
            any("cannot iterate" in e and "Float" in e for e in errs),
            errs,
        )

    def test_for_list_still_accepted(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = [1, 2, 3]\n"
            "    for i in xs\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_for_range_still_accepted(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..10\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


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


class TestFrozenStructTypes(unittest.TestCase):
    """Struct types that flow into a ``Set<...>`` or
    ``Map<...K, V>`` key position cannot have their fields
    mutated: doing so breaks the data-structure invariant on
    both backends (the Wasm linear scan misses entries; the
    Python ``CapaSet`` dict corrupts its hash bucket). The
    analyzer rejects field assignments on any value of a frozen
    type at analysis time. See ``capa/analyzer/_frozen.py`` for
    the rule and the H2 audit trail (2026-05)."""

    def test_direct_freeze_set_argument_rejects_field_write(self):
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<Point>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x = 5\n"
        )
        hits = [
            m for m in msgs
            if "'Point' is frozen" in m and "'x' of struct 'Point'" in m
        ]
        self.assertEqual(len(hits), 1, msgs)

    def test_map_key_freezes_struct(self):
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun lookup(m: Map<Point, Int>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x = 5\n"
        )
        self.assertTrue(
            any("'Point' is frozen" in m for m in msgs), msgs,
        )

    def test_map_struct_key_freezes_struct(self):
        # Follow-up slice (Map struct keys): declaring
        # ``Map<Point, Int>`` alone is enough to mark Point frozen,
        # so a subsequent ``p.x = 5`` on a locally-constructed
        # Point value must trigger the H2 frozen-struct diagnostic.
        # Exercises the locked-design promise that the slice does
        # not need to extend H2: the existing frozen-struct rule
        # walks every ``Map<T, V>`` type expression and adds T.
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Point, Int> = new_map()\n"
            "    var p = Point{x: 1, y: 2}\n"
            "    p.x = 5\n"
        )
        self.assertTrue(
            any(
                "'Point' is frozen" in m
                and "'x' of struct 'Point'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_map_value_does_not_freeze_struct(self):
        # Map values are not part of the hash key; mutating
        # them is safe and must remain allowed.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun lookup(m: Map<String, Point>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x = 5\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_transitive_freeze_via_struct_field(self):
        # Wrap contains a Point. Set<Wrap> freezes Wrap, and
        # the transitive closure pulls Point in too.
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "type Wrap {\n"
            "    p: Point\n"
            "}\n"
            "fun use_set(s: Set<Wrap>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x = 5\n"
        )
        self.assertTrue(
            any("'Point' is frozen" in m for m in msgs), msgs,
        )

    def test_nested_collection_set_of_list_of_struct(self):
        # Set<List<Point>> still extracts Point as a frozen key
        # base (the List is part of the key position; its element
        # type is what hashing ultimately depends on).
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<List<Point>>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x = 5\n"
        )
        self.assertTrue(
            any("'Point' is frozen" in m for m in msgs), msgs,
        )

    def test_construction_of_frozen_type_still_allowed(self):
        # The rule only forbids field mutation; constructing a
        # frozen struct (and reading its fields) is fine.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<Point>) -> Int\n"
            "    return 0\n"
            "fun build() -> Point\n"
            "    let p = Point{x: 1, y: 2}\n"
            "    return p\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_whole_value_rebinding_of_var_still_allowed(self):
        # ``p = Point{...}`` on a ``var`` is whole-value
        # rebinding: target is an Ident, not a FieldAccess, so
        # the rule does not (and must not) fire.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<Point>) -> Int\n"
            "    return 0\n"
            "fun swap()\n"
            "    var p = Point{x: 1, y: 2}\n"
            "    p = Point{x: 3, y: 4}\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_augmented_assignment_caught(self):
        # ``p.x += 1`` is parsed as AssignStmt(op='+=') with
        # target = FieldAccess; the rule must fire regardless
        # of the operator.
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<Point>) -> Int\n"
            "    return 0\n"
            "fun mutate(p: Point)\n"
            "    p.x += 1\n"
        )
        self.assertTrue(
            any("'Point' is frozen" in m for m in msgs), msgs,
        )

    def test_indexed_receiver_field_write_caught(self):
        # ``xs[i].x = 5`` where ``xs: List<Point>`` and Point
        # is frozen: target is FieldAccess(Index(xs, i), 'x'),
        # the FieldAccess receiver's type resolves to Point,
        # so the rule fires.
        msgs = errors_of(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun use_set(s: Set<Point>) -> Int\n"
            "    return 0\n"
            "fun mutate(xs: List<Point>)\n"
            "    xs[0].x = 5\n"
        )
        self.assertTrue(
            any("'Point' is frozen" in m for m in msgs), msgs,
        )


class TestIntLiteralRange(unittest.TestCase):
    """Slice 26 residual / P3: a bare 2**63 is out of i64 range; only
    ``-2**63`` (i64::MIN) is representable. The lexer admits the
    magnitude (it can't see a preceding unary minus); the analyzer
    rejects a positive use to close the Python/Wasm divergence
    (Python printed the bignum, Wasm wrapped)."""

    def _errs(self, body: str) -> list[str]:
        return errors_of(f"fun f()\n    {body}\n")

    def test_positive_2pow63_rejected(self):
        errs = self._errs("let x = 9223372036854775808")
        self.assertTrue(
            any("out of range" in e for e in errs), errs,
        )

    def test_negated_2pow63_is_i64_min_ok(self):
        self.assertEqual(self._errs("let x = -9223372036854775808"), [])

    def test_i64_max_ok(self):
        self.assertEqual(self._errs("let x = 9223372036854775807"), [])

    def test_positive_2pow63_in_expression_rejected(self):
        # Not just in a let -- any positive use is out of range.
        errs = self._errs("let x = 9223372036854775808 + 1")
        self.assertTrue(any("out of range" in e for e in errs), errs)


class TestTupleConstIndexType(unittest.TestCase):
    """A constant tuple index has a statically-known element type.
    The analyzer surfaces it so downstream consumers get the right
    type, an out-of-range constant index is a compile error, and a
    type mismatch on a tuple element is caught. Without this it
    diverged: Python raised IndexError at runtime while the Wasm
    backend silently returned 0."""

    def _errs(self, body: str) -> list[str]:
        return errors_of(f"fun f()\n    {body}\n")

    def test_in_bounds_index_types_correctly(self):
        # Control: an in-bounds index recovers the element type, so
        # binding it to a matching annotation is accepted.
        self.assertEqual(
            self._errs("let t = (1, 2)\n    let x: Int = t[0]"), [],
        )

    def test_in_bounds_index_string_element(self):
        # Control: heterogeneous tuple, element 1 is String.
        self.assertEqual(
            self._errs('let t = (1, "hi")\n    let s: String = t[1]'),
            [],
        )

    def test_const_out_of_range_rejected(self):
        errs = self._errs("let t = (1, 2)\n    let x = t[5]")
        self.assertTrue(
            any("out of range" in e for e in errs), errs,
        )

    def test_type_mismatch_caught(self):
        # t[0] is Int; binding it to String must error now that the
        # element type is recovered (was permissive TyUnknown before).
        errs = self._errs("let t = (1, 2)\n    let x: String = t[0]")
        self.assertTrue(
            any("expected String" in e and "got Int" in e for e in errs),
            errs,
        )


class TestForLoopIterable(unittest.TestCase):
    def test_for_over_map_rejected_with_keys_values_hint(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    for k in m\n"
            "        stdio.print(k)\n"
        )
        self.assertTrue(
            any("cannot iterate a Map" in m for m in msgs), msgs,
        )
        self.assertTrue(
            any(".keys()" in m and ".values()" in m for m in msgs), msgs,
        )

    def test_for_destructure_over_map_rejected(self):
        # The ``for (k, v) in m`` shape is the one that crashes the
        # Python backend at runtime today; it must be a clean
        # compile error too.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    for (k, v) in m\n"
            "        stdio.print(k)\n"
        )
        self.assertTrue(
            any("cannot iterate a Map" in m for m in msgs), msgs,
        )

    def test_for_over_int_scalar_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = 5\n"
            "    for x in n\n"
            "        stdio.print(\"${x}\")\n"
        )
        self.assertTrue(
            any("is not iterable" in m for m in msgs), msgs,
        )

    def test_for_over_list_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for x in [1, 2, 3]\n"
            "        stdio.print(\"${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_for_over_range_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        stdio.print(\"${i}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_for_over_set_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    for x in s\n"
            "        stdio.print(\"${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_for_over_string_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for c in \"abc\"\n"
            "        stdio.print(c)\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestCharStringCompat(unittest.TestCase):
    def test_one_char_literal_into_char_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let c: Char = \"a\"\n"
            "    stdio.print(\"${c}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_multi_char_literal_into_char_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let c: Char = \"abc\"\n"
        )
        self.assertTrue(
            any("expected Char" in m and "String" in m for m in msgs), msgs,
        )

    def test_string_value_into_char_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    let c: Char = s\n"
        )
        self.assertTrue(
            any("expected Char" in m and "String" in m for m in msgs), msgs,
        )

    def test_char_literal_into_string_ok(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s: String = 'z'\n"
            "    stdio.print(s)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_char_compare_against_string_iter_element_ok(self):
        # The String-iteration element is typed String; comparing it
        # to a char literal stays valid via the Char-is-a-String
        # direction, and using it as a String (interpolate, print,
        # concat, .length()) stays valid too.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    for c in s\n"
            "        if c == 'a'\n"
            "            stdio.print(c + \"!\")\n"
            "        let n = c.length()\n"
            "        stdio.print(\"${c}${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_multi_char_literal_into_char_field_rejected(self):
        msgs = errors_of(
            "type Box { c: Char }\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { c: \"ab\" }\n"
        )
        self.assertTrue(
            any("expects Char" in m and "String" in m for m in msgs), msgs,
        )

    def test_one_char_literal_into_char_field_ok(self):
        r = check(
            "type Box { c: Char }\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { c: \"a\" }\n"
            "    stdio.print(\"${b.c}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_string_value_into_char_param_rejected(self):
        msgs = errors_of(
            "fun take(c: Char) -> Char\n"
            "    return c\n"
            "fun main(stdio: Stdio)\n"
            "    let s = \"ab\"\n"
            "    let r = take(s)\n"
        )
        self.assertTrue(
            any("expects Char" in m and "String" in m for m in msgs), msgs,
        )

    def test_char_literal_into_string_param_ok(self):
        r = check(
            "fun take(s: String) -> String\n"
            "    return s\n"
            "fun main(stdio: Stdio)\n"
            "    let r = take('a')\n"
            "    stdio.print(r)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_one_char_literal_into_char_param_ok(self):
        r = check(
            "fun take(c: Char) -> Char\n"
            "    return c\n"
            "fun main(stdio: Stdio)\n"
            "    let r = take(\"a\")\n"
            "    stdio.print(\"${r}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestIndexAssignment(unittest.TestCase):
    def test_index_assign_constant_index_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var xs: List<Int> = [1, 2, 3]\n"
            "    xs[0] = 9\n"
        )
        self.assertTrue(
            any("list element is not supported" in m for m in msgs), msgs,
        )

    def test_index_assign_variable_index_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var xs: List<Int> = [1, 2, 3]\n"
            "    let i = 1\n"
            "    xs[i] = 9\n"
        )
        self.assertTrue(
            any("list element is not supported" in m for m in msgs), msgs,
        )

    def test_index_augmented_assign_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var xs: List<Int> = [1, 2, 3]\n"
            "    xs[0] += 1\n"
        )
        self.assertTrue(
            any("list element is not supported" in m for m in msgs), msgs,
        )

    def test_field_through_index_assign_ok(self):
        # Control: the struct-field-through-index form lowers via a
        # field store and must NOT be rejected.
        r = check(
            "type Cell { value: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    var xs: List<Cell> = [Cell { value: 1 }]\n"
            "    xs[0].value = 42\n"
            "    stdio.println(\"${xs[0].value}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_plain_reassignment_ok(self):
        # Control: ordinary var reassignment stays allowed.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    var x = 1\n"
            "    x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_struct_field_assign_ok(self):
        # Control: struct field-target assignment stays allowed.
        r = check(
            "type Counter { value: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    var c = Counter { value: 1 }\n"
            "    c.value = 2\n"
            "    stdio.println(\"${c.value}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestEmptyContainerElementPinning(unittest.TestCase):
    """Soundness: a container created EMPTY and UNANNOTATED (``[]``,
    ``new_map()``, ``new_set()``) has an INFERABLE element type. Handing
    it into a slot that fixes a concrete element type pins that type at the
    ORIGINAL binding, so a later read at a different, incompatible type is
    rejected at check time (instead of the two backends silently
    disagreeing). When a value is read out of such a container and the read
    does NOT itself pin the element type, it is rejected with a deferred
    "annotate the element type" diagnostic, judged only after the whole
    body has been analysed so a legitimate read-before-populate stays
    accepted. That diagnostic is a quality aid for the un-pinned case, not
    a blanket guarantee: a sole read landing directly in a concretely-typed
    slot pins the element type itself and stays silent, and such a program
    fails LOUD at run time on both backends rather than diverging."""

    def _errs(self, src: str) -> list[str]:
        return [e for e in errors_of(src) if "never used" not in e]

    # --- handoff shapes that must PIN (launder rejected) -------------

    def test_pin_via_function_arg(self):
        # The receiving function is NOT generic in the element, so its
        # concrete parameter fixes the element type at the caller's binding.
        errs = self._errs(
            "fun fill(xs: List<Int>)\n"
            "    xs.push(42)\n"
            "fun main(_s: Stdio)\n"
            "    var xs = []\n"
            "    fill(xs)\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_via_return_slot(self):
        errs = self._errs(
            "fun give(flag: Bool) -> List<Int>\n"
            "    var xs = []\n"
            "    if flag\n"
            "        return xs\n"
            "    let bad: String = xs[0]\n"
            "    return xs\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_via_struct_field_construction(self):
        errs = self._errs(
            "type Box { items: List<Int> }\n"
            "fun main(_s: Stdio)\n"
            "    let xs = []\n"
            "    let b = Box { items: xs }\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_via_struct_field_assignment(self):
        errs = self._errs(
            "type Box { items: List<Int> }\n"
            "fun main(_s: Stdio)\n"
            "    var b = Box { items: [10] }\n"
            "    let xs = []\n"
            "    b.items = xs\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_via_plain_assignment(self):
        errs = self._errs(
            "fun main(_s: Stdio)\n"
            "    var target: List<Int> = [1]\n"
            "    let xs = []\n"
            "    target = xs\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    # --- nested handoff (scenario 3) --------------------------------

    def test_pin_nested_in_tuple(self):
        errs = self._errs(
            "fun take(p: (List<Int>, Bool))\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    let xs = []\n"
            "    take((xs, true))\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_nested_in_container(self):
        errs = self._errs(
            "fun take(rows: List<List<Int>>)\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    let inner = []\n"
            "    take([inner])\n"
            "    let bad: String = inner[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    def test_pin_nested_in_struct_field_arg(self):
        errs = self._errs(
            "type Box { items: List<Int> }\n"
            "fun take(b: Box)\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    let xs = []\n"
            "    take(Box { items: xs })\n"
            "    let bad: String = xs[0]\n"
        )
        self.assertTrue(
            any("expected String, got Int" in e for e in errs), errs,
        )

    # --- map / set constructors start inferable (scenario 6) --------

    def test_new_map_populate_then_incompatible_read(self):
        errs = self._errs(
            "fun sink_s(x: String)\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    var m = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    sink_s(m.get(\"a\").unwrap())\n"
        )
        self.assertTrue(
            any("expects String, got Int" in e for e in errs), errs,
        )

    def test_new_set_populate_then_incompatible_read(self):
        errs = self._errs(
            "fun sink_s(x: String)\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    var s = new_set()\n"
            "    s.add(1)\n"
            "    for x in s\n"
            "        sink_s(x)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in e for e in errs), errs,
        )

    def test_two_incompatible_reads_first_fixing_wins(self):
        # A never-populated container read at two incompatible element
        # types: the FIRST read fixes the type, the second is rejected.
        errs = self._errs(
            "fun sink_i(x: Int)\n"
            "    return\n"
            "fun sink_s(x: String)\n"
            "    return\n"
            "fun main(_s: Stdio)\n"
            "    let xs = []\n"
            "    sink_i(xs[0])\n"
            "    sink_s(xs[0])\n"
        )
        self.assertTrue(
            any("expects String, got Int" in e for e in errs), errs,
        )

    # --- state-gate bypass ------------------------------------------

    def test_state_gate_bypass_rejected(self):
        # A Door[Closed] stashed in an unannotated list via a HANDOFF (a
        # function whose parameter fixes the element to Door[Closed]) and
        # pulled back out cannot reach an operation that requires
        # Door[Open]. Without the handoff pin the read came back at an open
        # element type, compatible with Door[Open], bypassing the gate.
        errs = self._errs(
            "typestate Door\n"
            "    Open\n"
            "    Closed\n"
            "fun needs_open(consume d: Door[Open]) -> Door[Closed]\n"
            "    return become(d, Closed)\n"
            "fun fill(xs: List<Door[Closed]>, d: Door[Closed])\n"
            "    xs.push(d)\n"
            "fun main(_s: Stdio)\n"
            "    var xs = []\n"
            "    fill(xs, Door[Closed] {})\n"
            "    let taken = xs[0]\n"
            "    let out = needs_open(taken)\n"
        )
        self.assertTrue(
            any("expects Door[Open], got Door[Closed]" in e for e in errs),
            errs,
        )

    # --- deferred never-determined guard (scenario 5) ---------------

    def test_never_determined_read_rejected(self):
        errs = self._errs(
            "fun main(s: Stdio)\n"
            "    let xs = []\n"
            "    let v = xs[0]\n"
            "    s.println(\"${v}\")\n"
        )
        self.assertTrue(
            any("never fixed anywhere in this function" in e for e in errs),
            errs,
        )

    def test_never_determined_names_the_map_kind(self):
        errs = self._errs(
            "fun main(s: Stdio)\n"
            "    var m = new_map()\n"
            "    let v = match m.get(\"a\")\n"
            "        Some(x) -> x\n"
            "        None -> panic(\"missing\")\n"
            "    s.println(\"${v}\")\n"
        )
        self.assertTrue(
            any(
                "element type of this map" in e
                and "never fixed anywhere in this function" in e
                for e in errs
            ),
            errs,
        )

    # --- legitimate patterns that must stay ACCEPTED ----------------

    def test_generic_destination_stays_open(self):
        # Handing the container to a function GENERIC in the element does
        # not pin it: polymorphic reuse across such calls stays legal.
        r = check(
            "fun store<T>(c: List<T>, x: T)\n"
            "    c.push(x)\n"
            "fun main(s: Stdio)\n"
            "    let xs = []\n"
            "    store(xs, 1)\n"
            "    store(xs, 2)\n"
            "    s.println(\"${xs[0]}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_read_before_populate_map_accepted(self):
        # get-or-default: read the map, fall back, THEN populate. The later
        # populate determines the element type, so the earlier read is fine.
        r = check(
            "fun main(s: Stdio)\n"
            "    var m = new_map()\n"
            "    let existing = match m.get(\"a\")\n"
            "        Some(v) -> v\n"
            "        None -> 0\n"
            "    m.set(\"a\", existing + 1)\n"
            "    s.println(\"${existing}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_read_before_populate_list_accepted(self):
        r = check(
            "fun main(s: Stdio)\n"
            "    var xs = []\n"
            "    let first = match xs.first()\n"
            "        Some(v) -> v\n"
            "        None -> 0\n"
            "    xs.push(first + 10)\n"
            "    s.println(\"${first}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_annotated_forms_unchanged(self):
        r = check(
            "fun main(s: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    let st: Set<Int> = new_set()\n"
            "    st.add(2)\n"
            "    let xs: List<Int> = []\n"
            "    xs.push(3)\n"
            "    s.println(\"${m.get(\"a\").unwrap()} ${xs[0]}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consistent_populate_and_read_accepted(self):
        # Populate and read at the SAME type is of course fine.
        r = check(
            "fun main(s: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(7)\n"
            "    let n: Int = xs[0]\n"
            "    s.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()

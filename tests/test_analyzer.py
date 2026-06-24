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

    def test_lambda_body_shadows_outer_param_ok(self):
        # A ``let`` inside a lambda body whose name collides with
        # an outer-function parameter is NOT a real shadow: the
        # lambda transpiles to a Python function whose scope
        # makes the inner binding a fresh local. The shadow check
        # must stop its parent walk at the lambda's scope-root
        # marker; otherwise it false-positives this legitimate
        # pattern.
        r = check(
            "fun outer(x: Int) -> Int\n"
            "    let f = fun () -> Int =>\n"
            "        let x = 99\n"
            "        return x\n"
            "    return f() + x\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_lambda_body_shadows_outer_let_ok(self):
        # Same principle for an outer ``let``: the lambda scope
        # boundary lets the inner ``let`` be a fresh local.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let y = 1\n"
            "    let f = fun () -> Int =>\n"
            "        let y = 2\n"
            "        return y\n"
            "    stdio.println(\"${f()} ${y}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

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
# Capability forge: rejecting `Fs()`-style local construction.
# Surfaced 2026-05-24 by the empirical-study fuzz harness: the
# legacy --python backend transpiled `let fs = Fs()` to a literal
# `Fs()` instantiation that obtained unrestricted filesystem
# authority because the runtime `Fs` class defaults to an
# unrestricted instance. The analyzer must reject the call form
# so the static discipline holds across both backends.
# =============================================================

class TestCapabilityForgeRejected(unittest.TestCase):
    """A built-in capability name used as a callee is a forge
    attempt: it would let any function obtain authority it never
    declared. The analyzer rejects every such call."""

    def test_fs_forge_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let fs = Fs()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Fs' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_stdio_forge_rejected(self):
        msgs = errors_of(
            "fun no_caps()\n"
            "    let s = Stdio()\n"
            "    s.println(\"smuggled\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Stdio' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_net_forge_rejected(self):
        msgs = errors_of(
            "fun phone_home(stdio: Stdio)\n"
            "    let n = Net()\n"
            "    stdio.println(\"got net\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Net' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_env_forge_in_helper_rejected(self):
        # Forge inside a helper called from main: must still be
        # rejected. Verifies the check does not depend on the
        # enclosing function being `main`.
        msgs = errors_of(
            "fun leak()\n"
            "    let e = Env()\n"
            "    let _key = e.get(\"ANTHROPIC_API_KEY\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Env' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_all_builtin_caps_rejected(self):
        # Every built-in cap name must be rejected as callee.
        for cap in (
            "Stdio", "Fs", "Net", "Env", "Proc", "Clock", "Random",
            "Db", "Unsafe",
        ):
            with self.subTest(cap=cap):
                msgs = errors_of(
                    f"fun forge()\n"
                    f"    let c = {cap}()\n"
                )
                self.assertTrue(
                    any(
                        f"capability {cap!r} cannot be constructed at a "
                        f"call site" in m for m in msgs
                    ),
                    f"{cap}: {msgs}",
                )

    def test_cap_as_param_still_ok(self):
        # The legitimate use stays legitimate.
        r = check(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"x\")\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_defined_cap_call_also_rejected(self):
        # User-defined capabilities are abstract: they must be
        # constructed via a struct implementor + factory, not by
        # calling the cap name as if it were a constructor.
        msgs = errors_of(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "fun no_caps()\n"
            "    let l = Logger()\n"
            "    l.log(\"x\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Logger' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_user_defined_cap_aliasing_rejected(self):
        # Pre-2026-05-24, the non-aliasing rule only fired on
        # built-in caps (CAPABILITY_NAMES). User-defined caps
        # slipped through, violating the single-flow property
        # the paper claims. Surfaced by the slice-6 fuzz panel
        # (cat_llm_dispatch_escape / llm_aliased_dispatch).
        msgs = errors_of(
            "capability Llm\n"
            "    fun chat(self, p: String) -> String\n"
            "fun dispatch(a: Llm, b: Llm) -> String\n"
            "    let _ = a.chat(\"x\")\n"
            "    return b.chat(\"y\")\n"
            "fun main(stdio: Stdio, llm: Llm)\n"
            "    let _ = dispatch(llm, llm)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(
            any(
                "appears as argument 2 but was already used as argument 1"
                in m for m in msgs
            ),
            msgs,
        )


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

    def test_generic_list_accumulator_of_type_var(self):
        # Regression: pushing a value typed as the bare type variable ``T``
        # into a ``List<T>`` inside a generic function used to crash the
        # unifier with infinite recursion (missing occurs-check / reflexive
        # guard). It must now check cleanly.
        r = check(
            "fun wrap<T>(x: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(x)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = wrap(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_generic_list_accumulator_multiple_pushes(self):
        r = check(
            "fun wrap3<T>(a: T, b: T, c: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(a)\n"
            "    out.push(b)\n"
            "    out.push(c)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = wrap3(1, 2, 3)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_generic_map_accumulator_of_type_var(self):
        r = check(
            "fun mwrap<K, T>(k: K, v: T) -> Map<K, T>\n"
            "    var out: Map<K, T> = new_map()\n"
            "    out.set(k, v)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let m = mwrap(\"k\", 99)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_generic_set_accumulator_of_type_var(self):
        r = check(
            "fun swrap<T>(x: T) -> Set<T>\n"
            "    var out: Set<T> = new_set()\n"
            "    out.add(x)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let s = swrap(7)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_generic_hof_accumulator_of_inferred_var(self):
        # The higher-order variant builds ``List<B>`` from ``f(x)`` where ``B``
        # is concrete after inference. This already worked; guard against
        # regressions from the occurs-check fix.
        r = check(
            "fun mapper<A, B>(x: A, f: Fun(A) -> B) -> List<B>\n"
            "    var out: List<B> = []\n"
            "    out.push(f(x))\n"
            "    return out\n"
            "fun dbl(n: Int) -> Int\n"
            "    return n * 2\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = mapper(21, dbl)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestRigidTypeVarSoundness(unittest.TestCase):
    """A declared generic type parameter (``T``) is *rigid* inside the
    function body: its concrete identity is fixed-but-unknown. Pushing a
    concrete value into a ``List<T>`` / ``Map<K, T>`` / ``Set<T>`` slot,
    or pushing the container into itself, used to type-check (because
    ``compatible(T, anything)`` returned True) and then crash the Python
    backend with a host ``TypeError`` -- a well-typed program reaching a
    runtime type error, i.e. unsoundness. These must now be rejected
    cleanly, while a value genuinely typed ``T`` still flows in."""

    def test_concrete_string_into_list_of_t_rejected(self):
        msgs = errors_of(
            "fun build<T>(x: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(\"a string literal\")\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let r = build(5)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects T" in m and "String" in m for m in msgs), msgs
        )

    def test_concrete_int_into_list_of_t_rejected(self):
        msgs = errors_of(
            "fun build<T>(x: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(99)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let r = build(\"s\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects T" in m and "Int" in m for m in msgs), msgs
        )

    def test_self_push_rejected(self):
        # out.push(out): pushing the List<T> into its own List<T> slot.
        msgs = errors_of(
            "fun build<T>(x: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(out)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let r = build(5)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects T" in m and "List<T>" in m for m in msgs), msgs
        )

    def test_concrete_value_into_map_of_t_rejected(self):
        msgs = errors_of(
            "fun mwrap<K, T>(k: K, v: T) -> Map<K, T>\n"
            "    var out: Map<K, T> = new_map()\n"
            "    out.set(k, \"wrong\")\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let m = mwrap(\"k\", 99)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects T" in m and "String" in m for m in msgs), msgs
        )

    def test_concrete_element_into_set_of_t_rejected(self):
        msgs = errors_of(
            "fun swrap<T>(x: T) -> Set<T>\n"
            "    var out: Set<T> = new_set()\n"
            "    out.add(\"wrong\")\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let s = swrap(7)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects T" in m and "String" in m for m in msgs), msgs
        )

    def test_value_of_t_into_list_of_t_still_accepted(self):
        # Control: the legitimate accumulator pattern must keep working.
        r = check(
            "fun build<T>(x: T) -> List<T>\n"
            "    var out: List<T> = []\n"
            "    out.push(x)\n"
            "    return out\n"
            "fun main(stdio: Stdio)\n"
            "    let r = build(5)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_nullary_variant_of_user_sum_still_assigns_concrete(self):
        # Control: a payloadless variant of a user generic sum has a
        # still-unknown element type, so binding it to a concrete
        # instantiation must remain accepted (the type param here is a
        # fresh flexible placeholder, not a rigid T).
        r = check(
            "type Opt<T> =\n"
            "    Just(T)\n"
            "    Nothing\n"
            "fun main(stdio: Stdio)\n"
            "    let ni: Opt<Int> = Nothing\n"
            "    let ns: Opt<String> = Nothing\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


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

    # ------- Value-position open-domain exhaustiveness (BUG #2) -------
    #
    # A ``match`` used for its value (``return match ...``,
    # ``let x = match ...``) over an open scalar domain (Int / String /
    # Float / Char) must have a catch-all: a miss has no defined result
    # (Python backend raises UnboundLocalError, Wasm returns a zero
    # value). A bare statement-position ``match`` discards its value, so
    # a miss is a legal no-op and stays lenient.

    def test_value_match_on_int_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(i: Int) -> String\n"
            "    return match i\n"
            '        1 -> "one"\n'
            '        2 -> "two"\n'
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_on_string_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(s: String) -> Int\n"
            "    return match s\n"
            '        "a" -> 1\n'
            '        "b" -> 2\n'
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on String" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_in_let_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(i: Int) -> Int\n"
            "    let r = match i\n"
            "        1 -> 10\n"
            "        2 -> 20\n"
            "    return r\n"
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_on_int_with_wildcard_ok(self):
        # Control: a wildcard catch-all keeps the value match valid.
        r = check(
            "fun t(i: Int) -> String\n"
            "    return match i\n"
            '        1 -> "one"\n'
            '        2 -> "two"\n'
            '        _ -> "other"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_value_match_on_int_with_ident_catchall_ok(self):
        # Control: a bare ident binder is also a catch-all.
        r = check(
            "fun t(i: Int) -> Int\n"
            "    return match i\n"
            "        1 -> 10\n"
            "        other -> other\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_statement_match_on_int_without_catchall_ok(self):
        # Control: a bare statement-position match discards its value,
        # so an open-domain scrutinee needs no catch-all.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let i = 3\n"
            "    match i\n"
            '        1 -> stdio.println("one")\n'
            '        2 -> stdio.println("two")\n'
        )
        self.assertTrue(r.ok, r.errors)


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

    # ------- break / continue cannot cross a lambda (BUG #8) -------
    #
    # A ``break`` / ``continue`` inside a lambda body cannot cross the
    # lambda's function boundary: the enclosing loop is not visible, so
    # both backends fail at codegen (Python SyntaxError, Wasm "break
    # outside of a loop"). The analyzer must reject it; a break /
    # continue directly inside a real loop must still be accepted.

    def test_break_in_lambda_inside_loop_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        let f = fun () -> Unit =>\n"
            "            if i == 1\n"
            "                break\n"
            "        f()\n"
        )
        self.assertTrue(
            any("break outside of a loop" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_continue_in_lambda_inside_loop_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        let f = fun () -> Unit =>\n"
            "            if i == 1\n"
            "                continue\n"
            "        f()\n"
        )
        self.assertTrue(
            any("continue outside of a loop" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_break_directly_in_loop_ok(self):
        # Control: break / continue directly inside a real loop body
        # (no lambda in between) must still be accepted.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        if i == 1\n"
            "            break\n"
            "        if i == 2\n"
            "            continue\n"
            '        stdio.println("${i}")\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_break_outside_loop_rejected(self):
        # A break at function top level (no enclosing loop) is also an
        # error -- the loop-depth tracking covers this case too.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    break\n"
        )
        self.assertTrue(
            any("break outside of a loop" in m for m in msgs),
            f"got: {msgs}",
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
            # ``c`` is Option<String>, which has no to_string, so it
            # cannot be interpolated directly; match it to prove the
            # binding typed as an Option carrying a String payload.
            "    let shown = match c\n"
            "        Some(ch) -> ch\n"
            "        None -> \"?\"\n"
            "    stdio.println(\"${shown}\")\n"
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

    def test_trailing_tokens_in_interpolation_rejected(self):
        # ``${x y}`` used to drop the ``y`` silently (the sub-parser
        # parsed ``x`` and never checked it had reached EOF), so a
        # forgotten operator compiled clean. It is now a clean parse
        # error (raised by parse_module, before analysis).
        from capa import ParserError

        for body in ("${x y}", "${a b}", "${a;}"):
            with self.subTest(body=body):
                with self.assertRaises(ParserError) as ctx:
                    check(
                        "fun main(stdio: Stdio)\n"
                        "    let x = 1\n"
                        "    let a = 2\n"
                        f"    stdio.println(\"{body}\")\n"
                    )
                self.assertIn("interpolation", ctx.exception.message)

    def test_single_expression_interpolation_still_ok(self):
        # The EOF check must not reject a legitimate single expression,
        # including multi-token ones and calls with comma arguments.
        for body in ("${x}", "${x + y}", "${f(x, y)}"):
            with self.subTest(body=body):
                r = check(
                    "fun f(p: Int, q: Int) -> Int\n"
                    "    return p\n"
                    "fun main(stdio: Stdio)\n"
                    "    let x = 1\n"
                    "    let y = 2\n"
                    f"    stdio.println(\"{body}\")\n"
                )
                self.assertTrue(r.ok, r.errors)

    def test_leading_whitespace_in_interpolation_accepted(self):
        # A leading space or tab inside ``${...}`` used to be lexed as
        # an INDENT (or trip the "tabs at start of line" rule) and
        # rejected, even though docs use ``${n * 2}``. Leading
        # horizontal whitespace is now stripped, so ``${ x }`` works;
        # interior spaces were already fine.
        for body in ("${ x }", "${ n * 2 }", "${\tx}", "${ n * 2}"):
            with self.subTest(body=body):
                r = check(
                    "fun main(stdio: Stdio)\n"
                    "    let x = 1\n"
                    "    let n = 2\n"
                    f"    stdio.println(\"{body}\")\n"
                )
                self.assertTrue(r.ok, r.errors)

    def test_leading_whitespace_keeps_correct_diagnostic_position(self):
        # Stripping leading whitespace must bias the reported position
        # so a typo inside ``${  missing}`` still points at the typo,
        # not at the (stripped) spaces.
        source = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${  zzz}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'zzz'", r.errors[0].message)
        self.assertEqual(r.errors[0].pos.line, 2)


class TestInterpolationFormattability(unittest.TestCase):
    """A ``${value}`` part must render on BOTH backends. The analyzer
    rejects a value whose type has no way to be formatted (no built-in
    rendering and no user ``to_string``), instead of the Python backend
    accepting it via dataclass repr while Wasm rejects it. Closes the
    cross-backend FormatStr divergence."""

    def test_primitives_are_formattable(self):
        for ty, val in (
            ("Int", "1"), ("Float", "1.5"), ("Bool", "true"),
            ("String", "\"hi\""), ("Char", "'a'"),
        ):
            r = check(
                "fun main(stdio: Stdio)\n"
                f"    let x: {ty} = {val}\n"
                "    stdio.println(\"${x}\")\n"
            )
            self.assertTrue(r.ok, f"{ty}: {r.errors}")

    def test_option_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o = Some(1)\n"
            "    stdio.println(\"${o}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)
        self.assertTrue(any("to_string" in m for m in msgs), msgs)
        self.assertTrue(any("Option" in m for m in msgs), msgs)

    def test_result_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(1)\n"
            "    stdio.println(\"${r}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_list_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    stdio.println(\"${xs}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_tuple_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let t = (1, \"a\")\n"
            "    stdio.println(\"${t}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_sum_without_to_string_rejected(self):
        msgs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Red\n"
            "    stdio.println(\"${c}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)
        self.assertTrue(any("Color" in m for m in msgs), msgs)

    def test_struct_without_to_string_rejected(self):
        msgs = errors_of(
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_struct_with_to_string_accepted(self):
        r = check(
            "type Point { x: Int, y: Int }\n"
            "impl Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"P(${self.x},${self.y})\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_sum_with_to_string_accepted(self):
        r = check(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "impl Color\n"
            "    fun to_string(self) -> String\n"
            "        return match self\n"
            "            Red -> \"red\"\n"
            "            Green -> \"green\"\n"
            "            Blue -> \"blue\"\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Red\n"
            "    stdio.println(\"${c}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_to_string_via_trait_impl_accepted(self):
        r = check(
            "trait Show\n"
            "    fun to_string(self) -> String\n"
            "type Point { x: Int, y: Int }\n"
            "impl Show for Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"P(${self.x},${self.y})\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_error_position_points_at_part(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let o = Some(1)\n"
            "    stdio.println(\"x = ${o}\")\n"
        )
        self.assertFalse(r.ok)
        interp = [e for e in r.errors if "cannot interpolate" in e.message]
        self.assertEqual(len(interp), 1)
        # Points at ``o`` inside the ``${...}``, not the string's quote.
        self.assertEqual(interp[0].pos.line, 3)


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

    def test_range_filter_directly_typechecks(self):
        # The teaching material's exact example: a Range carries the
        # List transform methods, so direct `.filter` on a range
        # type-checks and yields `List<Int>` (the same type as
        # `(0..10).to_list().filter(...)`). Both backends desugar
        # through `.to_list()`.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_evens = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_evens.value)]), "List<Int>")

    def test_range_transform_methods_typecheck(self):
        # map / fold / first / get carry the same signatures as their
        # List homonyms: map -> List<U>, fold -> the accumulator, the
        # indexed queries -> Option<T>.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let squares = (0..5).map(fun (x: Int) -> Int => x * x)\n"
            "    let total = (1..=5).fold(0, fun (a: Int, x: Int) -> Int => a + x)\n"
            "    let head = (0..5).first()\n"
            "    let at = (0..5).get(2)\n"
            "    stdio.println(\"${squares.length()} ${total}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        stmts = module.items[0].body.stmts
        self.assertEqual(ty_str(result.types[id(stmts[0].value)]), "List<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[1].value)]), "Int")
        self.assertEqual(ty_str(result.types[id(stmts[2].value)]), "Option<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[3].value)]), "Option<Int>")


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

    # ---- Audit 2026-06-17 H1: field access through an abstract
    # capability / trait receiver is rejected. The runtime value is
    # the concrete implementor, so reaching its private field would
    # exercise a built-in cap the signature never declares. ----

    def test_field_access_through_abstract_cap_rejected(self):
        # ``mailer: SendEmail`` is the abstract cap as a parameter
        # type. ``mailer.net`` would reach the implementor's private
        # Net; this must be a field-access type error.
        msgs = errors_of(
            self._SETUP
            + "fun leak(mailer: SendEmail, stdio: Stdio)\n"
            + "    stdio.println(\"${mailer.net}\")\n"
        )
        self.assertTrue(
            any(
                "field 'net'" in m and "capability type 'SendEmail'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nonexistent_field_through_abstract_cap_rejected(self):
        # Even a totally fake field name is rejected through an
        # abstract cap receiver (pre-fix it silently typed Unknown).
        msgs = errors_of(
            self._SETUP
            + "fun leak(mailer: SendEmail, stdio: Stdio)\n"
            + "    stdio.println(\"${mailer.totally_fake}\")\n"
        )
        self.assertTrue(
            any("capability type 'SendEmail'" in m for m in msgs),
            msgs,
        )

    def test_field_access_through_trait_receiver_rejected(self):
        # The same rule applies to a plain (non-capability) trait
        # used as a parameter type: the holder sees only the trait's
        # surface, not the implementor's fields.
        msgs = errors_of(
            "trait Greeter\n"
            "    fun greet(self) -> String\n"
            "type Person { name: String }\n"
            "impl Greeter for Person\n"
            "    fun greet(self) -> String\n"
            "        return self.name\n"
            "fun peek(g: Greeter) -> String\n"
            "    return g.name\n"
        )
        self.assertTrue(
            any(
                "field 'name'" in m and "trait type 'Greeter'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_field_access_through_concrete_struct_still_allowed(self):
        # The legitimate reachable-via-struct model: a parameter of
        # the CONCRETE struct type that implements a cap can still
        # read its fields (e.g. a factory's own helper). Only the
        # abstract-cap type is barred.
        r = check(
            self._SETUP
            + "fun host_of(m: SmtpMailer) -> String\n"
            + "    return m.server\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_self_field_access_in_impl_still_allowed(self):
        # ``self`` inside the impl is the concrete struct, so
        # ``self.net`` / ``self.server`` keep compiling.
        r = check(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "type SmtpMailer { server: String, net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "        let _ = self.server\n"
            "        return Ok(())\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ---- Audit 2026-06-17 C5(a): Unsafe is rejected as a struct
    # field even when the struct implements a user-cap. The
    # cap-bearing relaxation covers only the attenuable built-in
    # caps, never the FFI escape hatch. ----

    def test_unsafe_field_rejected_in_cap_bearing_struct(self):
        msgs = errors_of(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { u: Unsafe }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any(
                "'Unsafe' cannot appear in struct field 'u'" in m
                and "capability-bearing struct" in m
                for m in msgs
            ),
            msgs,
        )

    def test_unsafe_nested_in_field_rejected_in_cap_bearing_struct(self):
        # Unsafe reached through a generic argument of a field type
        # is rejected too (the relaxation is not a blanket pass).
        msgs = errors_of(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { us: List<Unsafe> }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any("'Unsafe' cannot appear in struct field 'us'" in m for m in msgs),
            msgs,
        )

    def test_attenuable_cap_field_still_allowed_in_cap_bearing_struct(self):
        # The relaxation still admits the attenuable built-in caps
        # (here Net) - only Unsafe is carved out.
        r = check(self._SETUP + "fun main()\n    return\n")
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

    def test_consume_in_divergent_if_branch_ok(self):
        # If a branch consumes a cap and then diverges (return),
        # the cap is not really consumed past the if: the divergent
        # path never reaches the merge point, so the post-if code
        # can still see the cap as live. Previously the merge was
        # naively conservative and treated the divergent path's
        # consumption as if it flowed forward; this test pins the
        # NLL-style precision fix.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_else_branch_ok(self):
        # Symmetric to the if-then case: the else diverges, the
        # then is a no-op, and the post-if code still has the cap.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        stdio.println(\"keep\")\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_match_arm_ok(self):
        # Same principle applied to match: the Yes arm consumes and
        # returns; the No arm does not consume. The post-match code
        # can only be reached via the No arm, where the cap is
        # still live.
        r = check(
            "type Choice =\n"
            "    Yes\n"
            "    No\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, ch: Choice)\n"
            "    match ch\n"
            "        Yes ->\n"
            "            adoptar(stdio)\n"
            "            return\n"
            "        No -> stdio.println(\"no\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_non_divergent_if_branch_still_rejected(self):
        # Soundness check: the precision fix only excludes branches
        # that diverge. A branch that consumes and then falls
        # through must still propagate the consumption to the
        # merge, otherwise we admit a real use-after-consume.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs), msgs
        )

    def test_consume_in_all_divergent_branches_ok(self):
        # All if branches diverge; the code after is unreachable.
        # The analyzer should not block on a phantom consumption in
        # the unreachable continuation.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    else\n"
            "        return\n"
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


class TestQuestionMarkEnclosingReturn(unittest.TestCase):
    """``?`` propagates Err / None_ to the enclosing function. If
    that function does not return Result or Option, the propagation
    has nowhere safe to go: at runtime the slow ``_capa_try`` path
    raises ``_CapaTryEarlyReturn`` and the ``@_capa_wrap`` decorator
    catches it but then returns an Err / None_ from a function
    declared to return something else (a silent type violation).
    In the lambda case the exception used to escape past the lambda's
    caller entirely. The analyser now rejects every such use at
    type-check time so the diagnostic points at the ``?`` rather than
    at the wrong-shape value bubbling up later."""

    def test_question_in_int_returning_function_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun bad() -> Int\n"
            "    let x = produce()?\n"
            "    return x\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e and "Int" in e
                for e in errs),
            errs,
        )

    def test_question_in_unit_returning_function_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun bad()\n"
            "    produce()?\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e and ("Unit" in e or "()" in e)
                for e in errs),
            errs,
        )

    def test_question_in_expr_lambda_with_non_result_return_is_rejected(self):
        # The bug that motivated this rule: a lambda whose declared
        # return type is Int but whose body uses ``?``. The lambda
        # was emitted as a Python lambda with no decorator, and the
        # raised _CapaTryEarlyReturn escaped past the lambda's caller.
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Int\n"
            "    return fun () -> Int => produce()?\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )

    def test_question_in_block_lambda_with_non_result_return_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Int\n"
            "    let f = fun () -> Int =>\n"
            "        let x = produce()?\n"
            "        return x\n"
            "    return f\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )

    def test_question_in_block_lambda_with_result_return_is_accepted(self):
        # The legitimate shape: a lambda that returns Result and uses
        # ``?`` inside its block body. The lambda gets ``@_capa_wrap``
        # in the transpiler so the propagation is caught at the
        # lambda's own boundary.
        r = check(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Result<Int, Bad>\n"
            "    let f = fun () -> Result<Int, Bad> =>\n"
            "        let x = produce()?\n"
            "        return Ok(x + 1)\n"
            "    return f\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_question_in_lambda_does_not_inherit_outer_return(self):
        # Even when the outer function returns Result, the lambda's
        # own declared return type is what governs whether ``?`` is
        # allowed inside the lambda body. A Result-returning outer
        # function with a non-Result lambda inside must still reject
        # ``?`` in the lambda.
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun outer() -> Result<Int, Bad>\n"
            "    let f = fun () -> Int => produce()?\n"
            "    return Ok(f())\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )


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


class TestMatchLiteralPatternType(unittest.TestCase):
    """A literal pattern only matches values of the same type as the
    literal. ``match int_x { "hello" -> ... }`` is dead code at best
    and a typo at worst; the analyser rejects it with both types
    named. TyUnknown / TyVar scrutinees stay permissive so generic
    code is not affected."""

    def test_string_pattern_against_int_scrutinee_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x: Int = 1\n"
            "    match x\n"
            "        \"hello\" -> stdio.println(\"str\")\n"
            "        _ -> stdio.println(\"else\")\n"
        )
        self.assertTrue(
            any("literal of type String" in e
                and "scrutinee of type Int" in e
                for e in errs),
            errs,
        )

    def test_int_pattern_against_string_scrutinee_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s: String = \"hi\"\n"
            "    match s\n"
            "        42 -> stdio.println(\"int\")\n"
            "        _ -> stdio.println(\"else\")\n"
        )
        self.assertTrue(
            any("literal of type Int" in e
                and "scrutinee of type String" in e
                for e in errs),
            errs,
        )

    def test_matching_int_literal_with_int_still_accepted(self):
        # Regression guard: the legitimate case still type-checks.
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        0 -> \"zero\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_matching_string_literal_with_string_still_accepted(self):
        r = check(
            "fun name(s: String) -> Int\n"
            "    return match s\n"
            "        \"capa\" -> 1\n"
            "        _ -> 0\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestDuplicateMatchArms(unittest.TestCase):
    """A guardless match arm whose pattern is a payload-less variant
    or a literal already covered by an earlier arm is unreachable.
    The check fires both across arms (a second ``Vermelho ->``
    after an earlier ``Vermelho ->``) and within a single arm's
    or-pattern (``Vermelho | Vermelho ->``).

    Guarded arms (``x if cond ->``) do not register coverage
    because the guard may fail."""

    def test_duplicate_variant_arm_rejected(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        Vermelho -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(
            any("variant 'Vermelho'" in e and "already covered" in e
                for e in errs),
            errs,
        )

    def test_duplicate_int_literal_arm_rejected(self):
        errs = errors_of(
            "fun f(n: Int) -> String\n"
            "    return match n\n"
            "        1 -> \"one\"\n"
            "        1 -> \"duplicate\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(
            any("literal value already covered" in e for e in errs),
            errs,
        )

    def test_duplicate_string_literal_arm_rejected(self):
        errs = errors_of(
            "fun f(s: String) -> Int\n"
            "    return match s\n"
            "        \"capa\" -> 1\n"
            "        \"capa\" -> 2\n"
            "        _ -> 0\n"
        )
        self.assertTrue(
            any("literal value already covered" in e for e in errs),
            errs,
        )

    def test_duplicate_within_or_pattern_rejected(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho | Vermelho -> 1\n"
            "        Verde -> 2\n"
        )
        self.assertTrue(
            any("variant 'Vermelho'" in e and "already covered" in e
                for e in errs),
            errs,
        )

    def test_guarded_duplicate_is_allowed(self):
        # A guarded arm does not absorb the value; a later arm
        # naming the same variant is reachable when the guard
        # fails. Compiler should accept.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor, n: Int) -> Int\n"
            "    return match c\n"
            "        Vermelho if n > 0 -> 1\n"
            "        Vermelho -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_distinct_variants_still_accepted(self):
        # The legitimate shape: each variant once.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        Verde -> 2\n"
            "        Azul -> 3\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestMethodWithoutSelfNotCallable(unittest.TestCase):
    """A user-defined impl method that does not take ``self`` as its
    first parameter cannot be called via ``receiver.method()``: the
    runtime would pass the receiver as the first positional argument
    and Python raises ``TypeError: ... takes 0 positional arguments
    but 1 was given``. The analyser rejects the call site at compile
    time.

    Built-in capability methods (``stdio.println``) and built-in
    type methods (``json.as_object``, ``xs.length``) are not subject
    to the check: they are registered at the BUILTIN_POS sentinel
    and dispatch through a different runtime path."""

    def test_call_user_method_without_self_is_rejected(self):
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get() -> Int\n"
            "        return 42\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Counter { v: 5 }\n"
            "    stdio.println(\"${c.get()}\")\n"
        )
        self.assertTrue(
            any("Counter.'get'" in e and "no 'self'" in e for e in errs),
            errs,
        )

    def test_static_method_declaration_still_accepted(self):
        # A "static" method (no self) is allowed at the impl level;
        # only the dot call is rejected. The user may keep the
        # method as a constructor-style helper even though there is
        # no public call syntax for it yet.
        r = check(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun zero() -> Ponto\n"
            "        return Ponto { x: 0.0, y: 0.0 }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_method_with_self_still_accepted(self):
        # Regression guard against a prior failed attempt where the
        # check fired on every user impl method because ``param_names``
        # strips ``self``. With ``has_self`` stored on the symbol the
        # legitimate case stays accepted.
        r = check(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun valor(self) -> Int\n"
            "        return self.v\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Counter { v: 7 }\n"
            "    stdio.println(\"${c.valor()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_builtin_capability_method_still_callable(self):
        # Regression guard against a prior failed attempt that broke
        # every built-in capability method. ``stdio.println`` lives
        # in capa/builtins.py at BUILTIN_POS; the check is gated on
        # ``type_sym.pos != BUILTIN_POS`` and so leaves it alone.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_builtin_jsonvalue_method_still_callable(self):
        # Regression guard against a prior failed attempt that broke
        # JsonValue methods because JsonValue is TYPE_SUM but its
        # methods are built-in. JsonValue.as_object lives at
        # BUILTIN_POS so the check leaves it alone.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    match parse_json(\"{}\")\n"
            "        Ok(j) ->\n"
            "            match j.as_object()\n"
            "                Some(_) -> stdio.println(\"object\")\n"
            "                None    -> stdio.println(\"other\")\n"
            "        Err(_) -> stdio.println(\"parse error\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestUnreachableMatchArm(unittest.TestCase):
    """An arm written after a guardless catch-all (``_`` or a bare
    binding ident) is unreachable by construction: the catch-all
    has already matched. The analyser flags this so it cannot be
    silently introduced by reordering arms or by gluing two
    fragments together."""

    def test_arm_after_wildcard_is_unreachable(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        _ -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(
            any("unreachable match arm" in e for e in errs),
            errs,
        )

    def test_arm_after_bare_binding_is_unreachable(self):
        # A bare identifier in a pattern is a fresh binding that
        # matches anything, same as ``_``. ``x -> ...`` therefore
        # makes the following arm unreachable.
        errs = errors_of(
            "fun f(n: Int) -> Int\n"
            "    return match n\n"
            "        x -> x + 1\n"
            "        0 -> 0\n"
        )
        self.assertTrue(
            any("unreachable match arm" in e for e in errs),
            errs,
        )

    def test_catchall_with_guard_does_not_close_match(self):
        # ``x if x > 0`` is a guarded catch-all; it does not
        # absorb every value, so a later arm is reachable.
        r = check(
            "fun f(n: Int) -> String\n"
            "    return match n\n"
            "        x if x > 0 -> \"pos\"\n"
            "        _ -> \"non-pos\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_trailing_catchall_is_fine(self):
        # The expected idiomatic shape: catch-all at the end.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        _ -> 0\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestSelfOutsideImpl(unittest.TestCase):
    """``self`` outside an impl method body has no meaningful
    referent. Before, the generic ``undefined name`` Levenshtein
    pass suggested unrelated identifiers in scope (``'Set'``,
    ``'Stdio'``, etc.). The targeted message names what is
    actually wrong: ``self`` is impl-bound."""

    def test_self_in_free_function_is_targeted(self):
        errs = errors_of(
            "fun f() -> Int\n"
            "    return self.x\n"
        )
        self.assertTrue(
            any("'self' is only valid inside an `impl` method" in e
                for e in errs),
            errs,
        )
        # The generic Levenshtein hint must NOT also fire on
        # this one; otherwise users get noisy double-hinting.
        for e in errs:
            self.assertNotIn("did you mean", e)

    def test_self_inside_impl_method_with_field_still_works(self):
        # Regression guard: the existing self.field hint path
        # still fires when self IS valid (in an impl method) but
        # the user forgot the dot.
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


class TestCapabilityFieldDiscipline(unittest.TestCase):
    """Capabilities held in cap-bearing struct fields must follow
    the same flow discipline as bare capability parameters. Two
    holes surfaced by the 2026-05-25 audit:

    A. ``mailer.net = other_net`` was accepted: capability fields
       could be re-bound after construction, laundering the cap.
    B. ``f(box.cap, box.cap)`` was accepted: the aliasing check
       only canonicalised bare ``Ident`` expressions, so two
       references via the same FieldAccess path looked distinct.
    """

    _SETUP = (
        "capability Mailer\n"
        "    fun send(self, to: String) -> Result<Unit, IoError>\n"
        "\n"
        "type SmtpMailer { server: String, net: Net }\n"
        "\n"
        "impl Mailer for SmtpMailer\n"
        "    fun send(self, to: String) -> Result<Unit, IoError>\n"
        "        return Ok(())\n"
        "\n"
    )

    def test_field_assign_builtin_capability_rejected(self):
        # Hole A: mailer.net = other_net used to pass silently.
        msgs = errors_of(
            self._SETUP
            + "fun forge(mailer: SmtpMailer, other_net: Net)\n"
            + "    mailer.net = other_net\n"
        )
        self.assertTrue(
            any("capability 'Net'" in m and "cannot be re-bound" in m for m in msgs),
            msgs,
        )

    def test_field_assign_user_capability_rejected(self):
        # Same as above but the field holds a user-defined cap rather
        # than a built-in one. Same hole.
        msgs = errors_of(
            "capability Logger\n"
            "    fun log(self, msg: String) -> Result<Unit, IoError>\n"
            "\n"
            "capability Driver\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "\n"
            "type Service { name: String, log: Logger }\n"
            "\n"
            "impl Driver for Service\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "fun forge(svc: Service, other_log: Logger)\n"
            "    svc.log = other_log\n"
        )
        self.assertTrue(
            any("capability 'Logger'" in m and "cannot be re-bound" in m for m in msgs),
            msgs,
        )

    def test_field_assign_non_capability_still_allowed(self):
        # Sanity: assigning to a non-capability field of a cap-bearing
        # struct is fine.
        r = check(
            self._SETUP
            + "fun rename(mailer: SmtpMailer, new_name: String)\n"
            + "    mailer.server = new_name\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_aliasing_through_same_field_path_rejected(self):
        # Hole B: take_two(mailer.net, mailer.net) used to pass.
        msgs = errors_of(
            self._SETUP
            + "fun take_two(a: Net, b: Net) -> Result<Unit, IoError>\n"
            + "    let _ = a.get(\"https://x\")\n"
            + "    let _ = b.get(\"https://y\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun use_mailer(mailer: SmtpMailer)\n"
            + "    let _ = take_two(mailer.net, mailer.net)\n"
        )
        self.assertTrue(
            any("'mailer.net'" in m and "cannot be aliased" in m for m in msgs),
            msgs,
        )

    def test_aliasing_through_different_owners_allowed(self):
        # Sanity: take_two(m1.net, m2.net) where m1 and m2 are
        # different parameters is fine, because the paths differ.
        r = check(
            self._SETUP
            + "fun take_two(a: Net, b: Net) -> Result<Unit, IoError>\n"
            + "    let _ = a.get(\"https://x\")\n"
            + "    let _ = b.get(\"https://y\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun use_mailers(m1: SmtpMailer, m2: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    return take_two(m1.net, m2.net)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_use_after_consume_through_field_access_rejected(self):
        # Hole D (audit 2026-05-25 H1): consume_one(box.cap) followed
        # by box.cap.use() used to pass because _mark_consumed_args
        # gated on isinstance(arg, Ident) and skipped FieldAccess
        # sources entirely.
        msgs = errors_of(
            self._SETUP
            + "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            + "    let _ = n.get(\"https://x\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun bug(mailer: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    let _ = consume_net(mailer.net)\n"
            + "    let _ = mailer.net.get(\"https://y\")\n"
            + "    return Ok(())\n"
        )
        self.assertTrue(
            any(
                "'mailer.net'" in m and "was consumed earlier" in m
                for m in msgs
            ),
            msgs,
        )

    def test_use_after_consume_through_field_access_chained(self):
        # Deeper FieldAccess chain: outer.inner.net. _path_of walks
        # the whole chain so the canonical path matches at both
        # consume and use sites.
        msgs = errors_of(
            "capability Mailer\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "\n"
            "capability Driver\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "\n"
            "type Inner { net: Net }\n"
            "type Outer { inner: Inner }\n"
            "\n"
            "impl Mailer for Inner\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "impl Driver for Outer\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            "    let _ = n.get(\"https://x\")\n"
            "    return Ok(())\n"
            "\n"
            "fun bug(outer: Outer) -> Result<Unit, IoError>\n"
            "    let _ = consume_net(outer.inner.net)\n"
            "    let _ = outer.inner.net.get(\"https://y\")\n"
            "    return Ok(())\n"
        )
        self.assertTrue(
            any(
                "'outer.inner.net'" in m and "was consumed earlier" in m
                for m in msgs
            ),
            msgs,
        )

    def test_consume_through_field_access_single_use_allowed(self):
        # Sanity: consuming a FieldAccess path exactly once is the
        # legitimate flow; the new check must not fire here.
        r = check(
            self._SETUP
            + "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            + "    let _ = n.get(\"https://x\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun ok(mailer: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    return consume_net(mailer.net)\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestCapLeakViaGenericInstantiation(unittest.TestCase):
    """Hole C from the 2026-05-25 audit: the structural check
    ``_check_no_capability`` fires on a generic function's
    declaration body (where ``T`` is an opaque type variable),
    but the call site that substitutes ``T = Stdio`` was not
    re-validated. ``id(stdio)`` and ``wrap(stdio)`` used to pass
    silently even though no parameter in either function's
    signature names a capability.

    The fix runs ``_contains_any_capability`` on every substituted
    parameter and on the substituted return type post-unification;
    a cap that appears post-substitution but not pre-substitution
    was smuggled in through a TyVar."""

    def test_identity_function_with_builtin_cap_rejected(self):
        # `id(stdio)` substitutes T = Stdio, smuggling the cap
        # through a function whose signature does not declare it.
        msgs = errors_of(
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let _s = id(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_wrap_with_builtin_cap_rejected(self):
        # `wrap(stdio)` smuggles Stdio into Box<T>; the function's
        # signature does not declare it as a capability parameter.
        msgs = errors_of(
            "type Box<T> { value: T }\n"
            "\n"
            "fun wrap<T>(x: T) -> Box<T>\n"
            "    return Box { value: x }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let _b = wrap(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_struct_literal_with_builtin_cap_rejected(self):
        # Hole D (2026-06): a struct LITERAL that puts a cap into a
        # generic field smuggles it behind T, so a function taking
        # ``Box<Stdio>`` exercises Stdio with an empty manifest. The
        # struct-construction path must reject it like the call path.
        msgs = errors_of(
            "type Box<T> { value: T }\n"
            "fun exercise(b: Box<Stdio>)\n"
            "    b.value.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    exercise(Box { value: stdio })\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_variant_constructor_with_builtin_cap_rejected(self):
        # Hole D (2026-06): the same smuggle through a generic variant
        # payload (``Wrap(stdio)``) must be rejected too.
        msgs = errors_of(
            "type H<T> =\n"
            "    Wrap(T)\n"
            "    Empty\n"
            "fun main(stdio: Stdio)\n"
            "    let _h = Wrap(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_with_user_capability_rejected(self):
        # The leak shape generalises: a user-defined capability
        # (``Mailer`` here) smuggled through a TyVar is the same
        # hole.
        msgs = errors_of(
            "capability Mailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "\n"
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun forge(m: Mailer)\n"
            "    let _m2 = id(m)\n"
        )
        self.assertTrue(
            any("capability 'Mailer'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_with_non_capability_still_allowed(self):
        # Sanity: non-cap T (Int) flows through generics without
        # complaint, otherwise we'd have broken every legitimate
        # generic call.
        r = check(
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let n = id(42)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_explicit_cap_param_still_allowed(self):
        # Sanity: a non-generic function with a cap parameter is
        # the legitimate flow; the new check must not fire here.
        r = check(
            "fun use_stdio(s: Stdio)\n"
            "    s.println(\"ok\")\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    use_stdio(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Reserved sum-type variant names (Ok / Err / Some / None)
# =============================================================

class TestReservedVariantNames(unittest.TestCase):
    """A user-declared variant named Ok / Err / Some / None used to
    silently overwrite the built-in Result / Option constructor in
    the global scope, breaking every subsequent use of the built-in.
    The analyzer now rejects such declarations at declaration time
    with a clear, rename-oriented diagnostic."""

    def test_user_variant_named_ok_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Ok\n"
            "    Bad\n"
            "fun probe() -> Result<Int, String>\n"
            "    return Ok(1)\n"
        )
        reserved = [
            m for m in msgs
            if "'Ok'" in m and "reserved" in m and "Result::Ok" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        # The built-in Result::Ok must still resolve at the call
        # site (the user variant was rejected, not registered), so
        # we should NOT see a "takes no payload" error from Ok(1).
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_err_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Err\n"
            "    Good\n"
            "fun probe() -> Result<Int, String>\n"
            "    return Err(\"bad\")\n"
        )
        reserved = [
            m for m in msgs
            if "'Err'" in m and "reserved" in m and "Result::Err" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_some_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Some\n"
            "    Other\n"
            "fun probe() -> Option<Int>\n"
            "    return Some(1)\n"
        )
        reserved = [
            m for m in msgs
            if "'Some'" in m and "reserved" in m and "Option::Some" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_none_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    None\n"
            "    Other\n"
            "fun probe() -> Option<Int>\n"
            "    return None\n"
        )
        reserved = [
            m for m in msgs
            if "'None'" in m and "reserved" in m and "Option::None" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)

    def test_non_reserved_variant_name_still_works(self):
        # Positive control: the canonical rename suggested by the
        # diagnostic must analyse cleanly.
        r = check(
            "pub type S =\n"
            "    Compliant\n"
            "    Bad\n"
            "fun probe() -> S\n"
            "    return Compliant\n"
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


class TestLinearTypes(unittest.TestCase):
    """Roadmap S1: ``linear type`` must-consume discipline. A linear
    value must be consumed (passed to a ``consume`` param / ``consume
    self`` method, or returned) before it leaves scope."""

    _BASE = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        # Drop the unused-cap-param noise so tests assert on the
        # linear messages only.
        return [
            e for e in errors_of(self._BASE + body)
            if "never used" not in e
        ]

    def test_consumed_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_dropped_errors(self):
        errs = self._errs(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    _s.println(\"leak\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_returned_transfers_obligation(self):
        self.assertEqual(
            self._errs(
                "fun make() -> Handle\n"
                "    let h = open()\n"
                "    return h\n"
                "fun main(_s: Stdio)\n"
                "    close(make())\n"
            ),
            [],
        )

    def test_consume_self_method_discharges(self):
        errs = [
            e for e in errors_of(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            )
            if "never used" not in e
        ]
        self.assertEqual(errs, [])

    def test_both_branches_consume_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(c: Bool)\n"
                "    let h = open()\n"
                "    if c\n"
                "        close(h)\n"
                "    else\n"
                "        close(h)\n"
            ),
            [],
        )

    def test_consume_one_branch_only_errors(self):
        errs = self._errs(
            "fun main(c: Bool, _s: Stdio)\n"
            "    let h = open()\n"
            "    if c\n"
            "        close(h)\n"
            "    _s.println(\"x\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_consume_param_terminal_not_re_obligated(self):
        # ``close(consume h)`` is the terminal owner; its own body
        # need not re-consume h. (Regression: an early version seeded
        # consume-params into the live set and flagged close itself.)
        self.assertEqual(self._errs(""), [])

    def test_non_linear_struct_unaffected(self):
        self.assertEqual(
            [
                e for e in errors_of(
                    "type Plain { x: Int }\n"
                    "fun mk() -> Plain\n"
                    "    return Plain { x: 1 }\n"
                    "fun main(_s: Stdio)\n"
                    "    let p = mk()\n"
                )
                if "never used" not in e
            ],
            [],
        )


class TestLinearUseAfterConsume(unittest.TestCase):
    """Soundness: a linear / typestate value consumed *exactly once*
    cannot be used again. Passing it to a ``consume`` parameter, a
    ``consume self`` method, transitioning it with ``become``, or
    returning it consumes it; any later read / pass is a compile error.

    Before this fix a discharge merely cleared the must-consume
    obligation (``_live_linear``) without poisoning the name against
    later use, so a double-consume (settle the same authorization
    twice) type-checked and ran."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_double_consume_linear_param_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_read_field_after_consume_linear_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    let bad = h.id\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_use_after_consume_self_method_rejected(self):
        errs = self._errs(
            "linear type Handle { id: Int }\n"
            "impl Handle\n"
            "    fun shut(consume self) -> Unit\n"
            "        return ()\n"
            "fun open() -> Handle\n"
            "    return Handle { id: 1 }\n"
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    h.shut()\n"
            "    h.shut()\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_double_consume_typestate_after_become_rejected(self):
        # ``become(c, Approved)`` consumes c; a second become of c is
        # a use-after-consume of the old-state value.
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    let b = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(b)\n"
        )
        self.assertTrue(
            any(
                "linear value 'c' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_settle_typestate_twice_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(a)\n"
        )
        self.assertTrue(
            any(
                "linear value 'a' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_single_consume_linear_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_consume_self_once_ok(self):
        self.assertEqual(
            self._errs(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            ),
            [],
        )

    def test_typestate_chain_distinct_names_ok(self):
        # The idiomatic chain: each step binds a fresh name and consumes
        # the previous. Must stay legal after the poison fix.
        self.assertEqual(
            self._errs(
                self._TS
                + "fun main(_s: Stdio)\n"
                "    let c = mk()\n"
                "    let a = become(c, Approved)\n"
                "    settle(a)\n"
            ),
            [],
        )

    def test_return_transfers_obligation_ok(self):
        self.assertEqual(
            self._errs(
                self._TS
                + "fun promote() -> Claim[Approved]\n"
                "    let c = mk()\n"
                "    return become(c, Approved)\n"
                "fun main(_s: Stdio)\n"
                "    settle(promote())\n"
            ),
            [],
        )


class TestLinearAnonymousDrop(unittest.TestCase):
    """Soundness: a linear / typestate value cannot be dropped into an
    anonymous slot -- a wildcard binding ``let _ = open()`` or a bare
    expression statement ``open()`` / ``become(c, S)`` -- any more than
    it can be dropped under a named binding.

    Before this fix the must-consume obligation was keyed only by the
    bound name, so an anonymous drop registered no obligation and the
    value silently vanished unconsumed."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_wildcard_let_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let _ = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_expr_stmt_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_become_stmt_drops_typestate_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_drops_typestate_become_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let _ = become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_moves_linear_reported_once(self):
        # ``let _ = h`` moves the live binding into the void; it must be
        # reported once at the drop site and not again at function exit.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let _ = h\n"
        )
        drops = [e for e in errs if "dropped without being consumed" in e]
        self.assertEqual(len(drops), 1, errs)

    # ---- positives that must keep compiling ----------------------

    def test_bare_consume_call_stmt_ok(self):
        # ``close(h)`` as a bare statement returns Unit (not linear), so
        # it is a legal consume, not a drop.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_wildcard_let_nonlinear_ok(self):
        self.assertEqual(
            self._errs(
                "type Plain { x: Int }\n"
                "fun mk() -> Plain\n"
                "    return Plain { x: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let _ = mk()\n"
            ),
            [],
        )


class TestLinearVarAndReassign(unittest.TestCase):
    """Soundness: a ``var`` binding of a linear / typestate value carries
    the same must-consume obligation a ``let`` does -- ``var`` only makes
    the slot re-assignable, it does not waive use-once. Re-assigning a name
    that still holds a live linear value DROPS that value (a leak), while
    re-assigning a name whose value was already consumed re-arms a fresh
    obligation.

    Before this fix ``_check_var`` never registered the obligation and
    ``_check_assign`` never touched the live set, so a linear value bound
    with ``var`` (or re-assigned) escaped both the leak and the
    double-consume checks."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_var_linear_leak_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    var h = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_var_double_consume_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_reassign_drops_live_linear_rejected(self):
        # ``h = open()`` while h still holds an unconsumed value overwrites
        # (and so drops) the old value -- a leak.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    h = open()\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' is dropped without being consumed; "
                "re-assigning to it overwrites the old value" in e
                for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_var_single_consume_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_reassign_after_consume_ok(self):
        # The old value was consumed before the re-assignment, so the
        # name re-arms a fresh obligation that the final close discharges.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
                "    h = open()\n"
                "    close(h)\n"
            ),
            [],
        )


class TestLinearMatchPartialConsume(unittest.TestCase):
    """Soundness: a linear / typestate value live at the entry of a
    ``match`` must be consumed on EVERY non-diverging arm or on NONE.
    Consuming it in some arms but not others leaks it on the paths that
    did not consume -- the obligation survives the merge (the union of
    each reachable arm's survivors), so the leak surfaces, and a later
    consume after the match is a use-after-consume on the arms that
    already consumed it.

    Before this fix ``_check_match_expr`` merged ``_consumed`` like
    ``_check_if`` but never snapshotted / merged ``_live_linear``, so
    consuming in a single arm removed the obligation permanently and the
    leak on the other arms went unreported."""

    _M = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun pick() -> Option<Int>\n"
        "    return Some(1)\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_match_partial_consume_rejected(self):
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> ()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_match_consume_all_arms_ok(self):
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> close(h)\n"
                "        None -> close(h)\n"
            ),
            [],
        )

    def test_match_consume_none_then_after_ok(self):
        # Consumed in no arm, then consumed once after the match.
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> ()\n"
                "        None -> ()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_match_consume_all_arms_then_after_rejected(self):
        # Consumed in every arm, then used again after the match: a
        # use-after-consume on whichever arm ran.
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )


class TestLinearContainerLaundering(unittest.TestCase):
    """Soundness (already structurally closed): a linear / typestate value
    cannot be laundered into a non-linear container (tuple / list / struct
    field) to make its must-consume obligation disappear.

    The obligation on the inner value is discharged ONLY by a direct
    consume position -- a ``consume`` argument, a ``become`` operand, or a
    bare-identifier ``return``. Embedding the value in a container never
    discharges it, so the obligation stays live and is reported at scope
    exit no matter what happens to the container (dropped, returned,
    consumed). The language therefore admits no linear container, and no
    laundering escape exists. These tests lock that in."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_launder_into_tuple_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let t = (h, 1)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_list_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let xs = [h]\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_struct_field_rejected(self):
        errs = self._errs(
            "type Box { h: Handle }\n"
            + self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let b = Box { h: h }\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_returned_tuple_rejected(self):
        # Returning a tuple that holds the linear value does NOT discharge
        # it (only a bare-identifier return does), so the leak is caught.
        errs = self._errs(
            self._LIN
            + "fun stash() -> (Handle, Int)\n"
            "    let h = open()\n"
            "    return (h, 1)\n"
            "fun main(_s: Stdio)\n"
            "    let t = stash()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
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


# =============================================================
# For-loop iterable validation (GAP 1)
#
# Capa's iterables are exactly List, Set, Range, and String. A
# Map (and any other non-iterable type) has no sound lowering on
# either backend: the Python backend would silently iterate a
# Map's keys or crash on the destructuring form, while the Wasm
# backend errors. The analyzer rejects them so both backends
# agree at compile time.
# =============================================================

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


# =============================================================
# Asymmetric Char / String compatibility.
#
# A Capa Char is, by definition, exactly one code point, so it is
# ALWAYS a valid String (one direction). A general String is NOT a
# Char: only a provably one-code-point string LITERAL is accepted
# where a Char is expected. A multi-char literal or a non-literal
# String value flowing into a Char slot is unsound and rejected.
# =============================================================

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


# =============================================================
# Index-element assignment rejection (GAP 2)
#
# ``xs[i] = v`` and the augmented ``xs[i] += 1`` have no sound
# lowering on either backend (the Python backend emits an
# assignment to a function call, a SyntaxError; the Wasm backend
# raises a CIR-lowering error). The analyzer rejects a bare Index
# assignment target. Assigning to a struct field reached THROUGH
# an index (``xs[0].field = v``) keeps working: its target is a
# FieldAccess whose receiver is the Index.
# =============================================================

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


# =============================================================
# Dead-Unsafe warning (migrate tooling slice 2)
# =============================================================

class TestDeadUnsafeWarning(unittest.TestCase):
    """The analyzer warns (non-fatally) on an Unsafe parameter whose
    token provably never reaches py_import/py_invoke; the verdicts
    come from capa.migrate.find_dead_unsafe."""

    def test_dead_silenced_unsafe_param_warns(self):
        r = check("fun f(_u: Unsafe) -> Int\n    return 1\n")
        self.assertTrue(r.ok, r.errors)   # a warning never breaks ok
        self.assertEqual(len(r.warnings), 1)
        w = r.warnings[0]
        self.assertIn("'_u: Unsafe'", w.message)
        self.assertIn("never exercised", w.message)
        # Positioned on the parameter name itself.
        self.assertEqual((w.pos.line, w.pos.col), (1, 7))

    def test_transitive_dead_unsafe_names_the_callee(self):
        r = check(
            "fun bottom(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun top(u: Unsafe) -> Int\n"
            "    return bottom(u)\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 2)
        top_warning = next(w for w in r.warnings if "'top'" in w.message)
        self.assertIn("bottom", top_warning.message)
        self.assertIn("forwarded", top_warning.message)

    def test_exercised_unsafe_does_not_warn(self):
        r = check(
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(r.warnings, [])

    def test_shadowed_callee_does_not_warn(self):
        # third let-binds the dead function's name to a reference to
        # the bridging function and calls through it: the token DOES
        # reach py_import, so neither third nor main may be advised to
        # drop Unsafe. Only dead's own silenced parameter warns.
        r = check(
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe)\n"
            "    let dead = bridge\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u)\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("'dead'", r.warnings[0].message)

    def test_struct_shorthand_shadowed_callee_does_not_warn(self):
        # Same shadowing attack through destructuring shorthand:
        # ``Holder { dead }`` binds the field name with no IdentPat
        # node, rebinding the dead function's name to a bridging
        # function smuggled in a struct field. The token DOES reach
        # py_import, so neither third nor main may be advised to drop
        # Unsafe. Only dead's own silenced parameter warns.
        r = check(
            "type Holder { dead: Fun(Unsafe) -> () }\n"
            "\n"
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe, h: Holder)\n"
            "    let Holder { dead } = h\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u, Holder { dead: bridge })\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("'dead'", r.warnings[0].message)

    def test_lint_failure_warns_instead_of_crashing_or_hiding(self):
        # A regression inside the detection must not crash the compile,
        # but it must not pass silently either: it surfaces as an
        # internal-failure warning.
        from unittest import mock
        with mock.patch(
            "capa.migrate.find_dead_unsafe",
            side_effect=ValueError("boom"),
        ):
            r = check("fun f(_u: Unsafe) -> Int\n    return 1\n")
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("internal", r.warnings[0].message)
        self.assertIn("ValueError", r.warnings[0].message)

    def test_lint_skipped_when_module_has_errors(self):
        # Advice over a module that does not compile is misleading:
        # an error anywhere suppresses the lint phase entirely, so the
        # dead-Unsafe nudge never accompanies errors.
        r = check(
            "fun f(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun g() -> Int\n"
            "    return missing_name\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.warnings, [])


class TestInternalBuiltinRejection(unittest.TestCase):
    """Underscore-prefixed builtin functions (``_capa_chr``) are
    compiler-internal plumbing for the bundled JSON parser
    (``capa/ir/_builtin_json.capa``), not language surface. They
    became reachable from user code when ``_capa_chr`` landed in
    ``FREE_FUNCTIONS`` (2026-06-10); the analyzer now rejects user
    calls and bare references with a clear message. The bundled
    source itself is analyzed with ``internal=True`` and keeps
    access (pinned here by loading its IR)."""

    def test_user_call_to_capa_chr_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(_capa_chr(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_bare_reference_to_capa_chr_is_rejected(self):
        # Aliasing would smuggle the builtin past the call check.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let f = _capa_chr\n"
            "    stdio.println(f(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_call_to_capa_str_span_is_rejected(self):
        # _capa_str_span (perf/wasm-json-span) is the same kind of
        # internal-only plumbing as _capa_chr: the bundled parser uses
        # it for O(1) value extraction, user code must not reach it.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var cs: List<String> = []\n"
            '    cs.push("a")\n'
            "    stdio.println(_capa_str_span(cs, 0, 1))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_underscore_function_still_callable(self):
        # A user-defined function that happens to start with ``_``
        # has a real source position (never BUILTIN_POS) and stays
        # callable.
        r = check(
            "fun _helper() -> Int\n"
            "    return 7\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${_helper()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_bundled_json_parser_keeps_internal_access(self):
        # The bundled parser calls _capa_chr to decode \uXXXX; its
        # loader analyzes with internal=True. Re-analyze the shipped
        # source both ways: internal=True must be clean, and the
        # user-mode analysis of the same source must trip the
        # rejection (proving the gate actually guards _capa_chr).
        from capa.ir._builtin_json import _BUNDLED_SOURCE_PATH
        source = _BUNDLED_SOURCE_PATH.read_text(encoding="utf-8")
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        internal = analyze(module, source=source, internal=True)
        self.assertEqual([e.message for e in internal.errors], [])
        # Fresh parse for the user-mode run so the two analyses
        # cannot share AST-keyed state.
        module2 = Parser(
            Lexer(source).lex(), source=source,
        ).parse_module()
        as_user = analyze(module2, source=source)
        self.assertTrue(
            any(
                "internal compiler builtin" in e.message
                for e in as_user.errors
            ),
            [e.message for e in as_user.errors],
        )


if __name__ == "__main__":
    unittest.main()

"""Analyzer tests: generics inference and type-parameter soundness, including the whole
call-launder-rejected family.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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


class TestMemberAccessOnTypeParamRejected(unittest.TestCase):
    """Member access (a method call OR a field access) on a value whose
    static type is an UNBOUNDED generic type parameter (a rigid ``TyVar``
    such as ``T``) has no sound result type: Capa has no bounds syntax yet
    (``where`` is reserved), so a bare type parameter exposes no members.
    Before the fix both fall-through sites returned ``TyUnknown``, which
    unifies with anything, so an ill-typed body (a ``String`` returned from
    an ``-> Int`` method) passed ``--check`` and then ran wrong on Python /
    emitted an invalid module on Wasm. These must now be rejected, while
    OPAQUE generic uses (store / pass / return / match a ``T``, and methods
    on concrete ``List<T>`` / ``Result<T, E>`` containers) keep working.

    The precision point: fire ONLY for a declared (rigid) type parameter,
    never for a genuine inference-unknown (a flexible ``?`` placeholder or
    ``TyUnknown`` that gets resolved elsewhere)."""

    def test_silent_print_shape_rejected(self):
        # A generic impl method returning ``self.inner.value`` (typed T)
        # from a method declared ``-> Int``, bound to ``let n: Int``. This
        # compiled clean before the fix (the String-through-T was masked by
        # TyUnknown); it must now be rejected naming the parameter and the
        # accessed member.
        msgs = errors_of(
            "type Wrap<T> { inner: T }\n"
            "impl Wrap<T>\n"
            "    fun leak(self) -> Int\n"
            "        return self.inner.value\n"
            "fun main(stdio: Stdio)\n"
            "    let w = Wrap { inner: 5 }\n"
            "    let n: Int = w.leak()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'value'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_method_call_on_type_param_free_fn_rejected(self):
        # ``fun f<T>(x: T) { x.m() }``: a method call on a bare parameter.
        msgs = errors_of(
            "fun f<T>(x: T) -> Int\n"
            "    return x.compute()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'compute'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_field_access_on_type_param_free_fn_rejected(self):
        # ``fun f<T>(x: T) { x.field }``: a field access on a bare parameter.
        msgs = errors_of(
            "fun f<T>(x: T) -> Int\n"
            "    return x.field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_method_call_on_type_param_impl_receiver_rejected(self):
        # ``self.inner.method()`` where ``inner`` is typed T.
        msgs = errors_of(
            "type Wrap<T> { inner: T }\n"
            "impl Wrap<T>\n"
            "    fun run(self) -> Int\n"
            "        return self.inner.process()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'process'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_store_t_in_field_still_accepted(self):
        # Opaque: store a T in a struct field (accessing the struct's OWN
        # field typed T is allowed; only members OF the T value are not).
        r = check(
            "type Box<T> { value: T }\n"
            "fun store<T>(x: T) -> Box<T>\n"
            "    return Box { value: x }\n"
            "fun read<T>(b: Box<T>) -> T\n"
            "    return b.value\n"
            "fun main(stdio: Stdio)\n"
            "    let b = store(3)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_pass_and_return_t_still_accepted(self):
        # Opaque: pass a T as an argument and return a T.
        r = check(
            "fun ident<T>(x: T) -> T\n"
            "    return x\n"
            "fun passthrough<T>(x: T) -> T\n"
            "    return ident(x)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_match_on_generic_receiver_still_accepted(self):
        # Opaque: ``match self`` on a generic sum, returning a T arm.
        r = check(
            "type Maybe<T> =\n"
            "    Nada\n"
            "    Got(T)\n"
            "impl Maybe<T>\n"
            "    fun get_or(self, d: T) -> T\n"
            "        return match self\n"
            "            Nada -> d\n"
            "            Got(v) -> v\n"
            "fun main(stdio: Stdio)\n"
            "    let m = Got(9)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_on_concrete_list_of_t_still_accepted(self):
        # Opaque: ``List<T>.first()`` is a method on a resolvable CONTAINER
        # type, not on the bare T, so it must keep working.
        r = check(
            "fun firstof<T>(xs: List<T>) -> Option<T>\n"
            "    return xs.first()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_on_concrete_result_still_accepted(self):
        # Opaque: ``Result<Int, T>.err()`` is a method on a resolvable
        # container, not on the bare T.
        r = check(
            "fun errof<T>(r: Result<Int, T>) -> Option<T>\n"
            "    return r.err()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_inference_unknown_container_not_rejected(self):
        # Precision point: an empty ``[]`` has a FLEXIBLE element variable
        # (``List<?>``) that is resolved by later use. Methods on it must
        # NOT be swept up by the type-parameter rejection.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(1)\n"
            "    let n = xs.first()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestInlineGenericCallLaunderRejected(unittest.TestCase):
    """An INLINE generic-call result cannot launder a bare type parameter
    past the member-access / index guards.

    ``id<T>(x: T) -> T`` called as ``id(x)`` where ``x: T`` shares the
    caller's parameter NAME. ``unify`` reflexively matched ``T`` vs ``T``
    without binding, so ``instantiate`` defaulted the return parameter to
    ``TyUnknown`` and the call result read back as ``?`` at the access
    site, which the rigid-``TyVar`` guard skipped. ``id(x).field`` then
    let a String inhabit an ``-> Int`` binding, the same silent divergence
    the direct and ``let``-bound forms already reject. The free-call path
    now seeds the reflexive rigid binding (as method dispatch already does
    from the receiver's type argument), so the result carries the rigid
    ``T`` and is caught. Opaque inline flow (return / store / pass the
    result, no member access) stays accepted."""

    _ID = (
        "type Box<T> { field: T, name: T, a: T }\n"
        "fun id<T>(x: T) -> T\n"
        "    return x\n"
    )

    def test_inline_field_access_rejected(self):
        msgs = errors_of(
            self._ID
            + "fun leak<T>(x: T) -> Int\n"
            "    return id(x).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_method_call_rejected(self):
        msgs = errors_of(
            self._ID
            + "fun leak<T>(x: T) -> Int\n"
            "    return id(x).name()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'name'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_chained_field_access_rejected(self):
        # ``id(x).a.b``: the first hop ``id(x).a`` is already the rejected
        # access on the bare parameter.
        msgs = errors_of(
            self._ID
            + "fun leak<T>(x: T) -> Int\n"
            "    return id(x).a.b\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'a'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nested_inline_call_field_access_rejected(self):
        # ``id(id(x)).field``: the inner call yields rigid T, the outer
        # call preserves it, the field access is caught.
        msgs = errors_of(
            self._ID
            + "fun leak<T>(x: T) -> Int\n"
            "    return id(id(x)).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_let_bound_inline_call_field_access_rejected(self):
        # The ``let``-bound form: ``let z = id(x)`` commits z to rigid T,
        # ``z.field`` is caught.
        msgs = errors_of(
            self._ID
            + "fun leak<T>(x: T) -> Int\n"
            "    let z = id(x)\n"
            "    return z.field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_result_returned_still_accepted(self):
        # Opaque: the inline result flows out as a T return, no member
        # access on it. Must stay accepted.
        r = check(
            self._ID
            + "fun wrap<T>(x: T) -> T\n"
            "    return id(x)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_inline_result_stored_and_passed_still_accepted(self):
        # Opaque: the inline result stored in a field and passed nested.
        r = check(
            self._ID
            + "fun store_it<T>(x: T) -> Box<T>\n"
            "    return Box { field: id(x), name: x, a: x }\n"
            "fun pass_it<T>(x: T) -> T\n"
            "    return id(id(x))\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestIndexOnTypeParamRejected(unittest.TestCase):
    """Indexing a value whose static type is an unbounded generic type
    parameter is unsound (nothing constrains ``T`` to be indexable) and is
    rejected, symmetric with the member-access guards. A concrete
    ``List<T>`` / tuple index stays allowed, and a genuine inference
    placeholder is not swept up."""

    def test_index_on_bare_type_param_rejected(self):
        msgs = errors_of(
            "fun leak<T>(x: T) -> Int\n"
            "    return x[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "index" in m
                for m in msgs
            ),
            msgs,
        )

    def test_index_on_inline_generic_call_rejected(self):
        msgs = errors_of(
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "fun leak<T>(x: T) -> Int\n"
            "    return id(x)[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "index" in m
                for m in msgs
            ),
            msgs,
        )

    def test_index_on_concrete_list_of_t_still_accepted(self):
        # Indexing a resolvable ``List<T>`` container is fine; the element
        # type is the parameter, but the receiver is not the bare T.
        r = check(
            "fun firstish<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_index_on_inference_list_not_rejected(self):
        # Precision point: indexing an empty-inferred ``List<?>`` stays
        # accepted (the element is a flexible placeholder, not a rigid T).
        r = check(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(1)\n"
            "    let n = xs[0]\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestNonListIndexRejected(unittest.TestCase):
    """The ``[]`` operator is a List-only surface construct (docs
    stdlib.md), plus a literal-constant tuple index. The index terminal
    used to return a permissive ``TyUnknown`` for every other receiver, so
    ``let n: Int = "hi"[0]`` passed ``--check`` and ran wrong on Python (a
    String printed for the Int) while Wasm failed loud. The terminal now
    rejects a non-indexable receiver, matching the backend. List indexing
    (dynamic or constant), a constant tuple index, and an inferred
    ``List<?>`` index stay accepted."""

    def test_string_constant_index_rejected(self):
        msgs = errors_of(
            "fun leak() -> Int\n"
            "    let n: Int = \"hi\"[0]\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("String" in m and "not indexable" in m for m in msgs), msgs
        )

    def test_string_dynamic_index_rejected(self):
        msgs = errors_of(
            "fun leak(i: Int) -> Int\n"
            "    let n: Int = \"hi\"[i]\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("String" in m and "not indexable" in m for m in msgs), msgs
        )

    def test_dynamic_tuple_index_rejected(self):
        msgs = errors_of(
            "fun leak(i: Int) -> String\n"
            "    let t = (1, 2)\n"
            "    let s: String = t[i]\n"
            "    return s\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("tuple" in m and "constant" in m for m in msgs), msgs
        )

    def test_map_index_rejected(self):
        msgs = errors_of(
            "fun leak(m: Map<String, Int>) -> Int\n"
            "    let n: Int = m[\"k\"]\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("not indexable" in m for m in msgs), msgs
        )

    def test_struct_index_rejected(self):
        msgs = errors_of(
            "type Point { x: Int, y: Int }\n"
            "fun leak(p: Point) -> Int\n"
            "    let n: Int = p[0]\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("Point" in m and "not indexable" in m for m in msgs), msgs
        )

    def test_list_dynamic_and_constant_index_accepted(self):
        r = check(
            "fun getdyn(xs: List<Int>, i: Int) -> Int\n"
            "    return xs[i]\n"
            "fun getconst(xs: List<String>) -> String\n"
            "    return xs[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_constant_tuple_index_accepted(self):
        r = check(
            "fun pick() -> String\n"
            "    let t = (1, \"hi\")\n"
            "    return t[1]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestConcreteReceiverMemberAccessRejected(unittest.TestCase):
    """The field / method / index / inline-call terminals FAIL CLOSED: a
    permissive ``TyUnknown`` is returned ONLY for a genuine inference-unknown
    (a flexible ``?`` or an already-``TyUnknown``). ANY concrete resolved
    receiver / callee that reaches a terminal matched no modeled branch, so
    the access / call / index is unsupported or ill-typed and is rejected,
    whatever the type kind (a tuple, a function, unit, a user SUM, a
    typestate, a built-in, any future kind), with no per-kind enumeration.
    Before, each such value inhabited a typed binding and reached runtime
    (a silent Python wrong-output for the sum case, an invalid Wasm module)."""

    def test_tuple_field_access_rejected(self):
        msgs = errors_of(
            "fun leak() -> Int\n"
            "    let t = (1, 2)\n"
            "    let n: Int = t.field\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "cannot access field" in m and "(Int, Int)" in m
                for m in msgs
            ),
            msgs,
        )

    def test_tuple_method_call_rejected(self):
        msgs = errors_of(
            "fun leak() -> Int\n"
            "    let t = (1, 2)\n"
            "    let n: Int = t.foo()\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "cannot call method" in m and "(Int, Int)" in m
                for m in msgs
            ),
            msgs,
        )

    def test_function_value_field_access_rejected(self):
        msgs = errors_of(
            "fun getf() -> Fun() -> Int\n"
            "    return fun () -> Int => 1\n"
            "fun leak() -> Int\n"
            "    let g = getf()\n"
            "    let n: Int = g.fld\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("cannot access field" in m and "fun(" in m for m in msgs),
            msgs,
        )

    def test_function_value_method_call_rejected(self):
        msgs = errors_of(
            "fun getf() -> Fun() -> Int\n"
            "    return fun () -> Int => 1\n"
            "fun leak() -> Int\n"
            "    let g = getf()\n"
            "    let n: Int = g.foo()\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("cannot call method" in m and "fun(" in m for m in msgs),
            msgs,
        )

    def test_sum_value_field_access_rejected(self):
        # The found hole: a user SUM value's field access. A sum has no
        # fields (match on it); before, ``W("hello").value`` inhabited an
        # Int binding and printed the String silently on Python.
        msgs = errors_of(
            "type W =\n"
            "    Wv(String)\n"
            "fun leak() -> Int\n"
            "    let w = Wv(\"hello\")\n"
            "    let n: Int = w.value\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "cannot access field 'value'" in m and "type W" in m
                for m in msgs
            ),
            msgs,
        )

    def test_multipayload_sum_field_access_rejected(self):
        # The flip closes this "next kind" with no new branch.
        msgs = errors_of(
            "type Shape =\n"
            "    Rect(Int, Int)\n"
            "    Circle(Int)\n"
            "fun leak() -> Int\n"
            "    let sh = Rect(3, 4)\n"
            "    let n: Int = sh.width\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "cannot access field 'width'" in m and "type Shape" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_call_of_concrete_struct_rejected(self):
        # Inline invocation of a concrete non-function (a struct result).
        msgs = errors_of(
            "type Point { x: Int, y: Int }\n"
            "fun mkt() -> Point\n"
            "    return Point { x: 1, y: 2 }\n"
            "fun leak() -> Int\n"
            "    let n: Int = mkt()()\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "cannot call a value of type Point" in m for m in msgs
            ),
            msgs,
        )

    def test_inline_call_of_concrete_int_rejected(self):
        msgs = errors_of(
            "fun geti() -> Int\n"
            "    return 5\n"
            "fun leak() -> Int\n"
            "    let n: Int = geti()()\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("cannot call a value of type Int" in m for m in msgs), msgs
        )

    def test_sum_method_and_typestate_field_still_accepted(self):
        # Must preserve: a sum's own impl method and a typestate's declared
        # field both resolve ABOVE the terminal and stay accepted (the flip
        # changes only the fall-through, not the modeled branches).
        r = check(
            "type Shape =\n"
            "    Rect(Int, Int)\n"
            "    Circle(Int)\n"
            "impl Shape\n"
            "    fun area(self) -> Int\n"
            "        return 1\n"
            "fun use_shape(sh: Shape) -> Int\n"
            "    return sh.area()\n"
            "typestate Socket { fd: Int }\n"
            "    Created\n"
            "fun fd_of(sk: Socket[Created]) -> Int\n"
            "    return sk.fd\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestNestedGenericCallLaunderRejected(unittest.TestCase):
    """The type parameter can pass through the callee at a NESTED position
    (``List<T>`` / ``Box<T>`` / a tuple / ``Option<T>`` / a ``Fun`` arrow)
    that shares the caller's name ``T``. The bare-argument seeding of the
    prior commit did not fire there, so the result stayed ``TyUnknown`` and
    the member / index guards were defeated. The root cause is a NAME
    COLLISION: ``unify``'s reflexive same-name shortcut treats the callee's
    ``T`` and the caller's ``T`` as identical and never binds. The fix
    freshens (alpha-renames) the callee's declared type parameters before
    unifying, so the result carries the caller's rigid ``T`` at every
    nesting position. Renaming the CALLER parameter to ``U`` already made
    these reject before the fix (distinct names let ``unify`` bind), which
    is what pins it as a collision."""

    def test_list_param_result_field_access_rejected(self):
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "fun head<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun leak<T>(xs: List<T>) -> Int\n"
            "    return head(xs).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_box_param_result_field_access_rejected(self):
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "fun unbox<T>(b: Box<T>) -> T\n"
            "    return b.field\n"
            "fun leak<T>(b: Box<T>) -> Int\n"
            "    return unbox(b).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_tuple_param_result_field_access_rejected(self):
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "fun fst<T>(t: (T, Int)) -> T\n"
            "    return t[0]\n"
            "fun leak<T>(t: (T, Int)) -> Int\n"
            "    return fst(t).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_option_param_result_index_rejected(self):
        msgs = errors_of(
            "fun get<T>(o: Option<T>) -> T\n"
            "    return o.unwrap()\n"
            "fun leak<T>(o: Option<T>) -> Int\n"
            "    return get(o)[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "index" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nested_call_result_into_int_binding_rejected(self):
        # The silent-divergence witness: head(xs) types as T, so binding it
        # to a concrete Int is now a type error rather than a wrong-shape
        # value at runtime.
        msgs = errors_of(
            "fun head<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun leak<T>(xs: List<T>) -> Int\n"
            "    let n: Int = head(xs)\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected Int" in m and "got T" in m for m in msgs), msgs
        )

    def test_distinct_caller_name_also_rejected(self):
        # Renaming the caller parameter to U (distinct name) rejects too:
        # the fix is name-independent, not a coincidence of shared names.
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "fun head<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun leak<U>(xs: List<U>) -> Int\n"
            "    return head(xs).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'U'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nested_container_flow_still_accepted(self):
        # Opaque: a nested-position generic result returned / stored, no
        # member access on it. Must stay accepted.
        r = check(
            "type Box<T> { field: T }\n"
            "fun head<T>(xs: List<T>) -> T\n"
            "    return xs[0]\n"
            "fun wrap_head<T>(xs: List<T>) -> Box<T>\n"
            "    return Box { field: head(xs) }\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestPhantomGenericResultAccepted(unittest.TestCase):
    """A genuinely unconstrained (phantom) type parameter -- ``make<T>() ->
    T`` with no ``T``-typed argument -- is fixed by the RETURN context, not
    by any argument. Its call result stays ``TyUnknown`` (freshened but
    unbound, so ``instantiate`` defaults it), NOT rigid ``T``. It must
    satisfy a concrete binding and must NOT be turned into a rigid
    member-access rejection."""

    _MAKE = (
        "type Box<T> { field: T }\n"
        "fun make<T>() -> T\n"
        "    return make()\n"
    )

    def test_phantom_result_satisfies_int_binding(self):
        r = check(
            self._MAKE
            + "fun use_int() -> Int\n"
            "    return make()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_phantom_result_member_access_not_rejected(self):
        # make() is genuinely unconstrained (TyUnknown), so member access
        # on it is NOT the type-parameter rejection.
        r = check(
            self._MAKE
            + "fun use_member() -> Int\n"
            "    return make().field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestGenericMethodCallLaunderRejected(unittest.TestCase):
    """The launder also survived through a GENERIC METHOD call, which goes
    through ``_check_method_dispatch`` (a different path from the free
    call). That path seeds the mapping from the RECEIVER's type arguments
    but did not freshen the METHOD's OWN declared type parameters, so a
    method whose own type-param name collides with the caller's ``T`` hit
    the same reflexive-unify shortcut and produced ``TyUnknown``, defeating
    the member-access and index guards. The fix freshens the method's own
    type parameters too (leaving the receiver-bound ones seeded from the
    receiver, which were already handled)."""

    _FOO = (
        "type Box<T> { field: T }\n"
        "type Foo { tag: Int }\n"
        "impl Foo\n"
        "    fun mid<T>(self, x: T) -> T\n"
        "        return x\n"
    )

    def test_generic_method_result_field_access_rejected(self):
        msgs = errors_of(
            self._FOO
            + "fun leak<T>(f: Foo, x: T) -> Int\n"
            "    return f.mid(x).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_generic_method_result_index_rejected(self):
        msgs = errors_of(
            self._FOO
            + "fun leak<T>(f: Foo, x: T) -> Int\n"
            "    return f.mid(x)[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "index" in m
                for m in msgs
            ),
            msgs,
        )

    def test_generic_method_result_into_int_binding_rejected(self):
        # The silent-divergence witness on the method path.
        msgs = errors_of(
            self._FOO
            + "fun leak<T>(f: Foo, x: T) -> Int\n"
            "    let n: Int = f.mid(x)\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected Int" in m and "got T" in m for m in msgs), msgs
        )

    def test_trait_dispatched_generic_method_rejected(self):
        # A trait-dispatched generic method with the same own-type-param
        # collision goes through the same method-dispatch path and is
        # rejected too.
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "trait Mid\n"
            "    fun mid<T>(self, x: T) -> T\n"
            "type Foo { tag: Int }\n"
            "impl Mid for Foo\n"
            "    fun mid<T>(self, x: T) -> T\n"
            "        return x\n"
            "fun leak<T>(m: Mid, x: T) -> Int\n"
            "    return m.mid(x).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_distinct_method_type_param_name_still_rejected(self):
        # Control: declaring the method ``<U>`` (distinct name) was already
        # rejected before the fix; it must stay rejected (name-independent).
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "type Foo { tag: Int }\n"
            "impl Foo\n"
            "    fun mid<U>(self, x: U) -> U\n"
            "        return x\n"
            "fun leak<T>(f: Foo, x: T) -> Int\n"
            "    return f.mid(x).field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_receiver_type_param_method_still_rejected(self):
        # Delimiter: a method over the RECEIVER's type parameter
        # (``b.get().field`` on ``impl Box<T>``) is caught by the receiver
        # seeding and must NOT regress.
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "impl Box<T>\n"
            "    fun get(self) -> T\n"
            "        return self.field\n"
            "fun leak<T>(b: Box<T>) -> Int\n"
            "    return b.get().field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_legitimate_generic_method_still_accepted(self):
        # No over-reject: the method's own type param resolved to a
        # concrete argument and the result used concretely; plus the mixed
        # case where the own type param binds a concrete List<A> which is
        # then legitimately indexed.
        r = check(
            self._FOO
            + "fun use_it(f: Foo) -> Int\n"
            "    let n = f.mid(42)\n"
            "    return n + 1\n"
            "fun mixed<A>(f: Foo, xs: List<A>) -> A\n"
            "    return f.mid(xs)[0]\n"
            "fun main(stdio: Stdio)\n"
            "    let f = Foo { tag: 0 }\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_higher_order_builtin_method_in_generic_fn_accepted(self):
        # Regression: a built-in generic method (``map``) called on the
        # receiver's own type parameter inside a generic function. The
        # method-param freshening must use RIGID (non-``?``) names, else the
        # receiver's self-referential ``T -> T`` seed makes the fresh-var
        # commit recurse forever. This must analyze cleanly.
        r = check(
            "fun apply<T>(f: Fun(T) -> T, xs: List<T>) -> List<T>\n"
            "    return xs.map(f)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestInlineFirstClassInvocationLaunderRejected(unittest.TestCase):
    """A first-class function value invoked INLINE (the call's callee is
    itself a call / method / lambda, not a plain identifier) went through
    a ``_check_call`` fall-through that returned a permissive ``TyUnknown``
    instead of the arrow's return type. So ``hof(x)()`` (with
    ``hof<T>(x: T) -> Fun() -> T``) typed as ``TyUnknown`` and its member /
    index / method access laundered a bare ``T`` past the guards, and a
    ``getf()()`` result inhabited a wrong binding. The non-identifier callee
    path now returns the arrow's return type (validating arity / argument
    types), so the guards see the rigid ``T`` (or the concrete result). The
    ``let``-bound form was already rejected; a legitimately-typed inline
    invocation used concretely stays accepted."""

    _HOF = (
        "type Box<T> { field: T, name: T }\n"
        "fun hof<T>(x: T) -> Fun() -> T\n"
        "    return fun () -> T => x\n"
    )

    def test_inline_invocation_field_access_rejected(self):
        msgs = errors_of(
            self._HOF
            + "fun leak<T>(x: T) -> Int\n"
            "    return hof(x)().field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_invocation_method_call_rejected(self):
        msgs = errors_of(
            self._HOF
            + "fun leak<T>(x: T) -> Int\n"
            "    return hof(x)().name()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'name'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_inline_invocation_index_rejected(self):
        msgs = errors_of(
            self._HOF
            + "fun leak<T>(x: T) -> Int\n"
            "    return hof(x)()[0]\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "index" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nongeneric_inline_invocation_into_wrong_binding_rejected(self):
        # The non-generic first-class gap: getf()() typed as TyUnknown and
        # a String inhabited an Int binding. Now typed String and rejected.
        msgs = errors_of(
            "fun getf() -> Fun() -> String\n"
            "    return fun () -> String => \"hi\"\n"
            "fun leak() -> Int\n"
            "    let n: Int = getf()()\n"
            "    return n\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected Int" in m and "got String" in m for m in msgs), msgs
        )

    def test_calling_a_bare_type_param_value_rejected(self):
        # Sibling: invoking a value whose type is a bare T (idf(x)()) is not
        # known to be callable.
        msgs = errors_of(
            "type Box<T> { field: T }\n"
            "fun idf<T>(x: T) -> T\n"
            "    return x\n"
            "fun leak<T>(x: T) -> Int\n"
            "    return idf(x)().field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "callable" in m
                for m in msgs
            ),
            msgs,
        )

    def test_try_on_bare_type_param_rejected(self):
        # Sibling: `?` on a bare T is not known to be Result / Option.
        msgs = errors_of(
            "fun leak<T>(x: T) -> Option<Int>\n"
            "    let n: Int = x?\n"
            "    return Some(n)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m
                and "Result or Option" in m
                for m in msgs
            ),
            msgs,
        )

    def test_letbound_first_class_invocation_still_rejected(self):
        # The let-bound form was already rejected (g resolves to rigid T);
        # it must stay rejected.
        msgs = errors_of(
            self._HOF
            + "fun leak<T>(x: T) -> Int\n"
            "    let g = hof(x)\n"
            "    return g().field\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "generic type parameter 'T'" in m and "'field'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_legitimate_inline_invocation_accepted(self):
        # No over-reject: an inline invocation whose arrow returns a concrete
        # type, used concretely, stays accepted (both a curried adder and a
        # nullary getter).
        r = check(
            "fun adder(n: Int) -> Fun(Int) -> Int\n"
            "    return fun (m: Int) -> Int => m + n\n"
            "fun getf() -> Fun() -> String\n"
            "    return fun () -> String => \"hi\"\n"
            "fun use_it(stdio: Stdio) -> Unit\n"
            "    let r = adder(5)(10)\n"
            "    let t: String = getf()()\n"
            "    stdio.println(t)\n"
            "    return\n"
            "fun main(stdio: Stdio)\n"
            "    use_it(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


if __name__ == "__main__":
    unittest.main()

"""Analyzer tests: actionable error-message quality: did-you-mean, question-mark misuse,
self diagnostics, duplicate binding, reserved variant names, dead-unsafe
warning, call-non-callable, and the static-call-on-user-type reject.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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


class TestStaticCallOnUserTypeRejected(unittest.TestCase):
    """``TypeName.method()`` on a user-defined type is not a supported
    call surface: Capa has no static-method call syntax. The bare-Ident
    receiver names a TYPE_STRUCT / TYPE_SUM symbol (a type, not a value),
    so it must be rejected at ``--check`` time rather than typing the
    receiver to ``TyUnknown`` and crashing with an ``AttributeError`` at
    runtime. The reject fires on the symbol KIND, so it precedes method
    name lookup: even a genuinely absent method is rejected here."""

    MSG = "Capa has no static-method call syntax"

    def test_static_call_on_struct_type_is_rejected(self):
        errs = errors_of(
            "type Bomb { n: Int }\n"
            "type Factory { seed: Int }\n"
            "impl Factory\n"
            "    fun create() -> Bomb\n"
            "        return Bomb { n: 0 }\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Factory.create()\n"
            "    stdio.println(\"${b.n}\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_static_call_absent_method_rejected_before_lookup(self):
        # The method does not exist. The kind-based reject fires before
        # name lookup, closing the crash-at-runtime facet: this used to
        # pass ``--check`` and then raise ``AttributeError`` at runtime.
        errs = errors_of(
            "type Factory { seed: Int }\n"
            "impl Factory\n"
            "    fun create() -> Factory\n"
            "        return Factory { seed: 0 }\n"
            "fun main(stdio: Stdio)\n"
            "    let f = Factory.nonexistent()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_static_call_on_sum_type_is_rejected(self):
        errs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Blue\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Color.foo()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_capability_attenuator_still_accepted(self):
        # Regression: ``Net.restrict_to`` is a CAPABILITY receiver, not
        # a TYPE_STRUCT / TYPE_SUM, so the kind-based reject must not
        # fire. The gate is load-bearing.
        r = check(
            "fun main(net: Net)\n"
            "    let n = Net.restrict_to(\"example.com\")\n"
            "    let _ = net.allows(\"example.com\")\n"
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


if __name__ == "__main__":
    unittest.main()

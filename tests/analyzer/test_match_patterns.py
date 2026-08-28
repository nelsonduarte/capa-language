"""Analyzer tests: match exhaustiveness, pattern binding, tuple/struct/or-patterns,
literal-pattern typing, and duplicate/unreachable arms.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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


class TestStructPatternBinding(unittest.TestCase):
    """``let`` / ``for`` accept a one-level struct-destructuring
    pattern, but a struct sub-pattern nested inside a field is
    rejected at analysis time: neither backend can lower it (the
    transpiler raised "nested struct-pattern in let/for not
    supported" and the IR lowerer raised UnsupportedInIR), so
    ``--check`` and ``--run`` must agree by rejecting it up front.
    ``match`` arms keep their nesting support (a different code
    path) and are exercised by TestTuplePatterns / the parity
    suite, not here."""

    _NESTED_MSG = "nested struct-pattern in a 'let' / 'for' binding"

    def test_one_level_let_struct_destructure_ok(self):
        r = check(
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    let Point { x, y } = p\n"
            "    let Point { x: a } = p\n"
            "    let Point { x: _, y: yy } = p\n"
            "    stdio.println(\"${x} ${y} ${a} ${yy}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_one_level_for_struct_destructure_ok(self):
        r = check(
            "type Pair { a: Int, b: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [Pair { a: 1, b: 2 }]\n"
            "    for Pair { a, b } in xs\n"
            "        stdio.println(\"${a} ${b}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_nested_struct_pattern_in_let_rejected(self):
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let o = Outer { inner: Inner { a: 7 } }\n"
            "    let Outer { inner: Inner { a } } = o\n"
            "    stdio.println(\"${a}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_nested_struct_pattern_in_for_rejected(self):
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [Outer { inner: Inner { a: 7 } }]\n"
            "    for Outer { inner: Inner { a } } in xs\n"
            "        stdio.println(\"${a}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_nested_struct_pattern_in_tuple_let_rejected(self):
        # A struct sub-pattern hidden inside a tuple element of a
        # let binding is the same unlowerable shape.
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let t = (Inner { a: 1 }, 2)\n"
            "    let (Inner { a }, b) = t\n"
            "    stdio.println(\"${a} ${b}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_match_nested_struct_pattern_still_ok(self):
        # The match path supports the nesting the let/for guard
        # rejects; confirm it was not caught in the crossfire.
        r = check(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let o = Outer { inner: Inner { a: 7 } }\n"
            "    match o\n"
            "        Outer { inner: Inner { a } } -> "
            "stdio.println(\"${a}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


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


if __name__ == "__main__":
    unittest.main()

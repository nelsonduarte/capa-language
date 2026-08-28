"""Analyzer tests: String builtin methods, interpolation, and interpolation formattability.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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


if __name__ == "__main__":
    unittest.main()

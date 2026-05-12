"""Unit tests for the Capa lexer.

Coverage: literals (all bases, all escapes), identifiers,
keywords (including reserved ones), operators (with maximal munch and compound
variants), comments (line, block, nested), significant indentation
(INDENT, DEDENT, blank lines, comments inside a block), line continuation
via parentheses and via backslash, and error detection with position.
"""

import unittest

from capa import Lexer, LexerError, TokenKind


def lex(source: str) -> list:
    """Lex and return the list of tokens (including layout and EOF)."""
    return Lexer(source).lex()


def kinds(source: str) -> list:
    """Lex and return only the sequence of TokenKind."""
    return [t.kind for t in lex(source)]


def kinds_no_layout(source: str) -> list:
    """Lex and return only the non-layout TokenKind (more useful for asserts)."""
    layout = {
        TokenKind.NEWLINE,
        TokenKind.INDENT,
        TokenKind.DEDENT,
        TokenKind.EOF,
    }
    return [t.kind for t in lex(source) if t.kind not in layout]


# =============================================================
# Integer literals
# =============================================================

class TestIntegerLiterals(unittest.TestCase):
    def test_zero(self):
        toks = lex("0")
        self.assertEqual(toks[0].kind, TokenKind.INT_LIT)
        self.assertEqual(toks[0].value, 0)

    def test_decimal(self):
        toks = lex("42")
        self.assertEqual(toks[0].value, 42)

    def test_decimal_with_underscores(self):
        toks = lex("1_000_000")
        self.assertEqual(toks[0].value, 1_000_000)

    def test_hex_lower(self):
        toks = lex("0xff")
        self.assertEqual(toks[0].value, 0xFF)

    def test_hex_upper(self):
        toks = lex("0xCAFE_BABE")
        self.assertEqual(toks[0].value, 0xCAFEBABE)

    def test_octal(self):
        toks = lex("0o755")
        self.assertEqual(toks[0].value, 0o755)

    def test_binary(self):
        toks = lex("0b1010_1010")
        self.assertEqual(toks[0].value, 0b10101010)

    def test_double_underscore_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex("1__000")
        self.assertIn("consecutive", str(ctx.exception).lower())

    def test_trailing_underscore_rejected(self):
        with self.assertRaises(LexerError):
            lex("100_")

    def test_no_digits_after_prefix(self):
        with self.assertRaises(LexerError):
            lex("0x")


# =============================================================
# Float literals
# =============================================================

class TestFloatLiterals(unittest.TestCase):
    def test_simple_float(self):
        toks = lex("3.14")
        self.assertEqual(toks[0].kind, TokenKind.FLOAT_LIT)
        self.assertAlmostEqual(toks[0].value, 3.14)

    def test_float_with_exponent(self):
        toks = lex("1e10")
        self.assertEqual(toks[0].kind, TokenKind.FLOAT_LIT)
        self.assertAlmostEqual(toks[0].value, 1e10)

    def test_float_negative_exponent(self):
        toks = lex("2.5E-3")
        self.assertEqual(toks[0].kind, TokenKind.FLOAT_LIT)
        self.assertAlmostEqual(toks[0].value, 2.5e-3)

    def test_dot_method_call_not_float(self):
        # 5.metodo() should produce INT_LIT, DOT, IDENT, LPAREN, RPAREN
        # Not FLOAT_LIT.
        result = kinds_no_layout("5.metodo()")
        self.assertEqual(result[0], TokenKind.INT_LIT)
        self.assertEqual(result[1], TokenKind.DOT)
        self.assertEqual(result[2], TokenKind.IDENT)


# =============================================================
# Strings
# =============================================================

class TestStringLiterals(unittest.TestCase):
    def test_simple(self):
        toks = lex('"hello"')
        self.assertEqual(toks[0].kind, TokenKind.STRING_LIT)
        self.assertEqual(toks[0].value, "hello")

    def test_empty(self):
        toks = lex('""')
        self.assertEqual(toks[0].value, "")

    def test_escape_newline(self):
        toks = lex(r'"line\nmore"')
        self.assertEqual(toks[0].value, "line\nmore")

    def test_escape_tab(self):
        toks = lex(r'"\t"')
        self.assertEqual(toks[0].value, "\t")

    def test_escape_backslash(self):
        toks = lex(r'"\\"')
        self.assertEqual(toks[0].value, "\\")

    def test_escape_quote(self):
        toks = lex(r'"\"quoted\""')
        self.assertEqual(toks[0].value, '"quoted"')

    def test_unicode_escape(self):
        toks = lex(r'"\u{1F600}"')
        self.assertEqual(toks[0].value, "\U0001F600")

    def test_unicode_escape_simple(self):
        toks = lex(r'"\u{61}"')
        self.assertEqual(toks[0].value, "a")

    def test_unicode_escape_too_long_rejected(self):
        with self.assertRaises(LexerError):
            lex(r'"\u{1234567}"')

    def test_unicode_escape_empty_rejected(self):
        with self.assertRaises(LexerError):
            lex(r'"\u{}"')

    def test_unicode_escape_out_of_range_rejected(self):
        with self.assertRaises(LexerError):
            lex(r'"\u{110000}"')

    def test_unknown_escape_rejected(self):
        with self.assertRaises(LexerError):
            lex(r'"\x"')

    def test_unterminated_string_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex('"hello')
        self.assertIn("unterminated", str(ctx.exception).lower())

    def test_newline_in_string_rejected(self):
        with self.assertRaises(LexerError):
            lex('"hello\n"')

    def test_utf8_content(self):
        toks = lex('"olá mundo"')
        self.assertEqual(toks[0].value, "olá mundo")


# =============================================================
# Raw string literals
# =============================================================

class TestRawStringLiterals(unittest.TestCase):
    def test_basic(self):
        toks = lex('r"abc"')
        self.assertEqual(toks[0].kind, TokenKind.STRING_LIT)
        self.assertEqual(toks[0].value, "abc")

    def test_backslashes_are_literal(self):
        toks = lex(r'r"\n\t\\"')
        # No escape processing: keep four characters literally.
        self.assertEqual(toks[0].value, r"\n\t\\")

    def test_windows_path(self):
        toks = lex(r'r"C:\Users\nelso\file.txt"')
        self.assertEqual(toks[0].value, r"C:\Users\nelso\file.txt")

    def test_regex_pattern(self):
        toks = lex(r'r"\d+\.\d+"')
        self.assertEqual(toks[0].value, r"\d+\.\d+")

    def test_dollar_brace_is_literal(self):
        # ``${...}`` interpolation is NOT recognised in raw strings.
        toks = lex(r'r"hello ${name}"')
        self.assertEqual(toks[0].value, "hello ${name}")

    def test_empty(self):
        toks = lex('r""')
        self.assertEqual(toks[0].kind, TokenKind.STRING_LIT)
        self.assertEqual(toks[0].value, "")

    def test_bare_r_is_identifier(self):
        # ``r`` not followed by a quote is still an ordinary identifier.
        toks = lex("r")
        self.assertEqual(toks[0].kind, TokenKind.IDENT)
        self.assertEqual(toks[0].value, "r")

    def test_newline_rejected(self):
        with self.assertRaises(LexerError):
            lex('r"hello\nworld"')

    def test_unterminated_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex('r"hello')
        self.assertIn("raw string", str(ctx.exception).lower())


# =============================================================
# Characters
# =============================================================

class TestCharLiterals(unittest.TestCase):
    def test_simple(self):
        toks = lex("'a'")
        self.assertEqual(toks[0].kind, TokenKind.CHAR_LIT)
        self.assertEqual(toks[0].value, "a")

    def test_escape(self):
        toks = lex(r"'\n'")
        self.assertEqual(toks[0].value, "\n")

    def test_unicode_escape(self):
        toks = lex(r"'\u{e1}'")
        self.assertEqual(toks[0].value, "á")

    def test_empty_rejected(self):
        with self.assertRaises(LexerError):
            lex("''")

    def test_unterminated_rejected(self):
        with self.assertRaises(LexerError):
            lex("'a")

    def test_two_chars_rejected(self):
        with self.assertRaises(LexerError):
            lex("'ab'")


# =============================================================
# Identifiers and keywords
# =============================================================

class TestIdentifiersAndKeywords(unittest.TestCase):
    def test_simple_identifier(self):
        toks = lex("foo")
        self.assertEqual(toks[0].kind, TokenKind.IDENT)
        self.assertEqual(toks[0].text, "foo")

    def test_with_digits(self):
        toks = lex("foo123")
        self.assertEqual(toks[0].kind, TokenKind.IDENT)

    def test_with_underscores(self):
        toks = lex("snake_case_name")
        self.assertEqual(toks[0].kind, TokenKind.IDENT)

    def test_leading_underscore(self):
        toks = lex("_private")
        self.assertEqual(toks[0].kind, TokenKind.IDENT)

    def test_lone_underscore_is_wildcard(self):
        toks = lex("_")
        self.assertEqual(toks[0].kind, TokenKind.UNDERSCORE)

    def test_keyword_fun(self):
        self.assertEqual(lex("fun")[0].kind, TokenKind.KW_FUN)

    def test_keyword_let_var(self):
        self.assertEqual(lex("let")[0].kind, TokenKind.KW_LET)
        self.assertEqual(lex("var")[0].kind, TokenKind.KW_VAR)

    def test_self_distinct_from_big_self(self):
        self.assertEqual(lex("self")[0].kind, TokenKind.KW_SELF)
        self.assertEqual(lex("Self")[0].kind, TokenKind.KW_BIG_SELF)

    def test_logical_keywords(self):
        self.assertEqual(lex("and")[0].kind, TokenKind.KW_AND)
        self.assertEqual(lex("or")[0].kind, TokenKind.KW_OR)
        self.assertEqual(lex("not")[0].kind, TokenKind.KW_NOT)

    def test_reserved_keywords_recognized(self):
        for kw, expected in [
            ("async", TokenKind.KW_ASYNC),
            ("await", TokenKind.KW_AWAIT),
            ("yield", TokenKind.KW_YIELD),
            ("defer", TokenKind.KW_DEFER),
            ("where", TokenKind.KW_WHERE),
            ("mut", TokenKind.KW_MUT),
        ]:
            self.assertEqual(lex(kw)[0].kind, expected, f"keyword {kw}")

    def test_case_sensitive(self):
        self.assertEqual(lex("Fun")[0].kind, TokenKind.IDENT)
        self.assertEqual(lex("FUN")[0].kind, TokenKind.IDENT)


# =============================================================
# Operators and maximal munch
# =============================================================

class TestOperators(unittest.TestCase):
    def test_arithmetic(self):
        result = kinds_no_layout("+ - * / %")
        self.assertEqual(
            result,
            [
                TokenKind.PLUS, TokenKind.MINUS, TokenKind.STAR,
                TokenKind.SLASH, TokenKind.PERCENT,
            ],
        )

    def test_compound_assignment(self):
        result = kinds_no_layout("+= -= *= /= %=")
        self.assertEqual(
            result,
            [
                TokenKind.PLUS_EQ, TokenKind.MINUS_EQ, TokenKind.STAR_EQ,
                TokenKind.SLASH_EQ, TokenKind.PERCENT_EQ,
            ],
        )

    def test_comparison(self):
        result = kinds_no_layout("== != < <= > >=")
        self.assertEqual(
            result,
            [
                TokenKind.EQ_EQ, TokenKind.BANG_EQ, TokenKind.LT,
                TokenKind.LT_EQ, TokenKind.GT, TokenKind.GT_EQ,
            ],
        )

    def test_arrow_vs_minus_gt(self):
        # -> is a single token.
        self.assertEqual(kinds_no_layout("->"), [TokenKind.ARROW])
        # - > are two tokens (space between them).
        self.assertEqual(
            kinds_no_layout("- >"),
            [TokenKind.MINUS, TokenKind.GT],
        )

    def test_dot_dot(self):
        self.assertEqual(kinds_no_layout(".."), [TokenKind.DOT_DOT])

    def test_dot_then_dot(self):
        # Doesn't split: .. is maximal munch.
        # But '. .' (with space) are two DOTs.
        self.assertEqual(
            kinds_no_layout(". ."),
            [TokenKind.DOT, TokenKind.DOT],
        )

    def test_eq_eq_vs_eq(self):
        self.assertEqual(kinds_no_layout("=="), [TokenKind.EQ_EQ])
        self.assertEqual(kinds_no_layout("="), [TokenKind.EQ])

    def test_fat_arrow(self):
        self.assertEqual(kinds_no_layout("=>"), [TokenKind.FAT_ARROW])

    def test_question(self):
        self.assertEqual(kinds_no_layout("?"), [TokenKind.QUESTION])

    def test_bang_alone_rejected(self):
        with self.assertRaises(LexerError):
            lex("!x")


# =============================================================
# Comments
# =============================================================

class TestComments(unittest.TestCase):
    def test_line_comment_skipped(self):
        result = kinds_no_layout("// comment\n42")
        self.assertEqual(result, [TokenKind.INT_LIT])

    def test_block_comment(self):
        result = kinds_no_layout("/* comment */ 42")
        self.assertEqual(result, [TokenKind.INT_LIT])

    def test_block_comment_multiline(self):
        result = kinds_no_layout("/* line 1\nline 2 */ 42")
        self.assertEqual(result, [TokenKind.INT_LIT])

    def test_nested_block_comment(self):
        result = kinds_no_layout(
            "/* outer /* inner */ still outer */ 42"
        )
        self.assertEqual(result, [TokenKind.INT_LIT])

    def test_deeply_nested_block_comment(self):
        source = "/* /* /* triple */ */ */ 42"
        result = kinds_no_layout(source)
        self.assertEqual(result, [TokenKind.INT_LIT])

    def test_unterminated_block_comment_rejected(self):
        with self.assertRaises(LexerError):
            lex("/* never ends")


# =============================================================
# Indentation
# =============================================================

class TestIndentation(unittest.TestCase):
    def test_simple_indent_dedent(self):
        source = "fun f()\n    return 1\n"
        seen = kinds(source)
        self.assertIn(TokenKind.INDENT, seen)
        self.assertIn(TokenKind.DEDENT, seen)
        # Equal number of INDENT and DEDENT.
        self.assertEqual(
            seen.count(TokenKind.INDENT), seen.count(TokenKind.DEDENT)
        )

    def test_nested_indent(self):
        source = "fun f()\n    if x\n        return 1\n"
        seen = kinds(source)
        self.assertEqual(seen.count(TokenKind.INDENT), 2)
        self.assertEqual(seen.count(TokenKind.DEDENT), 2)

    def test_dedent_to_same_level(self):
        source = "fun f()\n    let x = 1\n    return x\n"
        seen = kinds(source)
        # Only one INDENT and one DEDENT (only one block level).
        self.assertEqual(seen.count(TokenKind.INDENT), 1)
        self.assertEqual(seen.count(TokenKind.DEDENT), 1)

    def test_tab_at_line_start_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex("fun f()\n\treturn 1\n")
        self.assertIn("tab", str(ctx.exception).lower())

    def test_inconsistent_dedent_rejected(self):
        # 4, then 8 (inside), then 6 (non-existent)
        source = "a\n    b\n        c\n      d\n"
        with self.assertRaises(LexerError) as ctx:
            lex(source)
        self.assertIn("inconsistent", str(ctx.exception).lower())

    def test_blank_lines_inside_block_ignored(self):
        source = "fun f()\n    let x = 1\n\n    return x\n"
        seen = kinds(source)
        # Still just one INDENT/DEDENT.
        self.assertEqual(seen.count(TokenKind.INDENT), 1)
        self.assertEqual(seen.count(TokenKind.DEDENT), 1)

    def test_comment_only_lines_inside_block_ignored(self):
        source = (
            "fun f()\n"
            "    let x = 1\n"
            "    // comment in the middle\n"
            "    return x\n"
        )
        seen = kinds(source)
        self.assertEqual(seen.count(TokenKind.INDENT), 1)
        self.assertEqual(seen.count(TokenKind.DEDENT), 1)

    def test_multiple_dedents_at_eof(self):
        source = "fun f()\n    if x\n        return 1\n"
        seen = kinds(source)
        # The two DEDENTs are emitted at the end of the file.
        # We verify that they appear near the end.
        last_tokens = seen[-5:]
        self.assertIn(TokenKind.DEDENT, last_tokens)


# =============================================================
# Line continuation by parentheses
# =============================================================

class TestParenContinuation(unittest.TestCase):
    def test_newline_in_parens_no_indent(self):
        source = "f(\n    1,\n    2,\n)"
        seen = kinds(source)
        # No INDENT/DEDENT should be emitted inside the parentheses.
        # The only real indentation is of the outer program, which is 0.
        self.assertNotIn(TokenKind.INDENT, seen)

    def test_newline_in_brackets(self):
        source = "[\n    1,\n    2,\n]"
        seen = kinds(source)
        self.assertNotIn(TokenKind.INDENT, seen)

    def test_newline_in_braces(self):
        source = "{\n    a: 1,\n    b: 2,\n}"
        seen = kinds(source)
        self.assertNotIn(TokenKind.INDENT, seen)

    def test_unmatched_open_paren_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex("f(1, 2")
        self.assertIn("unclosed", str(ctx.exception).lower())

    def test_unmatched_close_paren_rejected(self):
        with self.assertRaises(LexerError):
            lex("1 + 2)")

    def test_mismatched_delimiters_rejected(self):
        with self.assertRaises(LexerError) as ctx:
            lex("(1, 2]")
        self.assertIn("mismatch", str(ctx.exception).lower())


# =============================================================
# Line continuation by backslash
# =============================================================

class TestBackslashContinuation(unittest.TestCase):
    def test_backslash_continues_line(self):
        # Without \, there's a NEWLINE in the middle + one at the end = 2 NEWLINEs.
        # With \, there's only the final NEWLINE = 1 NEWLINE.
        with_backslash = kinds("a + \\\nb")
        without_backslash = kinds("a +\nb")
        self.assertEqual(with_backslash.count(TokenKind.NEWLINE), 1)
        self.assertEqual(without_backslash.count(TokenKind.NEWLINE), 2)


# =============================================================
# Error messages and positions
# =============================================================

class TestErrorPositions(unittest.TestCase):
    # `$` outside a string literal is rejected by the lexer (it has no
    # meaning in the surface syntax, interpolation uses `${...}`
    # inside a string). It is a useful sentinel for testing that
    # the lexer reports positions and source context faithfully.

    def test_position_reported(self):
        try:
            lex("hello\n$")
            self.fail("expected LexerError")
        except LexerError as e:
            self.assertEqual(e.pos.line, 2)
            self.assertEqual(e.pos.col, 1)

    def test_error_message_includes_filename(self):
        try:
            Lexer("$", filename="teste.capa").lex()
            self.fail("expected LexerError")
        except LexerError as e:
            self.assertIn("teste.capa", e.format())

    def test_error_message_includes_caret(self):
        try:
            Lexer("foo $ bar").lex()
            self.fail("expected LexerError")
        except LexerError as e:
            self.assertIn("^", e.format())


# =============================================================
# Complete programs
# =============================================================

class TestRealisticPrograms(unittest.TestCase):
    def test_hello_world(self):
        source = (
            'fun main(stdio: Stdio)\n'
            '    stdio.print("Olá, mundo!")\n'
        )
        toks = lex(source)
        # Should not raise nor have premature EOF.
        self.assertEqual(toks[-1].kind, TokenKind.EOF)
        # Should have at least one string literal "Olá, mundo!".
        strings = [t for t in toks if t.kind == TokenKind.STRING_LIT]
        self.assertEqual(len(strings), 1)
        self.assertEqual(strings[0].value, "Olá, mundo!")

    def test_function_with_generics(self):
        source = "fun primeiro<T>(xs: List<T>) -> Option<T>\n    return None\n"
        toks = lex(source)
        kinds_seen = [t.kind for t in toks]
        self.assertIn(TokenKind.KW_FUN, kinds_seen)
        self.assertIn(TokenKind.LT, kinds_seen)
        self.assertIn(TokenKind.GT, kinds_seen)
        self.assertIn(TokenKind.ARROW, kinds_seen)

    def test_match_with_guards(self):
        source = (
            "match x\n"
            "    Alta if not concluida -> 1\n"
            "    Baixa -> 0\n"
        )
        toks = lex(source)
        kinds_seen = [t.kind for t in toks]
        self.assertIn(TokenKind.KW_MATCH, kinds_seen)
        self.assertIn(TokenKind.KW_IF, kinds_seen)
        self.assertIn(TokenKind.KW_NOT, kinds_seen)
        self.assertIn(TokenKind.ARROW, kinds_seen)


if __name__ == "__main__":
    unittest.main()

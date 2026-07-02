"""Tests for capa.formatter, the canonical-style formatter.

The formatter operates at the line level (trailing whitespace,
indentation, blank-line clusters, line-ending normalisation, final
newline) plus a small intra-line pass: collapse runs of spaces in
code, insert a space after a comma. Expression-level rewrites
(operator spacing around binary operators, brace placement, etc.)
are still deferred to the future AST-round-trip pass.
"""

import unittest

from capa import format_source, is_formatted


class TestLineEndings(unittest.TestCase):
    def test_crlf_normalised_to_lf(self):
        out = format_source("a\r\nb\r\n")
        self.assertEqual(out, "a\nb\n")

    def test_lone_cr_normalised_to_lf(self):
        out = format_source("a\rb\r")
        self.assertEqual(out, "a\nb\n")


class TestTrailingWhitespace(unittest.TestCase):
    def test_trailing_spaces_stripped(self):
        self.assertEqual(format_source("hello   \n"), "hello\n")

    def test_trailing_tabs_stripped(self):
        self.assertEqual(format_source("hello\t\t\n"), "hello\n")

    def test_blank_with_spaces_becomes_truly_blank(self):
        # A "blank" line that contains only spaces should collapse to
        # the empty line, which the dedupe rule then preserves.
        self.assertEqual(format_source("a\n   \nb\n"), "a\n\nb\n")


class TestSelectiveImportFormatting(unittest.TestCase):
    def test_selective_import_round_trips(self):
        src = "import foo (parse as csv_parse, Table)\n"
        self.assertEqual(format_source(src), src)
        self.assertTrue(is_formatted(src))

    def test_plain_import_forms_unchanged(self):
        for src in ("import foo\n", "import foo as bar\n"):
            self.assertEqual(format_source(src), src)


class TestIndentation(unittest.TestCase):
    def test_leading_tab_becomes_four_spaces(self):
        self.assertEqual(format_source("\tx\n"), "    x\n")

    def test_two_leading_tabs_become_eight_spaces(self):
        self.assertEqual(format_source("\t\tx\n"), "        x\n")

    def test_partial_indent_snaps_down(self):
        # Three leading spaces (not a multiple of 4) snap to zero;
        # five snap to four. The formatter never moves a line *out*
        # to a deeper level.
        self.assertEqual(format_source("   x\n"), "x\n")
        self.assertEqual(format_source("     x\n"), "    x\n")

    def test_already_aligned_indent_preserved(self):
        src = "fun f()\n    return 1\n"
        self.assertEqual(format_source(src), src)


class TestBlankLines(unittest.TestCase):
    def test_two_blank_lines_collapse_to_one(self):
        self.assertEqual(format_source("a\n\n\nb\n"), "a\n\nb\n")

    def test_many_blank_lines_collapse_to_one(self):
        self.assertEqual(format_source("a\n\n\n\n\n\nb\n"), "a\n\nb\n")

    def test_single_blank_line_preserved(self):
        # A single blank between top-level decls is idiomatic Capa
        # and must survive untouched.
        src = "fun a()\n    return 1\n\nfun b()\n    return 2\n"
        self.assertEqual(format_source(src), src)

    def test_trailing_blank_lines_dropped(self):
        self.assertEqual(format_source("a\n\n\n"), "a\n")


class TestFinalNewline(unittest.TestCase):
    def test_missing_final_newline_added(self):
        self.assertEqual(format_source("hello"), "hello\n")

    def test_existing_final_newline_preserved(self):
        self.assertEqual(format_source("hello\n"), "hello\n")

    def test_empty_input_stays_empty(self):
        self.assertEqual(format_source(""), "")


class TestBlockCommentPreservation(unittest.TestCase):
    """Lines inside ``/* ... */`` / ``/** ... */`` block comments
    keep their original indentation, so Javadoc-style ``*``
    continuation lines (typically sitting at column 1) survive."""

    def test_javadoc_block_canonicalised_to_line_form(self):
        # v3 round-trips block doc comments through the AST (the
        # parser stores them as ``FunDecl.doc: str`` regardless of
        # source form), and the emitter writes them in the canonical
        # ``///`` line form. The Javadoc-style ``*`` left margin is
        # stripped by the lexer's ``_strip_block_doc_margins`` helper
        # before the doc text reaches the AST, so the re-emitted form
        # has no ``*`` decoration. Same semantics, canonical shape.
        src = (
            "/** First line.\n"
            " *\n"
            " * Second paragraph.\n"
            " */\n"
            "fun f()\n"
            "    return\n"
        )
        expected = (
            "/// First line.\n"
            "///\n"
            "/// Second paragraph.\n"
            "fun f()\n"
            "    return\n"
        )
        self.assertEqual(format_source(src), expected)

    def test_non_doc_block_comment_preserved(self):
        src = (
            "/*\n"
            " * heading\n"
            " */\n"
            "fun f()\n"
            "    return\n"
        )
        self.assertEqual(format_source(src), src)

    def test_indentation_resumes_after_block_close(self):
        # After the closing ``*/``, normal indentation rules apply
        # again on the next line.
        src = (
            "/** doc */\n"
            "   fun f()\n"   # 3-space indent, not a multiple of 4
            "    return\n"
        )
        out = format_source(src)
        self.assertEqual(
            out,
            "/** doc */\n"
            "fun f()\n"
            "    return\n",
        )


class TestIdempotence(unittest.TestCase):
    """``format_source`` is idempotent: ``f(f(x)) == f(x)``."""

    SAMPLES = [
        "",
        "x",
        "\n\n\n",
        "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n",
        "\tdef\t\n  \n\n  bar\n",
        "/** doc */\nfun f()\n    return\n",
    ]

    def test_double_format_equals_single_format(self):
        for src in self.SAMPLES:
            once = format_source(src)
            twice = format_source(once)
            self.assertEqual(once, twice, f"not idempotent for: {src!r}")


class TestIsFormatted(unittest.TestCase):
    def test_canonical_text_is_formatted(self):
        self.assertTrue(
            is_formatted("fun f()\n    return 1\n")
        )

    def test_trailing_whitespace_is_not_formatted(self):
        self.assertFalse(is_formatted("fun f()\n    return 1  \n"))

    def test_crlf_is_not_formatted(self):
        self.assertFalse(is_formatted("x\r\n"))

    def test_missing_final_newline_is_not_formatted(self):
        self.assertFalse(is_formatted("x"))


class TestIntraLineSpacing(unittest.TestCase):
    def test_multiple_spaces_collapse(self):
        self.assertEqual(
            format_source("let x  =  1 +  2\n"),
            "let x = 1 + 2\n",
        )

    def test_space_inserted_after_comma(self):
        self.assertEqual(
            format_source("f(1,2,3)\n"),
            "f(1, 2, 3)\n",
        )

    def test_spacing_skipped_inside_string(self):
        # The triple space inside "..." must survive untouched.
        src = 'let s = "a   b"\n'
        self.assertEqual(format_source(src), src)

    def test_spacing_skipped_inside_char(self):
        src = "let c = ' '\n"
        self.assertEqual(format_source(src), src)

    def test_spacing_skipped_in_line_comment(self):
        # Everything after `//` is preserved character-for-character.
        # The double space BEFORE the `//` is still code, so it
        # collapses to a single space; the comment body is untouched.
        src = "let x = 1  // why    not?\n"
        self.assertEqual(format_source(src), "let x = 1 // why    not?\n")

    def test_comma_before_closing_paren_left_alone(self):
        # A trailing comma followed by ``)`` must NOT get a space inserted.
        self.assertEqual(
            format_source("f(1,)\n"),
            "f(1,)\n",
        )

    def test_idempotent(self):
        src = "fun add(a,b: Int) -> Int\n    return a  +  b\n"
        once = format_source(src)
        twice = format_source(once)
        self.assertEqual(once, twice)


class TestSecurityLabelRoundTrip(unittest.TestCase):
    """A formatter that drops an information-flow security label
    (``@secret`` / ``@public``) silently disarms the IFC: a leak that
    was rejected before formatting is accepted after. Every position a
    label is valid must round-trip. The label lives on ``TypeExpr``,
    so this exercises the full class, not just the reported struct
    field.
    """

    def test_struct_field_secret_preserved(self):
        src = (
            "pub type Probe {\n"
            "    name: String,\n"
            "    field: @secret String,\n"
            "    source: String\n"
            "}\n"
        )
        out = format_source(src)
        self.assertIn("@secret String", out)
        # Canonical already, so byte-exact round-trip.
        self.assertEqual(out, src)
        self.assertTrue(is_formatted(src))

    def test_struct_field_public_preserved(self):
        src = (
            "pub type Probe {\n"
            "    field: @public String\n"
            "}\n"
        )
        self.assertIn("@public String", format_source(src))

    def test_label_preserved_in_every_type_position(self):
        cases = {
            "param": "fun f(x: @secret String) -> Int\n    0\n",
            "return": 'fun f(x: Int) -> @secret String\n    "a"\n',
            "let": "fun f() -> Int\n    let x: @secret Int = 1\n    0\n",
            "var": "fun f() -> Int\n    var x: @public Int = 1\n    0\n",
            "generic": "fun f(x: List<@secret String>) -> Int\n    0\n",
            "tuple": "fun f(x: (@secret Int, String)) -> Int\n    0\n",
        }
        for name, src in cases.items():
            with self.subTest(position=name):
                out = format_source(src)
                self.assertTrue(
                    "@secret" in out or "@public" in out,
                    f"label dropped in {name}: {out!r}",
                )
                # Idempotent: formatting the output again is a no-op.
                self.assertEqual(out, format_source(out))

    def test_labelled_field_is_idempotent(self):
        src = (
            "pub type Probe {\n"
            "    field: @secret String\n"
            "}\n"
        )
        once = format_source(src)
        self.assertEqual(once, format_source(once))

    def test_fmt_check_does_not_claim_label_stripping_is_formatted(self):
        # A canonical labelled field must be reported as already
        # formatted (is_formatted True). Before the fix the formatter
        # produced an unlabelled form, so is_formatted was False and
        # --fmt would then have stripped the label.
        src = (
            "pub type Probe {\n"
            "    field: @secret String\n"
            "}\n"
        )
        self.assertTrue(is_formatted(src))

    def test_ifc_still_rejects_leak_after_formatting(self):
        # End-to-end: a program that leaks a @secret field to a public
        # sink is flagged by the analyzer. After formatting, the label
        # survives, so the SAME leak is still flagged. If the label
        # were stripped the leak would go silent.
        from capa import Lexer, Parser, analyze

        def ifc_flags(text):
            module = Parser(Lexer(text).lex(), source=text).parse_module()
            r = analyze(module, source=text)
            msgs = list(r.warnings) + list(r.errors)
            return [m for m in msgs if "public sink" in m.message]

        leak = (
            "pub type Probe {\n"
            "    field: @secret String\n"
            "}\n"
            "fun leak(p: Probe, stdio: Stdio)\n"
            "    stdio.println(p.field)\n"
        )
        self.assertEqual(len(ifc_flags(leak)), 1, "leak not flagged pre-fmt")
        formatted = format_source(leak)
        self.assertIn("@secret", formatted)
        self.assertEqual(
            len(ifc_flags(formatted)), 1,
            "IFC no longer flags the leak after formatting -- the "
            "@secret label was stripped by the formatter",
        )


class TestNeverEmpty(unittest.TestCase):
    """A valid, non-empty source must never format to empty output.
    Emitting empty for a valid file (especially when --fmt rewrites
    in place) would silently destroy the user's program."""

    def test_valid_sources_never_format_to_empty(self):
        samples = [
            "pub type Probe {\n    field: @secret String\n}\n",
            "fun f(x: @secret String) -> Int\n    0\n",
            'const K: @secret String = "x"\n',
            "type Color =\n    Red\n    Green\n",
            "fun main()\n    let x: @public Int = 1\n",
        ]
        for src in samples:
            with self.subTest(src=src):
                out = format_source(src)
                self.assertNotEqual(
                    out.strip(), "",
                    f"formatter emptied a valid source: {src!r}",
                )


if __name__ == "__main__":
    unittest.main()

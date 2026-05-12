"""Tests for capa.formatter, the canonical-style formatter.

The v1 formatter operates at the line level: trailing whitespace,
indentation, blank-line clusters, line-ending normalisation, and the
final newline. It does **not** rewrite expressions or operator
spacing; those tests should not exist yet.
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

    def test_javadoc_star_lines_preserved(self):
        src = (
            "/** First line.\n"
            " *\n"
            " * Second paragraph.\n"
            " */\n"
            "fun f()\n"
            "    return\n"
        )
        self.assertEqual(format_source(src), src)

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


if __name__ == "__main__":
    unittest.main()

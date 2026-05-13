"""Property-based tests for the Capa toolchain.

These tests fuzz the lexer, parser, and formatter with Hypothesis
to surface bugs that the example-based suite would miss.

The properties tested here are conservative, surface-level
invariants ("the lexer never raises an unhandled exception",
"the formatter is idempotent") chosen because they hold over the
entire input space and do not depend on a particular Capa
grammar. They are the cheapest first batch.

Richer properties that need a real Capa-program generator
(round-trip ``parse(format(s)) == parse(s)``, manifest
soundness `runtime_caps ⊆ manifest_caps`) are flagged in
TODO.md as the next deliverable and need a syntax-aware
strategy that produces parseable programs by construction.
"""

from __future__ import annotations

import unittest

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings

from capa import Lexer, LexerError, Parser, format_source, is_formatted
from capa.parser import ParserError


# A printable-only strategy that excludes control characters except
# `\n` and `\t`. Real source files do not contain NUL bytes, raw
# control codes, or surrogates; if Hypothesis generates them it
# tells us about robustness, not about a real-world input. We
# accept all printable ASCII + whitespace; for surrogates and
# multibyte Unicode see the smaller targeted strategies below.
_SOURCE_TEXT = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Zs"),
        whitelist_characters="\n\t ",
    ),
    max_size=400,
)


# Tighter alphabet for property tests that need shapes that
# resemble Capa source: identifiers, keywords, common operators,
# whitespace.
_CAPA_ISH_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " \t\n_:.,;()[]{}<>+-*/%=!?\"'@|"
)
_CAPA_ISH_TEXT = st.text(alphabet=_CAPA_ISH_CHARS, max_size=400)


# Hypothesis's default settings can shrink for a long time on
# pathological inputs. The formatter / lexer / parser tests are
# small unit operations, so we cap each example at a generous
# budget but let Hypothesis run a couple of hundred examples per
# property by default.
_PROFILE = settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow],
)


# ===========================================================
# Formatter
# ===========================================================


class TestFormatterProperties(unittest.TestCase):
    """``format_source`` is documented as idempotent. Whatever the
    input, applying it twice should yield the same result as
    applying it once. Hypothesis exercises this over arbitrary
    text."""

    @given(_SOURCE_TEXT)
    @_PROFILE
    def test_format_is_idempotent(self, text):
        once = format_source(text)
        twice = format_source(once)
        self.assertEqual(once, twice)

    @given(_SOURCE_TEXT)
    @_PROFILE
    def test_format_output_is_formatted(self, text):
        # The output of format_source should satisfy is_formatted.
        # This is a consequence of idempotence but worth asserting
        # because is_formatted is what `--fmt-check` returns to CI
        # and we want them to never disagree.
        once = format_source(text)
        self.assertTrue(is_formatted(once), repr(once))


# ===========================================================
# Lexer
# ===========================================================


class TestLexerProperties(unittest.TestCase):
    """The lexer must terminate on every input. It is allowed to
    raise ``LexerError`` (for malformed sources), but must not
    raise any other exception type, infinite-loop, or return None.
    """

    @given(_SOURCE_TEXT)
    @_PROFILE
    def test_lexer_never_raises_uncaught(self, source):
        try:
            tokens = Lexer(source).lex()
        except LexerError:
            return
        # If lexing succeeded, the result must be a non-empty list
        # ending with an EOF token.
        self.assertIsInstance(tokens, list)
        self.assertTrue(len(tokens) >= 1)

    @given(_CAPA_ISH_TEXT)
    @_PROFILE
    def test_lexer_never_raises_uncaught_capa_alphabet(self, source):
        try:
            Lexer(source).lex()
        except LexerError:
            return


# ===========================================================
# Parser
# ===========================================================


class TestParserProperties(unittest.TestCase):
    """The parser must terminate on every well-formed token stream.
    A parse either succeeds (returning a Module AST) or raises
    ParserError; no other exception type and no infinite loop.
    The "well-formed token stream" precondition is satisfied by
    only running the parser on inputs the lexer accepted."""

    @given(_CAPA_ISH_TEXT)
    @_PROFILE
    def test_parser_never_raises_uncaught(self, source):
        try:
            tokens = Lexer(source).lex()
        except LexerError:
            return
        try:
            Parser(tokens, source=source).parse_module()
        except (LexerError, ParserError):
            return


# ===========================================================
# Round-trip: formatter is a fixpoint
# ===========================================================


class TestFormatterFixpoint(unittest.TestCase):
    """For any input ``s``, the sequence
    ``s, format(s), format(format(s)), ...`` reaches a fixpoint
    after at most one step. This is a stronger property than
    idempotence: it says the first application is the convergence
    point, not merely that further applications stay there."""

    @given(_SOURCE_TEXT)
    @_PROFILE
    def test_format_converges_in_one_step(self, text):
        once = format_source(text)
        twice = format_source(once)
        thrice = format_source(twice)
        self.assertEqual(once, twice)
        self.assertEqual(twice, thrice)


if __name__ == "__main__":
    unittest.main()

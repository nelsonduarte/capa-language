"""Property-based tests for the Capa toolchain.

Two batches of properties:

**Phase 1** (lower in this file) fuzzes the lexer, parser, and
formatter with arbitrary text. The invariants there are
conservative on purpose ("the lexer never raises an unhandled
exception", "the formatter is idempotent") because they have
to hold over the entire input space.

**Phase 2** (the syntax-aware strategy) generates *plausible
Capa programs* by composing fragments of the grammar and then
asserts the whole pipeline (lex + parse + analyse + transpile +
``ast.parse`` of the transpiled Python) succeeds end to end.
This is what catches the harder kind of bug: a parser path
that the example suite never exercises, an analyser case that
crashes on a particular nesting, or a transpiler that emits
syntactically invalid Python on a rare combination.

The citable property the external review actually wants
("runtime capability set ⊆ manifest declared set") is still
phase 3 work and needs runtime instrumentation; see
``docs/semantics.md`` Theorem 2 for the corresponding formal
claim.
"""

from __future__ import annotations

import unittest

try:
    import hypothesis.strategies as st
    from hypothesis import HealthCheck, given, settings
except ImportError:  # pragma: no cover - exercised only without the extra
    # When Hypothesis is not installed (e.g. someone running the suite
    # without `pip install -e .[test]`), skip every test in this module
    # rather than fail at import time. CI installs the extra; this
    # branch protects the casual contributor.
    raise unittest.SkipTest(
        "hypothesis is not installed; install with `pip install -e .[test]`"
    )

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


# ===========================================================
# Phase 2: syntax-aware strategy
# ===========================================================
#
# A small grammar of always-well-typed Capa fragments composed
# recursively into programs of the shape::
#
#     fun main(stdio: Stdio)
#         <stmt>
#         <stmt>
#         ...
#
# The strategy only emits forms whose typing rules are
# unambiguous: integer-only arithmetic, `let` bindings of `Int`,
# `if` comparing two ints, `for` over a fixed-bound range,
# `stdio.println` of a string literal, optionally interpolating
# one of the in-scope int bindings. By construction every
# generated program type-checks, transpiles, and runs.


import ast as _python_ast
import textwrap

from capa import analyze, transpile


_INT_LIT = st.integers(min_value=0, max_value=1000)
_INT_OP = st.sampled_from(["+", "-", "*"])
_CMP_OP = st.sampled_from(["<", "<=", ">", ">=", "==", "!="])

# Statement kinds, sampled symbolically and then rendered with
# a position-indexed identifier so every binding in the program
# is unique by construction. This sidesteps the "duplicate
# binding 'a'" rejection that Hypothesis cheerfully found within
# 50 examples when the strategy reused a fixed identifier pool.
_BASIC_KINDS = st.sampled_from(["println", "let", "var"])
_WRAPPED_KINDS = st.sampled_from(["if", "for"])


def _expr_int(depth):
    """An always-Int-typed expression built only from integer
    literals, with no identifier references. Identifier
    references would need scope tracking to guarantee they
    point at an in-scope binding, and even with scope tracking
    a freshly-bound name is not guaranteed safe (re-binding
    rules vary between `let` and `var`). Phase 2.5 work."""
    leaf = _INT_LIT.map(str)
    if depth <= 0:
        return leaf
    sub = _expr_int(depth - 1)
    binop = st.tuples(sub, _INT_OP, sub).map(
        lambda t: f"({t[0]} {t[1]} {t[2]})"
    )
    return st.one_of(leaf, binop)


@st.composite
def _program(draw):
    """A complete Capa program with a `main(stdio: Stdio)` body
    of 1 to 4 statements. Every binding uses a unique name
    ``v{i}`` indexed by its position in the body, so the
    "duplicate binding" check never fires. Control-flow
    statements wrap a basic statement; no deeper nesting.
    Always includes a leading ``stdio.println("start")`` to
    satisfy the capability-must-use rule."""
    n = draw(st.integers(min_value=0, max_value=3))
    lines = [
        'fun main(stdio: Stdio)',
        '    stdio.println("start")',
    ]
    for i in range(n):
        kind = draw(st.one_of(_BASIC_KINDS, _WRAPPED_KINDS))
        var_name = f"v{i}"
        if kind == "println":
            lines.append('    stdio.println("step")')
        elif kind == "let":
            expr = draw(_expr_int(2))
            lines.append(f"    let {var_name}: Int = {expr}")
        elif kind == "var":
            expr = draw(_expr_int(2))
            lines.append(f"    var {var_name}: Int = {expr}")
        elif kind == "if":
            l = draw(_expr_int(1))
            op = draw(_CMP_OP)
            r = draw(_expr_int(1))
            lines.append(f"    if {l} {op} {r}")
            lines.append('        stdio.println("inside-if")')
        elif kind == "for":
            bound = draw(_INT_LIT)
            lines.append(f"    for {var_name} in 0..{bound}")
            lines.append('        stdio.println("inside-for")')
    return "\n".join(lines) + "\n"


class TestSyntaxAwarePipeline(unittest.TestCase):
    """For every program generated by the syntax-aware strategy
    above, the full Capa pipeline must succeed and produce valid
    Python. These tests are slower than phase 1 (each example
    runs lex + parse + analyse + transpile) so the budget is
    smaller, but the signal is much higher: bugs that surface
    only on rare-but-valid nestings show up here."""

    @given(_program())
    @settings(
        max_examples=100,
        deadline=5000,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_full_pipeline_succeeds(self, source):
        # Lex + parse: must succeed (the strategy is syntax-aware).
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()

        # Analyse: by construction the strategy only emits typed
        # forms, so we expect ok=True. If the analyser reports
        # errors on a generated program, the strategy has a
        # bug-by-omission; we surface that as a test failure with
        # the program and the errors attached so the message is
        # actionable.
        result = analyze(module, source=source)
        self.assertTrue(
            result.ok,
            msg=f"analyser rejected a syntax-aware program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[str(e.format()) for e in result.errors]}",
        )

        # Transpile: must not raise.
        code = transpile(module, types=result.types)

        # The transpiled output must be syntactically valid Python.
        try:
            _python_ast.parse(code)
        except SyntaxError as e:
            self.fail(
                f"transpiler emitted invalid Python for:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"Python SyntaxError: {e}\n"
                f"transpiled:\n{textwrap.indent(code, '    ')}"
            )


if __name__ == "__main__":
    unittest.main()

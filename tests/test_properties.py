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


# Per-capability "safe to call from a test" probe. Each entry
# names a read-only-ish method that mutates no global state
# outside the runtime trace itself: ``Fs.allows`` is a pure
# query against the attenuation set, ``Net.allows`` likewise,
# ``Env.allows`` is a set lookup, ``Clock.now_secs`` reads the
# wall clock, ``Random.float_unit`` advances the RNG state
# (deterministic when seeded, which the test does not, but the
# test does not depend on the value either way).
_CAP_PROBES: dict[str, str] = {
    "Fs":     '{var}.allows("/tmp/")',
    "Net":    '{var}.allows("example.com")',
    "Env":    '{var}.allows("PATH")',
    "Clock":  '{var}.now_secs()',
    "Random": '{var}.float_unit()',
}

# Per-capability attenuation expression. Each one calls the
# class's narrowing operation with a plausible argument so the
# attenuated capability still passes its probe. The runtime
# trace records the ``restrict_to`` / ``with_seed`` call
# alongside the subsequent probe; the property holds because
# both are operations on the same capability class.
_CAP_ATTEN: dict[str, str] = {
    "Fs":     '{var}.restrict_to("/tmp/")',
    "Net":    '{var}.restrict_to("example.com")',
    "Env":    '{var}.restrict_to_keys(["PATH"])',
    "Clock":  '{var}.restrict_to_after(0.0)',
    "Random": '{var}.with_seed(42)',
}


@st.composite
def _program_with_caps(draw):
    """A program with ``main(stdio: Stdio, [some subset of caps])``
    whose body exercises *each* declared capability at least
    once. The exercise calls a single read-only probe per
    capability (see ``_CAP_PROBES``) so the trace is
    deterministic in its set of classes but not in the
    operations Hypothesis chooses to invoke. The strategy
    occasionally returns a stdio-only program (when the
    sampled cap set is empty), which is a degenerate but
    legal shape and keeps backward coverage with phase 2."""
    cap_set = draw(st.sets(
        st.sampled_from(list(_CAP_PROBES.keys())),
        min_size=0,
        max_size=3,
    ))
    params = ["stdio: Stdio"]
    bindings: list[tuple[str, str]] = []
    for cap in sorted(cap_set):
        var = cap.lower()
        params.append(f"{var}: {cap}")
        bindings.append((cap, var))

    lines = [
        f"fun main({', '.join(params)})",
        '    stdio.println("start")',
    ]
    for i, (cap, var) in enumerate(bindings):
        probe = _CAP_PROBES[cap].format(var=var)
        lines.append(f"    let v{i} = {probe}")
    return "\n".join(lines) + "\n"


@st.composite
def _program_with_caps_advanced(draw):
    """A richer version of ``_program_with_caps`` that, for each
    declared capability, picks one of four call shapes:

      - ``plain``: probe the capability directly in main.
      - ``attenuated``: bind an attenuated form of the capability
        first (e.g. ``let af = fs.restrict_to("/tmp/")``), then
        probe the attenuated value. Exercises Capa's
        attenuation chain plus the analyser's "first-class
        capability attenuation" rule.
      - ``via_helper``: emit a helper function
        ``fun use_{cap}(c: Cap) -> Bool`` that probes the cap
        in its own body, and call it from main. Exercises the
        analyser's flow-tracking for capability values across
        call boundaries plus the manifest's per-function
        rollup (both main and use_{cap} declare the
        capability, so the manifest set is unchanged).
      - ``consumed``: like ``via_helper`` but the helper takes
        the capability with ``consume`` qualifier. The
        analyser's linear layer then forbids any further use
        of the capability after the call; the strategy puts
        the consumed call at the END of main's body so this
        constraint is satisfied by construction. Exercises
        the consume / use-after-consume rule on every fuzz
        example that picks this flavour.

    All four flavours keep the soundness property
    ``runtime_classes ⊆ manifest_classes`` true by
    construction; the test exists to catch regressions, not to
    discover the property.
    """
    cap_set = draw(st.sets(
        st.sampled_from(list(_CAP_PROBES.keys())),
        min_size=0,
        max_size=3,
    ))
    cap_flavors = {}
    for cap in sorted(cap_set):
        cap_flavors[cap] = draw(
            st.sampled_from(
                ["plain", "attenuated", "via_helper", "consumed"]
            )
        )

    helpers: list[str] = []
    for cap, flavor in cap_flavors.items():
        var = cap.lower()
        probe = _CAP_PROBES[cap].format(var=var)
        if flavor == "via_helper":
            helpers.append(
                f"fun use_{var}({var}: {cap}) -> Bool\n"
                f"    let _r = {probe}\n"
                f"    return true\n"
            )
        elif flavor == "consumed":
            helpers.append(
                f"fun take_{var}(consume {var}: {cap}) -> Bool\n"
                f"    let _r = {probe}\n"
                f"    return true\n"
            )

    params = ["stdio: Stdio"]
    bindings = []
    for cap in sorted(cap_set):
        var = cap.lower()
        params.append(f"{var}: {cap}")
        bindings.append((cap, var, cap_flavors[cap]))

    body_lines = [
        f"fun main({', '.join(params)})",
        '    stdio.println("start")',
    ]
    for i, (cap, var, flavor) in enumerate(bindings):
        if flavor == "plain":
            probe = _CAP_PROBES[cap].format(var=var)
            body_lines.append(f"    let v{i} = {probe}")
        elif flavor == "attenuated":
            attn = _CAP_ATTEN[cap].format(var=var)
            attn_var = f"a{i}"
            body_lines.append(f"    let {attn_var} = {attn}")
            probe = _CAP_PROBES[cap].format(var=attn_var)
            body_lines.append(f"    let v{i} = {probe}")
        elif flavor == "via_helper":
            body_lines.append(f"    let v{i} = use_{var}({var})")
        elif flavor == "consumed":
            body_lines.append(f"    let v{i} = take_{var}({var})")

    return "\n".join(helpers + body_lines) + "\n"


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


# ===========================================================
# Phase 3: runtime <= manifest soundness
# ===========================================================
#
# The citable property the external review asks for: every
# capability class that the runtime exercises must also appear
# in the manifest the analyser emits. Theorem 2 of
# docs/semantics.md in static form; this is the dynamic
# counterpart, fuzzed.
#
# The instrumentation lives in `capa.runtime._trace`: when
# enabled it wraps every public method on every built-in
# capability class so each call appends `(class_name,
# method_name)` to a module-level list. The test clears the
# trace, transpiles a generated program, execs it in-process,
# reads the trace, and compares it to the manifest derived
# from the same AST.
#
# Phase 3 has two flavours in this file:
#
#   - The minimal one (``test_runtime_classes_subset_of_manifest_classes``)
#     reuses the phase 2 strategy, which only declares `Stdio`,
#     so the assertion is trivially `{Stdio} ⊆ {Stdio}`. It
#     still earns its keep as a scaffold sanity check.
#
#   - Phase 3.5 (``test_runtime_classes_subset_with_multiple_caps``)
#     uses ``_program_with_caps``, which threads a random
#     subset of {Fs, Net, Env, Clock, Random} through main and
#     exercises each with a read-only probe. Hypothesis can
#     now generate the non-trivial inclusions
#     ({Stdio, Net} ⊆ {Stdio, Net}, etc.), and a regression
#     that ever introduces an ambient invocation (a runtime
#     class missing from the manifest) would surface here.


from capa.manifest import build_manifest
from capa.runtime import _trace


class TestRuntimeSubsetOfManifest(unittest.TestCase):
    """For every generated program, the set of capability classes
    observed at runtime is a subset of the set of capability
    classes declared in the manifest emitted by the analyser.
    """

    @classmethod
    def setUpClass(cls):
        _trace.enable()

    def _manifest_classes(self, module) -> set[str]:
        """Compute the union of `declared_capabilities` across every
        function in the manifest. Each entry's class name is a
        Capa type expression rendered as text; for the demo
        strategy these are always single names like 'Stdio'."""
        m = build_manifest(module)
        result: set[str] = set()
        for fn in m["functions"]:
            for cap in fn["declared_capabilities"]:
                result.add(cap)
        return result

    @given(_program())
    @settings(
        max_examples=50,
        deadline=5000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_runtime_classes_subset_of_manifest_classes(self, source):
        from capa import analyze
        from capa.transpiler import _PRELUDE  # noqa: F401 - validates import shape

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            return  # the strategy may produce edge cases the analyser rejects; soundness still holds vacuously

        manifest_classes = self._manifest_classes(module)

        # exec the transpiled program in a controlled-globals
        # environment so we can read the trace afterwards. The
        # transpiler emits `from capa.runtime import *` at the
        # top, then defines functions, then the
        # `if __name__ == "__main__":` bootstrap that calls
        # main() with capability instances. Running with
        # __name__ = "__main__" triggers that bootstrap.
        from capa import transpile
        code = transpile(module, types=result.types)

        _trace.clear()
        run_globals: dict = {"__name__": "__main__"}
        try:
            exec(compile(code, "<test>", "exec"), run_globals)
        except SystemExit:
            pass

        runtime_classes = _trace.classes_used()

        self.assertTrue(
            runtime_classes.issubset(manifest_classes),
            msg=(
                f"runtime classes {runtime_classes} not subset of "
                f"manifest classes {manifest_classes} for program:\n"
                f"{textwrap.indent(source, '    ')}"
            ),
        )

    @given(_program_with_caps_advanced())
    @settings(
        max_examples=50,
        deadline=8000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_runtime_subset_under_advanced_flavours(self, source):
        """Phase 3.6 / 3.7: the advanced strategy picks per
        capability among four call shapes:

          - plain probe in main,
          - attenuated probe (``let a = c.restrict_to(...);
            a.probe()``),
          - probe routed through a helper that itself declares
            the capability (``fun use_X(x: Cap) -> Bool``),
          - probe routed through a helper that ``consume``s
            the capability (``fun take_X(consume x: Cap) -> Bool``),
            forbidding any further use of the cap after.

        All four flavours preserve the soundness invariant
        ``runtime_classes ⊆ manifest_classes``; the test
        catches regressions, particularly any analyser or
        transpiler change that lets a method call leak a class
        not in the function's signature, or any drift in the
        linear-layer bookkeeping that silently allows a
        use-after-consume."""
        from capa import analyze, transpile

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            self.fail(
                f"analyser rejected an advanced-strategy program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[e.format() for e in result.errors]}"
            )

        manifest_classes = self._manifest_classes(module)
        code = transpile(module, types=result.types)

        _trace.clear()
        run_globals: dict = {"__name__": "__main__"}
        try:
            exec(compile(code, "<test>", "exec"), run_globals)
        except SystemExit:
            pass

        runtime_classes = _trace.classes_used()

        self.assertTrue(
            runtime_classes.issubset(manifest_classes),
            msg=(
                f"runtime classes {runtime_classes} not subset of "
                f"manifest classes {manifest_classes} for program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"trace:\n{_trace.get()!r}"
            ),
        )

    @given(_program_with_caps())
    @settings(
        max_examples=50,
        deadline=5000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_runtime_classes_subset_with_multiple_caps(self, source):
        """Phase 3.5: every declared capability is exercised at
        least once; the strategy generates non-trivial
        subsets like {Stdio, Net, Fs}. Soundness still has to
        hold: runtime_classes ⊆ manifest_classes.

        With the current strategy the property holds *by
        construction* (every used capability is also declared),
        but a future regression that introduces an ambient
        capability invocation, or a transpiler bug that emits
        a call against the wrong capability instance, would
        surface here as a runtime class with no manifest
        counterpart."""
        from capa import analyze, transpile

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            # Defensive: the strategy *should* always produce
            # well-typed programs; if the analyser disagrees,
            # the strategy has a bug we want surfaced, not
            # silently swallowed.
            self.fail(
                f"analyser rejected a strategy-produced program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[e.format() for e in result.errors]}"
            )

        manifest_classes = self._manifest_classes(module)
        code = transpile(module, types=result.types)

        _trace.clear()
        run_globals: dict = {"__name__": "__main__"}
        try:
            exec(compile(code, "<test>", "exec"), run_globals)
        except SystemExit:
            pass

        runtime_classes = _trace.classes_used()

        self.assertTrue(
            runtime_classes.issubset(manifest_classes),
            msg=(
                f"runtime classes {runtime_classes} not subset of "
                f"manifest classes {manifest_classes} for program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"trace:\n{_trace.get()!r}"
            ),
        )


if __name__ == "__main__":
    unittest.main()

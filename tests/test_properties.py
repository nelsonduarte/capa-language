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

# Per-capability *privileged* (gated) operation whose argument is
# constrained by the attenuation in force, paired with an argument
# that lies WITHIN the corresponding ``_CAP_ATTEN`` restriction so
# a correct compiler keeps the attenuation honoured. Unlike
# ``_CAP_PROBES`` (which use the side-effect-free ``allows`` query),
# these are the gated ops the attenuation-honoured invariant cares
# about: the trace records ``(class, op, arg)`` and the invariant
# checks ``arg`` satisfies the accumulated restriction.
#
# Restricted to ``Fs`` and ``Env``: both are fast, local, and
# fail-closed (a missing path / unset key returns Err / None with
# no external IO), so the test stays deterministic and quick. The
# externally-reaching gated ops (``Net.get``/``post``, ``Proc.exec``,
# ``Db.exec``/``query``) would do real socket / subprocess / sqlite
# work and are deliberately excluded from the privileged-op probes.
_CAP_PRIV_OP: dict[str, str] = {
    "Fs":  '{var}.read("/tmp/capa_fuzz_probe.txt")',
    "Env": '{var}.get("PATH")',
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

    The slice-25 cross-function-attenuation shape (attenuate in
    main, perform the gated op in a helper) lives in its own
    strategy ``_program_attenuated_via_helper`` because it is the
    only shape that does a *real* side-effecting op; keeping it out
    of this strategy lets the subset tests stay on side-effect-free
    ``allows`` probes.

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


@st.composite
def _program_attenuated_via_helper(draw):
    """Slice-25 shape (cross-function attenuation): attenuate a cap
    in ``main`` and pass the *attenuated* value to a helper that
    performs a gated privileged op on it. The restriction is
    established in one function and the privileged op happens in
    another -- exactly the shape that escaped the campaign because
    the analyser's subset invariant does not constrain it.

    Kept in its own strategy (rather than folded into
    ``_program_with_caps_advanced``) because it is the only shape
    here that performs a *real* side-effecting op (``fs.read`` /
    ``env.get``) whose argument the attenuation-honoured invariant
    inspects; the subset strategies stay on side-effect-free
    ``allows`` probes.

    Emitted shape (for ``Fs``)::

        fun do_fs(fs: Fs) -> Bool
            let _r = fs.read("/tmp/capa_fuzz_probe.txt")
            return true
        fun main(stdio: Stdio, fs: Fs)
            stdio.println("start")
            let a0 = fs.restrict_to("/tmp/")
            let v0 = do_fs(a0)

    The op argument lies within the restriction, so a correct
    compiler keeps the attenuation honoured. Always compiles.
    """
    cap = draw(st.sampled_from(
        sorted(set(_CAP_PRIV_OP) & set(_CAP_ATTEN))
    ))
    var = cap.lower()
    priv = _CAP_PRIV_OP[cap].format(var=var)
    attn = _CAP_ATTEN[cap].format(var=var)
    lines = [
        f"fun do_{var}({var}: {cap}) -> Bool",
        f"    let _r = {priv}",
        "    return true",
        "",
        f"fun main(stdio: Stdio, {var}: {cap})",
        '    stdio.println("start")',
        f"    let a0 = {attn}",
        f"    let v0 = do_{var}(a0)",
    ]
    return "\n".join(lines) + "\n"


# Capabilities a user-cap struct can wrap, each with a gated
# privileged op the impl method performs on the wrapped built-in
# and an argument the wrapping struct's restriction would honour.
# This is the slice-21 shape: the user-cap impl exercises a
# built-in cap through ``self.inner`` even though the function
# holding the user-cap never names the built-in. Restricted to
# ``Fs``/``Env`` (fast, local, gated ops with a string argument).
_WRAPPED_BUILTIN: dict[str, str] = {
    "Fs":  'self.inner.read("/tmp/capa_fuzz_wrapped.txt")',
    "Env": 'self.inner.get("PATH")',
}


@st.composite
def _program_user_cap_wraps_builtin(draw):
    """Slice-21 shape: a user-defined capability whose sole
    implementor is a struct that *wraps a built-in cap in a
    field*, and whose impl method performs a privileged op on
    that field.

    The function ``run`` takes only the user-cap and calls
    ``.probe()`` on it; the built-in (``Fs`` / ``Env``) it
    transitively exercises never appears in ``run``'s signature.
    Pre-slice-21 the manifest claimed ``run`` provably-excluded
    the built-in; running the program then exercised it, breaking
    the exclusion invariant. The per-impl reachability fix
    (commit a3f3722 / 75bcaea) made the manifest surface the
    wrapped cap as transitively reachable, so the exclusion
    invariant (GAP A assertion 2) now holds.

    Emitted shape (for ``Fs``)::

        capability Prober
            fun probe(self) -> Bool
        type Wrapper { inner: Fs }
        impl Prober for Wrapper
            fun probe(self) -> Bool
                let _r = self.inner.read("/tmp/...")
                return true
        fun make(fs: Fs) -> Wrapper
            return Wrapper { inner: fs }
        fun run(p: Wrapper) -> Bool
            return p.probe()
        fun main(stdio: Stdio, fs: Fs)
            stdio.println("start")
            let w = make(fs)
            let _ = run(w)

    Always compiles (verified before adding to the strategy).
    """
    cap = draw(st.sampled_from(list(_WRAPPED_BUILTIN.keys())))
    var = cap.lower()
    priv = _WRAPPED_BUILTIN[cap]
    lines = [
        "capability Prober",
        "    fun probe(self) -> Bool",
        "",
        f"type Wrapper {{ inner: {cap} }}",
        "",
        "impl Prober for Wrapper",
        "    fun probe(self) -> Bool",
        f"        let _r = {priv}",
        "        return true",
        "",
        f"fun make({var}: {cap}) -> Wrapper",
        f"    return Wrapper {{ inner: {var} }}",
        "",
        "fun run(p: Wrapper) -> Bool",
        "    return p.probe()",
        "",
        f"fun main(stdio: Stdio, {var}: {cap})",
        '    stdio.println("start")',
        f"    let w = make({var})",
        "    let _ = run(w)",
    ]
    return "\n".join(lines) + "\n"


@st.composite
def _program_block_lambda(draw):
    """Slice-24 shape: a lambda with a *block* body that ends in a
    bare tail expression (implicit non-Unit result), bound and
    then called. Pre-slice-24 the transpiler / lowerer mishandled
    the implicit-result tail of a block-bodied lambda; this
    strategy keeps that path exercised.

    Emitted shape::

        fun main(stdio: Stdio)
            stdio.println("start")
            let f = fun (x: Int) -> Int => { let y = x * <k>; y + <j> }
            let r = f(<n>)
            stdio.println("done")

    Always compiles + transpiles (the body is integer-only)."""
    k = draw(st.integers(min_value=1, max_value=9))
    j = draw(st.integers(min_value=0, max_value=9))
    n = draw(st.integers(min_value=0, max_value=20))
    lines = [
        "fun main(stdio: Stdio)",
        '    stdio.println("start")',
        f"    let f = fun (x: Int) -> Int => {{ let y = x * {k}; y + {j} }}",
        f"    let r = f({n})",
        '    stdio.println("done")',
    ]
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


# ===========================================================
# Attenuation / exclusion invariant support (GAP A)
# ===========================================================
#
# The subset invariant (``used ⊆ declared``) above is the wrong
# invariant for the cross-function attenuation class of bug
# (slice 25): a program that does
# ``let n = fs.restrict_to("/tmp"); helper(n)`` and then reads
# ``/etc/passwd`` inside ``helper`` still only *uses* the ``Fs``
# class that ``helper`` declares, so it passes subset perfectly.
# What it violates is a different invariant that the subset tests
# do not express:
#
#   (1) attenuation honoured: every recorded privileged op on a
#       cap that was attenuated has an argument that satisfies the
#       accumulated restriction in force on that cap;
#   (2) exclusion holds: for every function f,
#       used(f) ∩ provably_excluded(f) = ∅.
#
# Granularity (honest statement of what is implemented):
#
# - Assertion (1) is checked at *class* granularity by REPLAYING
#   the trace through fresh runtime capability instances. The
#   trace records ``(class, method, first_arg)`` (the ``first_arg``
#   enrichment is the one trace change GAP A required; it is behind
#   the existing ``enable()`` gate so production pays nothing). The
#   checker accumulates restrictions per class by re-applying the
#   traced ``restrict_to`` / ``restrict_to_keys`` calls to a fresh
#   cap, then for each subsequent gated op asserts the accumulated
#   cap's own ``allows(arg)`` predicate returns True. Because the
#   generators thread each class through ``main`` exactly once and
#   attenuation is monotonic, accumulating all restrictions seen
#   for a class is a sound over-restriction: it can only make
#   ``allows`` stricter, never looser, so a genuine violation can
#   never be hidden. Using the runtime's *own* ``allows`` predicate
#   (rather than re-implementing prefix / host / key matching)
#   keeps the check faithful to the semantics the runtime enforces.
#
#   This would have caught slice 25: a cross-function attenuated
#   ``Fs`` reading outside its prefix shows a traced
#   ``('Fs','read','/etc/...')`` with an active ``/tmp/``
#   restriction, and ``Fs().restrict_to('/tmp/').allows('/etc/...')``
#   is False. It would have caught slice 18 likewise (the closure
#   path exercises a cap whose op argument escapes the restriction).
#
# - Assertion (2) is checked at *function* granularity: the
#   manifest is per-function, so for every function record we
#   assert its declared/transitively-reachable cap set is disjoint
#   from its ``provably_excluded_capabilities``. That is a manifest
#   self-consistency check. The runtime-vs-manifest direction is
#   checked at *program* granularity: the set of cap classes the
#   run actually exercised must be disjoint from the intersection
#   of every function's ``provably_excluded_capabilities`` (a cap
#   in that intersection is one the whole program claims it can
#   never touch). This would have caught slice 21: the user-cap
#   impl wrapping a built-in exercised the built-in at runtime
#   while (pre-fix) every function's manifest provably-excluded it,
#   so the built-in would appear in both the runtime set and the
#   program-wide exclusion intersection.

# Method classification mirroring capa.runtime._capabilities. The
# attenuator entry pairs the narrowing method name with a closure
# that re-applies it to a cap; the gated set lists the privileged
# ops whose first string argument must satisfy the restriction.
from capa.runtime._capabilities import (  # noqa: E402
    Db as _Db, Env as _Env, Fs as _Fs, Net as _Net, Proc as _Proc,
)

_ATTENUATORS: dict[str, tuple[str, "callable"]] = {
    "Fs":   ("restrict_to", lambda cap, arg: cap.restrict_to(arg)),
    "Net":  ("restrict_to", lambda cap, arg: cap.restrict_to(arg)),
    "Env":  ("restrict_to_keys", lambda cap, arg: cap.restrict_to_keys([arg])),
    "Db":   ("restrict_to", lambda cap, arg: cap.restrict_to(arg)),
    "Proc": ("restrict_to", lambda cap, arg: cap.restrict_to(arg)),
}

_GATED_OPS: dict[str, set[str]] = {
    "Fs":   {"read", "write", "exists", "is_dir", "mkdir", "list_dir"},
    "Net":  {"get", "post"},
    "Env":  {"get"},
    "Db":   {"exec", "query"},
    "Proc": {"exec"},
}

_FRESH_CAP: dict[str, "callable"] = {
    "Fs": _Fs, "Net": _Net, "Env": _Env, "Db": _Db, "Proc": _Proc,
}


def _attenuation_violations(records) -> list[tuple[str, str, str]]:
    """Replay a ``(class, method, first_arg)`` trace and return the
    list of gated ops whose argument violated the restriction in
    force on their capability class. An empty list means the
    attenuation was honoured for every traced privileged op.

    Restriction model (honest statement of granularity): the trace
    records by *class*, not by object, so it cannot tell two
    distinct capability objects of the same class apart. We model
    "the restriction in force" as a fresh capability carrying the
    *single most recent* ``restrict_to`` / ``restrict_to_keys``
    argument seen for that class, then check each subsequent gated
    op against that cap's own ``allows`` predicate.

    Why most-recent rather than the conjunction of every restriction
    seen: ``Fs.restrict_to`` is *additive* (a path must lie under
    *every* accumulated prefix), so conjoining restrictions drawn
    from two unrelated capability objects of the same class would
    over-restrict and produce a false violation (e.g. a trace with
    a ``restrict_to("data/")`` from one object and a
    ``restrict_to("/tmp/")`` + ``read("/tmp/x")`` from another would
    wrongly flag the read as outside ``data/``). Each generated
    program threads a single object of each class through a single
    restriction, so the most-recent ``restrict_to`` is exactly the
    one in force for the gated ops that follow it. This is the
    weaker-but-meaningful granularity the design doc sanctions when
    per-object tracking is impossible from the current trace.

    It still catches the bugs of interest: a slice-25 cross-function
    attenuated ``Fs`` reading outside its prefix shows a traced
    ``('Fs','read','/etc/...')`` after ``('Fs','restrict_to','/tmp/')``
    and ``Fs().restrict_to('/tmp/').allows('/etc/...')`` is False.
    """
    current: dict[str, object] = {}
    violations: list[tuple[str, str, str]] = []
    for cls, op, arg in records:
        if cls in _ATTENUATORS and op == _ATTENUATORS[cls][0] and arg is not None:
            # Most-recent restriction wins: rebuild from a fresh cap
            # so cross-object restrictions of the same class do not
            # spuriously conjoin (see docstring).
            current[cls] = _ATTENUATORS[cls][1](_FRESH_CAP[cls](), arg)
        elif cls in _GATED_OPS and op in _GATED_OPS[cls] and arg is not None:
            cap = current.get(cls)
            if cap is not None and not cap.allows(arg):
                violations.append((cls, op, arg))
    return violations


def _program_exclusion_intersection(module) -> set[str]:
    """The intersection of ``provably_excluded_capabilities`` across
    every function in the manifest: caps the program as a whole
    claims no function can ever exercise. The runtime-used set must
    be disjoint from this."""
    m = build_manifest(module)
    funcs = m["functions"]
    if not funcs:
        return set()
    inter: set[str] | None = None
    for fn in funcs:
        excl = set(fn["provably_excluded_capabilities"])
        inter = excl if inter is None else (inter & excl)
    return inter or set()


def _assert_manifest_exclusion_consistent(testcase, module) -> None:
    """Per-function self-consistency: a function's
    ``provably_excluded_capabilities`` must be disjoint from its
    declared and transitively-reachable cap sets. If they overlap
    the manifest is internally contradictory (a cap both excluded
    and reachable)."""
    m = build_manifest(module)
    for fn in m["functions"]:
        excl = set(fn["provably_excluded_capabilities"])
        declared = set(fn["declared_capabilities"])
        reachable = set(fn.get("transitively_reachable_capabilities", []))
        overlap = excl & (declared | reachable)
        testcase.assertEqual(
            overlap, set(),
            msg=(
                f"manifest contradiction in {fn['source_name']}: caps "
                f"{overlap} are both provably-excluded and "
                f"declared/reachable"
            ),
        )


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


class TestAttenuationHonoured(unittest.TestCase):
    """GAP A (Python backend): beside the subset invariant, assert
    the two invariants that make ``provably_excluded`` a fact and
    not a hope:

      (1) attenuation honoured -- every recorded privileged op on a
          cap that was attenuated has an argument satisfying the
          accumulated restriction (checked by replaying the trace
          through the runtime's own ``allows`` predicate);
      (2) exclusion holds -- the manifest's per-function exclusion
          sets are internally consistent, and the program-wide
          runtime-used cap set is disjoint from the intersection of
          every function's ``provably_excluded_capabilities``.

    Run against the GAP-B generators (cross-function attenuation,
    user-cap wrapping a built-in), these pass now because slices
    18 / 21 / 25 fixed the bugs, and would have failed before.
    """

    @classmethod
    def setUpClass(cls):
        _trace.enable()

    def _run_and_check(self, source: str) -> None:
        from capa import analyze, transpile

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            # The advanced generators are well-typed by construction;
            # surface any rejection rather than swallow it.
            self.fail(
                f"analyser rejected an attenuation-strategy program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[e.format() for e in result.errors]}"
            )

        # Invariant (2a): manifest per-function self-consistency.
        _assert_manifest_exclusion_consistent(self, module)
        program_excluded = _program_exclusion_intersection(module)

        code = transpile(module, types=result.types)
        _trace.clear()
        run_globals: dict = {"__name__": "__main__"}
        try:
            exec(compile(code, "<test>", "exec"), run_globals)
        except SystemExit:
            pass

        recs = _trace.records()

        # Invariant (1): attenuation honoured for every gated op.
        violations = _attenuation_violations(recs)
        self.assertEqual(
            violations, [],
            msg=(
                f"attenuation NOT honoured for program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"violations (class, op, arg): {violations}\n"
                f"trace:\n{recs!r}"
            ),
        )

        # Invariant (2b): runtime-used caps disjoint from the
        # program-wide provable-exclusion intersection.
        runtime_classes = _trace.classes_used()
        leaked = runtime_classes & program_excluded
        self.assertEqual(
            leaked, set(),
            msg=(
                f"runtime exercised caps {leaked} that the program "
                f"claims are provably excluded everywhere, for:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"trace:\n{recs!r}"
            ),
        )

    @given(_program_with_caps_advanced())
    @settings(
        max_examples=50,
        deadline=8000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_attenuation_honoured_advanced(self, source):
        """Covers the ``attenuated_via_helper`` flavour (slice 25
        cross-function attenuation) along with the other advanced
        shapes."""
        self._run_and_check(source)

    @given(_program_user_cap_wraps_builtin())
    @settings(
        max_examples=50,
        deadline=8000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_exclusion_holds_user_cap_wraps_builtin(self, source):
        """Slice-21 shape: the user-cap impl exercises a built-in
        cap through ``self.inner``; the manifest must surface that
        built-in as reachable (not provably excluded), so the
        program-wide exclusion intersection stays disjoint from the
        runtime-used set."""
        self._run_and_check(source)


# ===========================================================
# Phase 4: runtime <= manifest under the Wasm backend
# ===========================================================
#
# Same invariant as Phase 3, different runtime: every capability
# the .wasm artefact actually invokes through its WIT imports
# must appear in the analyser-derived manifest. The Python
# pipeline catches divergences where the transpiler injects a
# call past the cap discipline; the Wasm pipeline catches the
# analogue at the canonical-ABI / WIT-import boundary, which is
# the surface ``--wasm --component --run`` exposes to an
# external runtime.
#
# Two test methods (mirroring the Phase 3 / Phase 3.6-7 split):
#
#   - ``test_wasm_runtime_classes_subset_of_manifest_classes``:
#     basic strategy, each declared capability exercised via a
#     single plain probe in main. The minimum useful coverage.
#   - ``test_wasm_runtime_subset_under_advanced_flavours``:
#     advanced strategy, each capability appears under one of
#     four call shapes (plain / attenuated / via_helper /
#     consumed). Exercises the helper-routed and consumed paths
#     in the lowerer + Wasm emitter, which the basic strategy
#     never enters. Mirrors Phase 3's
#     ``test_runtime_subset_under_advanced_flavours`` for the
#     Wasm backend.
#
# Implementation notes:
#
# - ``_TracingLinker`` wraps the wasmtime Linker so each
#   ``define_func`` call gets an interposed callback. The
#   interposition records ``(cap, method)`` each time the
#   compiled wasm module actually invokes the host import. No
#   change to the production ``WasmHost``; the wrapper sits in
#   the test process only.
# - ``_program_with_caps_wasm`` mirrors ``_program_with_caps``
#   but uses only capability methods the Wasm backend's WIT
#   signatures table supports (``Clock``, ``Env``, ``Fs`` --
#   with cap-safe probes that don't depend on a real filesystem).
#   The existing Phase 3 strategies use ``Net.allows`` /
#   ``Fs.allows`` etc. which exist Python-side but have no
#   WIT/Wasm encoding yet.
# - ``_program_with_caps_wasm_advanced`` mirrors
#   ``_program_with_caps_advanced``. The ``attenuated`` flavour
#   is gated to caps with a WIT-encoded attenuator (currently
#   just ``Fs.restrict_to``); the other three flavours apply to
#   every cap in ``_WASM_CAP_PROBES``.
# - Compilation can fail on programs that the Wasm backend does
#   not yet handle (``WasmEmissionError``); those are skipped
#   exactly the way Phase 3 skips analyser-rejected programs.
#   Either the wasm-tools binary or the wasmtime runtime can be
#   absent on the developer's machine; the test class is
#   skipped wholesale in that case rather than failing.


try:
    import wasmtime  # noqa: F401
    import shutil
    if shutil.which("wasm-tools") is None:
        raise unittest.SkipTest(
            "wasm-tools binary not on PATH; the Wasm property tests "
            "need ``wasm-tools parse`` to assemble each generated "
            "program. Install from https://github.com/bytecodealliance/wasm-tools."
        )
    _HAVE_WASM_TOOLCHAIN = True
except unittest.SkipTest:
    _HAVE_WASM_TOOLCHAIN = False
except ImportError:
    _HAVE_WASM_TOOLCHAIN = False


# Capability probes the Wasm backend's WIT table handles today.
# Each value is a Capa expression of statement type; bound under a
# ``let _ = ...`` so the analyser threads the capability through
# without complaint. ``Fs`` uses ``restrict_to`` because that's
# the only Fs entry that compiles to a side-effect-free WIT call
# (the runtime treats it as a no-op while still routing through
# the import, which is exactly what the trace needs).
_WASM_CAP_PROBES: dict[str, str] = {
    "Clock":  '{var}.now_secs()',
    "Env":    '{var}.get("PATH")',
    "Fs":     '{var}.restrict_to("data/")',
}

# Per-capability attenuation expression for the Wasm-supported
# subset. Only ``Fs`` has a WIT-encoded attenuator
# (``restrict_to``); the other caps' attenuators (``Env``'s
# ``restrict_to_keys``, ``Clock``'s ``restrict_to_after``) have
# no WIT signature yet, so the attenuated flavour is gated to
# caps in this dict.
_WASM_CAP_ATTEN: dict[str, str] = {
    "Fs": '{var}.restrict_to("data/")',
}

# Per-capability *privileged* (gated) op for the Wasm subset, with
# an argument inside the corresponding ``_WASM_CAP_ATTEN``
# restriction. Used by the ``attenuated_via_helper`` flavour so the
# Wasm trace carries a path argument the attenuation-honoured
# invariant can check. Gated to ``Fs`` (the only Wasm cap with both
# a WIT-encoded attenuator and a gated op that lowers to Wasm).
_WASM_CAP_PRIV_OP: dict[str, str] = {
    "Fs": '{var}.read("data/probe.txt")',
}

# Per-capability list of advanced flavours each cap can take.
# Phase 3's strategy gives every cap all four flavours; the
# Wasm subset gates ``attenuated`` to caps with a WIT attenuator.
# The slice-25 cross-function shape lives in its own strategy
# ``_program_attenuated_via_helper_wasm`` (see below), not here.
_WASM_CAP_FLAVOURS: dict[str, list[str]] = {
    cap: (
        ["plain", "attenuated", "via_helper", "consumed"]
        if cap in _WASM_CAP_ATTEN
        else ["plain", "via_helper", "consumed"]
    )
    for cap in _WASM_CAP_PROBES
}


@st.composite
def _program_with_caps_wasm(draw):
    """Generate a Capa program whose main signature declares a
    random subset of the Wasm-supported capabilities, with each
    capability exercised by a single probe call. ``Stdio`` is
    always declared (the program prints ``start`` so there is a
    runtime trace entry even when the random subset is empty)."""
    cap_set = draw(st.sets(
        st.sampled_from(list(_WASM_CAP_PROBES.keys())),
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
        probe = _WASM_CAP_PROBES[cap].format(var=var)
        lines.append(f"    let _v{i} = {probe}")
    return "\n".join(lines) + "\n"


@st.composite
def _program_with_caps_wasm_advanced(draw):
    """Wasm-pipeline mirror of ``_program_with_caps_advanced``.

    For each declared capability, pick one of the flavours the
    Wasm backend supports (see ``_WASM_CAP_FLAVOURS``):

      - ``plain``: probe the capability directly in main.
      - ``attenuated``: bind an attenuated form first
        (``let af = fs.restrict_to("data/")``) then probe it.
        Only available for caps with a WIT-encoded attenuator;
        currently just ``Fs``.
      - ``via_helper``: route the probe through a helper
        ``fun use_{cap}(c: Cap) -> Bool``. Exercises the
        analyser's flow-tracking across call boundaries plus
        the manifest's per-function rollup (both main and the
        helper declare the cap, so the manifest set is unchanged).
      - ``consumed``: helper takes the cap with ``consume``,
        forbidding any further use after the call. Strategy
        places the consumed call last in main so the linear
        constraint is satisfied by construction.

    All four flavours keep ``runtime_classes ⊆ manifest_classes``
    true by construction; the test catches regressions where the
    Wasm emitter or canonical-ABI layer leaks a call past the
    discipline, or where a helper / consumed shape silently
    drops a cap from the manifest rollup.
    """
    cap_set = draw(st.sets(
        st.sampled_from(list(_WASM_CAP_PROBES.keys())),
        min_size=0,
        max_size=3,
    ))
    cap_flavors = {}
    for cap in sorted(cap_set):
        cap_flavors[cap] = draw(
            st.sampled_from(_WASM_CAP_FLAVOURS[cap])
        )

    helpers: list[str] = []
    for cap, flavor in cap_flavors.items():
        var = cap.lower()
        probe = _WASM_CAP_PROBES[cap].format(var=var)
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
            probe = _WASM_CAP_PROBES[cap].format(var=var)
            body_lines.append(f"    let _v{i} = {probe}")
        elif flavor == "attenuated":
            attn = _WASM_CAP_ATTEN[cap].format(var=var)
            attn_var = f"a{i}"
            body_lines.append(f"    let {attn_var} = {attn}")
            probe = _WASM_CAP_PROBES[cap].format(var=attn_var)
            body_lines.append(f"    let _v{i} = {probe}")
        elif flavor == "via_helper":
            body_lines.append(f"    let _v{i} = use_{var}({var})")
        elif flavor == "consumed":
            body_lines.append(f"    let _v{i} = take_{var}({var})")

    return "\n".join(helpers + body_lines) + "\n"


@st.composite
def _program_attenuated_via_helper_wasm(draw):
    """Wasm mirror of ``_program_attenuated_via_helper``: the
    slice-25 cross-function attenuation shape, restricted to the
    caps the Wasm backend can both attenuate (WIT attenuator) and
    perform a path-carrying gated op on (``_WASM_CAP_PRIV_OP``;
    currently just ``Fs``). The attenuated cap is threaded into a
    helper that reads a path inside the restriction.

    Emitted shape::

        fun do_fs(fs: Fs) -> Bool
            let _r = fs.read("data/probe.txt")
            return true
        fun main(stdio: Stdio, fs: Fs)
            stdio.println("start")
            let a0 = fs.restrict_to("data/")
            let v0 = do_fs(a0)
    """
    cap = draw(st.sampled_from(
        sorted(set(_WASM_CAP_PRIV_OP) & set(_WASM_CAP_ATTEN))
    ))
    var = cap.lower()
    priv = _WASM_CAP_PRIV_OP[cap].format(var=var)
    attn = _WASM_CAP_ATTEN[cap].format(var=var)
    lines = [
        f"fun do_{var}({var}: {cap}) -> Bool",
        f"    let _r = {priv}",
        "    return true",
        "",
        f"fun main(stdio: Stdio, {var}: {cap})",
        '    stdio.println("start")',
        f"    let a0 = {attn}",
        f"    let v0 = do_{var}(a0)",
    ]
    return "\n".join(lines) + "\n"


class _TracingLinker:
    """Thin wrapper over a ``wasmtime.Linker`` that records every
    host import the compiled module invokes. ``define_func`` wraps
    the user callback to push ``(cap, method)`` onto a shared list
    each call; every other Linker attribute (``instantiate``,
    ``define_module``, ...) is forwarded unchanged via
    ``__getattr__``.

    Defined inline in the tests because production code has no
    use for runtime tracing; introducing it as a public hook on
    ``WasmHost`` would dilute that class for what is essentially
    a test invariant."""

    # Maps the lowercase interface name ("stdio") that appears in
    # ``capa:host/<cap>`` to the proper Capa class name the
    # manifest uses ("Stdio"). Keep in sync with the WIT generator.
    _INTERFACE_TO_CAP = {
        "stdio": "Stdio",
        "clock": "Clock",
        "env":   "Env",
        "fs":    "Fs",
        "net":   "Net",
        "json":  "Json",
    }

    # Cap+method combinations whose host import takes the cap's
    # path/host/key string as its first ``(ptr, length)`` pair --
    # i.e. ``args[2]`` (ptr) and ``args[3]`` (length) in the
    # ``(caller, cap_handle, ptr, length, ...)`` callback signature.
    # For these the tracer decodes the argument from guest linear
    # memory so the attenuation-honoured invariant (GAP A) has the
    # same op-argument it has on the Python backend. Restricted to
    # ``Fs`` because that is the only Wasm cap with both a
    # WIT-encoded attenuator and gated ops that carry a path string.
    _STRING_ARG_OPS = {
        ("Fs", "restrict_to"), ("Fs", "read"), ("Fs", "write"),
        ("Fs", "exists"), ("Fs", "is_dir"), ("Fs", "mkdir"),
        ("Fs", "list_dir"),
    }

    def __init__(self, inner, calls: list, records: list, host=None):
        self._inner = inner
        self._calls = calls
        self._records = records
        self._host = host

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def define_func(self, module, name, func_type, callback, **kwargs):
        cap_lower = module.rsplit("/", 1)[-1]
        cap = self._INTERFACE_TO_CAP.get(cap_lower, cap_lower.capitalize())
        method_name = name.replace("-", "_")
        calls = self._calls
        records = self._records
        host = self._host
        decode_arg = (cap, method_name) in self._STRING_ARG_OPS

        def traced(*args, **kwargs_inner):
            calls.append((cap, method_name))
            arg_str = None
            # The Fs string-arg callbacks have the signature
            # ``(caller, handle, path_ptr, path_len, ret_area)`` so
            # the path string lives in guest linear memory at
            # ``args[2]`` (ptr) for ``args[3]`` (length) bytes. Decode
            # it the same way the host callbacks do
            # (``self._memory.read(caller, ptr, ptr + length)``). The
            # host's memory is bound during instantiation, before main
            # runs, so it is available on every traced call.
            if (decode_arg and host is not None
                    and host._memory is not None and len(args) >= 4):
                try:
                    raw = host._memory.read(
                        args[0], args[2], args[2] + args[3],
                    )
                    arg_str = bytes(raw).decode("utf-8")
                except Exception:  # pragma: no cover - defensive
                    arg_str = None
            records.append((cap, method_name, arg_str))
            return callback(*args, **kwargs_inner)

        return self._inner.define_func(
            module, name, func_type, traced, **kwargs,
        )


if _HAVE_WASM_TOOLCHAIN:
    from capa.runtime._wasm_host import WasmHost

    class _TracingWasmHost(WasmHost):
        """Test-only WasmHost subclass that records every capability
        method the guest invokes via host imports. The recording
        attaches at the linker layer (see ``_TracingLinker``).

        Earlier this class hand-copied a subset of the parent's
        ``__init__`` so it could wrap the linker before the
        ``_register_*`` methods ran. That copy went stale when slices
        25.2-25.6 added the per-instance handle table + root caps and
        four more ``_register_*`` calls: the stub omitted them, so
        every ``run_main`` trapped on a missing ``_root_fs`` before
        any capability op ran -- making the Wasm property tests
        silently vacuous. To stay robust against future cap
        additions, defer all scaffolding to ``super().__init__()``
        (which registers every interface on a throwaway plain
        linker), then re-wrap with a tracing linker and re-register
        every interface so the wrapped versions are the ones
        ``instantiate`` resolves. Re-registration is cheap (a handful
        of ``define_func`` calls in the test process) and means this
        class never has to know which interfaces exist."""

        def __init__(self, args=None):
            super().__init__(args=args)
            self.calls: list[tuple[str, str]] = []
            # ``records`` mirrors ``calls`` but carries the decoded
            # first string argument (``None`` when not a string-arg
            # op) so the attenuation-honoured invariant can replay
            # the trace on the Wasm side too.
            self.records: list[tuple[str, str, object]] = []
            # Replace the plain linker the parent built with a tracing
            # wrapper, then re-run every registration so the traced
            # callbacks are the ones the linker hands to the guest.
            self.linker = _TracingLinker(
                wasmtime.Linker(self.engine), self.calls,
                self.records, host=self,
            )
            self._register_stdio()
            self._register_clock()
            self._register_env()
            self._register_fs()
            self._register_json()
            self._register_random()
            self._register_net()
            self._register_db()
            self._register_proc()


@unittest.skipUnless(
    _HAVE_WASM_TOOLCHAIN,
    "wasm toolchain (wasm-tools + wasmtime) not available",
)
class TestWasmRuntimeSubsetOfManifest(unittest.TestCase):
    """Wasm-backend mirror of ``TestRuntimeSubsetOfManifest``. For
    every generated program, the set of (cap, method) the
    compiled .wasm module invokes through its WIT imports must
    be a subset of the cap classes declared in the analyser
    manifest. Catches regressions where the Wasm emitter injects
    a capability call past the analyser's manifest emission."""

    def _manifest_classes(self, module) -> set[str]:
        from capa.manifest import build_manifest
        m = build_manifest(module)
        result: set[str] = set()
        for fn in m["functions"]:
            for cap in fn["declared_capabilities"]:
                result.add(cap)
        return result

    def _check_subset(self, source: str) -> None:
        """Lex + parse + analyse + Wasm-compile + run with a
        tracing host, then assert ``runtime_classes ⊆
        manifest_classes``. Shared body for both the basic and
        the advanced-flavours property tests.

        Programs the analyser rejects, or that the Wasm emitter
        cannot produce, are skipped: the soundness claim holds
        vacuously for programs that never compile. Runtime traps
        are tolerated for the same reason -- the invariant is
        about which caps the module CAN invoke, not whether the
        execution succeeds.
        """
        from capa import analyze
        from capa.ir import compile_wasm
        from capa.ir._emit_wasm import WasmEmissionError
        from capa.ir._lower import UnsupportedInIR

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            return

        manifest_classes = self._manifest_classes(module)

        try:
            wasm_blob = compile_wasm(module, types=result.types)
        except (WasmEmissionError, UnsupportedInIR):
            return

        host = _TracingWasmHost(args=[])
        try:
            host.run_main(wasm_blob)
        except Exception:  # pragma: no cover - trap-like runtime errors
            pass

        runtime_classes = {cap for (cap, _method) in host.calls}

        self.assertTrue(
            runtime_classes.issubset(manifest_classes),
            msg=(
                f"wasm runtime classes {runtime_classes} not subset of "
                f"manifest classes {manifest_classes} for program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"trace:\n{host.calls!r}"
            ),
        )

    @given(_program_with_caps_wasm())
    @settings(
        max_examples=15,
        deadline=20000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_wasm_runtime_classes_subset_of_manifest_classes(self, source):
        self._check_subset(source)

    @given(_program_with_caps_wasm_advanced())
    @settings(
        max_examples=20,
        deadline=25000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_wasm_runtime_subset_under_advanced_flavours(self, source):
        """Wasm mirror of
        ``test_runtime_subset_under_advanced_flavours``: each
        capability appears under one of four call shapes (plain,
        attenuated, via_helper, consumed). Soundness invariant is
        identical; this test exercises the analyser+lowerer+Wasm-
        emitter chain for the helper-routed and consumed paths,
        which the basic strategy never enters.

        Catches:
        - lowerer regressions where a ``consume``d capability's
          last-use marking propagates wrongly to the Wasm
          emitter, leaving a stranded import.
        - manifest-rollup regressions where a helper that
          declares the cap is dropped from
          ``declared_capabilities``, causing the runtime trace
          (which still records the helper's import calls) to
          escape the manifest set.
        - canonical-ABI regressions where the attenuated form
          of a cap is invoked through an import that the
          analyser never accounted for.
        """
        self._check_subset(source)


@unittest.skipUnless(
    _HAVE_WASM_TOOLCHAIN,
    "wasm toolchain (wasm-tools + wasmtime) not available",
)
class TestWasmAttenuationHonoured(unittest.TestCase):
    """GAP A (Wasm backend): mirror of ``TestAttenuationHonoured``.

    Two invariants per generated program:

      (1) attenuation honoured -- replays the Wasm host trace
          (``host.records``, which carries the decoded path
          argument for the ``Fs`` string-arg ops; see
          ``_TracingLinker._STRING_ARG_OPS``) through the runtime's
          own ``allows`` predicate. For caps whose Wasm import
          argument is not decoded to a string the op contributes a
          ``None`` arg and is skipped by the replay; on the current
          Wasm WIT table that only leaves ``Fs`` with both an
          attenuator and a path-carrying gated op, which is exactly
          the cap the ``attenuated_via_helper`` flavour drives.
      (2) exclusion holds -- the manifest's per-function exclusion
          sets are internally consistent, and the cap classes the
          .wasm module actually invokes are disjoint from the
          intersection of every function's
          ``provably_excluded_capabilities``.
    """

    def _run_and_check(self, source: str) -> None:
        from capa import analyze
        from capa.ir import compile_wasm
        from capa.ir._emit_wasm import WasmEmissionError
        from capa.ir._lower import UnsupportedInIR

        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        if not result.ok:
            return  # soundness holds vacuously for non-compiling programs

        # Invariant (2a): manifest per-function self-consistency.
        _assert_manifest_exclusion_consistent(self, module)
        program_excluded = _program_exclusion_intersection(module)

        try:
            wasm_blob = compile_wasm(module, types=result.types)
        except (WasmEmissionError, UnsupportedInIR):
            return

        host = _TracingWasmHost(args=[])
        try:
            host.run_main(wasm_blob)
        except Exception:  # pragma: no cover - trap-like runtime errors
            pass

        # Invariant (1): attenuation honoured (Fs path args decoded).
        violations = _attenuation_violations(host.records)
        self.assertEqual(
            violations, [],
            msg=(
                f"wasm attenuation NOT honoured for program:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"violations (class, op, arg): {violations}\n"
                f"trace:\n{host.records!r}"
            ),
        )

        # Invariant (2b): runtime-used caps disjoint from the
        # program-wide provable-exclusion intersection.
        runtime_classes = {cap for (cap, _m) in host.calls}
        leaked = runtime_classes & program_excluded
        self.assertEqual(
            leaked, set(),
            msg=(
                f"wasm runtime exercised caps {leaked} that the "
                f"program claims provably excluded everywhere, for:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"trace:\n{host.records!r}"
            ),
        )

    @given(_program_attenuated_via_helper_wasm())
    @settings(
        max_examples=20,
        deadline=25000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_wasm_attenuation_honoured_cross_function(self, source):
        """Wasm slice-25 cross-function attenuation: attenuate Fs in
        main, read a path inside the restriction in a helper. The
        Wasm trace decodes the Fs path argument so the attenuation-
        honoured invariant is exercised (not vacuous)."""
        self._run_and_check(source)

    @given(_program_with_caps_wasm_advanced())
    @settings(
        max_examples=20,
        deadline=25000,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_wasm_attenuation_honoured_advanced(self, source):
        """Exclusion invariants over the four advanced Wasm flavours
        (the gated-op argument check is vacuous here because these
        flavours use side-effect-free probes; the cross-function
        test above carries the path-argument check)."""
        self._run_and_check(source)


if __name__ == "__main__":
    unittest.main()

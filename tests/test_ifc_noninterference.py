"""Randomised (property-based) NONINTERFERENCE harness over the real
Capa IFC analyzer + runtime.

This is machine-RUN evidence (not a proof) that Capa's
information-flow enforcement is sound at runtime: a program the
analyzer ACCEPTS under ``@strict_ifc`` must actually be
noninterferent - its PUBLIC output must not depend on its SECRET
inputs.

Soundness invariant (the valuable direction)
---------------------------------------------
For a generated program with ``@strict_ifc()`` on ``main``, IF the
analyzer accepts it (compiles clean, no IFC error), THEN running it
twice - with IDENTICAL public inputs but DIFFERING secret inputs (the
environment variables that flow in as ``@secret`` via ``env.get``) -
must produce BYTE-IDENTICAL stdout. A mismatch means the analyzer
accepted a program that leaks a secret through a public channel = a
noninterference SOUNDNESS BUG. We assert equality and, on mismatch,
fail loudly with the program text, both outputs, and both secret
environments.

Completeness-ish invariant (weaker, secondary)
----------------------------------------------
A generated program that routes a secret to a public sink WITHOUT
declassify, under ``@strict_ifc()``, must be REJECTED (hard error).
Two complementary generators feed this direction: an EXPLICIT
data-flow one (a secret read straight into ``Stdio.println``) and an
IMPLICIT control-flow one (a public sink under a secret-conditioned
loop, and the implicit assign-then-sink channel). The implicit
generator specifically guards the loop-pc-raise and pc-into-assignment
rules, which the soundness generator - branching only on PUBLIC
conditions - could not exercise.

How a program is run
--------------------
Same in-process path the existing Phase 3 property tests use: the
program is analysed, transpiled to Python, then ``exec``'d with
``__name__ == "__main__"`` so the transpiler's bootstrap
``main(Stdio(), Env())`` fires. ``env.get(VAR)`` reads
``os.environ`` at runtime, so the two runs are driven by patching
``os.environ`` with two dicts that AGREE on public vars and DIFFER on
secret vars. stdout is captured with ``contextlib.redirect_stdout``.

Generated programs are deterministic by construction: no Clock /
Random / Net, only ``Stdio`` + ``Env``, so the only thing that can
make two runs differ is a genuine secret-to-public flow.
"""

from __future__ import annotations

import contextlib
import io
import os
import textwrap
import unittest
from unittest import mock

try:
    import hypothesis.strategies as st
    from hypothesis import HealthCheck, given, settings
except ImportError:  # pragma: no cover - exercised only without the extra
    raise unittest.SkipTest(
        "hypothesis is not installed; install with `pip install -e .[test]`"
    )

from capa import Lexer, Parser, analyze, transpile
from capa.parser import ParserError


# ===========================================================
# Generator grammar
# ===========================================================
#
# Every program has the shape::
#
#     [type Box { f_secret: String, f_open: String }]   # optional
#     @strict_ifc()
#     fun main(stdio: Stdio, env: Env)
#         let s0 = env.get("SECRET0").unwrap_or("d0")    # secret source(s)
#         ...
#         <body statements>
#         stdio.println(<sink expr>)                     # at least one sink
#
# The secret sources are one or more ``env.get(VAR).unwrap_or(...)``
# bindings - VAR names are the SECRET environment variables the two
# runs disagree on. Public inputs are literals and a fixed public
# env-independent constant. Operations cover string concat /
# interpolation, integer arithmetic (including an int derived from a
# secret string's ``.length()``), and booleans. Control flow branches
# on PUBLIC conditions for the soundness direction; a separate
# "leaky" generator deliberately routes a secret to the sink (and,
# optionally, branches on a secret) to feed the rejection direction.
#
# ``Env`` is a declared capability and Capa requires every declared
# capability be USED, so ``main`` always performs at least one
# ``env.get`` - which also makes the secret source present by
# construction.

# Secret environment variable names. The two runs share public state
# and differ on exactly these keys.
_SECRET_VARS = ["SECRET0", "SECRET1", "SECRET2"]

# Fixed public values reused across both runs (a public, env-independent
# constant pool the generator draws from).
_PUB_STR = st.sampled_from(["alpha", "beta", "gamma", "", "x-y"])
_PUB_INT = st.integers(min_value=0, max_value=99)
_INT_OP = st.sampled_from(["+", "-", "*"])
_CMP_OP = st.sampled_from(["<", "<=", ">", ">=", "==", "!="])


def _public_int_expr(draw, depth):
    """An always-public, always-Int expression: integer literals and
    +/-/* over them. No identifier references (keeps it well-typed by
    construction and provably public)."""
    if depth <= 0:
        return str(draw(_PUB_INT))
    left = _public_int_expr(draw, depth - 1)
    right = _public_int_expr(draw, depth - 1)
    op = draw(_INT_OP)
    return f"({left} {op} {right})"


def _public_str_expr(draw):
    """An always-public String expression: a literal, or a concat /
    interpolation of public literals and a public int."""
    kind = draw(st.sampled_from(["lit", "concat", "interp"]))
    if kind == "lit":
        return f'"{draw(_PUB_STR)}"'
    if kind == "concat":
        return f'("{draw(_PUB_STR)}" + "{draw(_PUB_STR)}")'
    n = _public_int_expr(draw, 1)
    return f'"v=${{{n}}}"'


@st.composite
def _accepted_program(draw):
    """Generate a program that SHOULD be accepted under @strict_ifc:
    secrets are read and may be stored / derived from, but only PUBLIC
    values ever reach a sink. Returns ``(source, declassifies)`` where
    ``declassifies`` is True when the program intentionally leaks via
    ``declassify`` (excluded from the outputs-must-match invariant).

    Shapes drawn from:
      - secret source(s): one to three ``env.get(VAR).unwrap_or(d)``;
      - store a secret in a struct's secret field, sink the OPEN field
        (exercises per-field precision: accepted, must be noninterferent);
      - derive an int from a secret's ``.length()`` but sink only a
        PUBLIC int (the secret int is computed and discarded);
      - if / while on a PUBLIC condition with a public sink in the body;
      - declassify(secret) then sink (intentional leak; compiles, but
        excluded from outputs-must-match).
    """
    n_secrets = draw(st.integers(min_value=1, max_value=3))
    secret_vars = _SECRET_VARS[:n_secrets]

    use_struct = draw(st.booleans())
    shape = draw(st.sampled_from(
        ["public_sink", "struct_open_field", "len_then_public",
         "if_public", "while_public", "declassify"]
    ))
    # struct_open_field needs the struct decl regardless of use_struct.
    if shape == "struct_open_field":
        use_struct = True

    header = []
    if use_struct:
        header.append("type Box { f_secret: String, f_open: String }")

    lines = ["@strict_ifc()", "fun main(stdio: Stdio, env: Env)"]
    for i, var in enumerate(secret_vars):
        lines.append(
            f'    let s{i} = env.get("{var}").unwrap_or("d{i}")'
        )

    declassifies = False

    if shape == "public_sink":
        lines.append(f"    stdio.println({_public_str_expr(draw)})")

    elif shape == "struct_open_field":
        lines.append(
            f'    let b = Box {{ f_secret: s0, f_open: {_public_str_expr(draw)} }}'
        )
        lines.append("    stdio.println(b.f_open)")

    elif shape == "len_then_public":
        # Derive a SECRET int from the secret string, but never sink it;
        # sink a public int instead. Accepted, noninterferent.
        lines.append("    let _ln = s0.length()")
        lines.append(f'    stdio.println("n=${{{_public_int_expr(draw, 1)}}}")')

    elif shape == "if_public":
        cond = f"{_public_int_expr(draw, 1)} {draw(_CMP_OP)} {_public_int_expr(draw, 1)}"
        lines.append(f"    if {cond}")
        lines.append(f"        stdio.println({_public_str_expr(draw)})")
        lines.append("    else")
        lines.append(f"        stdio.println({_public_str_expr(draw)})")

    elif shape == "while_public":
        bound = draw(st.integers(min_value=0, max_value=3))
        lines.append("    var i = 0")
        lines.append(f"    while i < {bound}")
        lines.append(f"        stdio.println({_public_str_expr(draw)})")
        lines.append("        i = i + 1")

    elif shape == "declassify":
        declassifies = True
        reason = draw(st.sampled_from(["audit", "intended", "demo"]))
        lines.append(
            f'    stdio.println(declassify(s0, reason: "{reason}"))'
        )

    source = "\n".join(header + lines) + "\n"
    return source, declassifies


@st.composite
def _leaky_program(draw):
    """Generate a program that DOES route a secret to a public sink
    without declassify - the analyzer MUST reject it under
    @strict_ifc. Restricted to clear explicit data-flow shapes (no
    over-assertion of subtle implicit flows). Returns ``source``.

    Shapes:
      - sink the secret directly;
      - concat the secret with a public string, sink the result;
      - interpolate the secret into a string, sink it;
      - store the secret in a struct field and sink THAT field;
      - launder the secret through a ``match`` expression value, sink it;
      - launder the secret through an ``if`` expression value, sink it;
      - capture the secret in a closure, call it, sink the result;
      - pass a secret-capturing closure to a HOF, sink the HOF result.
    """
    var = _SECRET_VARS[0]
    shape = draw(st.sampled_from(
        ["direct", "concat", "interp", "struct_secret_field",
         "match_expr", "if_expr", "closure_capture", "closure_hof"]
    ))
    pub = draw(_PUB_STR)
    header = []
    lines = ["@strict_ifc()", "fun main(stdio: Stdio, env: Env)"]
    lines.append(f'    let s = env.get("{var}").unwrap_or("d")')

    if shape == "direct":
        lines.append("    stdio.println(s)")
    elif shape == "concat":
        lines.append(f'    let m = "{pub}" + s')
        lines.append("    stdio.println(m)")
    elif shape == "interp":
        lines.append('    stdio.println("leak=${s}")')
    elif shape == "struct_secret_field":
        header.append("type Box { f_secret: String, f_open: String }")
        lines.append(
            f'    let b = Box {{ f_secret: s, f_open: "{pub}" }}'
        )
        lines.append("    stdio.println(b.f_secret)")
    elif shape == "match_expr":
        # The match-expression VALUE inherits the secret-bound arm body;
        # sinking it must be caught (no laundering through ``match``).
        lines.append(f'    let v = match true {{ true -> s, false -> "{pub}" }}')
        lines.append("    stdio.println(v)")
    elif shape == "if_expr":
        # The if-expression VALUE is the join of both branches; the secret
        # branch makes it secret. Sinking it must be caught.
        lines.append(f'    let x = if true then s else "{pub}"')
        lines.append("    stdio.println(x)")
    elif shape == "closure_capture":
        # A closure that captures the secret returns a secret value when
        # called; sinking the call result must be caught.
        lines.append("    let leak = fun () -> String => s")
        lines.append("    stdio.println(leak())")
    elif shape == "closure_hof":
        # A secret-capturing closure passed to a higher-order function and
        # invoked inside it launders the secret out via the HOF result.
        header.append("fun apply(f: Fun() -> String) -> String")
        header.append("    return f()")
        lines.append("    stdio.println(apply(fun () -> String => s))")

    return "\n".join(header + lines) + "\n"


@st.composite
def _leaky_implicit_program(draw):
    """Generate a program that leaks a secret through an IMPLICIT
    (control-flow) channel - no @secret value reaches a sink directly,
    but the program's PUBLIC output still depends on a secret. Under
    @strict_ifc the analyzer MUST reject every shape here. These are
    exactly the shapes the explicit-data-flow generator above cannot
    reach (it branches on PUBLIC conditions), so they guard the
    loop-pc-raise and implicit-assign rules specifically. Returns
    ``source``.

    Shapes:
      - a public sink inside a ``while`` whose guard is secret;
      - a public sink inside a ``for`` over a secret collection;
      - the implicit-assign channel: a public var made secret by an
        assignment under a secret ``if``, then sunk;
      - the same channel where the assignment happens under a secret
        loop body;
      - the struct-field analogue: a public field assigned under a
        secret ``if``, then sunk;
      - a secret-conditioned divergence carried by a ``match`` (finding
        C-F1: the ``match`` analogue of advisory 2026-06-17 B3, which
        the original B3 fix overlooked). A ``match`` in STATEMENT
        position or in VALUE position (let / var / assign RHS) with a
        ``return`` / ``break`` / ``continue`` arm, guarded by a secret
        scrutinee or a secret arm-guard, followed by a public sink whose
        execution reveals whether the diverging arm fired.
    """
    shape = draw(st.sampled_from(
        ["while_secret_guard", "for_secret_collection",
         "assign_under_secret_if", "assign_under_secret_loop",
         "field_assign_under_secret_if",
         "match_secret_return", "match_secret_break",
         "match_secret_continue", "match_secret_guard_return",
         "val_match_secret_return", "val_match_secret_break",
         "assign_match_secret_return",
         # IFC-1: cross-function implicit flow -- a public sink behind a
         # helper CALL inside a secret-conditioned construct. The sink runs
         # a secret-dependent number of times / conditionally, so these are
         # genuine leaks (the REJECT direction), one per branch form plus a
         # 3-hop transitive chain and a method receiver.
         "call_helper_secret_if", "call_helper_secret_while",
         "call_helper_secret_for", "call_helper_secret_match_arm",
         "call_helper_depth3", "call_method_helper_secret_if"]
    ))
    pub = draw(_PUB_STR)
    header = []
    lines = ["@strict_ifc()", "fun main(stdio: Stdio, env: Env)"]
    # A secret String source is always present (Env must be used).
    lines.append(f'    let s = env.get("{_SECRET_VARS[0]}").unwrap_or("d")')

    if shape == "while_secret_guard":
        # Loop a secret number of times (the secret string's length),
        # with a public sink in the body: the iteration count - hence
        # whether/how often the sink fires - depends on the secret.
        lines.append("    var i = 0")
        lines.append("    while i < s.length()")
        lines.append(f'        stdio.println("{pub}")')
        lines.append("        i = i + 1")

    elif shape == "for_secret_collection":
        # Iterate a secret-derived collection (the secret string split
        # into parts inherits the secret's label); the body's public
        # sink then runs a secret number of times.
        lines.append('    let parts = s.split("-")')
        lines.append("    for _p in parts")
        lines.append(f'        stdio.println("{pub}")')

    elif shape == "assign_under_secret_if":
        # Classic implicit-assign channel: leaked is public at decl,
        # made secret-by-context inside a secret-conditioned branch.
        lines.append(f'    var leaked = "{pub}"')
        lines.append("    if s.length() > 3")
        lines.append('        leaked = "long"')
        lines.append("    stdio.println(leaked)")

    elif shape == "assign_under_secret_loop":
        # The assignment happens inside a secret-conditioned loop body.
        lines.append(f'    var leaked = "{pub}"')
        lines.append("    var i = 0")
        lines.append("    while i < s.length()")
        lines.append('        leaked = "seen"')
        lines.append("        i = i + 1")
        lines.append("    stdio.println(leaked)")

    elif shape == "field_assign_under_secret_if":
        header.append("type Box { f: String }")
        lines.append(f'    var b = Box {{ f: "{pub}" }}')
        lines.append("    if s.length() > 3")
        lines.append('        b.f = "long"')
        lines.append("    stdio.println(b.f)")

    elif shape == "match_secret_return":
        # A statement-position ``match`` on a secret scrutinee with a
        # ``return`` arm: reaching the sink after it reveals the
        # non-diverging arm ran, hence a fact about the secret.
        lines.append("    match s.length()")
        lines.append("        0 -> return")
        lines.append('        _ -> "y"')
        lines.append(f'    stdio.println("{pub}")')

    elif shape == "match_secret_break":
        # A ``break`` arm inside a match under a PUBLIC while: the break
        # is secret-conditioned (secret scrutinee), so whether the sink
        # LATER in the loop body runs depends on the secret.
        lines.append("    var i = 0")
        lines.append("    while i < 2")
        lines.append("        match s.length()")
        lines.append("            0 -> break")
        lines.append('            _ -> "y"')
        lines.append(f'        stdio.println("{pub}")')
        lines.append("        i = i + 1")

    elif shape == "match_secret_continue":
        lines.append("    var i = 0")
        lines.append("    while i < 2")
        lines.append("        match s.length()")
        lines.append("            0 -> continue")
        lines.append('            _ -> "y"')
        lines.append(f'        stdio.println("{pub}")')
        lines.append("        i = i + 1")

    elif shape == "match_secret_guard_return":
        # PUBLIC scrutinee, SECRET arm-guard: the guard label alone
        # raises the control label, so the guarded ``return`` is
        # secret-conditioned even though the scrutinee is public.
        lines.append("    let n = 1")
        lines.append("    match n")
        lines.append("        _ if s.length() > 0 -> return")
        lines.append('        _ -> "y"')
        lines.append(f'    stdio.println("{pub}")')

    elif shape == "val_match_secret_return":
        # VALUE position (let RHS): the divergence is carried by the
        # match bound to ``v``; sink a PUBLIC literal after it.
        lines.append("    let v = match s.length()")
        lines.append("        0 -> return")
        lines.append('        _ -> "y"')
        lines.append(f'    stdio.println("{pub}")')

    elif shape == "val_match_secret_break":
        lines.append("    var i = 0")
        lines.append("    while i < 2")
        lines.append("        let v = match s.length()")
        lines.append("            0 -> break")
        lines.append('            _ -> "y"')
        lines.append(f'        stdio.println("{pub}")')
        lines.append("        i = i + 1")

    elif shape == "assign_match_secret_return":
        # ASSIGN position (assign RHS): the match value is assigned to
        # ``v`` but the sink is a PUBLIC literal, so the leak is the
        # implicit divergence, not the assigned value.
        lines.append('    var v = "init"')
        lines.append("    v = match s.length()")
        lines.append("        0 -> return")
        lines.append('        _ -> "y"')
        lines.append(f'    stdio.println("{pub}")')

    elif shape == "call_helper_secret_if":
        # IFC-1: the public sink is behind a helper CALL inside a secret
        # ``if``. The sink runs iff the secret-conditioned branch is taken.
        header.append("fun leak(stdio: Stdio)")
        header.append(f'    stdio.println("{pub}")')
        lines.append("    if s.length() > 3")
        lines.append("        leak(stdio)")

    elif shape == "call_helper_secret_while":
        header.append("fun leak(stdio: Stdio)")
        header.append(f'    stdio.println("{pub}")')
        lines.append("    var i = 0")
        lines.append("    while i < s.length()")
        lines.append("        leak(stdio)")
        lines.append("        i = i + 1")

    elif shape == "call_helper_secret_for":
        header.append("fun leak(stdio: Stdio)")
        header.append(f'    stdio.println("{pub}")')
        lines.append('    let parts = s.split("-")')
        lines.append("    for _p in parts")
        lines.append("        leak(stdio)")

    elif shape == "call_helper_secret_match_arm":
        # A secret scrutinee raises the pc inside each arm, so a helper call
        # in an arm runs under secret control flow.
        header.append("fun leak(stdio: Stdio)")
        header.append(f'    stdio.println("{pub}")')
        lines.append("    match s.length()")
        lines.append("        0 -> leak(stdio)")
        lines.append("        _ -> leak(stdio)")

    elif shape == "call_helper_depth3":
        # A 3-hop transitive chain: only ``h3`` sinks, but the summary
        # fixpoint carries the sink-reaching-pc bit up through ``h2`` /
        # ``h1``, so calling ``h1`` under secret control flow is flagged.
        header.append("fun h3(stdio: Stdio)")
        header.append(f'    stdio.println("{pub}")')
        header.append("fun h2(stdio: Stdio)")
        header.append("    h3(stdio)")
        header.append("fun h1(stdio: Stdio)")
        header.append("    h2(stdio)")
        lines.append("    if s.length() > 3")
        lines.append("        h1(stdio)")

    elif shape == "call_method_helper_secret_if":
        # A METHOD receiver: ``show`` sinks via a built-in Stdio call, so
        # the method carries the bit and the call under a secret ``if`` is
        # flagged.
        header.append("type Printer { tag: String }")
        header.append("impl Printer")
        header.append("    fun show(self, stdio: Stdio)")
        header.append("        stdio.println(self.tag)")
        lines.append('    let p = Printer { tag: "t" }')
        lines.append("    if s.length() > 3")
        lines.append("        p.show(stdio)")

    return "\n".join(header + lines) + "\n"


# ===========================================================
# Execution helpers
# ===========================================================


def _public_env() -> dict:
    """The shared PUBLIC environment both runs see (agrees across
    runs). Kept fixed so any difference between runs can only come
    from the secret vars."""
    return {"PUBLIC_CONST": "shared"}


def _run_capa(code: str, env_overrides: dict) -> str:
    """Exec transpiled Capa ``code`` in-process under a patched
    ``os.environ`` (public + the given secret overrides) and return
    captured stdout. ``env.get`` reads ``os.environ`` at runtime, so
    the overrides are exactly the values that flow in as @secret."""
    full_env = {**_public_env(), **env_overrides}
    buf = io.StringIO()
    run_globals: dict = {"__name__": "__main__"}
    with mock.patch.dict(os.environ, full_env, clear=False):
        with contextlib.redirect_stdout(buf):
            try:
                exec(compile(code, "<noninterference-test>", "exec"), run_globals)
            except SystemExit:
                pass
    return buf.getvalue()


def _compile_or_skip(testcase, source: str):
    """Lex + parse + analyse ``source``. Returns ``(module, result)``
    if it compiles clean, or ``None`` if it failed for a NON-IFC
    reason (a generator imperfection - discarded via ``assume`` by the
    caller, never counted as a finding). IFC rejections are returned
    as ``(module, result)`` with ``result.ok == False`` so the caller
    can distinguish them."""
    try:
        module = Parser(Lexer(source).lex(), source=source).parse_module()
    except ParserError:
        return None
    result = analyze(module, source=source)
    return module, result


def _is_ifc_rejection(result) -> bool:
    """True if the analysis failure is (entirely) an information-flow
    rejection - the rejection direction wants exactly these."""
    if result.ok:
        return False
    return all("information-flow" in e.message for e in result.errors)


# ===========================================================
# The harness
# ===========================================================


class TestIfcNoninterference(unittest.TestCase):
    """Randomised noninterference over the real analyzer + runtime."""

    @given(_accepted_program())
    @settings(
        max_examples=150,
        deadline=8000,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_accepted_strict_ifc_is_noninterferent(self, program):
        """SOUNDNESS: a program accepted under @strict_ifc must produce
        byte-identical public output for identical public inputs and
        differing secret inputs. A mismatch is a noninterference
        soundness bug in the analyzer.
        """
        source, declassifies = program
        compiled = _compile_or_skip(self, source)
        if compiled is None:
            # Non-IFC compile failure: generator noise, discard.
            from hypothesis import assume
            assume(False)
        module, result = compiled

        if not result.ok:
            # The analyzer rejected this program. For the SOUNDNESS
            # direction we only care about ACCEPTED programs, so a
            # rejection is simply out of scope here (not a finding):
            # discard it. (The accepted generator aims to stay clean,
            # but if a shape trips an IFC rule, that is the analyzer
            # being conservative, which is sound.)
            from hypothesis import assume
            assume(False)

        code = transpile(module, types=result.types)

        # Two runs: identical public inputs, DIFFERING secret inputs.
        secret_a = {v: f"AAA-{v}-aaaaa" for v in _SECRET_VARS}
        secret_b = {v: f"ZZ-{v}-z" for v in _SECRET_VARS}
        out_a = _run_capa(code, secret_a)
        out_b = _run_capa(code, secret_b)

        if declassifies:
            # declassify deliberately reveals the secret, so the two
            # outputs are EXPECTED to differ. We only assert the
            # program compiled and ran; it is excluded from the
            # outputs-must-match invariant by design.
            return

        self.assertEqual(
            out_a,
            out_b,
            msg=(
                "NONINTERFERENCE SOUNDNESS BUG: a program accepted under "
                "@strict_ifc produced DIFFERENT public output for "
                "identical public inputs and differing secret inputs.\n"
                f"program:\n{textwrap.indent(source, '    ')}\n"
                f"secret env A: {secret_a}\n"
                f"secret env B: {secret_b}\n"
                f"stdout A: {out_a!r}\n"
                f"stdout B: {out_b!r}\n"
            ),
        )

    @given(_leaky_program())
    @settings(
        max_examples=100,
        deadline=8000,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_explicit_leak_is_rejected(self, source):
        """COMPLETENESS-ish (secondary): a program that routes a secret
        to a public sink WITHOUT declassify, under @strict_ifc, must be
        REJECTED with an information-flow error. Restricted to clear
        explicit data-flow shapes."""
        compiled = _compile_or_skip(self, source)
        if compiled is None:
            from hypothesis import assume
            assume(False)
        module, result = compiled

        self.assertFalse(
            result.ok,
            msg=(
                "COMPLETENESS GAP: a program that explicitly routes a "
                "@secret to Stdio.println without declassify was "
                "ACCEPTED under @strict_ifc (expected a hard IFC error).\n"
                f"program:\n{textwrap.indent(source, '    ')}"
            ),
        )
        self.assertTrue(
            _is_ifc_rejection(result),
            msg=(
                "explicit-leak program was rejected, but NOT (only) for "
                "an information-flow reason - the generator emitted a "
                "program with an unrelated error:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[e.message for e in result.errors]}"
            ),
        )

    @given(_leaky_implicit_program())
    @settings(
        max_examples=100,
        deadline=8000,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_implicit_leak_is_rejected(self, source):
        """COMPLETENESS-ish (implicit flows): a program that leaks a
        secret through CONTROL FLOW - a public sink under a
        secret-conditioned loop, or a value made secret by an
        assignment under a secret pc and then sunk - must be REJECTED
        under @strict_ifc. These are exactly the shapes the
        soundness/explicit generators cannot reach (they never branch
        or loop on a secret), so this is the regression guard for the
        loop-pc-raise and pc-into-assignment enforcement.

        Non-vacuous by construction: each generated program compiles
        (no unrelated error -> the rejection assertion is reached) and
        the analyzer must reject it for an information-flow reason. If
        the loop/implicit-assign enforcement regressed, the program
        would be ACCEPTED and this would fail."""
        compiled = _compile_or_skip(self, source)
        if compiled is None:
            from hypothesis import assume
            assume(False)
        module, result = compiled

        self.assertFalse(
            result.ok,
            msg=(
                "IMPLICIT-FLOW GAP: a program that leaks a @secret "
                "through control flow (a public sink under a "
                "secret-conditioned loop, or an assign-under-secret-pc "
                "channel) was ACCEPTED under @strict_ifc (expected a "
                "hard information-flow error).\n"
                f"program:\n{textwrap.indent(source, '    ')}"
            ),
        )
        self.assertTrue(
            _is_ifc_rejection(result),
            msg=(
                "implicit-leak program was rejected, but NOT (only) for "
                "an information-flow reason - the generator emitted a "
                "program with an unrelated error:\n"
                f"{textwrap.indent(source, '    ')}\n"
                f"errors: {[e.message for e in result.errors]}"
            ),
        )


# ===========================================================
# Deterministic match-divergence cases (finding C-F1)
# ===========================================================
#
# Advisory 2026-06-17 finding B3 raised the enclosing block's pc after a
# secret-conditioned divergence (return / break / continue / panic) for
# if / while / for, but overlooked ``match``. Finding C-F1 extends that
# same mechanism to ``match``. The randomised generator above exercises
# the return / break / continue arms; the deterministic cases below pin
# the ``panic`` and nested-arm shapes (whose non-diverging sibling needs
# a Unit-typed block body so an arm-type mismatch does not mask the IFC
# check), the two accept controls (which must stay accepted and run to a
# fixed public output), and the disclosed-open residuals (a deeper-nested
# match, and an arm that diverges via the ``?`` / ``Try`` operator).

# A ``match`` whose secret-conditioned diverging arm is a ``panic``,
# whose sibling is a Unit-typed block so the arms unify to Unit; each is
# followed by a public sink that must be rejected under @strict_ifc.
_MATCH_PANIC_REJECTIONS = {
    # A secret arm-guard on a ``panic`` arm (public scrutinee).
    "match_secret_guard_panic": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    match n
        _ if s.length() > 0 -> panic("x")
        _ ->
            let _z = 0
    stdio.println("leak")
''',
    # The diverging arm's body is itself a nested ALL-arms-panic match.
    "micro_nested_all_panic_match": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    match n
        _ if s.length() > 0 ->
            match n
                0 -> panic("a")
                _ -> panic("b")
        _ ->
            let _z = 0
    stdio.println("leak")
''',
    # The diverging arm's body is a nested both-branches-panic if-expr.
    "micro_nested_both_panic_ifexpr": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    match n
        _ if s.length() > 0 -> if true then panic("a") else panic("b")
        _ ->
            let _z = 0
    stdio.println("leak")
''',
    # A diverging ``match`` nested inside a secret ``if`` body: the if's
    # own divergence check must see the match's return arm.
    "nested_match_in_secret_if": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    if s.length() > 3
        match n
            0 -> return
            _ -> "y"
    stdio.println("leak")
''',
}

# Accept controls: each must stay ACCEPTED and run to a FIXED public
# output regardless of the secret (noninterferent).
_MATCH_ACCEPT_CONTROLS = {
    # Secret scrutinee, but every arm is non-diverging, so the block pc
    # is not raised and the following public sink is clean.
    "accept_secret_scrutinee_all_nondiverging": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let v = match s.length()
        0 -> "zero"
        _ -> "many"
    stdio.println("fixed")
''',
    # A diverging arm, but the controlling label is PUBLIC (public
    # scrutinee, no secret guard), so the sink after is clean.
    "accept_public_scrutinee_diverging_arm": '''@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    match n
        0 -> return
        _ -> "y"
    stdio.println("fixed")
''',
}

# Disclosed-open residual: a ``MatchExpr`` nested DEEPER than the
# directly-carried value (here as a call argument) is not inspected,
# consistent with the top-level-only inspection the if / elif path
# already uses. This shape leaks (the secret arm-guard decides whether
# the program panics before the sink) yet is currently ACCEPTED. Pinned
# so a future change that closes the residual updates this deliberately.
_MATCH_DEEPER_NESTED_RESIDUAL = '''fun take(u: Unit) -> Int
    return 0

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let n = 1
    let _v = take(match n { _ if s.length() > 0 -> panic("x"), _ -> () })
    stdio.println("leak")
'''

# Disclosed-open residual: a directly-carried secret-scrutinee ``match``
# whose arm diverges via the ``?`` / ``Try`` operator. ``Try`` is a
# first-class early return, but the divergence detector recognizes only
# syntactic forms (panic / return / break / continue / nested match /
# if-expr), NOT the ``A.Try`` node, so this leaks: whether the ``?`` arm
# early-returns (hence whether the sink after runs) depends on the secret
# scrutinee, yet it is currently ACCEPTED. Pre-existing and symmetric
# with the if / while / for path, which does not recognize ``Try``
# either; deferred, not a regression of the C-F1 fix. Pinned so the
# extension that handles ``Try`` flips this deliberately.
_MATCH_TRY_DIVERGENCE_RESIDUAL = '''fun always_err() -> Result<Int, String>
    return Err("boom")

@strict_ifc()
fun main(stdio: Stdio, env: Env) -> Result<Int, String>
    let s = env.get("SECRET0").unwrap_or("d")
    let v = match s.length()
        0 -> always_err()?
        _ -> 1
    stdio.println("leak")
    return Ok(0)
'''


class TestMatchDivergenceCF1(unittest.TestCase):
    """Deterministic guards for finding C-F1 (secret-conditioned
    divergence carried by a ``match``)."""

    def _analyze(self, source: str):
        module = Parser(Lexer(source).lex(), source=source).parse_module()
        return module, analyze(module, source=source)

    def test_match_panic_divergence_rejected(self):
        """Each secret-conditioned ``panic`` / nested-diverging ``match``
        shape is rejected for an information-flow reason."""
        for name, source in _MATCH_PANIC_REJECTIONS.items():
            with self.subTest(shape=name):
                _module, result = self._analyze(source)
                self.assertFalse(
                    result.ok,
                    msg=(
                        f"C-F1 REGRESSION: shape {name!r} was ACCEPTED under "
                        f"@strict_ifc (expected an information-flow "
                        f"rejection).\n{textwrap.indent(source, '    ')}"
                    ),
                )
                self.assertTrue(
                    _is_ifc_rejection(result),
                    msg=(
                        f"shape {name!r} was rejected, but NOT (only) for an "
                        f"information-flow reason:\n"
                        f"{textwrap.indent(source, '    ')}\n"
                        f"errors: {[e.message for e in result.errors]}"
                    ),
                )

    def test_match_accept_controls_run_to_fixed_output(self):
        """Each accept control stays accepted and produces byte-identical
        public output for differing secret inputs (noninterferent)."""
        for name, source in _MATCH_ACCEPT_CONTROLS.items():
            with self.subTest(shape=name):
                module, result = self._analyze(source)
                self.assertTrue(
                    result.ok,
                    msg=(
                        f"accept control {name!r} was REJECTED (expected it "
                        f"to stay accepted):\n"
                        f"{textwrap.indent(source, '    ')}\n"
                        f"errors: {[e.message for e in result.errors]}"
                    ),
                )
                code = transpile(module, types=result.types)
                out_a = _run_capa(code, {"SECRET0": "AAA-aaaaaaaa"})
                out_b = _run_capa(code, {"SECRET0": "Z"})
                self.assertEqual(out_a, out_b)
                self.assertEqual(out_a, "fixed\n")

    def test_deeper_nested_match_residual_is_accepted(self):
        """PIN (disclosed residual): a diverging ``match`` nested deeper
        than the directly-carried value is not inspected and stays
        accepted. If this ever flips to a rejection, close the residual
        note in ``capa/analyzer/_statements.py`` and update this pin."""
        _module, result = self._analyze(_MATCH_DEEPER_NESTED_RESIDUAL)
        self.assertTrue(
            result.ok,
            msg=(
                "the disclosed deeper-nested-match residual is no longer "
                "accepted; update the residual note and this pin:\n"
                f"{textwrap.indent(_MATCH_DEEPER_NESTED_RESIDUAL, '    ')}\n"
                f"errors: {[e.message for e in result.errors]}"
            ),
        )

    def test_try_divergence_match_residual_is_accepted(self):
        """PIN (disclosed residual): a directly-carried secret-scrutinee
        ``match`` whose arm diverges via the ``?`` / ``Try`` operator is
        not recognized as a divergence and stays accepted (it leaks). If
        this ever flips to a rejection, the ``Try`` extension has landed:
        update the residual note in ``capa/analyzer/_statements.py`` and
        this pin."""
        _module, result = self._analyze(_MATCH_TRY_DIVERGENCE_RESIDUAL)
        self.assertTrue(
            result.ok,
            msg=(
                "the disclosed Try-divergence match residual is no longer "
                "accepted; the Try extension may have landed, so update "
                "the residual note and this pin:\n"
                f"{textwrap.indent(_MATCH_TRY_DIVERGENCE_RESIDUAL, '    ')}\n"
                f"errors: {[e.message for e in result.errors]}"
            ),
        )


# ===========================================================
# Deterministic cross-call implicit-flow cases (IFC-1)
# ===========================================================
#
# Under @strict_ifc the intra-procedural implicit-flow rule caught a public
# sink inside a secret-conditioned branch, but did NOT compose across a
# function call: a sink behind a HELPER call under a secret branch was
# certified clean and leaked at runtime (every sink cap, any depth, any
# branch form). IFC-1 closes this with a per-callable sink-reaching-pc
# summary bit plus a call-site check. These deterministic cases pin both
# directions the randomised generator cannot: the must-REJECT mirrors
# (so the fix bites) and the must-COMPILE controls (so it does not
# over-reject -- especially ``xs.get(i)``, whose ``get`` collides by name
# with ``Net.get`` but is type-resolved to a clean ``List`` receiver).

# Must-REJECT: 1-hop + 3-hop; if / while / for / match; free fn + method;
# one case per sink capability (Stdio / Net / Fs / Db). Each is a genuine
# cross-call implicit leak and must be a hard information-flow error.
_IFC1_CROSSCALL_REJECTIONS = {
    "free_if_stdio": '''fun leak(stdio: Stdio)
    stdio.println("pub")

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        leak(stdio)
''',
    "free_while_stdio": '''fun leak(stdio: Stdio)
    stdio.println("pub")

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    var i = 0
    while i < s.length()
        leak(stdio)
        i = i + 1
''',
    "free_for_stdio": '''fun leak(stdio: Stdio)
    stdio.println("pub")

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let parts = s.split("-")
    for _p in parts
        leak(stdio)
''',
    "free_match_arm_stdio": '''fun leak(stdio: Stdio)
    stdio.println("pub")

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    match s.length()
        0 -> leak(stdio)
        _ -> leak(stdio)
''',
    "free_depth3_stdio": '''fun h3(stdio: Stdio)
    stdio.println("pub")
fun h2(stdio: Stdio)
    h3(stdio)
fun h1(stdio: Stdio)
    h2(stdio)

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        h1(stdio)
''',
    "method_if_stdio": '''type Printer { tag: String }
impl Printer
    fun show(self, stdio: Stdio)
        stdio.println(self.tag)

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let p = Printer { tag: "t" }
    if s.length() > 3
        p.show(stdio)
''',
    "free_if_net": '''fun leak(net: Net)
    let _r = net.get("http://example.com")

@strict_ifc()
fun main(net: Net, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        leak(net)
''',
    "free_if_fs": '''fun leak(fs: Fs)
    let _r = fs.write("/tmp/x", "data")

@strict_ifc()
fun main(fs: Fs, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        leak(fs)
''',
    "free_if_db": '''fun leak(db: Db)
    let _r = db.exec("INSERT", "x")

@strict_ifc()
fun main(db: Db, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        leak(db)
''',
}

# Must-COMPILE controls (the over-reject guard): each stays ACCEPTED before
# AND after the fix.
_IFC1_CROSSCALL_ACCEPT_CONTROLS = {
    # (i) A sink-reaching helper called under a PUBLIC pc: no secret branch,
    # so the call is clean.
    "sink_helper_public_pc": '''fun leak(stdio: Stdio)
    stdio.println("pub")

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let _s = env.get("SECRET0").unwrap_or("d")
    leak(stdio)
''',
    # (ii) A helper with NO real sink, called under a secret pc: the bit is
    # never set, so no leak.
    "no_sink_helper_secret_pc": '''fun compute(x: Int) -> Int
    return x + 1

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    if s.length() > 3
        let _v = compute(2)
    stdio.println("fixed")
''',
    # (iii) THE critical control: ``xs.get(i)`` on a ``List`` receiver under
    # a secret pc. ``get`` collides by NAME with ``Net.get``, but the
    # receiver is TYPE-resolved to ``List`` (not a sink), so the bit stays
    # clear and the call compiles.
    "list_get_helper_secret_pc": '''fun peek(xs: List<String>, i: Int) -> Option<String>
    return xs.get(i)

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let s = env.get("SECRET0").unwrap_or("d")
    let xs = ["a", "b"]
    if s.length() > 3
        let _v = peek(xs, 0)
    stdio.println("fixed")
''',
    # (iv) A recursive sink helper called under a PUBLIC pc: the fixpoint
    # converges (self-recursion) and, with no secret branch at the call, the
    # program compiles.
    "recursive_sink_helper_public_pc": '''fun rec(stdio: Stdio, n: Int)
    if n > 0
        stdio.println("x")
        rec(stdio, n - 1)

@strict_ifc()
fun main(stdio: Stdio, env: Env)
    let _s = env.get("SECRET0").unwrap_or("d")
    rec(stdio, 2)
''',
}


class TestImplicitCrossCallIFC1(unittest.TestCase):
    """Deterministic guards for IFC-1 (strict implicit-flow composed across
    a function call)."""

    def _analyze(self, source: str):
        module = Parser(Lexer(source).lex(), source=source).parse_module()
        return module, analyze(module, source=source)

    def test_crosscall_implicit_leak_rejected(self):
        """Each cross-call implicit-flow shape (1-hop + 3-hop; if / while /
        for / match; free + method; per sink cap) is a hard
        information-flow rejection. RED on the pre-fix analyzer (accepted),
        GREEN after."""
        for name, source in _IFC1_CROSSCALL_REJECTIONS.items():
            with self.subTest(shape=name):
                _module, result = self._analyze(source)
                self.assertFalse(
                    result.ok,
                    msg=(
                        f"IFC-1 GAP: shape {name!r} was ACCEPTED under "
                        f"@strict_ifc (expected a cross-call implicit-flow "
                        f"rejection).\n{textwrap.indent(source, '    ')}"
                    ),
                )
                self.assertTrue(
                    _is_ifc_rejection(result),
                    msg=(
                        f"shape {name!r} was rejected, but NOT (only) for an "
                        f"information-flow reason:\n"
                        f"{textwrap.indent(source, '    ')}\n"
                        f"errors: {[e.message for e in result.errors]}"
                    ),
                )

    def test_crosscall_accept_controls_stay_accepted(self):
        """Each over-reject control stays ACCEPTED. The load-bearing one is
        ``list_get_helper_secret_pc``: ``xs.get(i)`` must not be mistaken
        for ``Net.get`` (the receiver-capability test is TYPE-resolved, not
        by-name)."""
        for name, source in _IFC1_CROSSCALL_ACCEPT_CONTROLS.items():
            with self.subTest(shape=name):
                _module, result = self._analyze(source)
                self.assertTrue(
                    result.ok,
                    msg=(
                        f"IFC-1 OVER-REJECT: control {name!r} was REJECTED "
                        f"(expected it to stay accepted):\n"
                        f"{textwrap.indent(source, '    ')}\n"
                        f"errors: {[e.message for e in result.errors]}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()

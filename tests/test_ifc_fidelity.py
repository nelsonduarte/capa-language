"""Differential FIDELITY harness: the REAL Capa IFC analyzer vs an
executable model of the lambda_if calculus.

The Agda proof
[`proofs/CapaNoninterference.agda`](../proofs/CapaNoninterference.agda)
guarantees that lambda_if (syntax + semantics in
[`proofs/CapaIF.agda`](../proofs/CapaIF.agda)) enforces
noninterference. This harness gives MACHINE-RUN evidence that the
real analyzer's accept/reject decisions AND its runtime traces MATCH
lambda_if on the fragment lambda_if models -- narrowing (not closing)
the model-versus-implementation gap of `docs/semantics.md` Section
9.8. It is evidence, not proof: it is coverage-bounded (Hypothesis
sampling) and fragment-only (scalar variables, env-get, declassify,
assign, seq, if, while, sink; no structs / per-field / containers /
cross-function).

Two differential checks (both under ``@strict_ifc``, the regime
lambda_if's hard T-Sink constraint models):

  TYPING AGREEMENT
    For every generated program, the lambda_if reference's
    well-typed verdict must EQUAL the analyzer's "accepts under
    @strict_ifc" verdict (rejection = an information-flow error). A
    disagreement is a fidelity finding (analyzer unsound vs the
    proven-safe model, or over-restrictive).

  RUNTIME AGREEMENT
    For every WELL-TYPED program, the public output trace of the
    rendered Capa (run via the same in-process path
    `tests/test_ifc_noninterference.py` uses) must MATCH the
    lambda_if reference interpreter on the same secret input -- and,
    run twice with differing secrets, must be independent of the
    secret. A mismatch is a semantics-fidelity finding.

The reference (`tests/_lambda_if_ref.py`) is an INDEPENDENT
transcription of CapaIF.agda, not a wrapper of the analyzer, so the
agreement is evidence rather than a tautology.

If a genuine disagreement is found, the harness fails loudly with the
minimal disagreeing program and both verdicts / outputs.
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
    from hypothesis import HealthCheck, assume, given, settings
except ImportError:  # pragma: no cover - exercised only without the extra
    raise unittest.SkipTest(
        "hypothesis is not installed; install with `pip install -e .[test]`"
    )

from capa import Lexer, Parser, analyze, transpile
from capa.parser import ParserError

from tests import _lambda_if_ref as ref


# The single secret environment variable env-get reads. The renderer
# emits ``env.get(SECRET_VAR).unwrap_or(default)`` and the two runtime
# runs disagree on exactly this key.
SECRET_VAR = "FIDELITY_SECRET"

# Public string literals the generator draws from (the ``lit n`` and
# guard-threshold pool). Kept short and ASCII so lengths are obvious
# and println output is byte-stable.
_PUB_LITS = ["a", "bb", "ccc", "", "xy"]


# ===========================================================
# Generator: lambda_if-FRAGMENT programs
# ===========================================================
#
# Grammar (mirrors CapaIF.agda Expr / Stmt on the modelled fragment):
#
#   expr  ::= lit S | var X | op expr expr | env_get | declassify expr
#   stmt  ::= assign X expr | seq stmt+ | if guard stmt stmt
#           | while guard stmt | sink expr
#
# Variables are scalar strings. ``env_get`` is the secret source.
# Programs are kept small, deterministic, and type-correct as Capa
# (the renderer always produces a parseable, type-checking module), so
# the ONLY cross-implementation difference under test is the IFC
# verdict / output -- never a parse or type error.
#
# To exercise BOTH branches of typing agreement the generator can:
#   * keep every sink argument PUBLIC / declassified (well-typed), or
#   * route a secret (or a secret-pc sink) into a sink (ill-typed).


def _gen_expr(draw, depth, vars_in_scope, allow_secret):
    """Draw a lambda_if expression. ``allow_secret`` gates whether
    env_get / a secret variable may appear (so a guaranteed-public
    expression can be produced for well-typed sinks)."""
    choices = ["lit"]
    if vars_in_scope:
        choices.append("var")
    if depth > 0:
        choices.append("op")
    if allow_secret:
        choices.append("env_get")
        choices.append("declassify")
    kind = draw(st.sampled_from(choices))
    if kind == "lit":
        return ref.Lit(draw(st.sampled_from(_PUB_LITS)))
    if kind == "var":
        return ref.Var(draw(st.sampled_from(sorted(vars_in_scope))))
    if kind == "op":
        return ref.Op(
            _gen_expr(draw, depth - 1, vars_in_scope, allow_secret),
            _gen_expr(draw, depth - 1, vars_in_scope, allow_secret),
        )
    if kind == "env_get":
        return ref.EnvGet()
    if kind == "declassify":
        return ref.Declassify(
            _gen_expr(draw, depth - 1, vars_in_scope, True)
        )
    raise AssertionError(kind)


def _public_expr(draw, depth, vars_in_scope):
    """A guaranteed-PUBLIC expression: literals, public vars, op over
    those, and declassify of anything. Never a bare env_get / secret
    var, so its label is provably PUBLIC."""
    return _gen_expr(draw, depth, _public_vars(vars_in_scope), allow_secret=False)


def _public_vars(scope):
    """The subset of in-scope variables currently labelled public in
    the generator's shadow environment."""
    return {name for name, lbl in scope.items() if lbl == ref.PUBLIC}


@st.composite
def _program(draw):
    """Generate a lambda_if-fragment program plus its shadow label
    environment. Returns ``(stmt, intends_leak)`` where ``stmt`` is
    the lambda_if AST and ``intends_leak`` records whether the
    generator deliberately built an ill-typed (leaky) shape -- used
    only as a sanity cross-check against the reference's own verdict,
    never as the source of truth.

    The body is a sequence of statements. ``env`` tracks each
    variable's label as the generator builds, so a guaranteed-public
    sink can always be produced. A final coin flip optionally appends
    a leaky shape (a secret sink, or a public sink under a secret
    guard) to drive the reject branch."""
    n_stmts = draw(st.integers(min_value=1, max_value=4))
    env: dict = {}        # var name -> label, the generator's shadow
    stmts: list = []
    counter = 0           # fresh variable names s0, s1, ...

    for _ in range(n_stmts):
        shape = draw(st.sampled_from(
            ["assign_public", "assign_secret", "assign_declassify",
             "sink_public", "if_public", "while_public",
             "if_secret_nosink", "while_secret_nosink"]
        ))
        if shape == "assign_public":
            name = f"v{counter}"; counter += 1
            e = _public_expr(draw, 1, env)
            stmts.append(ref.Assign(name, e))
            env[name] = ref.label_of(env, e)
        elif shape == "assign_secret":
            name = f"v{counter}"; counter += 1
            e = ref.EnvGet()
            stmts.append(ref.Assign(name, e))
            env[name] = ref.label_of(env, e)
        elif shape == "assign_declassify":
            name = f"v{counter}"; counter += 1
            e = ref.Declassify(ref.EnvGet())
            stmts.append(ref.Assign(name, e))
            env[name] = ref.label_of(env, e)
        elif shape == "sink_public":
            stmts.append(ref.Sink(_public_expr(draw, 1, env)))
        elif shape == "if_public":
            cond = _public_expr(draw, 0, env)
            thr = draw(st.integers(min_value=0, max_value=4))
            then_b = ref.Sink(_public_expr(draw, 1, env))
            else_b = ref.Sink(_public_expr(draw, 1, env))
            stmts.append(ref.If(cond, thr, then_b, else_b))
        elif shape == "while_public":
            # A terminating public loop: a fresh public counter string
            # grows one char per iteration until its length reaches the
            # threshold, with a public sink in the body.
            cname = f"w{counter}"; counter += 1
            thr = draw(st.integers(min_value=0, max_value=3))
            stmts.append(ref.Assign(cname, ref.Lit("")))
            env[cname] = ref.PUBLIC
            body = ref.Seq((
                ref.Sink(_public_expr(draw, 1, env)),
                ref.Assign(cname, ref.Op(ref.Var(cname), ref.Lit("a"))),
            ))
            stmts.append(ref.While(ref.Var(cname), thr, body))
        elif shape == "if_secret_nosink":
            # CONFINEMENT FRONTIER: a SECRET-guarded if whose branches
            # ASSIGN but do NOT sink. pc is raised to SECRET for both
            # branches, T-Assign joins SECRET onto the target, but
            # nothing is sunk -- so lambda_if confinement makes this
            # WELL-TYPED and the analyzer must ACCEPT. Both branches
            # assign the SAME fresh var (exercising the cross-branch /
            # branch-local declaration shape the renderer must hoist).
            name = f"v{counter}"; counter += 1
            thr = draw(st.integers(min_value=0, max_value=4))
            then_b = ref.Assign(name, ref.Lit(draw(st.sampled_from(_PUB_LITS))))
            else_b = ref.Assign(name, ref.Lit(draw(st.sampled_from(_PUB_LITS))))
            stmts.append(ref.If(ref.EnvGet(), thr, then_b, else_b))
            # After a SECRET-guarded assign in both branches the var is
            # SECRET in the shadow env (it must never be sunk afterwards).
            env[name] = ref.SECRET
        elif shape == "while_secret_nosink":
            # CONFINEMENT FRONTIER (loop form): a SECRET-guarded while
            # whose body ASSIGNS but does NOT sink. The guard reads a
            # public counter joined with env-get, so its label is SECRET
            # (pc raised) yet its length grows each iteration (the public
            # counter advances), guaranteeing termination. The body
            # assigns a fresh var to a public literal; nothing is sunk,
            # so confinement keeps it well-typed and the analyzer accepts.
            cname = f"w{counter}"; counter += 1
            aname = f"v{counter}"; counter += 1
            thr = draw(st.integers(min_value=1, max_value=3))
            stmts.append(ref.Assign(cname, ref.Lit("")))
            env[cname] = ref.PUBLIC
            guard = ref.Op(ref.Var(cname), ref.EnvGet())
            body = ref.Seq((
                ref.Assign(aname, ref.Lit(draw(st.sampled_from(_PUB_LITS)))),
                ref.Assign(cname, ref.Op(ref.Var(cname), ref.Lit("a"))),
            ))
            stmts.append(ref.While(guard, thr, body))
            # The loop body runs under SECRET pc, raising both names.
            env[cname] = ref.SECRET
            env[aname] = ref.SECRET

    intends_leak = draw(st.booleans())
    if intends_leak:
        leak = draw(st.sampled_from(
            ["secret_sink", "op_secret_sink", "var_laundered_sink",
             "sink_under_secret_if", "assign_under_secret_if"]
        ))
        if leak == "secret_sink":
            # Explicit data flow: sink env-get directly.
            stmts.append(ref.Sink(ref.EnvGet()))
        elif leak == "op_secret_sink":
            # The L-Op join rule: op(public, secret) is SECRET.
            stmts.append(ref.Sink(ref.Op(ref.Lit("p"), ref.EnvGet())))
        elif leak == "var_laundered_sink":
            # T-Assign carries the secret label onto a variable, which
            # is then sunk (the laundering-through-a-binding shape).
            name = f"v{counter}"; counter += 1
            stmts.append(ref.Assign(name, ref.EnvGet()))
            stmts.append(ref.Sink(ref.Var(name)))
        elif leak == "sink_under_secret_if":
            # Implicit flow: public sink under a SECRET guard. The pc is
            # raised to SECRET for the body, so T-Sink's (l join pc)
            # flows PUBLIC fails.
            stmts.append(ref.If(
                ref.EnvGet(), 3,
                ref.Sink(ref.Lit("hit")),
                ref.Skip(),
            ))
        else:
            # Implicit assign channel: a public var is reassigned under a
            # SECRET guard (T-Assign joins pc=SECRET into its label), then
            # sunk. The classic implicit-flow shape T-If + T-Assign catch.
            name = f"v{counter}"; counter += 1
            stmts.append(ref.Assign(name, ref.Lit("init")))
            stmts.append(ref.If(
                ref.EnvGet(), 3,
                ref.Assign(name, ref.Lit("hit")),
                ref.Skip(),
            ))
            stmts.append(ref.Sink(ref.Var(name)))
    else:
        # Ensure at least one sink so the program has observable output
        # and env-get is referenced somewhere (Capa requires the Env
        # capability to be used -- guaranteed below by the source line).
        if not _has_sink(stmts):
            stmts.append(ref.Sink(_public_expr(draw, 1, env)))

    program = ref.Seq(tuple(stmts))
    return program, intends_leak


def _has_declassify_expr(e) -> bool:
    if isinstance(e, ref.Declassify):
        return True
    if isinstance(e, ref.Op):
        return _has_declassify_expr(e.left) or _has_declassify_expr(e.right)
    return False


def _has_declassify(s) -> bool:
    """True if the program contains a ``declassify`` anywhere. A
    declassify deliberately reveals the secret value, so such a
    program's PUBLIC output may legitimately depend on the secret --
    the noninterference INDEPENDENCE check is excluded for it (exactly
    as tests/test_ifc_noninterference.py excludes its ``declassifies``
    shape). The model-vs-Capa trace-agreement check still applies."""
    if isinstance(s, ref.Sink):
        return _has_declassify_expr(s.expr)
    if isinstance(s, ref.Assign):
        return _has_declassify_expr(s.expr)
    if isinstance(s, ref.Seq):
        return any(_has_declassify(x) for x in s.stmts)
    if isinstance(s, ref.If):
        return (_has_declassify_expr(s.guard)
                or _has_declassify(s.then_branch)
                or _has_declassify(s.else_branch))
    if isinstance(s, ref.While):
        return _has_declassify_expr(s.guard) or _has_declassify(s.body)
    return False


def _has_sink(stmts) -> bool:
    return any(_contains_sink(s) for s in stmts)


def _contains_sink(s) -> bool:
    if isinstance(s, ref.Sink):
        return True
    if isinstance(s, ref.Seq):
        return any(_contains_sink(x) for x in s.stmts)
    if isinstance(s, ref.If):
        return _contains_sink(s.then_branch) or _contains_sink(s.else_branch)
    if isinstance(s, ref.While):
        return _contains_sink(s.body)
    return False


# ===========================================================
# Renderer: lambda_if program -> equivalent Capa source
# ===========================================================
#
# A faithful 1:1 rendering, wrapped in a @strict_ifc entry point:
#   env_get      -> env.get(SECRET_VAR).unwrap_or("")   (secret source)
#   sink e       -> stdio.println(<e>)                  (public sink)
#   assign x e   -> var x = <e>                         (mutable; reassign elsewhere)
#   op a b       -> (<a> + <b>)                         (string concat)
#   declassify e -> declassify(<e>, reason: "fidelity")
#   if g thr a b -> if <g>.length() < thr / else        (length truthiness)
#   while g thr b-> while <g>.length() < thr
#   lit s        -> "s"


def _render_expr(e) -> str:
    if isinstance(e, ref.Lit):
        return f'"{e.value}"'
    if isinstance(e, ref.Var):
        return e.name
    if isinstance(e, ref.Op):
        return f"({_render_expr(e.left)} + {_render_expr(e.right)})"
    if isinstance(e, ref.EnvGet):
        return f'env.get("{SECRET_VAR}").unwrap_or("")'
    if isinstance(e, ref.Declassify):
        return f'declassify({_render_expr(e.inner)}, reason: "fidelity")'
    raise TypeError(e)


def _render_stmt(s, indent, declared) -> list:
    """Render a statement to a list of Capa source lines at the given
    indent. ``declared`` is the set of variable names already
    introduced with ``var`` (so a re-assignment renders ``x = ...``
    rather than ``var x = ...``)."""
    pad = "    " * indent
    if isinstance(s, ref.Skip):
        # An empty branch needs a body in Capa; a no-op public print of
        # the empty string keeps the branch non-empty without observable
        # difference (it appends a single blank line on both Capa and
        # the reference -- but Skip never carries a sink in the model,
        # so we instead emit a harmless self-assign only when needed).
        return [f'{pad}let _skip = ""']
    if isinstance(s, ref.Assign):
        rhs = _render_expr(s.expr)
        if s.name in declared:
            return [f"{pad}{s.name} = {rhs}"]
        declared.add(s.name)
        return [f"{pad}var {s.name} = {rhs}"]
    if isinstance(s, ref.Seq):
        out: list = []
        for sub in s.stmts:
            out.extend(_render_stmt(sub, indent, declared))
        return out
    if isinstance(s, ref.If):
        out = [f"{pad}if {_render_expr(s.guard)}.length() < {s.threshold}"]
        out.extend(_render_stmt(s.then_branch, indent + 1, declared))
        out.append(f"{pad}else")
        out.extend(_render_stmt(s.else_branch, indent + 1, declared))
        return out
    if isinstance(s, ref.While):
        out = [f"{pad}while {_render_expr(s.guard)}.length() < {s.threshold}"]
        out.extend(_render_stmt(s.body, indent + 1, declared))
        return out
    if isinstance(s, ref.Sink):
        return [f"{pad}stdio.println({_render_expr(s.expr)})"]
    raise TypeError(s)


def _branch_assigned_names(s, inside_branch=False) -> set:
    """Names a program assigns INSIDE any if/while body. Capa scopes a
    branch-local ``var`` to its branch, so such a name must be declared
    at the enclosing scope before the if/while or a sibling-branch
    reassignment / a post-if read is an "undefined name" (a renderer
    scoping artifact, not an IFC disagreement). In lambda_if, ``assign``
    targets a pre-existing store cell, so hoisting the declaration is a
    faithful 1:1 of the model, not a semantic change."""
    found: set = set()
    if isinstance(s, ref.Assign):
        if inside_branch:
            found.add(s.name)
    elif isinstance(s, ref.Seq):
        for sub in s.stmts:
            found |= _branch_assigned_names(sub, inside_branch)
    elif isinstance(s, ref.If):
        found |= _branch_assigned_names(s.then_branch, True)
        found |= _branch_assigned_names(s.else_branch, True)
    elif isinstance(s, ref.While):
        found |= _branch_assigned_names(s.body, True)
    return found


def _render_program(program) -> str:
    """Wrap a lambda_if program as a complete @strict_ifc Capa
    module. The Env capability is always exercised (every program the
    generator emits sinks or assigns via env-get somewhere; but to be
    safe against a degenerate program with no env-get, a leading
    discard read guarantees the declared Env capability is used).

    Any variable assigned inside an if/while body is HOISTED: declared
    once at the function scope with a public initial value ("") before
    the program body, so the rendering is well-scoped regardless of
    which branch runs. This is faithful (lambda_if assigns to a
    pre-existing cell) and removes the scoping artifact that previously
    discarded every secret-guarded if/while whose branches assign."""
    declared: set = set()
    lines = ["@strict_ifc()", "fun main(stdio: Stdio, env: Env)"]
    # Guarantee the Env capability is USED (Capa rejects an unused
    # declared capability) without affecting the trace: a discard read.
    lines.append(f'    let _seed = env.get("{SECRET_VAR}").unwrap_or("")')
    # Hoist branch-assigned names with a public "" initial value so a
    # branch-local declaration never escapes its branch.
    for name in sorted(_branch_assigned_names(program)):
        lines.append(f'    var {name} = ""')
        declared.add(name)
    body = _render_stmt(program, 1, declared)
    lines.extend(body)
    return "\n".join(lines) + "\n"


# ===========================================================
# Execution helpers (reused conventions from
# tests/test_ifc_noninterference.py)
# ===========================================================


def _run_capa(code: str, secret_value: str) -> str:
    """Exec transpiled Capa ``code`` in-process under a patched
    ``os.environ`` and return captured stdout. ``env.get`` reads
    ``os.environ`` at runtime, so ``secret_value`` is exactly what
    flows in as @secret."""
    full_env = {SECRET_VAR: secret_value}
    buf = io.StringIO()
    run_globals: dict = {"__name__": "__main__"}
    with mock.patch.dict(os.environ, full_env, clear=False):
        with contextlib.redirect_stdout(buf):
            try:
                exec(compile(code, "<fidelity-test>", "exec"), run_globals)
            except SystemExit:
                pass
    return buf.getvalue()


def _compile(source: str):
    """Lex + parse + analyse. Returns ``(module, result)`` or ``None``
    on a parser error (generator noise -> discard via ``assume``)."""
    try:
        module = Parser(Lexer(source).lex(), source=source).parse_module()
    except ParserError:
        return None
    result = analyze(module, source=source)
    return module, result


def _is_ifc_rejection(result) -> bool:
    """True iff the analysis failed ENTIRELY for information-flow
    reasons (the only rejection the model accounts for)."""
    if result.ok:
        return False
    return all("information-flow" in e.message for e in result.errors)


def _capa_trace(secret_value: str, code: str) -> list:
    """The public output trace of the rendered Capa as a list of
    lines (stripped of the trailing newline), comparable to the
    reference interpreter's list-of-strings trace."""
    out = _run_capa(code, secret_value)
    if out == "":
        return []
    lines = out.split("\n")
    # ``println`` appends a newline per call, so a trace of k lines
    # ends with a trailing "" element after split; drop it.
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


# ===========================================================
# Coverage counters (non-vacuity evidence)
# ===========================================================

_COVERAGE = {
    "well_typed": 0,
    "ill_typed": 0,
    "runtime_checked": 0,
    # The confinement frontier: a SECRET-guarded if/while whose body
    # ASSIGNS but does NOT sink. Well-typed via confinement (pc raised,
    # assignment tainted, nothing sunk); the analyzer must ACCEPT.
    "secret_guarded_nosink": 0,
}


def _has_secret_guarded_nosink(s, pc_secret=False) -> bool:
    """True iff the program contains an if/while under a SECRET guard
    whose body assigns at least one variable but sinks NOTHING (the
    confinement frontier). ``pc_secret`` tracks whether we are already
    inside secret-guarded control flow. A guard is SECRET iff it reads
    ``env-get`` (the sole secret source), independent of any public
    counter it is joined with."""
    if isinstance(s, ref.Seq):
        return any(_has_secret_guarded_nosink(x, pc_secret) for x in s.stmts)
    if isinstance(s, ref.If):
        here = _guard_is_secret(s.guard) or pc_secret
        body_assigns = (_assigns_any(s.then_branch) or _assigns_any(s.else_branch))
        body_sinks = (_contains_sink(s.then_branch) or _contains_sink(s.else_branch))
        if here and body_assigns and not body_sinks:
            return True
        return (_has_secret_guarded_nosink(s.then_branch, here)
                or _has_secret_guarded_nosink(s.else_branch, here))
    if isinstance(s, ref.While):
        here = _guard_is_secret(s.guard) or pc_secret
        if here and _assigns_any(s.body) and not _contains_sink(s.body):
            return True
        return _has_secret_guarded_nosink(s.body, here)
    return False


def _guard_is_secret(e) -> bool:
    """True iff ``e`` reads env-get anywhere (so its label is SECRET)."""
    if isinstance(e, ref.EnvGet):
        return True
    if isinstance(e, ref.Op):
        return _guard_is_secret(e.left) or _guard_is_secret(e.right)
    if isinstance(e, ref.Declassify):
        return False  # declassify downgrades to PUBLIC
    return False


def _assigns_any(s) -> bool:
    if isinstance(s, ref.Assign):
        return True
    if isinstance(s, ref.Seq):
        return any(_assigns_any(x) for x in s.stmts)
    if isinstance(s, ref.If):
        return _assigns_any(s.then_branch) or _assigns_any(s.else_branch)
    if isinstance(s, ref.While):
        return _assigns_any(s.body)
    return False


# ===========================================================
# The harness
# ===========================================================


class TestIfcFidelity(unittest.TestCase):
    """Differential fidelity: the real analyzer vs the lambda_if model."""

    @given(_program())
    @settings(
        max_examples=300,
        deadline=8000,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_typing_and_runtime_agreement(self, generated):
        program, intends_leak = generated
        source = _render_program(program)

        compiled = _compile(source)
        if compiled is None:
            # A parser-level imperfection in the renderer for this
            # shape -- generator noise, not a finding. Discard.
            assume(False)
        module, result = compiled

        # A non-IFC analysis error means the renderer produced an
        # otherwise-invalid program (e.g. an unrelated type error):
        # generator noise, discard so we never mistake it for a
        # fidelity disagreement.
        if not result.ok and not _is_ifc_rejection(result):
            assume(False)

        model_ok = ref.well_typed(program)
        analyzer_ok = result.ok

        if model_ok:
            _COVERAGE["well_typed"] += 1
            if _has_secret_guarded_nosink(program):
                _COVERAGE["secret_guarded_nosink"] += 1
        else:
            _COVERAGE["ill_typed"] += 1

        # ---- TYPING AGREEMENT ----------------------------------
        self.assertEqual(
            model_ok,
            analyzer_ok,
            msg=(
                "IFC FIDELITY DISAGREEMENT (typing): the lambda_if "
                "reference and the real analyzer disagree on whether this "
                "program is accepted under @strict_ifc. The Agda proof "
                "guarantees the lambda_if verdict enforces noninterference, "
                "so a disagreement is a soundness or precision gap in the "
                "analyzer.\n"
                f"lambda_if well-typed: {model_ok}\n"
                f"analyzer accepts:     {analyzer_ok}\n"
                f"(generator intended a leak: {intends_leak})\n"
                f"rendered program:\n{textwrap.indent(source, '    ')}\n"
                + (
                    f"analyzer errors: {[e.message for e in result.errors]}\n"
                    if not analyzer_ok else ""
                )
            ),
        )

        if not model_ok:
            # Rejected by both (agreement already asserted): the reject
            # branch is exercised; nothing to run.
            return

        # ---- RUNTIME AGREEMENT (well-typed programs only) ------
        code = transpile(module, types=result.types)
        secret_a = "AAAAAAA"
        secret_b = "z"

        model_trace_a = ref.run(secret_a, program)
        model_trace_b = ref.run(secret_b, program)
        capa_trace_a = _capa_trace(secret_a, code)
        capa_trace_b = _capa_trace(secret_b, code)

        _COVERAGE["runtime_checked"] += 1

        # Model vs analyzer-backed runtime, on the SAME secret.
        self.assertEqual(
            model_trace_a,
            capa_trace_a,
            msg=(
                "IFC FIDELITY DISAGREEMENT (runtime): the lambda_if "
                "reference interpreter and the Capa runtime produced "
                "DIFFERENT public output traces for the same input.\n"
                f"secret: {secret_a!r}\n"
                f"lambda_if trace: {model_trace_a!r}\n"
                f"capa trace:      {capa_trace_a!r}\n"
                f"rendered program:\n{textwrap.indent(source, '    ')}"
            ),
        )
        self.assertEqual(
            model_trace_b,
            capa_trace_b,
            msg=(
                "IFC FIDELITY DISAGREEMENT (runtime): trace mismatch on "
                "the second secret.\n"
                f"secret: {secret_b!r}\n"
                f"lambda_if trace: {model_trace_b!r}\n"
                f"capa trace:      {capa_trace_b!r}\n"
                f"rendered program:\n{textwrap.indent(source, '    ')}"
            ),
        )

        # Noninterference (independence of the secret): a well-typed
        # program's public output must not depend on the secret value.
        # EXCLUDED when the program contains ``declassify``, which
        # deliberately reveals the secret -- there the model and Capa
        # both legitimately emit the secret (and they AGREE on it, as
        # the trace-agreement asserts above), so independence does not
        # hold by design.
        if not _has_declassify(program):
            self.assertEqual(
                capa_trace_a,
                capa_trace_b,
                msg=(
                    "NONINTERFERENCE: a program accepted under @strict_ifc "
                    "produced DIFFERENT public output for differing "
                    "secrets.\n"
                    f"secret A: {secret_a!r} -> {capa_trace_a!r}\n"
                    f"secret B: {secret_b!r} -> {capa_trace_b!r}\n"
                    f"rendered program:\n{textwrap.indent(source, '    ')}"
                ),
            )


class TestZZZFidelityNonVacuity(unittest.TestCase):
    """Confirm the property test reached BOTH typing branches and
    actually executed the runtime-agreement assertion on real
    programs (not all discarded). The ``ZZZ`` prefix makes this class
    sort AFTER ``TestIfcFidelity`` so the shared coverage counters are
    populated by the time it reads them."""

    def test_both_branches_and_runtime_reached(self):
        wt = _COVERAGE["well_typed"]
        it = _COVERAGE["ill_typed"]
        rt = _COVERAGE["runtime_checked"]
        # If the property test was deselected / skipped, all counters
        # are zero and there is nothing to assert about coverage.
        if wt == 0 and it == 0:
            self.skipTest("fidelity property test did not run in this session")
        self.assertGreater(
            wt, 0,
            f"non-vacuity: no WELL-TYPED program reached (accept branch "
            f"never exercised). counters={_COVERAGE}",
        )
        self.assertGreater(
            it, 0,
            f"non-vacuity: no ILL-TYPED program reached (reject branch "
            f"never exercised). counters={_COVERAGE}",
        )
        self.assertGreater(
            rt, 0,
            f"non-vacuity: runtime-agreement assertion never executed on a "
            f"real program. counters={_COVERAGE}",
        )
        self.assertGreater(
            _COVERAGE["secret_guarded_nosink"], 0,
            f"non-vacuity: the CONFINEMENT FRONTIER (a SECRET-guarded "
            f"if/while whose body assigns but does not sink) was never "
            f"generated, so the analyzer-accepts-confinement branch is "
            f"unexercised. counters={_COVERAGE}",
        )


if __name__ == "__main__":
    unittest.main()

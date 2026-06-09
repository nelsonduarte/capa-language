"""Executable reference for the lambda_if information-flow calculus.

This is an independent, hand-written transcription of the
machine-checked source of truth
[`proofs/CapaIF.agda`](../proofs/CapaIF.agda) (prose mirror:
`docs/semantics.md` Section 9): the two-point lattice, the
expression labelling judgement, the flow-sensitive pc-carrying
statement typing, and the big-step operational semantics with a
public output trace. It exists so the differential fidelity harness
(`tests/test_ifc_fidelity.py`) can cross-check the REAL Capa IFC
analyzer's accept/reject decisions and runtime traces against the
proven-safe model on the fragment lambda_if models.

It is deliberately a SEPARATE implementation from
`capa/analyzer/_ifc.py` so that typing-agreement between the two is
evidence, not a tautology.

VALUE CARRIER (the one implementation choice Section 9 leaves open).
-------------------------------------------------------------------
CapaIF.agda evaluates expressions to ``Nat`` with ``op`` taken as
"any total deterministic binary function" (the proofs use only its
determinism, never its algebra; see the ``eval`` comment in
CapaIF.agda lines 277-296). We pick the concrete carrier to be
STRINGS, with ``op`` = string concatenation, so that:

  * ``env-get`` (the single secret source) maps directly onto Capa's
    ``env.get(VAR).unwrap_or(d)`` which yields a ``String``, with no
    parsing glue, and
  * the model's public output trace is a list of strings that is
    byte-comparable with the lines Capa's ``stdio.println`` emits.

This is purely the value carrier; every IFC-relevant rule (labels,
pc, source, sink, declassify) is transcribed from CapaIF.agda
unchanged. Strings have no native "is it zero" test, so a guard
expression's truthiness (the Agda ``eval e == zero`` / ``== suc v``
of E-IfF / E-IfT / E-WhileF / E-WhileT) is taken to be a comparison
of the guard value's LENGTH against a literal threshold. Length is a
pure function of the value, so this is faithful to "evaluate the
guard to a Nat, then branch on it"; the guard's LABEL is unchanged
by taking its length (Capa's ``String.length`` is a pure derivation
whose label is the receiver's), so the pc-raise of T-If / T-While is
exactly as in CapaIF.agda.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

# ---------------------------------------------------------------
# The two-point security lattice (CapaIF.agda lines 120-178;
# capa/_labels.py). PUBLIC is bottom, SECRET is top.
# ---------------------------------------------------------------

PUBLIC = "public"
SECRET = "secret"

_RANK = {PUBLIC: 0, SECRET: 1}


def join(a: str, b: str) -> str:
    """Least upper bound (CapaIF.agda ``_join_``, lines 132-134):
    ``PUBLIC join b = b`` ; ``SECRET join _ = SECRET``."""
    return a if _RANK[a] >= _RANK[b] else b


def flows_to(src: str, dst: str) -> bool:
    """``src flows dst`` (CapaIF.agda ``_flows_``, lines 141-143):
    PUBLIC flows everywhere; SECRET flows only to SECRET."""
    return _RANK[src] <= _RANK[dst]


# ---------------------------------------------------------------
# Expressions (CapaIF.agda ``Expr``, lines 186-191). One secret
# source (env-get), one label-joining binary op, one downgrade
# (declassify), literals and variable reads.
# ---------------------------------------------------------------


@dataclass(frozen=True)
class Lit:
    """``lit n`` -- a public literal (carrier: a string)."""
    value: str


@dataclass(frozen=True)
class Var:
    """``evar x`` -- a variable read."""
    name: str


@dataclass(frozen=True)
class Op:
    """``op a b`` -- the label-joining binary op (carrier: concat)."""
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True)
class EnvGet:
    """``env-get`` -- the single secret source."""


@dataclass(frozen=True)
class Declassify:
    """``declassify e`` -- downgrade to PUBLIC, identity on value."""
    inner: "Expr"


Expr = Union[Lit, Var, Op, EnvGet, Declassify]


# ---------------------------------------------------------------
# Statements (CapaIF.agda ``Stmt``, lines 206-212). A guard carries
# its threshold so the carrier-specific truthiness (length < thr) is
# explicit; see the module docstring.
# ---------------------------------------------------------------


@dataclass(frozen=True)
class Skip:
    """``skip``."""


@dataclass(frozen=True)
class Assign:
    """``assign x e``."""
    name: str
    expr: Expr


@dataclass(frozen=True)
class Seq:
    """``seq s1 s2`` (n-ary here for convenience; folds to right-
    nested seqs, which CapaIF.agda's T-Seq / E-Seq handle)."""
    stmts: tuple


@dataclass(frozen=True)
class If:
    """``sif e s1 s2`` with guard truthiness ``len(eval e) < thr``."""
    guard: Expr
    threshold: int
    then_branch: "Stmt"
    else_branch: "Stmt"


@dataclass(frozen=True)
class While:
    """``swhile e s`` with guard truthiness ``len(eval e) < thr``.

    The body is required to make progress toward falsifying the guard
    (the harness only generates bodies that increment a public
    counter the guard reads), matching the termination-insensitive
    but terminating shapes the calculus admits."""
    guard: Expr
    threshold: int
    body: "Stmt"


@dataclass(frozen=True)
class Sink:
    """``sink e`` -- the single public output channel."""
    expr: Expr


Stmt = Union[Skip, Assign, Seq, If, While, Sink]


# ---------------------------------------------------------------
# Expression labelling judgement (CapaIF.agda ``_|-e_~>_``,
# lines 303-320). Deterministic and total.
# ---------------------------------------------------------------


def label_of(env: dict, e: Expr) -> str:
    """``env |-e e ~> l`` -- the security label of ``e`` under label
    environment ``env``.

      * L-Lit:        lit n        ~> PUBLIC               (line 305)
      * L-Var:        evar x       ~> env(x)               (line 308)
      * L-Op:         op a b       ~> label(a) join label(b)(line 311)
      * L-Env:        env-get      ~> SECRET               (line 316)
      * L-Declassify: declassify e ~> PUBLIC               (line 318)
    """
    if isinstance(e, Lit):
        return PUBLIC
    if isinstance(e, Var):
        return env[e.name]
    if isinstance(e, Op):
        return join(label_of(env, e.left), label_of(env, e.right))
    if isinstance(e, EnvGet):
        return SECRET
    if isinstance(e, Declassify):
        # The inner expression is still labelled (CapaIF requires a
        # derivation ``g |-e e ~> l`` as the premise), but the result
        # is PUBLIC regardless of l.
        label_of(env, e.inner)
        return PUBLIC
    raise TypeError(f"unknown expr {e!r}")


# ---------------------------------------------------------------
# Statement typing (CapaIF.agda ``_,_|-s_~>_``, lines 351-379).
# Flow-sensitive: returns the OUTPUT label environment, or signals
# ill-typedness by raising ``IllTyped`` (the only untypable rule is
# T-Sink's side condition ``(l join pc) flows PUBLIC``).
# ---------------------------------------------------------------


class IllTyped(Exception):
    """Raised when no typing derivation exists -- i.e. a sink whose
    argument label joined with the pc does not flow to PUBLIC
    (CapaIF.agda T-Sink side condition, line 378). This is the single
    hard constraint of the @strict_ifc regime the model captures."""


def _envjoin(g1: dict, g2: dict) -> dict:
    """Pointwise join of two label environments (CapaIF.agda
    ``_envjoin_``, lines 250-251) -- the T-If branch merge."""
    keys = set(g1) | set(g2)
    return {k: join(g1.get(k, PUBLIC), g2.get(k, PUBLIC)) for k in keys}


def type_stmt(pc: str, env: dict, s: Stmt) -> dict:
    """``pc , env |-s s ~> env'``. Returns the output label
    environment. Raises ``IllTyped`` exactly when the derivation does
    not exist.

      * T-Skip:   pc , g |-s skip ~> g                       (line 353)
      * T-Assign: g |-e e ~> l
                  => pc , g |-s assign x e ~> g[x :> l join pc] (line 356)
      * T-Seq:    thread the env left to right                (line 360)
      * T-If:     g |-e e ~> l ; raise pc by l for both
                  branches ; output = g1 envjoin g2           (line 365)
      * T-While:  g |-e e ~> l ; (pc join l) , g |-s s ~> g
                  (fixpoint body env = input env)             (line 371)
      * T-Sink:   g |-e e ~> l ; require (l join pc) flows
                  PUBLIC                                       (line 376)
    """
    if isinstance(s, Skip):
        return env
    if isinstance(s, Assign):
        l = label_of(env, s.expr)
        out = dict(env)
        out[s.name] = join(l, pc)
        return out
    if isinstance(s, Seq):
        cur = env
        for sub in s.stmts:
            cur = type_stmt(pc, cur, sub)
        return cur
    if isinstance(s, If):
        l = label_of(env, s.guard)
        branch_pc = join(pc, l)
        g1 = type_stmt(branch_pc, env, s.then_branch)
        g2 = type_stmt(branch_pc, env, s.else_branch)
        return _envjoin(g1, g2)
    if isinstance(s, While):
        l = label_of(env, s.guard)
        branch_pc = join(pc, l)
        # T-While takes the body fixpoint as the typing environment.
        # The analyser realises it by monotone label raising to a
        # least fixpoint over the height-2 lattice; we compute the
        # same fixpoint here so the model matches a body that raises a
        # variable's label on iteration.
        cur = dict(env)
        while True:
            after = type_stmt(branch_pc, cur, s.body)
            merged = _envjoin(cur, after)
            if merged == cur:
                break
            cur = merged
        return cur
    if isinstance(s, Sink):
        l = label_of(env, s.expr)
        if not flows_to(join(l, pc), PUBLIC):
            raise IllTyped(
                "sink: (label join pc) does not flow to PUBLIC"
            )
        return env
    raise TypeError(f"unknown stmt {s!r}")


def well_typed(s: Stmt, initial_env: Optional[dict] = None) -> bool:
    """True iff ``PUBLIC , initial_env |-s s ~> _`` has a derivation
    (the program is well-typed under the @strict_ifc regime). The
    initial pc is PUBLIC (top-level code is not under any secret
    control flow); the initial label environment is empty (every
    variable is introduced by an assignment before use in the
    generated fragment)."""
    try:
        type_stmt(PUBLIC, dict(initial_env or {}), s)
        return True
    except IllTyped:
        return False


# ---------------------------------------------------------------
# Big-step operational semantics (CapaIF.agda ``_,_,_=>_,_``,
# lines 392-428). ``run(kappa, s)`` returns the public output trace
# (a list of strings). ``kappa`` is the ambient secret value that
# ``env-get`` reads, fixed for the whole run.
# ---------------------------------------------------------------


def eval_expr(kappa: str, store: dict, e: Expr) -> str:
    """``eval kappa s e`` (CapaIF.agda ``eval``, lines 291-296),
    carrier = strings, ``op`` = concatenation, ``declassify`` =
    identity on the value (it changes only the label, never the
    value).

      * lit n        -> n                                    (line 292)
      * evar x       -> store(x)                             (line 293)
      * op a b       -> eval a ++ eval b                     (line 294)
      * env-get      -> kappa                                (line 295)
      * declassify e -> eval e                               (line 296)
    """
    if isinstance(e, Lit):
        return e.value
    if isinstance(e, Var):
        return store[e.name]
    if isinstance(e, Op):
        return eval_expr(kappa, store, e.left) + eval_expr(kappa, store, e.right)
    if isinstance(e, EnvGet):
        return kappa
    if isinstance(e, Declassify):
        return eval_expr(kappa, store, e.inner)
    raise TypeError(f"unknown expr {e!r}")


def _guard_true(kappa: str, store: dict, e: Expr, threshold: int) -> bool:
    """Carrier-specific truthiness for a guard: ``len(eval e) <
    threshold`` (see the module docstring). Stands in for Agda's
    ``eval e == suc v`` (true) vs ``== zero`` (false)."""
    return len(eval_expr(kappa, store, e)) < threshold


def run(kappa: str, s: Stmt, store: Optional[dict] = None) -> list:
    """``kappa , s , store => store' , trace`` -- run ``s`` and
    return the public output ``trace`` (the sink emissions, in order).

      * E-Skip:   emit nothing                               (line 394)
      * E-Assign: store[x] := eval e ; emit nothing          (line 397)
      * E-Seq:    run s1 then s2 ; concatenate traces        (line 400)
      * E-IfT/F:  branch on the guard ; thread store / trace (line 406)
      * E-WhileF/T: iterate while the guard holds            (line 417)
      * E-Sink:   emit eval e                                (line 427)
    """
    store = {} if store is None else store
    trace: list = []
    _exec(kappa, s, store, trace)
    return trace


def _exec(kappa: str, s: Stmt, store: dict, trace: list) -> None:
    if isinstance(s, Skip):
        return
    if isinstance(s, Assign):
        store[s.name] = eval_expr(kappa, store, s.expr)
        return
    if isinstance(s, Seq):
        for sub in s.stmts:
            _exec(kappa, sub, store, trace)
        return
    if isinstance(s, If):
        if _guard_true(kappa, store, s.guard, s.threshold):
            _exec(kappa, s.then_branch, store, trace)
        else:
            _exec(kappa, s.else_branch, store, trace)
        return
    if isinstance(s, While):
        # Termination is the generator's responsibility (the body
        # advances a public counter the guard reads); a guard cap
        # below is a defensive stop, never reached for generated
        # programs.
        guard_iters = 0
        while _guard_true(kappa, store, s.guard, s.threshold):
            _exec(kappa, s.body, store, trace)
            guard_iters += 1
            if guard_iters > 10000:
                raise RuntimeError("lambda_if reference: while did not terminate")
        return
    if isinstance(s, Sink):
        trace.append(eval_expr(kappa, store, s.expr))
        return
    raise TypeError(f"unknown stmt {s!r}")

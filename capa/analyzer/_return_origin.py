"""Per-callable RETURN-ORIGIN summary (E3, the generic-return-aliasing fix).

v3 SEMANTIC FAIL-CLOSED recast of PRED 1 (throwaway QA build): the origin
resolver no longer short-circuits to EMPTY on an unknown identifier. When the
declared return type is a bare type parameter ``T`` (the gate), any return
expression that does not PRECISELY resolve to a parameter / known local fails
CLOSED to "all parameters of type T" -- a tuple/struct/match-arm pattern bind,
a shadowed / chained ident through a pattern local, a nested call, an
aggregate access, and if/match all route through the default. When the gate is
off (a concrete return type) origin is precise-or-empty, which is sound: a
concrete return cannot alias a bare generic parameter by identity.
"""

from __future__ import annotations

import dataclasses

from .. import capa_ast as A
from ._callables import iter_user_callables
from ._ifc_tables import _bind


def compute_return_origins(module: A.Module) -> tuple[dict, dict]:
    origins: dict = {}
    callables: dict = {}
    for uc in iter_user_callables(module):
        param_names = [p.name for p in uc.params]
        callables[uc.key] = (param_names, uc.is_method)
        origins[uc.key] = frozenset(_origin_of(uc))
    return origins, callables


def map_call_args(expr, param_names: list, is_method: bool) -> dict:
    if is_method and isinstance(expr, A.MethodCall):
        out = {0: expr.receiver}
        sub = _bind(expr.args, expr.arg_names, param_names[1:])
        for pidx, aidx in sub.items():
            out[pidx + 1] = expr.args[aidx]
        return out
    args = getattr(expr, "args", [])
    sub = _bind(args, getattr(expr, "arg_names", None), param_names)
    return {pidx: args[aidx] for pidx, aidx in sub.items()}


# ---- per-callable origin ------------------------------------------------


class _Ctx:
    __slots__ = (
        "param_index", "type_params", "params",
        "ret_tv_name", "local_origin",
    )

    def __init__(self, uc) -> None:
        self.params = uc.params
        self.param_index = {p.name: i for i, p in enumerate(uc.params)}
        self.type_params = frozenset(uc.type_params)
        self.ret_tv_name = _bare_type_var(uc.return_type, self.type_params)
        self.local_origin: dict = {}


def _origin_of(uc) -> set:
    body = _body_block(uc)
    if body is None:
        return set()
    ctx = _Ctx(uc)
    for name, rhs in _binding_sites(body):
        ctx.local_origin.setdefault(name, set()).update(_origin_expr(rhs, ctx))
    out: set = set()
    for rexpr in _return_exprs(body):
        out |= _origin_expr(rexpr, ctx)
    return out


def _all_params_of_ret_tv(ctx: _Ctx) -> set:
    """The fail-closed default: every parameter whose declared type is the
    SAME bare type variable as the return type. Empty when the return type is
    not a bare type variable (gate off) -- a concrete return cannot alias a
    generic parameter by identity."""
    if ctx.ret_tv_name is None:
        return set()
    return {
        i for i, p in enumerate(ctx.params)
        if _bare_type_var(p.type_expr, ctx.type_params) == ctx.ret_tv_name
    }


def _origin_expr(e, ctx: _Ctx) -> set:
    """The parameter-index origin set of a returned / bound expression.

    PRECISE forms: a parameter Ident is that parameter; a known-local Ident is
    the local's unioned origin; an ``if`` / ``match`` / block unions its
    branch / tail origins (each branch itself failing closed if non-precise).
    EVERY OTHER shape -- an unknown / pattern-bound / shadowed ident, a nested
    call, an aggregate access -- FALLS THROUGH to the fail-closed default
    (:func:`_all_params_of_ret_tv`), which is ``{all params of T}`` under a
    bare-``T`` return and ``{}`` under a concrete return. The unknown-ident
    branch MUST NOT short-circuit to ``{}`` (that was the v2 CRIT-1 hole)."""
    if isinstance(e, A.Ident):
        if e.name in ctx.local_origin:
            return set(ctx.local_origin[e.name])
        if e.name in ctx.param_index:
            return {ctx.param_index[e.name]}
        # unknown / pattern-bound / shadowed ident: fall through fail-closed.
    elif isinstance(e, A.IfExpr):
        out = _origin_expr(e.then_expr, ctx)
        if e.else_expr is not None:
            out = out | _origin_expr(e.else_expr, ctx)
        return out
    elif isinstance(e, A.MatchExpr):
        out = set()
        for arm in e.arms:
            if isinstance(arm.body, A.Expr):
                out |= _origin_expr(arm.body, ctx)
            else:
                out |= _all_params_of_ret_tv(ctx)
        return out
    elif isinstance(e, A.Block):
        out = set()
        tails = _tail_exprs(e)
        if not tails:
            return _all_params_of_ret_tv(ctx)
        for te in tails:
            out |= _origin_expr(te, ctx)
        return out
    return _all_params_of_ret_tv(ctx)


# ---- syntactic helpers --------------------------------------------------


def _bare_type_var(type_expr, type_params: frozenset):
    if not isinstance(type_expr, A.TypeName):
        return None
    if getattr(type_expr, "args", None):
        return None
    if getattr(type_expr, "state", None) is not None:
        return None
    return type_expr.name if type_expr.name in type_params else None


def _body_block(uc):
    node = uc.node
    body = getattr(node, "body", None)
    if isinstance(body, A.Block):
        return body
    if body is not None:
        return A.Block(pos=uc.node.pos, stmts=[A.ExprStmt(pos=uc.node.pos, expr=body)])
    return None


def _return_exprs(body: A.Block) -> list:
    out: list = []
    for stmt in _iter_stmts(body):
        if isinstance(stmt, A.ReturnStmt) and stmt.value is not None:
            out.append(stmt.value)
    out.extend(_tail_exprs(body))
    return out


def _tail_exprs(body: A.Block) -> list:
    if not body.stmts:
        return []
    last = body.stmts[-1]
    if isinstance(last, A.ExprStmt):
        return [last.expr]
    return []


def _binding_sites(body: A.Block):
    for stmt in _iter_stmts(body):
        if isinstance(stmt, A.LetStmt) and isinstance(stmt.pattern, A.IdentPat):
            yield (stmt.pattern.name, stmt.value)
        elif isinstance(stmt, A.VarStmt):
            yield (stmt.name, stmt.value)
        elif isinstance(stmt, A.AssignStmt) and isinstance(stmt.target, A.Ident):
            yield (stmt.target.name, stmt.value)


def _iter_stmts(node):
    if isinstance(node, A.LambdaExpr):
        return
    if isinstance(node, A.Stmt):
        yield node
    if dataclasses.is_dataclass(node):
        for f in dataclasses.fields(node):
            yield from _iter_stmts(getattr(node, f.name))
    elif isinstance(node, (list, tuple)):
        for x in node:
            yield from _iter_stmts(x)

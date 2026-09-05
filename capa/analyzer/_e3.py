"""E3 resolver: move the argument a generic call's result aliases.

v3 SEMANTIC FAIL-CLOSED recast of PRED 2 (throwaway QA build). The call-site
backstop no longer whitelists a few "linear operand" SHAPES; it classifies an
operand by its RESOLVED TYPE and a small closed PROVABLY-FRESH whitelist. An
operand carries a live obligation iff its resolved type reaches a
linear/typestate value AND it is NOT provably fresh (a literal, a struct /
typestate literal, or a call to a callee summarised with EMPTY origin -- a
proven factory). Every other shape (if / match / block wrap, bare ident, field
access, nested non-factory call, receiver, unknown) is NOT provably fresh, so
it counts. The backstop, scoped to an un-summarisable callee, fires the single
fail-closed reject when any such live-obligation argument could be laundered.
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import TyFun, TyName
from ._callables import fun_key, lambda_key, method_key
from ._return_origin import map_call_args


class _E3Mixin:
    def _call_result_alias_args(self, expr: A.Expr) -> list:
        kind, data = self._e3_resolve(expr)
        if kind == "args":
            if len(data) >= 2:
                self._reject_multi_origin_return(expr)
                return []
            return data
        if kind == "backstop":
            self._reject_e3_backstop(expr)
        return []

    def _call_result_alias_operand(self, expr: A.Expr):
        """The SINGLE operand a laundering call's result aliases, or ``None``.

        The PURE half of :meth:`_call_result_alias_args`: same resolution, no
        diagnostic. Splitting reporting from resolution is what lets a READ
        position ask the question -- ``_path_of`` runs at read sites too, and
        a mere read of a laundered value is legal -- while the move seam keeps
        the fail-closed rejects it must emit.

        ``None`` for a fresh factory, for a callee whose result may alias more
        than one argument (fail-closed: which obligation moves is unknown),
        and for an un-summarisable callee (the backstop reports that at the
        move seam, so resolving it here would report it twice)."""
        kind, data = self._e3_resolve(expr)
        if kind != "args" or len(data) != 1:
            return None
        return data[0]

    # ---- callee-key resolution (single source for resolve + freshness) ----

    def _e3_callee_key(self, expr: A.Expr) -> tuple:
        """``(key_or_None, unresolved_bool)`` for a ``Call`` / ``MethodCall``
        callee. ``key`` is the origin-table key when the callee is
        summarisable; ``unresolved`` is True for a Fun-value / lambda-var /
        trait-dynamic / absent callee (an un-summarisable one). ``(None,
        False)`` for a non-call or a plainly-unknown non-Fun name. THE one
        place the callee is resolved, so ``_e3_resolve`` and the provably-fresh
        test cannot drift."""
        origins = getattr(self, "_return_origins", None)
        if origins is None:
            return (None, False)
        if isinstance(expr, A.Call) and isinstance(expr.callee, A.Ident):
            nm = expr.callee.name
            if fun_key(nm) in origins:
                return (fun_key(nm), False)
            sym = self.bindings.get(id(expr.callee)) or self.scope.lookup(nm)
            lam = self._binding_lambdas.get(id(sym)) if sym is not None else None
            if isinstance(lam, A.LambdaExpr) and lambda_key(lam) in origins:
                return (lambda_key(lam), False)
            if sym is not None and isinstance(sym.ty, TyFun):
                return (None, True)
            return (None, False)
        if isinstance(expr, A.MethodCall):
            recv_ty = self.types.get(id(expr.receiver))
            tn = recv_ty.name if isinstance(recv_ty, TyName) else None
            if tn is None:
                return (None, True)
            from . import SymbolKind
            sym = self.global_scope.lookup(tn)
            if sym is not None and sym.kind == SymbolKind.TRAIT:
                return (None, True)
            if method_key(tn, expr.method) in origins:
                return (method_key(tn, expr.method), False)
            return (None, True)
        return (None, False)

    def _e3_resolve(self, expr: A.Expr) -> tuple:
        origins = getattr(self, "_return_origins", None)
        if origins is None:
            return ("none", None)
        if not self._owned_obligation(self.types.get(id(expr))):
            return ("none", None)
        if not isinstance(expr, (A.Call, A.MethodCall)):
            return ("none", None)
        key, unresolved = self._e3_callee_key(expr)
        if key is not None:
            idxs = origins.get(key)
            callee = self._return_origin_callables.get(key)
            if not idxs or callee is None:
                return ("args", [])
            mapping = map_call_args(expr, callee[0], callee[1])
            return ("args", [mapping[j] for j in sorted(idxs) if j in mapping])
        if unresolved and self._e3_backstop_fires(expr):
            return ("backstop", None)
        return ("none", None)

    def _e3_backstop_fires(self, expr: A.Expr) -> bool:
        """True iff an un-summarisable call carries an ARGUMENT (or receiver)
        that carries a LIVE obligation the callee could return -- so a fresh
        factory taking only fresh / non-obligation arguments passes."""
        args = list(getattr(expr, "args", []))
        if isinstance(expr, A.MethodCall):
            args = [expr.receiver] + args
        return any(self._origin_arg_is_linear(a) for a in args)

    def _origin_arg_is_linear(self, e: A.Expr) -> bool:
        """v3: True iff ``e``'s RESOLVED TYPE reaches a linear/typestate value
        AND ``e`` is NOT provably fresh. Keys on the single-source type
        predicate, not a shape whitelist, so an if/match/block-wrapped or
        aggregate-accessed live obligation counts by construction."""
        ty = self.types.get(id(e))
        if not self._reaches_linear(ty):
            return False
        return not self._provably_fresh(e)

    def _provably_fresh(self, e: A.Expr) -> bool:
        """The small, CLOSED provably-fresh whitelist: a literal, a struct /
        typestate literal (a ``StructLit``, with or without a typestate), or a
        call whose callee is summarised with EMPTY origin (a proven factory).
        Everything else is NOT provably fresh."""
        if isinstance(e, (A.IntLit, A.StringLit, A.BoolLit,
                          A.FloatLit, A.CharLit, A.UnitLit, A.StructLit)):
            return True
        if isinstance(e, (A.Call, A.MethodCall)):
            return self._call_proven_fresh(e)
        return False

    def _call_proven_fresh(self, e: A.Expr) -> bool:
        """True iff ``e`` is a call to a callee SUMMARISED with empty origin.
        An un-summarisable callee (Fun value, trait-dynamic, absent) is NOT
        proven fresh -- it could hand back a laundered obligation."""
        origins = getattr(self, "_return_origins", None)
        if origins is None:
            return False
        key, _unresolved = self._e3_callee_key(e)
        if key is None:
            return False
        return not origins.get(key)

    def _reject_multi_origin_return(self, expr: A.Expr) -> None:
        self._err(
            "this call's result may alias one of several linear/typestate "
            "arguments, so which must-consume obligation it carries cannot be "
            "determined; rejected fail-closed -- take ownership of the routed "
            "value with a `consume` parameter, or call a concrete "
            "(non-generic) function whose return is unambiguous",
            expr.pos,
        )

    def _reject_e3_backstop(self, expr: A.Expr) -> None:
        self._err(
            "a linear/typestate value may be laundered through this call, "
            "whose callee cannot be summarised (an imported/absent function, "
            "a trait-dynamic method, or an ambiguous function value); "
            "rejected fail-closed -- take ownership with a `consume` "
            "parameter, or call a concrete (non-generic) function",
            expr.pos,
        )

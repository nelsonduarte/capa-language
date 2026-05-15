"""Capability discipline mixin.

The Capa core: capabilities cannot be hidden in data structures,
returned by ordinary functions, bound to ``let``/``var``, or
aliased within a single call. These methods enforce those rules
and the use-after-``consume`` flow analysis that supports them.

The mixin assumes ``self`` has the analyzer state set up by
``Analyzer.__init__``: ``scope`` / ``global_scope`` / ``errors``,
``_consumed`` (set of capability names consumed so far in the
current flow), ``_lambda_local_names_stack`` (frames of local
names per nested lambda), plus the ``_err`` helper for reporting.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import Pos
from ..typesys import (
    CAPABILITY_NAMES, Ty, TyFun, TyName, TyTuple, compatible,
)


class _DisciplineMixin:
    def _mark_consumed_args(
        self, args: list[A.Expr], consuming_flags: list[bool],
    ) -> None:
        """For each arg that is a capability Ident and whose flag
        is True, mark the name as consumed. Called after evaluating
        the args so the use of those idents in the args themselves
        (the first occurrence) does not trigger the use-after-
        consume error.

        Capture inside a lambda: if the consumed name does not
        belong to the local parameters (or to enclosing lambdas
        that contain us), it is a captured cap, and consuming a
        captured cap is an error because the lambda may be
        invoked multiple times.
        """
        for arg, consuming in zip(args, consuming_flags):
            if not consuming:
                continue
            if not isinstance(arg, A.Ident):
                continue
            sym = self.scope.lookup(arg.name)
            if sym is None or sym.ty is None:
                continue
            if isinstance(sym.ty, TyName) and sym.ty.name in CAPABILITY_NAMES:
                if self._lambda_local_names_stack:
                    is_local_to_some_lambda = any(
                        arg.name in frame
                        for frame in self._lambda_local_names_stack
                    )
                    if not is_local_to_some_lambda:
                        self._err(
                            f"cannot consume capability {arg.name!r} "
                            f"captured from enclosing scope; closures may "
                            f"be invoked multiple times, but a capability "
                            f"can only be consumed once",
                            arg.pos,
                        )
                        continue
                self._consumed.add(arg.name)

    def _substitute_self(self, ty: Ty, self_ty: Ty) -> Ty:
        """Substitute ``TyName('Self')`` in ``ty`` with ``self_ty``.
        Used to resolve trait method signatures in the context of
        a concrete impl."""
        if isinstance(ty, TyName):
            if ty.name == "Self":
                return self_ty
            if ty.args:
                new_args = tuple(self._substitute_self(a, self_ty) for a in ty.args)
                return TyName(ty.name, new_args)
            return ty
        if isinstance(ty, TyTuple):
            return TyTuple(tuple(
                self._substitute_self(e, self_ty) for e in ty.elements
            ))
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._substitute_self(p, self_ty) for p in ty.params),
                self._substitute_self(ty.ret, self_ty),
            )
        return ty

    def _is_capability_ident(self, expr: A.Expr) -> Optional[str]:
        """If ``expr`` is an Ident bound to a capability in
        scope, return the name; otherwise ``None``. Used by the
        aliasing check, which only cares about direct identifier
        references (not the values of more complex expressions)."""
        if not isinstance(expr, A.Ident):
            return None
        sym = self.scope.lookup(expr.name)
        if sym is None or sym.ty is None:
            return None
        if isinstance(sym.ty, TyName) and sym.ty.name in CAPABILITY_NAMES:
            return expr.name
        return None

    def _check_no_aliasing(self, slots: list[tuple[A.Expr, str]]) -> None:
        """Check that no capability appears twice in ``slots``.

        ``slots`` is a list of ``(expr, role)`` pairs where role
        is a description (``"receiver"``, ``"argument 2"``) for
        the error message. Each slot represents a position in a
        call where a capability could be passed. Aliasing a cap
        within a single call violates the single-flow property
        that gives Capa signatures their meaning.
        """
        seen: dict[str, str] = {}  # name -> first role where it appeared
        for expr, role in slots:
            name = self._is_capability_ident(expr)
            if name is None:
                continue
            if name in seen:
                self._err(
                    f"capability {name!r} appears as {role} but was already "
                    f"used as {seen[name]} of the same call; capabilities "
                    f"cannot be aliased (each call uses each capability at "
                    f"most once)",
                    expr.pos,
                )
            else:
                seen[name] = role

    def _check_no_capability(self, ty: Ty, pos: Pos, context: str) -> None:
        """Enforce the structural capability discipline: caps
        cannot be hidden in data structures, returned by ordinary
        functions, or bound to local / constant slots.
        Recognises both built-in capabilities and user-defined
        ones (declared with the ``capability`` keyword)."""
        cap = self._contains_any_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"capabilities only flow through function parameters",
            pos,
        )

    def _contains_any_capability(self, ty: Ty) -> Optional[TyName]:
        """Recursive walk that returns the first capability found
        in ``ty``. Three kinds count:

        - built-in caps (``Stdio``, ``Net``, ...), in
          ``CAPABILITY_NAMES``;
        - user-defined caps (Symbol with ``kind=CAPABILITY``);
        - cap-bearing structs (a ``TYPE_STRUCT`` Symbol whose
          ``implements`` set contains at least one user-defined
          capability).
        """
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            sym = self.global_scope.lookup(ty.name)
            if sym is not None:
                from . import SymbolKind   # late to avoid cycles
                if sym.kind == SymbolKind.CAPABILITY:
                    return ty
                if (
                    sym.kind == SymbolKind.TYPE_STRUCT
                    and any(self._is_user_capability(t) for t in sym.implements)
                ):
                    return ty
            for a in ty.args:
                found = self._contains_any_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_any_capability(elem)
                if found is not None:
                    return found
        return None

    def _is_user_capability(self, name: str) -> bool:
        """True iff ``name`` resolves to a user-defined
        capability (a Symbol whose kind is CAPABILITY but whose
        name is not in the built-in set). User-defined caps are
        subject to most of the same rules as built-ins, with two
        relaxations: they can be the return type of a regular
        function (factories produce fresh instances), and they
        can wrap built-in capabilities as struct fields when the
        struct implements a user-defined cap."""
        if name in CAPABILITY_NAMES:
            return False
        from . import SymbolKind
        sym = self.global_scope.lookup(name)
        return sym is not None and sym.kind == SymbolKind.CAPABILITY

    def _contains_builtin_capability(self, ty: Ty) -> Optional[TyName]:
        """Like ``_contains_any_capability`` but flags only
        **built-in** capabilities (Stdio, Fs, Net, Env, ...).
        Used by call sites that legitimately let user-defined
        caps flow through."""
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            for a in ty.args:
                found = self._contains_builtin_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_builtin_capability(elem)
                if found is not None:
                    return found
        return None

    def _check_no_builtin_capability(
        self, ty: Ty, pos: Pos, context: str,
    ) -> None:
        """Variant of :meth:`_check_no_capability` that only
        rejects **built-in** capabilities. Used at sites that
        legitimately accept user-defined ones (the return type
        of a factory function, for instance)."""
        cap = self._contains_builtin_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"built-in capabilities only flow through function parameters",
            pos,
        )

    def _compatible_with_impls(self, expected: Ty, actual: Ty) -> bool:
        """Like :func:`capa.typesys.compatible` plus nominal
        subtyping via trait / capability implementations.

        When the expected type is a trait or user-defined
        capability, and the actual type is a struct / sum whose
        Symbol records an ``impl`` of that trait / capability,
        the two are compatible (the concrete type is a valid
        implementor).
        """
        if compatible(expected, actual):
            return True
        if isinstance(expected, TyName) and isinstance(actual, TyName):
            from . import SymbolKind
            exp_sym = self.global_scope.lookup(expected.name)
            act_sym = self.global_scope.lookup(actual.name)
            if (
                exp_sym is not None and act_sym is not None
                and exp_sym.kind in (SymbolKind.TRAIT, SymbolKind.CAPABILITY)
                and expected.name in act_sym.implements
            ):
                return True
        return False

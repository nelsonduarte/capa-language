"""Statement-level checking mixin.

Implements ``_check_block`` and ``_check_stmt`` plus the
per-shape checkers:

- ``_check_let`` / ``_check_var``: binding introductions with
  inference and capability-flow exceptions for call-returned
  fresh capabilities.
- ``_check_assign``: assignment with mutability validation
  (immutable ``let``s, constants, and parameters cannot be
  reassigned).
- ``_check_if``: branch-aware ``_consumed`` snapshot + merge.
- ``_check_while``, ``_check_for``: two-pass dry-run / real-run
  analysis so capabilities consumed in body iteration N are
  flagged as consumed before iteration N+1 sees them.
- ``_check_return``: validate the return value against the
  current function's expected return type.
- ``_snapshot_for_dry_run`` / ``_restore_after_dry_run``: the
  flow-analysis bookkeeping the loop checkers rely on.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers from the other mixins (``_check_expr``,
``_bind_pattern``, ``_resolve_type``, ``_check_no_capability``,
``_err``, ``_push_scope``, ``_pop_scope``).
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import (
    Ty, TyBool, TyName, TyUnit, TyUnknown, compatible, ty_str,
)


class _StatementsMixin:
    def _check_block(self, block: A.Block) -> None:
        self._push_scope()
        for stmt in block.stmts:
            self._check_stmt(stmt)
        self._pop_scope()

    def _check_stmt(self, stmt: A.Stmt) -> None:
        if isinstance(stmt, A.LetStmt):
            self._check_let(stmt)
        elif isinstance(stmt, A.VarStmt):
            self._check_var(stmt)
        elif isinstance(stmt, A.AssignStmt):
            self._check_assign(stmt)
        elif isinstance(stmt, A.IfStmt):
            self._check_if(stmt)
        elif isinstance(stmt, A.WhileStmt):
            self._check_while(stmt)
        elif isinstance(stmt, A.ForStmt):
            self._check_for(stmt)
        elif isinstance(stmt, A.ReturnStmt):
            self._check_return(stmt)
        elif isinstance(stmt, A.BreakStmt):
            pass  # only allow inside loops? leave for v1.1
        elif isinstance(stmt, A.ContinueStmt):
            pass
        elif isinstance(stmt, A.ExprStmt):
            self._check_expr(stmt.expr)
        else:
            self._err(
                f"unknown statement type {type(stmt).__name__}", stmt.pos,
            )

    def _check_let(self, s: A.LetStmt) -> None:
        actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not compatible(declared, actual):
                self._err(
                    f"let binding: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            actual = declared
        # Capabilities normally cannot be bound to a ``let`` to
        # prevent aliasing. Exception: a fresh capability
        # produced by a call (method call -> built-in
        # attenuation; regular call -> user-defined factory)
        # is a brand-new instance, not an alias. The flow-layer
        # non-aliasing rule still applies if the binding is
        # later passed around.
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'let' binding")
        self._bind_pattern(s.pattern, actual, mutable=False)

    def _check_var(self, s: A.VarStmt) -> None:
        from . import Symbol, SymbolKind

        actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not compatible(declared, actual):
                self._err(
                    f"var declaration: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            actual = declared
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'var' binding")
        if self.scope.lookup_local(s.name) is not None:
            self._err(f"duplicate declaration of {s.name!r}", s.pos)
        self.scope.define(
            Symbol(
                name=s.name, kind=SymbolKind.LOCAL_VAR,
                pos=s.pos, ty=actual,
            )
        )

    def _check_assign(self, s: A.AssignStmt) -> None:
        from . import SymbolKind

        target_ty = self._check_expr(s.target)
        value_ty = self._check_expr(s.value)
        if isinstance(s.target, A.Ident):
            sym = self.bindings.get(id(s.target))
            if sym is not None and sym.kind == SymbolKind.LOCAL:
                self._err(
                    f"cannot assign to immutable binding {sym.name!r} "
                    f"(use 'var' instead of 'let' to make it mutable)",
                    s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.CONSTANT:
                self._err(
                    f"cannot assign to constant {sym.name!r}", s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.PARAM:
                self._err(
                    f"cannot assign to parameter {sym.name!r}", s.pos,
                )
        if not compatible(target_ty, value_ty):
            self._err(
                f"assignment: cannot assign {ty_str(value_ty)} to "
                f"{ty_str(target_ty)}",
                s.value.pos,
            )

    def _snapshot_for_dry_run(self) -> dict:
        """Capture mutable analyzer state before a speculative
        pass. Used by loop analysis: we run the body once
        silently to discover which caps will be consumed, then
        replay the run for real after pre-marking those caps."""
        return {
            "consumed": self._consumed.copy(),
            "errors_len": len(self.errors),
            "bindings_keys": set(self.bindings.keys()),
            "types_keys": set(self.types.keys()),
        }

    def _restore_after_dry_run(self, snap: dict) -> None:
        """Reverse :meth:`_snapshot_for_dry_run`. Added bindings /
        types are removed by key; new errors are truncated;
        ``_consumed`` reverts."""
        self._consumed = snap["consumed"]
        self.errors = self.errors[: snap["errors_len"]]
        for k in list(self.bindings.keys()):
            if k not in snap["bindings_keys"]:
                del self.bindings[k]
        for k in list(self.types.keys()):
            if k not in snap["types_keys"]:
                del self.types[k]

    def _check_if(self, s: A.IfStmt) -> None:
        cond_ty = self._check_expr(s.cond)
        if not compatible(TyBool, cond_ty):
            self._err(
                f"if condition must be Bool, got {ty_str(cond_ty)}",
                s.cond.pos,
            )
        # Flow analysis: snapshot ``_consumed`` before each branch
        # and take the conservative union after. If any branch
        # consumes a cap, treat it as consumed past the ``if``.
        before = set(self._consumed)
        branch_results: list[set[str]] = []

        self._consumed = set(before)
        self._check_block(s.then_block)
        branch_results.append(self._consumed)

        for cond, blk in s.elif_arms:
            self._consumed = set(before)
            cty = self._check_expr(cond)
            if not compatible(TyBool, cty):
                self._err(
                    f"elif condition must be Bool, got {ty_str(cty)}",
                    cond.pos,
                )
            self._check_block(blk)
            branch_results.append(self._consumed)

        if s.else_block is not None:
            self._consumed = set(before)
            self._check_block(s.else_block)
            branch_results.append(self._consumed)
        else:
            # No else: the all-conditions-false path falls
            # through and consumes nothing additional.
            branch_results.append(before)

        merged: set[str] = set()
        for s_set in branch_results:
            merged |= s_set
        self._consumed = merged

    def _check_while(self, s: A.WhileStmt) -> None:
        cty = self._check_expr(s.cond)
        if not compatible(TyBool, cty):
            self._err(
                f"while condition must be Bool, got {ty_str(cty)}",
                s.cond.pos,
            )
        # Two-pass fixed-point flow analysis. Pass 1 (dry-run):
        # visit the body silently to discover which caps will be
        # consumed. Pass 2 (real): pre-mark those caps and run
        # the body for real, so use-after-consume across loop
        # iterations is caught in a single static analysis.
        snap = self._snapshot_for_dry_run()
        self._check_block(s.body)
        consumed_in_body = self._consumed - snap["consumed"]
        self._restore_after_dry_run(snap)

        self._consumed |= consumed_in_body
        self._check_block(s.body)

    def _check_for(self, s: A.ForStmt) -> None:
        iter_ty = self._check_expr(s.iter)
        elem_ty: Ty = TyUnknown
        # ``List<T>`` and ``Range<T>`` are the two built-in
        # iterables today; both expose their element type as the
        # single type argument. A future ``Iterable`` trait would
        # consolidate this dispatch, but the two-case enumeration
        # is sound until the trait lands.
        if (
            isinstance(iter_ty, TyName)
            and iter_ty.name in ("List", "Range") and iter_ty.args
        ):
            elem_ty = iter_ty.args[0]

        # Same two-pass dry-run / real-run dance as ``_check_while``.
        snap = self._snapshot_for_dry_run()
        self._push_scope()
        self._bind_pattern(s.pattern, elem_ty, mutable=False)
        for stmt in s.body.stmts:
            self._check_stmt(stmt)
        self._pop_scope()
        consumed_in_body = self._consumed - snap["consumed"]
        self._restore_after_dry_run(snap)

        self._consumed |= consumed_in_body
        self._push_scope()
        self._bind_pattern(s.pattern, elem_ty, mutable=False)
        for stmt in s.body.stmts:
            self._check_stmt(stmt)
        self._pop_scope()

    def _check_return(self, s: A.ReturnStmt) -> None:
        if s.value is None:
            actual = TyUnit
        else:
            actual = self._check_expr(s.value)
        expected = self.current_return_type or TyUnit
        if not compatible(expected, actual):
            self._err(
                f"return: expected {ty_str(expected)}, got {ty_str(actual)}",
                s.pos,
            )

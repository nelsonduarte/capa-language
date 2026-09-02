"""Expression-checking mixin.

Implements ``_check_expr`` plus the per-shape checkers for every
expression node: literals (inline in ``_check_expr_inner``),
identifiers, binary and unary operators, ranges, field accesses,
struct / list / tuple literals, ``match`` expressions, ``if``
expressions, lambdas, indexing, and the ``?`` operator. Call
and method-call dispatch are in :class:`_DispatchMixin`.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers from the other mixins (``_resolve_type``,
``_bind_pattern``, ``_check_no_capability``, ``_check_call``,
``_check_method_call``, ``_check_match_exhaustiveness``,
``_check_stmt``, ``_hint_did_you_mean``, ``_names_in_scope``,
``_type_names``, ``_resolve_ty``, ``_fresh_ty_var``).
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from .. import _labels as L
from ..builtins import BUILTIN_POS as _BUILTIN_POS
from ..typesys import (
    Ty, TyBool, TyChar, TyFloat, TyFun, TyInt, TyName, TyString,
    TyTuple, TyUnit, TyUnknown, TyVar,
    compatible, is_flexible, substitute, ty_str, unify,
)


# 2**63: the magnitude of i64::MIN. The lexer admits a literal up to
# this value (a bare ``9223372036854775808``) because it cannot see
# whether a unary minus precedes it -- ``-9223372036854775808`` is the
# only legal use, denoting i64::MIN. Used POSITIVELY the same literal
# is out of i64 range, and the two backends disagree (Python prints
# the bignum, Wasm wraps to i64::MIN) -- a silent divergence. The
# analyzer closes it: an ``IntLit`` of exactly 2**63 is only allowed
# as the immediate operand of unary ``-`` (slice 26 residual / P3).
_I64_MIN_MAGNITUDE = 1 << 63


#: The AST expression kinds ``_check_expr_inner`` dispatches on, one per
#: ``isinstance`` branch in that method. This is the declared handled-set
#: the M1 exhaustiveness net pins against ``capa_ast.Expr.__subclasses__()``
#: (``tests/test_node_exhaustiveness.py``): a new ``Expr`` node that this
#: dispatcher forgets fails that test rather than falling through to the
#: ``unknown expression`` default at runtime on one path only. Keep it in
#: lockstep with the branches below.
CHECKED_EXPR_KINDS = frozenset({
    A.IntLit, A.FloatLit, A.StringLit, A.InterpolatedString, A.CharLit,
    A.BoolLit, A.UnitLit, A.Ident, A.BinOp, A.UnaryOp, A.Call, A.MethodCall,
    A.FieldAccess, A.Index, A.Try, A.Become, A.StructLit, A.ListLit,
    A.TupleLit, A.MatchExpr, A.IfExpr, A.LambdaExpr, A.RangeExpr,
})


class _ExpressionsMixin:
    # Built-in types both backends know how to render in a string
    # interpolation without a user ``to_string``. Mirrors the Wasm
    # FormatStr emitter (``_emit_format_part_stash``): String / Int /
    # Float / Bool plus the IoError special case. ``Char`` is here
    # too: a Capa Char is a single-codepoint String at the value
    # level, and the Wasm path normalises the ``Char`` type token to
    # ``String`` (``_normalize_char``) before the FormatStr emitter
    # runs, so ``${c}`` renders as that one character on both sides.
    _FORMATTABLE_BUILTINS = frozenset({
        "Int", "Float", "Bool", "String", "Char", "IoError",
    })

    def _is_formattable(self, ty: Ty) -> bool:
        """True when a value of type ``ty`` can be rendered into a
        string interpolation by BOTH backends.

        Mirrors the Wasm FormatStr emitter exactly: a built-in
        renderable type, OR a user type (struct / sum) whose head
        declares a ``to_string`` method (inherent or via a trait
        impl -- both land in the type symbol's ``methods`` table).
        Unresolved types (``?`` / type variables) stay permissive:
        the Wasm emitter defaults an unknown FormatStr value to Int,
        so rejecting them here would invent a new divergence."""
        from . import SymbolKind

        if ty is TyUnknown or isinstance(ty, TyVar):
            return True
        if not isinstance(ty, TyName):
            return False
        if ty.name in self._FORMATTABLE_BUILTINS:
            return True
        sym = self.global_scope.lookup(ty.name)
        if sym is not None and sym.kind in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
        ):
            return "to_string" in sym.methods
        return False

    def _check_lambda(self, e: A.LambdaExpr) -> Ty:
        """Type a lambda expression. The body is checked in a
        local scope with the parameters as bindings.

        **Linear restriction (v1)**: inside the body of a lambda,
        any call that consumes a capability *captured from
        outside* is rejected. The lambda may be invoked multiple
        times, but a capability can only be consumed once.
        Capabilities that are parameters of the lambda itself
        may be consumed freely (each call receives its own).

        Implementation: parameters land in a stack frame on
        ``_lambda_local_names_stack`` that :meth:`_check_call`
        consults before marking a name as consumed; a name not
        in any local frame is a capture and is an error.
        """
        from . import Symbol, SymbolKind

        # Lambda parameter / return-type inference. A lambda with an
        # omitted parameter type or return type is checked LAZILY: if
        # no expected ``Fun(..)`` type has been pushed for this node
        # yet (by the higher-order-call dispatch code), defer it. The
        # dispatch code re-checks it once the expected type is known.
        expected = self._expected_lambda_ty.get(id(e))
        needs_inference = expected is None and self._lambda_has_omissions(e)
        if needs_inference:
            # Record as pending; ``_flush_pending_inferred_lambdas``
            # turns any never-resolved entry into a clear error.
            self._pending_inferred_lambdas[id(e)] = e.pos
            # A provisional function type with unknown params keeps
            # downstream typing from crashing; the real type lands when
            # the lambda is re-checked with its expected type.
            return TyFun(tuple(TyUnknown for _ in e.params), TyUnknown)
        if expected is not None:
            # Fill the omitted annotations from the expected type so the
            # IR lowerer sees exactly what a hand-annotated lambda would
            # produce (byte-identical CIR / output across both backends).
            self._fill_lambda_annotations(e, expected)
            # No longer pending: it now has a context to infer from.
            self._pending_inferred_lambdas.pop(id(e), None)

        # Mark the lambda's scope as a function-root (so the
        # same-function block-shadow check stops its parent walk
        # here) AND as a lambda-root: the closure-shadow check reads
        # the latter to reject a ``let`` / ``var`` / pattern-bind in
        # this body that shadows a parameter or local of an ENCLOSING
        # scope, which the two backends compile differently (the
        # Python transpiler raises ``UnboundLocalError`` while the
        # Wasm lowerer keeps the outer capture and discloses it).
        self._push_scope(is_function_root=True, is_lambda_root=True)
        # Track this lambda's AST so the closure-shadow check can inspect
        # its body (for a module const / function shadow, whether the name
        # is referenced before the shadowing binding). Popped on exit.
        self._lambda_ast_stack.append(e)
        param_tys: list[Ty] = []
        param_names: set[str] = set()
        for p in e.params:
            if p.name == "self":
                self._err("'self' is not allowed in lambda parameters", p.pos)
                continue
            pty = self._resolve_type(p.type_expr) if p.type_expr else TyUnknown
            param_tys.append(pty)
            sym = Symbol(
                name=p.name, kind=SymbolKind.PARAM, pos=p.pos, ty=pty,
            )
            if self.scope.lookup_local(p.name) is not None:
                self._err(
                    f"duplicate parameter name {p.name!r} in lambda", p.pos,
                )
            self.scope.define(sym)
            param_names.add(p.name)

        # The lambda has no effect on the outer ``_consumed`` set
        # (consumption happens only when the lambda is called).
        prev_consumed = self._consumed
        self._consumed = set(prev_consumed)

        # Push the lambda's local-name frame so call-site
        # consumption checks know which names are local.
        self._lambda_local_names_stack.append(param_names)

        # A ``break`` / ``continue`` in the lambda body cannot cross the
        # lambda's function boundary, so the enclosing loop context is
        # NOT visible inside the body: reset the loop depth to 0 (a jump
        # there reports "break outside of a loop"), restore on exit.
        prev_loop_depth = self._loop_depth
        self._loop_depth = 0

        # Body: single expression (its type is the return type)
        # or an indented block (return statements are checked
        # against ``current_return_type``; without a return,
        # the block returns Unit).
        if isinstance(e.body, A.Block):
            if e.return_type is not None:
                decl_ret_block: Ty = self._resolve_type(e.return_type)
            else:
                decl_ret_block = TyUnit
            prev_ret = self.current_return_type
            self.current_return_type = decl_ret_block
            for stmt in e.body.stmts:
                self._check_stmt(stmt)
            self.current_return_type = prev_ret
            ret_ty: Ty = decl_ret_block
        else:
            # Push the lambda's declared return type (or None when
            # absent) so that any `?` inside the body checks against
            # *this* lambda's contract, not the enclosing function's.
            # Without this, `fun () -> Int => result_thing()?` would
            # inherit the outer function's return type and the `?`
            # check would erroneously accept it.
            decl_ret_expr: Optional[Ty] = (
                self._resolve_type(e.return_type)
                if e.return_type is not None else None
            )
            prev_ret = self.current_return_type
            self.current_return_type = decl_ret_expr
            body_ty = self._check_expr(e.body)
            self.current_return_type = prev_ret
            if decl_ret_expr is not None:
                if not self._assignable(decl_ret_expr, body_ty, e.body):
                    self._err(
                        f"lambda body has type {ty_str(body_ty)}, but "
                        f"declared return type is {ty_str(decl_ret_expr)}",
                        e.body.pos,
                    )
                ret_ty = decl_ret_expr
            else:
                ret_ty = body_ty

        # Roadmap S2 (IFC): record the join of the labels of the free
        # variables the body captures, so a call to this closure inherits
        # any captured @secret (computed before the scope is popped, while
        # the body's idents are still resolvable / labelled).
        self._lambda_capture_labels[id(e)] = self._lambda_capture_label(e)
        # The label of the value an INVOCATION of this closure produces:
        # its body's result label. Used by the invoke-sink-reaching
        # boundary check, where what reaches the callee's sink is the
        # closure's RESULT (``f()``), not the closure value itself. A body
        # that declassifies its captured secret returns PUBLIC here even
        # though the capture label above is SECRET.
        result_label = self._lambda_body_result_label(e)
        self._lambda_result_labels[id(e)] = result_label

        self._lambda_local_names_stack.pop()
        self._lambda_ast_stack.pop()
        self._loop_depth = prev_loop_depth
        self._consumed = prev_consumed
        self._pop_scope()

        # Roadmap S2 (higher-order IFC): stamp the closure's inferred
        # RETURN label onto its function type. It is the body-result label
        # -- which already sees THROUGH an in-body ``declassify`` (a
        # closure that declassifies its captured secret is public here) --
        # so a secret-capturing closure that returns the secret is
        # ``ret_label="secret"`` while a declassifying one is public. This
        # is the channel the store-site leak check reads.
        param_labels = tuple(L.PUBLIC for _ in param_tys)
        return TyFun(
            tuple(param_tys), ret_ty,
            param_labels=param_labels,
            ret_label=L.normalize(result_label),
        )

    # -----------------------------------------------------------
    # Lambda parameter / return-type inference
    # -----------------------------------------------------------

    def _lambda_has_omissions(self, e: A.LambdaExpr) -> bool:
        """True when the lambda left at least one PARAMETER type to be
        inferred. A missing return type alone is NOT an omission that
        needs context: it has always been inferred from the body
        (``fun (x: Int) => x + 1`` returns ``Int``). Only an untyped
        parameter requires an expected ``Fun(..)`` type to resolve."""
        return any(
            p.type_expr is None for p in e.params if p.name != "self"
        )

    def _fill_lambda_annotations(
        self, e: A.LambdaExpr, expected: TyFun,
    ) -> None:
        """Write the inferred parameter / return types back into the
        lambda AST from its expected ``Fun(..)`` type. An explicitly
        annotated parameter / return type is kept as-is (so a partial
        mix ``fun (x, y: Int) => ..`` infers only ``x``); only omitted
        annotations are filled. Inferring from an expected type whose
        own slot is still unknown leaves the annotation omitted, which
        surfaces as the clear "add a type annotation" error.

        Writing the types back into the AST is what makes an inferred
        lambda lower to byte-identical CIR (and identical Python / Wasm
        output) as the same lambda written out by hand: the IR lowerer
        reads ``p.type_expr`` / ``e.return_type`` directly."""
        non_self = [p for p in e.params if p.name != "self"]
        if len(expected.params) == len(non_self):
            for p, pty in zip(non_self, expected.params):
                if p.type_expr is None and self._ty_fully_resolved(pty):
                    p.type_expr = self._reify_ty(pty)
        if e.return_type is None and self._ty_fully_resolved(expected.ret):
            e.return_type = self._reify_ty(expected.ret)

    def _ty_fully_resolved(self, ty: Ty) -> bool:
        """True when ``ty`` is concrete enough to reify into an
        annotation: it is not ``TyUnknown`` and contains no unresolved
        ``TyVar`` (a result-only type variable like ``U`` in ``map``'s
        ``fun(T, U)`` is still open at the point a parameter type is
        filled, and inferring it as a literal type name would be
        wrong). The lambda's body fixes such variables, and the return
        type is then back-filled from the checked body type."""
        if ty is TyUnknown or isinstance(ty, TyVar):
            return False
        if isinstance(ty, TyName):
            return all(self._ty_fully_resolved(a) for a in ty.args)
        if isinstance(ty, TyTuple):
            return all(self._ty_fully_resolved(e) for e in ty.elements)
        if isinstance(ty, TyFun):
            return (
                all(self._ty_fully_resolved(p) for p in ty.params)
                and self._ty_fully_resolved(ty.ret)
            )
        return True

    def _reify_ty(self, ty: Ty) -> A.TypeExpr:
        """Convert a resolved analyzer ``Ty`` back into an AST
        ``TypeExpr``. The inverse of ``_resolve_type`` for the shapes
        a lambda's parameter / return type can take. The produced
        node carries a builtin position; it is consumed only by the IR
        lowerer (which reads names off it), never re-checked."""
        if ty is TyUnit:
            return A.UnitType(pos=_BUILTIN_POS)
        if isinstance(ty, TyTuple):
            return A.TupleType(
                pos=_BUILTIN_POS,
                elements=[self._reify_ty(e) for e in ty.elements],
            )
        if isinstance(ty, TyFun):
            return A.FunType(
                pos=_BUILTIN_POS,
                param_types=[self._reify_ty(p) for p in ty.params],
                return_type=self._reify_ty(ty.ret),
            )
        if isinstance(ty, TyVar):
            return A.TypeName(pos=_BUILTIN_POS, name=ty.name)
        if isinstance(ty, TyName):
            return A.TypeName(
                pos=_BUILTIN_POS, name=ty.name,
                args=[self._reify_ty(a) for a in ty.args],
                state=ty.state,
            )
        # TyUnknown or any unexpected shape: a bare ``?``-like name the
        # lowerer renders as "Unknown" (same as an omitted annotation).
        return A.TypeName(pos=_BUILTIN_POS, name="Unknown")

    def _recheck_lambda_with_expected(
        self, e: A.LambdaExpr, expected: TyFun,
    ) -> Ty:
        """Re-run lambda checking with a now-known expected type, so
        the omitted annotations are filled and the body is checked.
        Called by the higher-order-call dispatch once the argument
        slot's ``Fun(..)`` type is resolved. Returns the lambda's
        real type, which the caller writes into ``self.types`` and the
        argument-type list. A no-op for a lambda with no omissions."""
        if id(e) not in self._pending_inferred_lambdas:
            # Either fully annotated (already checked) or already
            # resolved: nothing to redo.
            return self.types.get(id(e), TyFun((), TyUnknown))
        self._expected_lambda_ty[id(e)] = expected
        ty = self._check_expr(e)
        del self._expected_lambda_ty[id(e)]
        # If the return type was still omitted after filling from the
        # expected type (a result-only type variable like ``U`` in
        # ``map``'s ``fun(T, U)``), back-fill it from the body type the
        # check just produced, so the IR lowerer emits the same return
        # type a hand-annotated lambda would. This keeps the inferred
        # and the spelled-out lambda byte-identical in both backends.
        if (
            e.return_type is None
            and isinstance(ty, TyFun)
            and ty.ret is not TyUnknown
        ):
            e.return_type = self._reify_ty(ty.ret)
        return ty

    def _flush_pending_inferred_lambdas(self) -> None:
        """Emit a clear error for every lambda whose parameter /
        return types were left to be inferred but that never received
        an expected type (no higher-order-function context fixed it)."""
        for lam_id, pos in self._pending_inferred_lambdas.items():
            self._err(
                "cannot infer the type of this lambda: it has no "
                "context to infer from (it is not passed to a "
                "higher-order function such as map / filter / fold). "
                "Add type annotations to its parameters and, if needed, "
                "a return type: fun (x: Int) -> Int => x + 1",
                pos,
            )
        self._pending_inferred_lambdas.clear()

    def _check_if_expr(self, e: A.IfExpr) -> Ty:
        """Type ``if cond then e1 else e2``. ``cond`` must be
        ``Bool``; the two branches must have compatible types.
        Returns the more informative of the two branch types."""
        cond_ty = self._check_expr(e.cond)
        if not compatible(TyBool, cond_ty):
            self._err(
                f"if-expression: condition must be Bool, got {ty_str(cond_ty)}",
                e.cond.pos,
            )
        # Roadmap S2.implicit: both arms are guarded by ``cond``, so the
        # pc-label rises by its label while checking them.
        saved_pc = self._pc_label
        self._pc_label = L.join(saved_pc, self._label_of(e.cond))
        # Roadmap S4: a @constant_time function cannot branch on a secret.
        self._ct_reject(
            self._label_of(e.cond), e.cond.pos, "an if-expression condition"
        )
        # Branch-scoped container-mutation taint, as for the if / match
        # statement forms: isolate each branch from the pre-expression
        # snapshot, then union both deltas back.
        before_ct = dict(self._container_taint_map())
        self._container_isolate(before_ct)
        then_ty = self._check_expr(e.then_expr)
        then_ct = self._container_taint
        self._container_isolate(before_ct)
        else_ty = self._check_expr(e.else_expr)
        else_ct = self._container_taint
        self._container_merge(before_ct, [then_ct, else_ct])
        self._pc_label = saved_pc
        if not compatible(then_ty, else_ty):
            self._err(
                f"if-expression: branches have incompatible types: "
                f"then is {ty_str(then_ty)}, else is {ty_str(else_ty)}",
                e.else_expr.pos,
            )
        if then_ty is TyUnknown:
            return else_ty
        return then_ty

    def _check_match_expr(self, s: A.MatchExpr) -> Ty:
        """Type a ``match`` expression. Each arm is checked in
        its own pattern-introduced scope; arm types must be
        compatible. Flow analysis snapshots ``_consumed`` before
        each arm and takes the conservative union after.
        Exhaustiveness is checked when the scrutinee has a sum
        type.

        Arms whose body diverges (ends in ``return``, ``break``,
        ``continue``) do not contribute to the match's result
        type: the divergent control flow leaves the match
        without producing a value, so unification against other
        arms is unsound. ``arm_types`` carries ``None`` for
        divergent arms and the actual type otherwise.
        """
        scrutinee_ty = self._check_expr(s.scrutinee)
        arm_types: list[Ty | None] = []
        before = set(self._consumed)
        branch_results: list[set[str]] = []
        # Roadmap S1: snapshot the live linear obligations before each arm
        # and merge the survivors after, exactly as ``_check_if`` does. A
        # value live at the match entry must be consumed on EVERY
        # non-diverging arm or on NONE: the post-match live set is the
        # UNION of each reachable arm's survivors, so consuming it in some
        # arms but not others leaves it outstanding here (the leak surfaces
        # at the merge, and a later consume after the match is rejected as
        # use-after-consume on the arms that already consumed it). Diverging
        # arms are excluded -- their path does not reach the merge.
        before_live = dict(self._live_linear)
        branch_live: list[dict] = []
        # Connection C: per-FIELD discharge is INTERSECTION-merged across the
        # reachable arms (a field is discharged past the match only if moved
        # on every arm), the opposite lattice to the union-merged
        # ``_consumed``. Each arm starts from the pre-match snapshot.
        before_field_moved = set(self._linear_field_moved)
        branch_field_moved: list[set[str]] = []
        # A scrutinee that is a bare identifier holding a live linear value
        # is moved into the match; whether it is consumed is decided
        # per-arm, so it stays in ``before_live`` and each arm sees it.

        # Roadmap S2: the scrutinee's IFC label flows to every name a
        # pattern binds. ``match env.get(...) { Some(key) -> ... }``
        # makes ``key`` secret, so the headline read-secret-then-leak
        # case is caught after the match destructure.
        scrutinee_label = self._label_of(s.scrutinee)
        # Roadmap S4: a @constant_time function cannot match on a secret.
        self._ct_reject(scrutinee_label, s.scrutinee.pos, "a match scrutinee")
        # Roadmap S2.implicit: every arm is selected by the scrutinee's
        # value, so a secret scrutinee raises the pc-label inside the
        # arm bodies (and guards) -- a sink there leaks which arm ran.
        saved_pc = self._pc_label
        arm_pc = L.join(saved_pc, scrutinee_label)
        # Branch-scoped container-mutation taint: each arm starts from the
        # pre-match snapshot in isolation and its additions are unioned back
        # after the match, so a push in one arm is not seen by a
        # mutually-exclusive sibling arm's read but is seen after the match.
        # A guard cannot be a direct container mutation (the mutators return
        # Unit, not Bool), so isolating the whole arm loses no in-body push.
        before_ct = dict(self._container_taint_map())
        branch_ct: list[dict] = []
        for arm in s.arms:
            self._consumed = set(before)
            self._live_linear = dict(before_live)
            self._linear_field_moved = set(before_field_moved)
            self._push_scope()
            self._bind_pattern(arm.pattern, scrutinee_ty, mutable=False)
            self._label_pattern_binds(arm.pattern, scrutinee_label, scrutinee_ty)
            self._pc_label = arm_pc
            self._container_isolate(before_ct)
            if arm.guard is not None:
                gty = self._check_expr(arm.guard)
                if not compatible(TyBool, gty):
                    self._err(
                        f"match guard must be Bool, got {ty_str(gty)}",
                        arm.guard.pos,
                    )
            arm_diverges = False
            if isinstance(arm.body, A.Block):
                for stmt in arm.body.stmts:
                    self._check_stmt(stmt)
                if _block_diverges(arm.body):
                    arm_types.append(None)
                    arm_diverges = True
                elif (
                    arm.body.stmts
                    and isinstance(arm.body.stmts[-1], A.ExprStmt)
                ):
                    # Trailing bare expression: the block evaluates
                    # to its value (block-as-expression semantics,
                    # à la Rust). Previously the arm always typed as
                    # Unit; this lets a multi-statement arm body in
                    # ``let x = match ...`` actually carry the
                    # trailing expression's value out.
                    last = arm.body.stmts[-1]
                    arm_types.append(self.types.get(id(last.expr), TyUnknown))
                else:
                    arm_types.append(TyUnit)
            else:
                arm_types.append(self._check_expr(arm.body))
            self._pop_scope()
            # Divergent arms cannot reach the merge point, so their
            # ``_consumed`` set must not flow past the match. Same
            # principle the type-side unification uses: a divergent
            # arm contributes ``None`` to ``arm_types``; here it
            # simply does not contribute to ``branch_results``.
            if not arm_diverges:
                branch_results.append(self._consumed)
                branch_live.append(dict(self._live_linear))
                branch_field_moved.append(set(self._linear_field_moved))
                branch_ct.append(self._container_taint)

        # Restore the pc-label raised for the arm bodies (S2.implicit).
        self._pc_label = saved_pc
        # Union each reachable arm's container-mutation taint back (deferred).
        self._container_merge(before_ct, branch_ct)

        if branch_results:
            merged: set[str] = set()
            for r in branch_results:
                merged |= r
            self._consumed = merged
            # Union of surviving linear obligations across reachable arms:
            # a value still live after any arm is still outstanding.
            merged_live: dict = {}
            for live in branch_live:
                merged_live.update(live)
            self._live_linear = merged_live
            # Intersection of per-field moves across reachable arms.
            self._linear_field_moved = set.intersection(*branch_field_moved)
        else:
            # All arms diverge: the code after this match is
            # unreachable. Keep ``_consumed`` / ``_live_linear`` at the
            # pre-match state.
            self._consumed = before
            self._live_linear = before_live
            self._linear_field_moved = before_field_moved

        self._check_match_exhaustiveness(s, scrutinee_ty)

        # Pick the first concrete (non-None, non-TyUnknown) arm
        # type as the reference and check the other non-divergent
        # arms against it. Divergent arms (``None``) skip unification.
        ref_ty: Ty = TyUnknown
        for t in arm_types:
            if t is None:
                continue
            if not isinstance(t, type(TyUnknown)) and t != TyUnknown:
                ref_ty = t
                break
        # The reference arm may still carry FLEXIBLE inference
        # placeholders (an empty-list arm types as ``List<?lst_N>``);
        # refine them against the other arms so the match's result
        # type is as concrete as any arm can make it. Without this,
        # ``match m.get(k) { None -> [] ; Some(xs) -> xs }`` typed
        # ``List<?lst_N>`` and the Wasm backend treated later pushes
        # of String / pointer elements as scalar i64 (a validator
        # rejection at best, a silent miscompile at worst). Only
        # flexible ``?``-prefixed vars are substituted: a rigid
        # generic parameter (``T``) must not be narrowed to one
        # arm's concrete type.
        for t in arm_types:
            if t is None or t is ref_ty:
                continue
            mapping: dict[str, Ty] = {}
            if unify(ref_ty, t, mapping):
                flexible = {
                    name: bound for name, bound in mapping.items()
                    if name.startswith("?")
                }
                if flexible:
                    ref_ty = substitute(ref_ty, flexible)
        for i, t in enumerate(arm_types):
            if t is None:
                continue
            if not compatible(ref_ty, t):
                self._err(
                    f"match arm {i + 1} has type {ty_str(t)}, "
                    f"incompatible with previous arms ({ty_str(ref_ty)})",
                    s.arms[i].pos,
                )
        return ref_ty

    def _check_expr(self, e: A.Expr) -> Ty:
        ty = self._check_expr_inner(e)
        self.types[id(e)] = ty
        # Capability-container use-gate, framed on the RESOLVED TYPE and
        # independent of the surrounding syntax. A value whose type NAMES
        # a capability inside a list / set / map / tuple can never be
        # produced, stored, passed, or used: no legitimate program ever
        # has such a value, so flagging every sub-expression that resolves
        # to one closes -- at a single site -- the whole family of
        # read-out / smuggle shapes (a container literal built with a
        # capability element, a cap-container as a method receiver, a
        # for-loop iterable, a call argument, or the base of an index,
        # including a ``.values()`` result and any nesting depth, and a
        # higher-order ``map`` / ``fold`` / ``flat_map`` whose closure
        # would receive the capability). The check is by NAME (see
        # ``_cap_in_container``): authority CAPTURED inside a closure --
        # a ``Fun`` whose signature does not name the capability -- is a
        # separate, known accounting limitation and is not covered here.
        # The type is resolved first, so this fires as soon as inference
        # has fixed the element type; a container whose element type only
        # settles LATER is caught by the end-of-function deferred recheck
        # instead. Deduped per node so a re-checked node reports once.
        cap = self._cap_in_container(ty)
        if cap is not None and id(e) not in self._cap_container_reported:
            self._cap_container_reported.add(id(e))
            self._err(
                f"capability {cap.name!r} cannot be used here: this value "
                f"is a container of capabilities, and a capability may only "
                f"flow as a bare, top-level value (a direct function "
                f"parameter), never packed inside a list, set, map, or tuple",
                e.pos,
            )
        # Linear/typestate mirror of the cap use-gate: a value whose resolved
        # type packs a linear/typestate value inside a list / set / map / tuple
        # can never be produced, stored, passed, or read out soundly (a later
        # read hands out aliases to a value that must be consumed exactly once,
        # a double-free / leak). Flagging every sub-expression that resolves to
        # one closes the whole family of shapes at a single site: a container /
        # tuple literal built with a linear element, a producing higher-order
        # ``map`` / ``flat_map`` whose closure returns a linear value, a
        # container-typed binding / param / return on use, and any nesting. The
        # check is by NAME (see ``_container_carries_linear``): a linear value
        # captured inside a closure is barred separately by the capture-consume
        # check, not here. A container whose element type only settles LATER is
        # caught by the end-of-function deferred recheck instead.
        self._linear_container_use_gate(e, ty)
        # Finding 1: a linear/typestate value flowing through an if/match
        # EXPRESSION whose arm selects an existing place (a bare Ident or
        # Ident-rooted linear FieldAccess) aliases an obligation the move /
        # consume / return / receiver seams cannot see (they match only bare
        # Ident / FieldAccess nodes), so the wrapper opens a second obligation
        # on the same runtime value -- a double-free. Barring it at this single
        # resolved-type site closes the RHS, consume-arg, consume-self
        # receiver, return, become, and struct-literal-element forms at once,
        # while the fresh-factory conditional (arms are calls) stays legal.
        self._check_linear_conditional_alias(e, ty)
        # A value read OUT of an empty-origin container surfaces the bare
        # element variable (``xs[0]``, a matched ``Some(v)`` from
        # ``m.get(k)``, a ``for`` element of a set). Referencing the
        # container itself keeps the variable WRAPPED (``List<?lst>``), so
        # only a genuine extraction reaches here. Record it; the
        # end-of-function guard rejects it if the element type was never
        # determined anywhere in the body. Deferred (not inline) so a
        # legitimate read-before-populate stays accepted.
        resolved = self._resolve_ty(ty)
        if is_flexible(resolved) and resolved.name in self._empty_container_vars:
            self._deferred_elem_reads.setdefault(resolved.name, e.pos)
        # Roadmap S2.3: record the IFC label of this expression now
        # that its children (visited during _check_expr_inner) are
        # already labelled. Propagation only -- no flow is rejected
        # in this slice.
        self._label_expr(e)
        return ty

    def _check_expr_inner(self, e: A.Expr) -> Ty:
        if isinstance(e, A.IntLit):
            # Slice 26 residual / P3: a bare 2**63 is out of i64 range
            # (only ``-2**63`` = i64::MIN is legal). Allowed solely as
            # the immediate operand of unary ``-`` (which marks its
            # operand id in ``_neg_int_operand_ids`` before descending).
            if (
                e.value == _I64_MIN_MAGNITUDE
                and id(e) not in self._neg_int_operand_ids
            ):
                self._err(
                    f"integer literal {e.value} is out of range for Int "
                    f"(signed 64-bit; max is {_I64_MIN_MAGNITUDE - 1}). "
                    f"Only -{e.value} (i64::MIN) is representable.",
                    e.pos,
                )
            return TyInt
        if isinstance(e, A.FloatLit):
            return TyFloat
        if isinstance(e, A.StringLit):
            return TyString
        if isinstance(e, A.InterpolatedString):
            # Every expression part is typed; the value is rendered
            # into the string. Both backends only know how to render
            # a fixed set of types, so a part whose type is outside
            # that set is rejected here (in ``--check``) rather than
            # accepted by the Python backend (via dataclass ``repr``)
            # and rejected only by the Wasm backend. The literal text
            # parts are plain Python ``str`` instances.
            for part in e.parts:
                if isinstance(part, str):
                    continue
                pty = self._check_expr(part)
                if not self._is_formattable(pty):
                    self._err(
                        f"cannot interpolate a value of type "
                        f"{ty_str(pty)} in a string: it has no "
                        f"`to_string` method, so neither backend can "
                        f"render it. Use a `match` expression to format "
                        f"it explicitly, or define "
                        f"`fun to_string(self) -> String` for "
                        f"{ty_str(pty)}.",
                        part.pos,
                    )
            return TyString
        if isinstance(e, A.CharLit):
            return TyChar
        if isinstance(e, A.BoolLit):
            return TyBool
        if isinstance(e, A.UnitLit):
            return TyUnit
        if isinstance(e, A.Ident):
            return self._check_ident(e)
        if isinstance(e, A.BinOp):
            return self._check_binop(e)
        if isinstance(e, A.UnaryOp):
            return self._check_unary(e)
        if isinstance(e, A.Call):
            return self._check_call(e)
        if isinstance(e, A.MethodCall):
            return self._check_method_call(e)
        if isinstance(e, A.FieldAccess):
            return self._check_field_access(e)
        if isinstance(e, A.Index):
            recv_ty = self._check_expr(e.receiver)
            self._check_expr(e.index)
            # Roadmap S4: indexing with a secret leaks it via cache timing.
            self._check_ct_index(e)
            if (
                isinstance(recv_ty, TyName)
                and recv_ty.name == "List" and recv_ty.args
            ):
                return recv_ty.args[0]
            if isinstance(recv_ty, TyTuple) and isinstance(e.index, A.IntLit):
                # A constant tuple index has a statically-known element
                # type; surface it so downstream consumers get the right
                # type and so out-of-range / mismatch errors are caught.
                # Without this it diverged: Python raised IndexError at
                # runtime while the Wasm backend silently returned 0. The
                # arity and index are both statically known here, so an
                # out-of-range constant index is a compile-time error.
                idx = e.index.value
                if 0 <= idx < len(recv_ty.elements):
                    return recv_ty.elements[idx]
                self._err(
                    f"tuple index {idx} is out of range for a "
                    f"{len(recv_ty.elements)}-element tuple",
                    e.pos,
                )
                return TyUnknown
            # Beyond ``List<T>[i]`` (any index) and a constant-indexed tuple,
            # both handled above, the ``[]`` operator does not index a value.
            # ``xs[i]`` is documented for List only (docs/stdlib.md); String
            # access is ``char_at``, Map access is ``get``, and a tuple takes
            # a literal-constant index only. The Wasm backend already enforces
            # this ("only List indexing is supported"), but the analyzer's
            # fall-through returned a permissive ``TyUnknown``, so a
            # non-indexable receiver in a typed binding (``let n: Int =
            # "hi"[0]``) passed ``--check`` and then ran wrong on Python (a
            # String inhabiting an Int binding, printed silently) while Wasm
            # failed loud. Reject here so ``--check`` agrees with the backend.
            # Resolve first so an inference variable since bound to a real
            # type is judged on its real shape.
            resolved_recv = self._resolve_ty(recv_ty)
            if isinstance(resolved_recv, TyVar) and not is_flexible(resolved_recv):
                self._err(
                    f"cannot index into a value of generic type parameter "
                    f"{resolved_recv.name!r}; an unconstrained type "
                    f"parameter is not known to be indexable (a bound would "
                    f"be required, and bounds are not yet available)",
                    e.pos,
                )
                return TyUnknown
            # A genuine inference-unknown (an unresolved ``?`` placeholder or
            # ``TyUnknown``) stays permissive: it resolves elsewhere.
            if resolved_recv is TyUnknown or is_flexible(resolved_recv):
                return TyUnknown
            # A List reached only after resolution (the receiver was an
            # inference variable now bound to a List) is indexable.
            if isinstance(resolved_recv, TyName) and resolved_recv.name == "List":
                return resolved_recv.args[0] if resolved_recv.args else TyUnknown
            # A tuple: a literal-constant index yields the slot type; a
            # dynamic (non-literal) index is not a Capa surface construct,
            # matching the Wasm backend (``dynamic indexing into tuples isn't
            # a Capa surface construct``).
            if isinstance(resolved_recv, TyTuple):
                if isinstance(e.index, A.IntLit):
                    idx = e.index.value
                    if 0 <= idx < len(resolved_recv.elements):
                        return resolved_recv.elements[idx]
                    self._err(
                        f"tuple index {idx} is out of range for a "
                        f"{len(resolved_recv.elements)}-element tuple",
                        e.pos,
                    )
                    return TyUnknown
                self._err(
                    "a tuple can only be indexed by a literal constant "
                    "integer; dynamic tuple indexing is not supported "
                    "(destructure with `let (a, b) = ...` instead)",
                    e.pos,
                )
                return TyUnknown
            # Every other concrete receiver is not indexable.
            self._err(
                f"a value of type {ty_str(resolved_recv)} is not indexable; "
                f"only `List<T>` supports `[]` indexing (use `char_at` for a "
                f"String, `get` for a Map)",
                e.pos,
            )
            return TyUnknown
        if isinstance(e, A.Try):
            inner = self._check_expr(e.expr)
            # When the inner expression is a Result<T, E> or
            # Option<T>, the ? operator unwraps and yields T.
            if isinstance(inner, TyName) and inner.args:
                if inner.name in ("Result", "Option"):
                    unwrap_ty: Ty = inner.args[0]
                else:
                    self._err(
                        f"`?` is only valid on Result<T, E> or Option<T>; "
                        f"this expression has type {ty_str(inner)}",
                        e.pos,
                    )
                    return TyUnknown
            elif isinstance(inner, TyVar) and not is_flexible(inner):
                # A RIGID type parameter (a declared ``T``) is not known to
                # be Result or Option, so ``x?`` on a bare ``T`` is unsound:
                # it would inhabit the unwrapped binding with a value of an
                # unknown shape (``let n: Int = x?``) and defeat the type
                # check via the permissive ``TyUnknown`` below. Reject here,
                # symmetric with the member-access / index / call guards. A
                # FLEXIBLE ``?`` placeholder stays permissive (it may yet
                # resolve to a Result / Option through inference).
                self._err(
                    f"cannot use `?` on a value of generic type parameter "
                    f"{inner.name!r}; an unconstrained type parameter is not "
                    f"known to be Result or Option (a bound would be "
                    f"required, and bounds are not yet available)",
                    e.pos,
                )
                return TyUnknown
            elif isinstance(inner, (TyVar,)) or inner is TyUnknown:
                # TyUnknown / flexible ``?`` TyVar stay permissive: the
                # runtime helper handles whatever shape they take, and we do
                # not want to false-positive on generic code that produces a
                # Result through an as-yet-unresolved inference variable.
                unwrap_ty = TyUnknown
            elif isinstance(inner, TyName) and inner.name in ("Result", "Option"):
                # No args yet; payload type is unknown but the shape
                # is fine. Same permissive return as above.
                unwrap_ty = TyUnknown
            else:
                # Concrete non-Result / non-Option type: ``?`` makes no
                # sense and would raise at runtime as ``? applied to a
                # value that is not Result or Option``. Surface it now
                # with the actual type the user wrote so the fix is
                # obvious from the diagnostic.
                self._err(
                    f"`?` is only valid on Result<T, E> or Option<T>; "
                    f"this expression has type {ty_str(inner)}",
                    e.pos,
                )
                return TyUnknown
            # The enclosing function or lambda must also return
            # Result or Option, otherwise `?` would propagate an
            # Err / None_ out of a function declared to return a
            # different type -- a type violation that previously
            # surfaced as a silent wrong-shape return at runtime,
            # or as an uncaught _CapaTryEarlyReturn when the `?`
            # sat inside a lambda whose decorator was elided.
            ret = self.current_return_type
            ret_ok = (
                isinstance(ret, TyName)
                and ret.name in ("Result", "Option")
            )
            if not ret_ok:
                ret_desc = ty_str(ret) if ret is not None else "Unit"
                self._err(
                    f"`?` can only be used in a function or lambda that "
                    f"returns Result or Option; the enclosing function "
                    f"returns {ret_desc}",
                    e.pos,
                )
            return unwrap_ty
        if isinstance(e, A.Become):
            return self._check_become(e)
        if isinstance(e, A.StructLit):
            if e.state is not None:
                return self._check_typestate_new(e)
            return self._check_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._check_list_lit(e)
        if isinstance(e, A.TupleLit):
            # B-F1: a borrowed linear / typestate value must not escape
            # into a tuple element.
            for x in e.elements:
                self._linear_check_borrowed_escape(x, x.pos)
            elems = tuple(self._check_expr(x) for x in e.elements)
            return TyTuple(elems)
        if isinstance(e, A.MatchExpr):
            return self._check_match_expr(e)
        if isinstance(e, A.IfExpr):
            return self._check_if_expr(e)
        if isinstance(e, A.LambdaExpr):
            return self._check_lambda(e)
        if isinstance(e, A.RangeExpr):
            return self._check_range(e)
        self._err(f"unknown expression {type(e).__name__}", e.pos)
        return TyUnknown

    def _check_range(self, e: A.RangeExpr) -> Ty:
        """Range expressions ``a..b`` / ``a..=b`` evaluate to a
        ``Range<Int>``. Both endpoints must be ``Int``; Float
        ranges are deliberately excluded because precision
        around the endpoint is awkward. ``Range<T>`` is a
        distinct type from ``List<T>`` with a minimal query API
        (``length``, ``contains``, ``is_empty``, ``to_list``);
        the user calls ``.to_list()`` explicitly when they want
        the full ``List<T>`` method surface. ``for`` loops
        consume ``Range<T>`` directly without materialising.
        """
        start_ty = self._check_expr(e.start)
        end_ty = self._check_expr(e.end)
        op = "..=" if e.inclusive else ".."
        if not compatible(TyInt, start_ty):
            self._err(
                f"range '{op}' requires Int endpoints; "
                f"left side has type {ty_str(start_ty)}",
                e.start.pos,
            )
        if not compatible(TyInt, end_ty):
            self._err(
                f"range '{op}' requires Int endpoints; "
                f"right side has type {ty_str(end_ty)}",
                e.end.pos,
            )
        return TyName("Range", (TyInt,))

    def _hint_self_field(self, name: str) -> str:
        """When ``name`` looks up to nothing in scope but matches a
        field of ``self``'s struct type inside an ``impl`` method,
        return ``"; did you mean `self.<name>`?"``. Empty string
        otherwise. Capa requires explicit ``self.field`` access
        and the bare-name mistake is the single most common
        port-from-Python error in user-defined types."""
        from . import SymbolKind
        if self.self_type is None or not isinstance(self.self_type, TyName):
            return ""
        # The ``self`` parameter must be visible in scope; otherwise
        # the hint would be misleading (the method may have a
        # different first-parameter shape).
        if self.scope.lookup("self") is None:
            return ""
        target = self.global_scope.lookup(self.self_type.name)
        if target is None or target.kind != SymbolKind.TYPE_STRUCT:
            return ""
        if name in target.struct_fields:
            return f"; did you mean `self.{name}`?"
        return ""

    def _check_ident(self, e: A.Ident) -> Ty:
        from . import SymbolKind

        sym = self.scope.lookup(e.name)
        if sym is None:
            # ``self`` outside an impl method is almost always the
            # user trying to access fields like they would in
            # Python's method body or in a non-method context. Give
            # them the targeted message instead of the generic
            # Levenshtein guess (which tends to suggest 'Set' or
            # 'self_type'-shaped noise).
            if e.name == "self" and self.self_type is None:
                self._err(
                    "'self' is only valid inside an `impl` method; "
                    "free functions and the top level do not have "
                    "a receiver",
                    e.pos,
                )
                return TyUnknown
            # Inside an ``impl`` method, a bare identifier that
            # matches a field of ``self`` is almost certainly a
            # forgotten ``self.``. Surface the targeted hint
            # before falling back to the generic typo guess.
            self_hint = self._hint_self_field(e.name)
            if self_hint:
                self._err(
                    f"undefined name {e.name!r}{self_hint}",
                    e.pos,
                )
                return TyUnknown
            hint = self._hint_did_you_mean(e.name, self._names_in_scope())
            self._err(f"undefined name {e.name!r}{hint}", e.pos)
            return TyUnknown
        self.bindings[id(e)] = sym
        # Bare reference to an underscore-prefixed internal builtin
        # (e.g. ``let f = _capa_chr``): rejected like the direct
        # call in ``_check_call``, otherwise the alias would smuggle
        # the internal builtin into user code.
        if self._is_internal_builtin(sym):
            self._err(
                f"{e.name!r} is an internal compiler builtin and "
                f"cannot be referenced from user code; it is not "
                f"part of the Capa language surface",
                e.pos,
            )
            return TyUnknown
        if e.name in self._consumed:
            kind = (
                "linear value" if e.name in self._linear_names
                else "capability"
            )
            self._err(
                f"{kind} {e.name!r} was consumed earlier and cannot "
                f"be used again",
                e.pos,
            )
        if sym.kind == SymbolKind.MODULE:
            return TyUnknown   # module accesses not typed in v1
        if sym.kind == SymbolKind.CAPABILITY:
            return TyName(sym.name)
        if sym.kind == SymbolKind.VARIANT:
            # Constructor without payload: the type is the
            # owning sum type. For generic types whose
            # parameters we cannot infer from context, use
            # TyUnknown (built-ins) or a FRESH flexible TyVar
            # (user types) so later unification can refine. The
            # var must be a fresh ``?`` placeholder, NOT the
            # declared rigid parameter name: ``Nothing`` of
            # ``Opt<T>`` has a still-unknown element type, so
            # ``let ni: Opt<Int> = Nothing`` has to unify it to
            # Int. A rigid ``T`` here would be incompatible with
            # every concrete instantiation.
            if not sym.variant_payload_tys and sym.variant_owner is not None:
                owner = sym.variant_owner
                if owner.pos is _BUILTIN_POS:
                    args = tuple(TyUnknown for _ in owner.type_params)
                else:
                    args = tuple(
                        self._fresh_ty_var(p) for p in owner.type_params
                    )
                return TyName(owner.name, args)
            return TyUnknown
        if sym.ty is not None:
            return self._resolve_ty(sym.ty)
        return TyUnknown

    def _check_binop(self, e: A.BinOp) -> Ty:
        lt = self._check_expr(e.left)
        rt = self._check_expr(e.right)
        op = e.op
        self._check_ct_arith(e)
        # Roadmap S4: in a @constant_time function, a short-circuiting
        # String / List comparison on a @secret operand is a timing oracle.
        self._check_ct_compare(e)
        if op in ("+", "-", "*", "/", "%"):
            if compatible(TyInt, lt) and compatible(TyInt, rt):
                return TyInt
            if compatible(TyFloat, lt) and compatible(TyFloat, rt):
                return TyFloat
            if op == "+" and compatible(TyString, lt) and compatible(TyString, rt):
                return TyString
            self._err(
                f"operator {op!r}: incompatible operand types "
                f"{ty_str(lt)} and {ty_str(rt)}",
                e.pos,
            )
            return TyUnknown
        if op in ("&", "|", "^", "<<", ">>"):
            # Bitwise operators are Int-only. We deliberately do NOT
            # accept Float (the bit pattern of an IEEE-754 double is
            # not what users mean when they write ``f & g``) or Bool
            # (Capa's Bool is logical, not a 1-bit integer; use
            # ``and`` / ``or`` for boolean combinators). The shift
            # operators inherit the same restriction: shift amounts
            # are Int. Negative-RHS behaviour for shifts diverges
            # between backends (Python raises; Wasm masks the count
            # to 6 bits), but that's a runtime corner of correctly
            # typed code, not a type error.
            if compatible(TyInt, lt) and compatible(TyInt, rt):
                return TyInt
            self._err(
                f"operator {op!r}: bitwise operators require Int operands; "
                f"got {ty_str(lt)} and {ty_str(rt)}",
                e.pos,
            )
            return TyUnknown
        if op in ("==", "!="):
            if not compatible(lt, rt) and not compatible(rt, lt):
                self._err(
                    f"operator {op!r}: cannot compare {ty_str(lt)} with "
                    f"{ty_str(rt)}",
                    e.pos,
                )
            return TyBool
        if op in ("<", "<=", ">", ">="):
            if not (
                (compatible(TyInt, lt) and compatible(TyInt, rt))
                or (compatible(TyFloat, lt) and compatible(TyFloat, rt))
                or (compatible(TyString, lt) and compatible(TyString, rt))
            ):
                self._err(
                    f"operator {op!r}: incompatible operand types "
                    f"{ty_str(lt)} and {ty_str(rt)}",
                    e.pos,
                )
            return TyBool
        if op in ("and", "or"):
            if not compatible(TyBool, lt):
                self._err(
                    f"operator {op!r}: left operand must be Bool, "
                    f"got {ty_str(lt)}",
                    e.left.pos,
                )
            if not compatible(TyBool, rt):
                self._err(
                    f"operator {op!r}: right operand must be Bool, "
                    f"got {ty_str(rt)}",
                    e.right.pos,
                )
            return TyBool
        return TyUnknown

    def _check_unary(self, e: A.UnaryOp) -> Ty:
        # Mark a directly-negated integer literal so the IntLit check
        # permits 2**63 (i64::MIN's magnitude) here and nowhere else.
        if e.op == "-" and isinstance(e.operand, A.IntLit):
            self._neg_int_operand_ids.add(id(e.operand))
        ot = self._check_expr(e.operand)
        if e.op == "-":
            if compatible(TyInt, ot):
                return TyInt
            if compatible(TyFloat, ot):
                return TyFloat
            self._err(
                f"unary '-': operand must be numeric, got {ty_str(ot)}",
                e.pos,
            )
            return TyUnknown
        if e.op == "not":
            if not compatible(TyBool, ot):
                self._err(
                    f"'not': operand must be Bool, got {ty_str(ot)}",
                    e.pos,
                )
            return TyBool
        return TyUnknown

    def _check_field_access(self, e: A.FieldAccess) -> Ty:
        from . import SymbolKind

        rty = self._check_expr(e.receiver)
        # Use-after-consume on a FieldAccess path: ``consume_one(box.cap)``
        # then ``box.cap.use()``. Audit 2026-05-25 H1 (hole D).
        # ``_mark_consumed_args`` canonicalises both Ident and
        # FieldAccess sources into dotted paths, so the same key
        # we recorded at the consume site is compared here.
        path = self._path_of(e)
        if path is not None and path in self._consumed:
            kind = (
                "linear value" if path in self._linear_names
                else "capability"
            )
            self._err(
                f"{kind} {path!r} was consumed earlier and cannot "
                f"be used again",
                e.pos,
            )
        if isinstance(rty, TyName):
            sym = self.global_scope.lookup(rty.name)
            # Audit 2026-06-17 H1: field access through a value whose
            # *static* type is an abstract capability (or trait) is
            # rejected. The runtime value is the concrete implementor,
            # so ``m.net`` on ``m: SendEmail`` would otherwise reach
            # the implementor's private built-in cap and exercise
            # Fs/Net under a signature that only declares the user-cap.
            # The implementor's fields are private to its ``impl``.
            # Three cases stay distinct:
            #   (i)  receiver of a concrete STRUCT type that implements
            #        a cap -> field access stays allowed (the legitimate
            #        reachable-via-struct model; falls into the
            #        TYPE_STRUCT branch below);
            #   (ii) receiver of an abstract CAPABILITY / TRAIT type
            #        (the cap name used as a parameter type) -> rejected
            #        here;
            #   (iii) ``self`` inside an ``impl`` -> ``self``'s type is
            #        the concrete struct (TYPE_STRUCT), so it never
            #        reaches this branch.
            if sym is not None and sym.kind in (
                SymbolKind.CAPABILITY, SymbolKind.TRAIT,
            ):
                kind = (
                    "capability" if sym.kind == SymbolKind.CAPABILITY
                    else "trait"
                )
                self._err(
                    f"cannot access field {e.field_name!r} through a "
                    f"value of {kind} type {rty.name!r}; the "
                    f"implementor's fields are private to its `impl` "
                    f"and a holder of the abstract {kind} only sees "
                    f"the {kind}'s methods",
                    e.pos,
                )
                return TyUnknown
            if sym is not None and sym.kind == SymbolKind.TYPE_STRUCT:
                fty = sym.struct_fields.get(e.field_name)
                if fty is None:
                    hint = self._hint_did_you_mean(
                        e.field_name, list(sym.struct_fields.keys()),
                    )
                    self._err(
                        f"struct {rty.name!r} has no field "
                        f"{e.field_name!r}{hint}",
                        e.pos,
                    )
                    return TyUnknown
                if sym.type_params and rty.args:
                    mapping = dict(zip(sym.type_params, rty.args))
                    return substitute(fty, mapping)
                return fty
        # Field access on a value whose static type is an UNBOUNDED
        # generic type parameter (a rigid ``TyVar`` such as ``T``) has no
        # sound result type: without a bound, a bare type parameter
        # exposes no fields. Falling through to ``TyUnknown`` here would
        # let an ill-typed body pass ``--check`` (``TyUnknown`` unifies
        # with anything) and then run wrong on Python / emit an invalid
        # module on Wasm. Reject at the source. A FLEXIBLE ``?`` inference
        # variable is excluded: it is a genuine not-yet-resolved
        # placeholder, not a declared parameter. Accessing the struct's
        # OWN field whose declared type is ``T`` is a different thing and
        # is handled by the TYPE_STRUCT branch above.
        resolved_rty = self._resolve_ty(rty)
        if isinstance(resolved_rty, TyVar) and not is_flexible(resolved_rty):
            self._err(
                f"cannot access field {e.field_name!r} on a value of "
                f"generic type parameter {resolved_rty.name!r}; an "
                f"unconstrained type parameter exposes no members (a bound "
                f"would be required, and bounds are not yet available)",
                e.pos,
            )
            return TyUnknown
        # FAIL CLOSED. Only structs have fields, and a struct receiver
        # resolves above (its field type or a ``has no field`` error). Any
        # other CONCRETE receiver that reached this fall-through (a tuple, a
        # function, unit, a user sum, a typestate, a built-in, ...) has no
        # such field: reject it, whatever the type kind, rather than return a
        # permissive ``TyUnknown`` that lets an ill-typed ``t.field`` /
        # ``sumval.field`` inhabit a typed binding. A GENUINE inference-
        # unknown (``TyUnknown`` / flexible ``?``) stays permissive.
        if not self._is_inference_unknown(resolved_rty):
            self._err(
                f"cannot access field {e.field_name!r} on a value of type "
                f"{ty_str(resolved_rty)}; only structs have fields",
                e.pos,
            )
        return TyUnknown

    def _check_typestate_new(self, e: A.StructLit) -> Ty:
        """Roadmap S3.2/S3.4: ``Name[State] { fields }`` constructs a
        fresh typestate value in ``State`` carrying its declared fields.
        The value is linear (the constructing ``let`` registers the
        must-consume obligation). Fields are validated against the
        typestate's declaration exactly like a struct literal."""
        name = e.type_name
        states = self._typestates.get(name)
        if states is None:
            self._err(
                f"{name!r} is not a typestate; only a typestate can be "
                f"constructed with a state index ``{name}[State] {{ ... }}``",
                e.pos,
            )
            for _, v in e.fields:
                self._check_expr(v)
            return TyUnknown
        if e.state not in states:
            self._err(
                f"typestate {name!r} has no state {e.state!r} "
                f"(states: {', '.join(states)})",
                e.pos,
            )
        # Validate the fields against the typestate's declaration
        # (registered in ``struct_fields``), mirroring struct-literal
        # checking. Typestates take no generic parameters in v1.
        sym = self.global_scope.lookup(name)
        fields = sym.struct_fields if sym is not None else {}
        seen: set[str] = set()
        for fname, fexpr in e.fields:
            if fname in seen:
                self._err(f"duplicate field {fname!r} in {name!r}", e.pos)
            seen.add(fname)
            # A borrowed linear/typestate value must not escape into a
            # typestate field, and a bare OWNED one packed here is MOVED out
            # of its source -- the same aggregate-pack discipline a struct
            # literal applies (a typestate is a state-indexed struct).
            self._linear_check_borrowed_escape(fexpr, fexpr.pos)
            actual = self._check_expr(fexpr)
            self._move_linear_operand(fexpr)
            if fname not in fields:
                hint = self._hint_did_you_mean(fname, list(fields.keys()))
                self._err(
                    f"typestate {name!r} has no field {fname!r}{hint}",
                    fexpr.pos,
                )
                continue
            if not self._assignable(fields[fname], actual, fexpr):
                self._err(
                    f"typestate {name!r}: field {fname!r} expects "
                    f"{ty_str(fields[fname])}, got {ty_str(actual)}",
                    fexpr.pos,
                )
        missing = set(fields.keys()) - seen
        if missing:
            self._err(
                f"typestate {name!r}: missing fields "
                f"{', '.join(sorted(missing))}",
                e.pos,
            )
        return TyName(name, state=e.state)

    def _check_become(self, e: A.Become) -> Ty:
        """Roadmap S3.2: ``become(value, State)`` transitions a
        typestate value. It consumes ``value`` in its current state
        (the must-consume obligation moves to the result) and yields the
        same value re-typed to ``State``, so the protocol advances
        without dropping or duplicating the value."""
        val_ty = self._check_expr(e.value)
        if not (isinstance(val_ty, TyName) and val_ty.name in self._typestates):
            self._err(
                f"become expects a typestate value, got {ty_str(val_ty)}",
                e.value.pos,
            )
            return TyUnknown
        states = self._typestates[val_ty.name]
        if e.state not in states:
            self._err(
                f"typestate {val_ty.name!r} has no state {e.state!r} "
                f"(states: {', '.join(states)})",
                e.pos,
            )
            return TyName(val_ty.name, state=val_ty.state)
        # The old-state value is consumed: its linear obligation moves
        # to the freshly-typed result (which the surrounding binding
        # re-registers as live).
        if isinstance(e.value, (A.Call, A.MethodCall)):
            # E3: ``become(id(c), Settled)`` transitions a value whose result
            # LAUNDERS the argument's obligation; move the aliased argument out
            # through the ONE move seam so the transition is accounted once.
            self._move_linear_operand(e.value)
        elif isinstance(e.value, A.Ident):
            self._linear_discharge(e.value.name, e.value.pos)
        elif isinstance(e.value, A.FieldAccess):
            # ``become(s.claim, Settled)`` transitions a linear FIELD in
            # place; move it out of its carrier so it is accounted for.
            place = self._linear_place(e.value)
            if place is not None:
                self._linear_move_field(place, e.value.pos)
        return TyName(val_ty.name, state=e.state)

    def _check_struct_lit(self, e: A.StructLit) -> Ty:
        from . import SymbolKind

        sym = self.global_scope.lookup(e.type_name)
        if sym is None:
            hint = self._hint_did_you_mean(e.type_name, self._type_names())
            self._err(f"undefined type {e.type_name!r}{hint}", e.pos)
            for _, v in e.fields:
                self._check_expr(v)
            return TyUnknown
        if sym.kind != SymbolKind.TYPE_STRUCT:
            self._err(f"{e.type_name!r} is not a struct type", e.pos)
            for _, v in e.fields:
                self._check_expr(v)
            return TyUnknown
        mapping: dict[str, Ty] = {}
        seen: set[str] = set()
        # Phase 1: evaluate field values and try to infer.
        for fname, fexpr in e.fields:
            if fname in seen:
                self._err(
                    f"duplicate field {fname!r} in struct literal", e.pos,
                )
            seen.add(fname)
            # B-F1: a borrowed linear / typestate value must not escape
            # into a struct field.
            self._linear_check_borrowed_escape(fexpr, fexpr.pos)
            if fname not in sym.struct_fields:
                hint = self._hint_did_you_mean(
                    fname, list(sym.struct_fields.keys()),
                )
                self._err(
                    f"struct {e.type_name!r} has no field "
                    f"{fname!r}{hint}",
                    fexpr.pos,
                )
                self._check_expr(fexpr)
                continue
            expected = sym.struct_fields[fname]
            actual = self._check_expr(fexpr)
            unify(expected, actual, mapping)
            # Roadmap S1 (carrier): a bare OWNED linear/typestate value (or
            # a linear field) packed into this field is MOVED out of its
            # source, so a later re-use double-frees. The borrowed-escape
            # reject above handles a borrowed operand; this moves an owned
            # one, through the same seam the consume-arg path uses.
            self._move_linear_operand(fexpr)
        # Phase 2: check compatibility after substitution.
        for fname, fexpr in e.fields:
            if fname not in sym.struct_fields:
                continue
            expected = sym.struct_fields[fname]
            substituted = substitute(expected, mapping)
            actual_ty = self.types.get(id(fexpr), TyUnknown)
            if not self._assignable(substituted, actual_ty, fexpr):
                self._err(
                    f"struct {e.type_name!r}: field {fname!r} expects "
                    f"{ty_str(substituted)}, got {ty_str(actual_ty)}",
                    fexpr.pos,
                )
            # Higher-order IFC: storing a secret-returning closure into a
            # public-returning struct field launders the secret through
            # the field's declared (public) type; a later read-and-invoke
            # at a public sink would leak it. Flag it at the store.
            self._check_closure_ret_flow(
                substituted, actual_ty, fexpr.pos,
                f"stored in field {fname!r}",
            )
            # Audit hole D (2026-06): the function-call path rejects a
            # capability substituted into a generic type parameter
            # (``_reject_cap_leak_via_substitution``); the same must hold
            # for a struct literal, else ``Box { value: stdio }`` smuggles
            # a cap behind a ``T`` so a function taking ``Box<Stdio>``
            # exercises Stdio while its manifest reports no capability.
            self._reject_cap_leak_via_substitution(
                expected, substituted, e.type_name, fexpr.pos,
                slot=f"field {fname!r}",
            )
            # The container-of-linear invariant mirrors that: a struct field
            # whose generic slot is instantiated to a container-of-linear
            # (``Box<List<T>>`` at ``T = Conn``) smuggles a single-owner value
            # into storage behind a ``T``, so reject it at the same site.
            self._reject_linear_leak_via_substitution(
                expected, substituted, e.type_name, fexpr.pos,
                slot=f"field {fname!r}",
            )
        missing = set(sym.struct_fields.keys()) - seen
        if missing:
            self._err(
                f"struct {e.type_name!r}: missing fields "
                f"{', '.join(sorted(missing))}",
                e.pos,
            )
        field_pairs = [
            (sym.struct_fields[fname], self.types.get(id(fexpr), TyUnknown))
            for fname, fexpr in e.fields
            if fname in sym.struct_fields
        ]
        type_args = self._constructor_result_args(
            tuple(sym.type_params), mapping, field_pairs,
        )
        return TyName(sym.name, type_args)

    def _check_list_lit(
        self, e: A.ListLit, expected_elem: Optional[Ty] = None,
    ) -> Ty:
        # B-F1: a borrowed linear / typestate value must not escape into a
        # list element.
        for el in e.elements:
            self._linear_check_borrowed_escape(el, el.pos)
        if not e.elements:
            # Fresh TyVar: the element type will be refined by
            # later uses (push, indexing, etc.). An annotated empty
            # list (``let xs: List<Shape> = []``) keeps the declared
            # element type so the later ``_assignable`` check passes.
            if expected_elem is not None:
                return TyName("List", (expected_elem,))
            elem = self._fresh_ty_var("lst")
            # Created empty and unannotated: remember the element variable
            # so a handoff can pin it and an end-of-function guard can
            # reject a value read out of a never-determined list.
            self._empty_container_vars.add(elem.name)
            return TyName("List", (elem,))
        # With an annotated element type (``let xs: List<Shape> = [...]``)
        # every element is checked against THAT type (trait / capability
        # membership via ``_assignable``) rather than against the first
        # element. This lets a heterogeneous list of distinct implementors
        # of a common trait honour its annotation -- ``[Sq{...}, Rec{...}]``
        # typed ``List<Shape>`` -- instead of inferring ``List<Sq>`` from
        # the first element and then rejecting the rest. Without an
        # annotation the element type is still inferred from the first
        # element (unchanged behaviour), so an unannotated heterogeneous
        # list is still an error.
        if expected_elem is not None:
            actual_elems = []
            for el in e.elements:
                ety = self._check_expr(el)
                actual_elems.append(ety)
                if not self._assignable(expected_elem, ety, el):
                    self._err(
                        f"list literal: element has type {ty_str(ety)}, "
                        f"expected {ty_str(expected_elem)}",
                        el.pos,
                    )
            # Higher-order IFC: keep the declared element STRUCTURE (so a
            # heterogeneous annotated list still type-checks) but preserve
            # the actual elements' function return labels, so a secret-
            # returning closure in a public-declared list is not laundered
            # -- the store-site check then sees List<Fun -> secret>.
            elem = self._raise_fun_labels(expected_elem, actual_elems)
            return TyName("List", (elem,))
        first_ty = self._check_expr(e.elements[0])
        for el in e.elements[1:]:
            ety = self._check_expr(el)
            if not compatible(first_ty, ety):
                self._err(
                    f"list literal: element has type {ty_str(ety)}, "
                    f"expected {ty_str(first_ty)}",
                    el.pos,
                )
        return TyName("List", (first_ty,))



def _block_diverges(block: "A.Block") -> bool:
    """True if the block's last statement is divergent (``return``,
    ``break``, or ``continue``). Used by the match-arm checker to
    treat divergent block-bodied arms as not contributing to the
    match's result type.
    """
    if not block.stmts:
        return False
    last = block.stmts[-1]
    return isinstance(last, (A.ReturnStmt, A.BreakStmt, A.ContinueStmt))

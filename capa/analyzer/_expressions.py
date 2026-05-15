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

from .. import capa_ast as A
from ..builtins import BUILTIN_POS as _BUILTIN_POS
from ..typesys import (
    Ty, TyBool, TyChar, TyFloat, TyFun, TyInt, TyName, TyString,
    TyTuple, TyUnit, TyUnknown, TyVar,
    compatible, substitute, ty_str, unify,
)


class _ExpressionsMixin:
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

        self._push_scope()
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
            body_ty = self._check_expr(e.body)
            if e.return_type is not None:
                decl_ret_expr = self._resolve_type(e.return_type)
                if not compatible(decl_ret_expr, body_ty):
                    self._err(
                        f"lambda body has type {ty_str(body_ty)}, but "
                        f"declared return type is {ty_str(decl_ret_expr)}",
                        e.body.pos,
                    )
                ret_ty = decl_ret_expr
            else:
                ret_ty = body_ty

        self._lambda_local_names_stack.pop()
        self._consumed = prev_consumed
        self._pop_scope()

        return TyFun(tuple(param_tys), ret_ty)

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
        then_ty = self._check_expr(e.then_expr)
        else_ty = self._check_expr(e.else_expr)
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

        for arm in s.arms:
            self._consumed = set(before)
            self._push_scope()
            self._bind_pattern(arm.pattern, scrutinee_ty, mutable=False)
            if arm.guard is not None:
                gty = self._check_expr(arm.guard)
                if not compatible(TyBool, gty):
                    self._err(
                        f"match guard must be Bool, got {ty_str(gty)}",
                        arm.guard.pos,
                    )
            if isinstance(arm.body, A.Block):
                for stmt in arm.body.stmts:
                    self._check_stmt(stmt)
                if _block_diverges(arm.body):
                    arm_types.append(None)
                else:
                    arm_types.append(TyUnit)
            else:
                arm_types.append(self._check_expr(arm.body))
            self._pop_scope()
            branch_results.append(self._consumed)

        merged: set[str] = set()
        for r in branch_results:
            merged |= r
        self._consumed = merged

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
        return ty

    def _check_expr_inner(self, e: A.Expr) -> Ty:
        if isinstance(e, A.IntLit):
            return TyInt
        if isinstance(e, A.FloatLit):
            return TyFloat
        if isinstance(e, A.StringLit):
            return TyString
        if isinstance(e, A.InterpolatedString):
            # Every expression part is typed; the runtime
            # converts each value via str(). The literal text
            # parts are plain Python ``str`` instances.
            for part in e.parts:
                if not isinstance(part, str):
                    self._check_expr(part)
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
            if (
                isinstance(recv_ty, TyName)
                and recv_ty.name == "List" and recv_ty.args
            ):
                return recv_ty.args[0]
            return TyUnknown
        if isinstance(e, A.Try):
            inner = self._check_expr(e.expr)
            # When the inner expression is a Result<T, E> or
            # Option<T>, the ? operator unwraps and yields T;
            # otherwise we don't know the inner type yet, so we
            # fall back to TyUnknown. Tracking this is what makes
            # type-aware dispatch (e.g. Map.get) work on the
            # result of a `?` chain.
            if isinstance(inner, TyName) and inner.args:
                if inner.name in ("Result", "Option"):
                    return inner.args[0]
            return TyUnknown
        if isinstance(e, A.StructLit):
            return self._check_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._check_list_lit(e)
        if isinstance(e, A.TupleLit):
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

    def _check_ident(self, e: A.Ident) -> Ty:
        from . import SymbolKind

        sym = self.scope.lookup(e.name)
        if sym is None:
            hint = self._hint_did_you_mean(e.name, self._names_in_scope())
            self._err(f"undefined name {e.name!r}{hint}", e.pos)
            return TyUnknown
        self.bindings[id(e)] = sym
        if e.name in self._consumed:
            self._err(
                f"capability {e.name!r} was consumed earlier and cannot "
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
            # TyUnknown (built-ins) or TyVar (user types) so
            # later unification can refine.
            if sym.variant_payload_ty is None and sym.variant_owner is not None:
                owner = sym.variant_owner
                if owner.pos is _BUILTIN_POS:
                    args = tuple(TyUnknown for _ in owner.type_params)
                else:
                    args = tuple(TyVar(p) for p in owner.type_params)
                return TyName(owner.name, args)
            return TyUnknown
        if sym.ty is not None:
            return self._resolve_ty(sym.ty)
        return TyUnknown

    def _check_binop(self, e: A.BinOp) -> Ty:
        lt = self._check_expr(e.left)
        rt = self._check_expr(e.right)
        op = e.op
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
        if isinstance(rty, TyName):
            sym = self.global_scope.lookup(rty.name)
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
        return TyUnknown

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
        # Phase 2: check compatibility after substitution.
        for fname, fexpr in e.fields:
            if fname not in sym.struct_fields:
                continue
            expected = sym.struct_fields[fname]
            substituted = substitute(expected, mapping)
            actual_ty = self.types.get(id(fexpr), TyUnknown)
            if not compatible(substituted, actual_ty):
                self._err(
                    f"struct {e.type_name!r}: field {fname!r} expects "
                    f"{ty_str(substituted)}, got {ty_str(actual_ty)}",
                    fexpr.pos,
                )
        missing = set(sym.struct_fields.keys()) - seen
        if missing:
            self._err(
                f"struct {e.type_name!r}: missing fields "
                f"{', '.join(sorted(missing))}",
                e.pos,
            )
        type_args = tuple(
            mapping.get(p, TyUnknown) for p in sym.type_params
        )
        return TyName(sym.name, type_args)

    def _check_list_lit(self, e: A.ListLit) -> Ty:
        if not e.elements:
            # Fresh TyVar: the element type will be refined by
            # later uses (push, indexing, etc.).
            return TyName("List", (self._fresh_ty_var("lst"),))
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

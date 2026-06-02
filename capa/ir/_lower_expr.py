"""Expression-level AST -> CIR lowering.

Every AST expression node has a corresponding ``_lower_*``
method here. Each returns a ``Value`` referencing either a
literal or a fresh local bound to an intermediate; the
parent statement consumes the value or threads it forward.

The ANF flavour means intermediates accumulate: a binop
``a + b * c`` produces two locals (the inner ``b * c`` and the
outer ``+``). The Python emitter folds them back into nested
expressions where readable.

Audit P1 refactor: split per AST family.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._capa_types import BUILTIN_CAPS
from ._lower_helpers import _type_name, _ty_to_str, UnsupportedInIR
from ._nodes import (
    AssignConst, BinOp, Call, FieldAccess, FormatStr, If, Index, MakeLambda,
    MakeList, MakeMap, MakeRange, MakeSet, MakeStruct, MakeTuple, Match,
    MatchArm, MethodCall, Param, Reassign, Return,
    TryUnwrap, UnaryOp, Value, fresh_local,
)


class _LowerExprMixin:
    def _lower_expr(self, e: A.Expr) -> Value:
        if isinstance(e, A.IntLit):
            return Value(kind="lit_int", literal=e.value, ty="Int")
        if isinstance(e, A.FloatLit):
            return Value(kind="lit_float", literal=e.value, ty="Float")
        if isinstance(e, A.StringLit):
            return Value(kind="lit_str", literal=e.value, ty="String")
        if isinstance(e, A.CharLit):
            # Capa ``Char`` is a single-codepoint String at the
            # Python layer; the legacy transpiler emits a one-char
            # string literal for it. Map to the same lit_str kind so
            # the emitter's repr-based rendering writes it correctly.
            return Value(kind="lit_str", literal=e.value, ty="Char")
        if isinstance(e, A.BoolLit):
            return Value(kind="lit_bool", literal=e.value, ty="Bool")
        if isinstance(e, A.UnitLit):
            return Value(kind="lit_unit", literal=None, ty="Unit")
        if isinstance(e, A.Ident):
            return self._lower_ident(e)
        if isinstance(e, A.BinOp):
            return self._lower_binop(e)
        if isinstance(e, A.UnaryOp):
            return self._lower_unary(e)
        if isinstance(e, A.Call):
            return self._lower_call(e)
        if isinstance(e, A.MethodCall):
            return self._lower_method_call(e)
        if isinstance(e, A.FieldAccess):
            return self._lower_field_access(e)
        if isinstance(e, A.Index):
            return self._lower_index(e)
        if isinstance(e, A.StructLit):
            return self._lower_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._lower_list_lit(e)
        if isinstance(e, A.TupleLit):
            return self._lower_tuple_lit(e)
        if isinstance(e, A.InterpolatedString):
            return self._lower_interpolated_string(e)
        if isinstance(e, A.Try):
            return self._lower_try(e)
        if isinstance(e, A.LambdaExpr):
            return self._lower_lambda(e)
        if isinstance(e, A.MatchExpr):
            return self._lower_match_expr(e)
        if isinstance(e, A.IfExpr):
            return self._lower_if_expr(e)
        if isinstance(e, A.RangeExpr):
            return self._lower_range(e)
        raise UnsupportedInIR(f"expression {type(e).__name__}")

    def _lower_range(self, e: A.RangeExpr) -> Value:
        """Lower ``a..b`` / ``a..=b`` to a ``MakeRange`` IR
        instruction. The Python emitter renders this as
        ``CapaRange(start, stop)``; the Wasm emitter allocates a
        24-byte Range record + emits a counted loop when the
        ``For`` iterator's type is ``Range<Int>``."""
        start = self._lower_expr(e.start)
        end = self._lower_expr(e.end)
        dst = fresh_local(self._counter, prefix="rng")
        self._locals[dst] = "Range<Int>"
        self._instrs.append(
            MakeRange(
                dst=dst, start=start, end=end, inclusive=e.inclusive,
            )
        )
        return Value(kind="local", name=dst, ty="Range<Int>")

    def _lower_if_expr(self, e: A.IfExpr) -> Value:
        """Lower ``if cond then a else b`` (ternary expression form).
        Allocates a result local; each branch lowers normally and is
        appended with an assignment to the result. Uses the existing
        ``If`` instruction so the emitter renders a Python ``if/else``
        block rather than the ``a if c else b`` expression form. The
        ANF shape would not survive the latter cleanly because each
        branch may have sub-expressions of its own that need
        intermediate locals."""
        cond = self._lower_expr(e.cond)
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter, prefix="ife")
        self._locals[dst] = result_ty
        # then branch
        outer = self._instrs
        self._instrs = []
        v_then = self._lower_expr(e.then_expr)
        self._instrs.append(AssignConst(dst=dst, src=v_then))
        then_body = self._instrs
        # else branch
        self._instrs = []
        v_else = self._lower_expr(e.else_expr)
        self._instrs.append(AssignConst(dst=dst, src=v_else))
        else_body = self._instrs
        self._instrs = outer
        self._instrs.append(
            If(cond=cond, then_body=then_body, else_body=else_body)
        )
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_match_expr(self, m: A.MatchExpr) -> Value:
        """Lower a match used in expression position. Allocates a
        result local; each arm body lowers normally and is then
        appended with an AssignConst writing its value into the
        result local. The emitter's existing Match emission renders
        the whole thing as a Python ``match`` / ``case`` block; the
        result local is in function scope (Python has no per-case
        scope), so subsequent instructions read it naturally.

        Block-bodied arms are deferred: lowering a block to a Value
        would require the analyzer to mark the implicit-result
        expression inside, which we do not have access to here.
        Capa's expression-position matches in practice use
        expression bodies (``pattern -> expr``), which is the
        90% case."""
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(m))
            if t is not None:
                result_ty = _ty_to_str(t)
        result_dst = fresh_local(self._counter, prefix="m")
        self._locals[result_dst] = result_ty
        scrut = self._lower_expr(m.scrutinee)
        arms: list[MatchArm] = []
        for arm in m.arms:
            self._enter_scope()
            self._refine_pattern_binds(arm.pattern, scrut.ty)
            pat = self._lower_pattern(arm.pattern)
            guard_value = None
            guard_setup: list = []
            if arm.guard is not None:
                guard_value, guard_setup = self._lower_guard(arm.guard)
            outer = self._instrs
            self._instrs = []
            if isinstance(arm.body, A.Block):
                # Block-as-expression: if the block's last statement
                # is an ExprStmt, that expression is the block's
                # value (Capa's implicit-result-block semantics).
                # Otherwise the block produces ``Unit``; an early
                # ``return`` inside the block can still short-circuit
                # the AssignConst at the tail. Mirrors the legacy
                # transpiler's ``_emit_arm_body_to``.
                stmts = arm.body.stmts
                if stmts and isinstance(stmts[-1], A.ExprStmt):
                    for s in stmts[:-1]:
                        self._lower_stmt(s)
                    v = self._lower_expr(stmts[-1].expr)
                    self._instrs.append(AssignConst(dst=result_dst, src=v))
                else:
                    self._lower_block(arm.body)
                    unit_v = Value(kind="lit_unit", literal=None, ty="Unit")
                    self._instrs.append(
                        AssignConst(dst=result_dst, src=unit_v)
                    )
            else:
                v = self._lower_expr(arm.body)
                self._instrs.append(AssignConst(dst=result_dst, src=v))
            body = self._instrs
            self._instrs = outer
            self._exit_scope()
            arms.append(MatchArm(
                pattern=pat, body=body,
                guard=guard_value, guard_setup=guard_setup,
            ))
        self._instrs.append(
            Match(scrutinee=scrut, arms=arms, result_dst=result_dst)
        )
        return Value(kind="local", name=result_dst, ty=result_ty)

    def _lower_lambda(self, e: A.LambdaExpr) -> Value:
        """Lower a lambda. The resulting Value is a local whose name
        is the lambda's synthetic identifier; the emitter renders it
        as a nested ``def`` with that name. Outer-scope state
        (instruction buffer, locals, params, cap-params) is snapshotted
        and restored across the lambda body's lowering."""
        from .. import capa_ast as A_local
        name = fresh_local(self._counter, prefix="lambda")
        # Save outer state; the lambda body lowers into a fresh
        # instruction buffer and a parameter-set augmented with its
        # own params. Locals and the counter remain shared (the
        # counter keeps fresh-name allocation unique across the
        # whole function; locals carry type info only, which the
        # Python emitter ignores).
        outer_instrs = self._instrs
        outer_params = self._params
        outer_caps = self._cap_params
        self._instrs = []
        self._params = dict(outer_params)
        self._cap_params = dict(outer_caps)
        lambda_params: list[Param] = []
        for p in e.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in BUILTIN_CAPS
            lambda_params.append(
                Param(name=p.name, ty=ty_name, is_capability=is_cap)
            )
            self._params[p.name] = ty_name
            if is_cap:
                self._cap_params[p.name] = ty_name
        # Body: an expression body produces a value the lambda must
        # ``return``. A block body that ends in an ExprStmt uses
        # Capa's implicit-result-block semantics — the tail
        # expression is the lambda's return value (matches
        # ``_lower_match_expr``'s arm-body handling at
        # _lower_expr.py:174-185). Otherwise the block lowers
        # as plain statements with the analyzer-enforced
        # explicit ``return``, or fall-through for Unit lambdas.
        # Audit slice 24 (2026-05-30): pre-fix the Block branch
        # always fell through, so a non-Unit lambda like
        # ``fun (x) -> Int => { let y = x*2; y + 1 }`` returned
        # None on Python and trapped on Wasm — silent divergence
        # that no parity test exercised because every existing
        # block-body lambda used explicit ``return``.
        self._enter_scope()
        if isinstance(e.body, A_local.Block):
            ret_ty_name = _type_name(e.return_type) if e.return_type else "Unit"
            stmts = e.body.stmts
            if (
                ret_ty_name != "Unit"
                and stmts
                and isinstance(stmts[-1], A_local.ExprStmt)
            ):
                for s in stmts[:-1]:
                    self._lower_stmt(s)
                v = self._lower_expr(stmts[-1].expr)
                self._instrs.append(Return(value=v))
            else:
                self._lower_block(e.body)
        else:
            v = self._lower_expr(e.body)
            self._instrs.append(Return(value=v))
        self._exit_scope()
        body = self._instrs
        # Restore outer state and emit the MakeLambda instruction.
        self._instrs = outer_instrs
        self._params = outer_params
        self._cap_params = outer_caps
        ret_ty = _type_name(e.return_type) if e.return_type else "Unknown"
        # The lambda's runtime type, for IR-internal use only; the
        # Python emitter ignores it. We pick the source-level
        # ``Fun(P1, P2) -> Ret`` rendering so the type map and the
        # IR-side string stay consistent.
        param_tys = ", ".join(p.ty for p in lambda_params)
        fun_ty = f"Fun({param_tys}) -> {ret_ty}"
        self._locals[name] = fun_ty
        self._instrs.append(
            MakeLambda(
                dst=name,
                params=lambda_params,
                return_type=ret_ty,
                body=body,
            )
        )
        return Value(kind="local", name=name, ty=fun_ty)

    def _lower_try(self, e: A.Try) -> Value:
        # Three-address IR uses a single TryUnwrap instruction for
        # every ``?`` site, regardless of whether the source-level
        # context was a statement-top position or a sub-expression.
        # The Python emitter expands TryUnwrap into the inline
        # isinstance / is-None_ check + early return; no exception
        # path is involved.
        inner = self._lower_expr(e.expr)
        # The unwrapped type is the inner's type-arg if known;
        # without precise inference here we settle for Unknown and
        # let the emitter rely on duck-typing.
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(TryUnwrap(dst=dst, src=inner))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_ident(self, e: A.Ident) -> Value:
        # Parameters take precedence over local aliases so a lambda
        # parameter ``|x| ...`` correctly shadows an outer local ``x``
        # captured into the lambda body.
        if e.name in self._params:
            return Value(kind="param", name=e.name, ty=self._params[e.name])
        # Resolve through the alpha-renaming alias stack: a reference
        # inside a shadowing scope must point at the fresh binding,
        # not at the outer-scope same-named local. ``_resolve_name``
        # returns the original name when no shadow is active.
        resolved = self._resolve_name(e.name)
        if resolved in self._locals:
            return Value(
                kind="local", name=resolved, ty=self._locals[resolved],
            )
        if e.name in self._module_names:
            # A reference to a top-level constant or a function name
            # used as a value (e.g. higher-order use). Treated as a
            # Python-level global; the emitter renders ``Value`` as
            # the bare name. Use the analyzer's recorded type for
            # the Ident so downstream dispatch (Wasm FormatStr part
            # selection, type-aware method routing) sees the actual
            # type rather than a placeholder.
            ty = "Unknown"
            if self.types:
                t = self.types.get(id(e))
                if t is not None:
                    ty = _ty_to_str(t)
            return Value(kind="global", name=e.name, ty=ty)
        if e.name == "None":
            # Capa's ``None`` is the Option singleton, named ``None_``
            # at the Python level to avoid the keyword clash.
            return Value(kind="variant_ctor", name="None", ty="Option")
        if e.name in self._payloadless_variants:
            # Use as a value: emitter renders ``Name()`` so the
            # constructor produces an instance.
            return Value(kind="variant_ctor", name=e.name, ty=e.name)
        if e.name in BUILTIN_CAPS:
            return Value(kind="cap_const", name=e.name, ty=e.name)
        raise UnsupportedInIR(f"identifier reference {e.name!r}")

    def _lower_binop(self, e: A.BinOp) -> Value:
        # ``and`` / ``or`` need short-circuit semantics: Capa source
        # like ``pos < len(tokens) and tokens[pos] == 'WITH'`` relies
        # on the right side being skipped when the left short-circuits.
        # Naïve ANF would lower both sides into locals before the
        # BinOp, which evaluates the right side eagerly and crashes
        # on out-of-bounds access. We rewrite to a sequence using the
        # existing ``If`` instruction so the right side lives inside
        # a conditional branch:
        #   a and b  ->  dst = a; if dst:        dst = b
        #   a or  b  ->  dst = a; if not dst:    dst = b
        if e.op in ("and", "or"):
            return self._lower_short_circuit(e)
        left = self._lower_expr(e.left)
        right = self._lower_expr(e.right)
        # Result type: trust the type map if present; otherwise default
        # to the left operand's type. Phase 1 does not need precise
        # inference here because the Python emitter does not specialise
        # on type.
        result_ty = self.types.get(id(e), left.ty) if self.types else left.ty
        if hasattr(result_ty, "__class__") and result_ty.__class__.__name__ != "str":
            result_ty = _ty_to_str(result_ty)
        dst = fresh_local(self._counter)
        self._locals[dst] = str(result_ty)
        self._instrs.append(BinOp(dst=dst, op=e.op, left=left, right=right))
        return Value(kind="local", name=dst, ty=str(result_ty))

    def _lower_short_circuit(self, e: A.BinOp) -> Value:
        """Lower ``and`` / ``or`` so the right side only evaluates
        when the left's value forces it. Uses the existing ``If``
        instruction; the dst is the result.  The right side's
        sub-expressions land in the If's then_body, preserving
        Python's short-circuit behaviour for IR-emitted code."""
        left = self._lower_expr(e.left)
        result_ty = "Bool"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        # dst = a
        self._instrs.append(AssignConst(dst=dst, src=left))
        # Lower the right side into a side buffer so we can splice it
        # into the If's body.
        outer = self._instrs
        self._instrs = []
        right = self._lower_expr(e.right)
        self._instrs.append(
            Reassign(dst=dst, src=right)
        )
        right_body = self._instrs
        self._instrs = outer
        if e.op == "and":
            cond = Value(kind="local", name=dst, ty=result_ty)
            self._instrs.append(If(
                cond=cond, then_body=right_body, else_body=[],
            ))
        else:
            # ``or``: short-circuit on truthy left; evaluate right when
            # left is falsy. We wrap the cond in a UnaryOp(not, dst)
            # by binding it to a temp first; the emitter doesn't
            # support a bare ``not`` in an If's cond, so we feed it
            # the negated value.
            ncond_dst = fresh_local(self._counter)
            self._locals[ncond_dst] = "Bool"
            self._instrs.append(UnaryOp(
                dst=ncond_dst, op="not",
                operand=Value(kind="local", name=dst, ty=result_ty),
            ))
            cond = Value(kind="local", name=ncond_dst, ty="Bool")
            self._instrs.append(If(
                cond=cond, then_body=right_body, else_body=[],
            ))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_unary(self, e: A.UnaryOp) -> Value:
        operand = self._lower_expr(e.operand)
        result_ty = operand.ty
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(UnaryOp(dst=dst, op=e.op, operand=operand))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_call(self, e: A.Call) -> Value:
        # Phase 1: only supports direct identifier-callee calls (not
        # method-on-value or function-in-variable forms). Resolves the
        # callee by its source name.
        if not isinstance(e.callee, A.Ident):
            raise UnsupportedInIR(
                f"call with callee {type(e.callee).__name__}"
            )
        callee_name = e.callee.name
        # Capa exposes ``new_map()`` / ``new_set()`` as builtins that
        # construct empty collections. They have no runtime function
        # of the same name, so we recognise them here and emit
        # dedicated MakeMap / MakeSet instructions; the Python
        # emitter renders these as literal ``{}`` / ``set()``.
        if callee_name in ("new_map", "new_set") and not e.args:
            dst = fresh_local(self._counter)
            result_ty = (
                _ty_to_str(self.types.get(id(e)))
                if self.types and self.types.get(id(e)) is not None
                else ("Map" if callee_name == "new_map" else "Set")
            )
            self._locals[dst] = result_ty
            if callee_name == "new_map":
                self._instrs.append(MakeMap(dst=dst))
            else:
                self._instrs.append(MakeSet(dst=dst))
            return Value(kind="local", name=dst, ty=result_ty)
        # declassify(value, reason) is identity (roadmap S2.5): lower
        # just the value and return it directly, so the result flows
        # through in whatever representation the lowerer gave the value
        # (String ptr+len, i64, struct handle, ...) with no Call
        # instruction emitted. The @secret -> @public relabel and the
        # SBOM audit record are compile-time only; the reason literal
        # is dropped from the IR. (The Python backend keeps a real
        # runtime ``declassify`` identity call via the transpiler.)
        if callee_name == "declassify" and len(e.args) == 2:
            return self._lower_expr(e.args[0])
        args = [self._lower_expr(arg) for arg in e.args]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(Call(dst=dst, callee_name=callee_name, args=args))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_field_access(self, e: A.FieldAccess) -> Value:
        recv = self._lower_expr(e.receiver)
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(
            FieldAccess(dst=dst, receiver=recv, field=e.field_name)
        )
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_index(self, e: A.Index) -> Value:
        recv = self._lower_expr(e.receiver)
        idx = self._lower_expr(e.index)
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        # Tuple-element type recovery: when the receiver is a known
        # tuple shape and the index is a compile-time literal, the
        # tuple type string carries the authoritative per-slot type.
        # Prefer that over whatever the analyzer recorded for the
        # whole ``tuple[i]`` expression (which for arity > 2 may be
        # missing or have collapsed to ``Int``). Without this the
        # dst lands as i64 in Wasm even for String / Bool slots,
        # tripping the wasm verifier with an i32-vs-i64 type
        # mismatch at the next consumer.
        if (recv.ty and recv.ty.startswith("(")
                and recv.ty.endswith(")")
                and idx.kind == "lit_int"):
            from ._lower_helpers import _split_tuple_elem_types
            elems = _split_tuple_elem_types(recv.ty)
            i = int(idx.literal)
            if 0 <= i < len(elems):
                cand = elems[i]
                if cand and cand not in ("Unknown", "?"):
                    result_ty = cand
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(Index(dst=dst, receiver=recv, index=idx))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_struct_lit(self, e: A.StructLit) -> Value:
        # Each field's value is lowered into the instruction list
        # first; the MakeStruct then references the produced locals.
        fields: list[tuple[str, Value]] = []
        for fname, fexpr in e.fields:
            fields.append((fname, self._lower_expr(fexpr)))
        dst = fresh_local(self._counter)
        self._locals[dst] = e.type_name
        self._instrs.append(
            MakeStruct(dst=dst, type_name=e.type_name, fields=fields)
        )
        return Value(kind="local", name=dst, ty=e.type_name)

    def _lower_list_lit(self, e: A.ListLit) -> Value:
        elements = [self._lower_expr(x) for x in e.elements]
        result_ty = "List"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(MakeList(dst=dst, elements=elements))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_tuple_lit(self, e: A.TupleLit) -> Value:
        if not e.elements:
            return Value(kind="lit_unit", literal=None, ty="Unit")
        elements = [self._lower_expr(x) for x in e.elements]
        # Render as ``(T1, T2)`` so downstream consumers
        # (TuplePat destructure, Wasm emitter) can read precise
        # element types instead of seeing a bare ``Tuple``.
        # Prefer the analyzer's recorded type for the whole
        # expression when present; fall back to element Value
        # types otherwise.
        result_ty = "Tuple"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        if result_ty == "Tuple":
            inner = ", ".join(v.ty or "Unknown" for v in elements)
            result_ty = f"({inner})"
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(MakeTuple(dst=dst, elements=elements))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_interpolated_string(self, e: A.InterpolatedString) -> Value:
        # InterpolatedString carries a list of segments; each is
        # either a literal string fragment or an embedded expression.
        # We collect the parts into the FormatStr instruction's
        # ``parts`` list (alternating str / Value), lowering each
        # embedded expression into instructions first.
        parts: list = []
        for seg in e.parts:
            if isinstance(seg, str):
                parts.append(seg)
            else:
                parts.append(self._lower_expr(seg))
        dst = fresh_local(self._counter)
        self._locals[dst] = "String"
        self._instrs.append(FormatStr(dst=dst, parts=parts))
        return Value(kind="local", name=dst, ty="String")

    def _lower_method_call(self, e: A.MethodCall) -> Value:
        # Look up attenuations on the receiver's source-level binding
        # name BEFORE lowering. The intra-function flow analyser
        # (``capa.manifest._flow._build_attenuation_map``) keys by the
        # AST ``IdentPat.name``, which the lowerer's alpha-rename
        # would erase. When the AST receiver is a bare Ident bound to
        # a tracked attenuation chain (``let tmp = fs.restrict_to(
        # "/tmp/")``), copy the list onto the IR MethodCall so the
        # Wasm backend can emit a runtime check before the host call.
        atts = None
        if isinstance(e.receiver, A.Ident):
            tracked = self._attenuation_map.get(e.receiver.name)
            if tracked:
                atts = list(tracked)
        receiver = self._lower_expr(e.receiver)
        args = [self._lower_expr(arg) for arg in e.args]
        cap_used: Optional[str] = None
        # If the receiver is a capability-typed parameter, record the
        # capability class so the manifest builder can attribute this
        # method invocation.
        if receiver.kind == "param" and receiver.name in self._cap_params:
            cap_used = self._cap_params[receiver.name]
        elif (receiver.ty or "").split("<", 1)[0] in BUILTIN_CAPS:
            # Receiver is a built-in cap reached via field access or
            # local binding (e.g. ``self.fs.read(...)`` inside an
            # impl method, or ``let f = my_cap; f.read(...)`` in a
            # parent function). Without this branch the Wasm
            # backend's canonical-ABI indirect-return detection
            # (_collect_locals' has_indirect_cap_call gate) would
            # miss the call and ``$_ret_area`` would go undeclared,
            # producing WAT that wasm-tools rejects. Tag with the
            # receiver's cap type so the manifest builder + the
            # Wasm emitter both see it.
            cap_used = (receiver.ty or "").split("<", 1)[0]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(
            MethodCall(
                dst=dst, receiver=receiver, method=e.method,
                args=args, cap_used=cap_used, attenuations=atts,
            )
        )
        return Value(kind="local", name=dst, ty=result_ty)


# ----------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------


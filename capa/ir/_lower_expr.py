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
from .._declassify import is_declassify_call
from ._capa_types import BUILTIN_CAPS
from ._lower_helpers import (
    _type_name, _ty_to_str, _unwrap_try_payload_ty, UnsupportedInIR,
)
from ._nodes import (
    AssignConst, BinOp, Call, FieldAccess, FormatStr, If, Index, MakeLambda,
    MakeList, MakeMap, MakeRange, MakeSet, MakeStruct, MakeTuple, Match,
    MatchArm, MethodCall, Param, Reassign, Return,
    TryUnwrap, UnaryOp, Value, fresh_local, ForeignCall,
)


# Range methods that are NOT emitted natively by the Wasm backend
# and instead desugar to ``range.to_list().<method>(...)``. The four
# native Range methods (length / contains / is_empty / to_list) are
# emitted directly against the Range record and are excluded here.
_RANGE_DESUGAR_METHODS = frozenset({
    "map", "filter", "fold",
    "first", "last", "get", "find", "find_index",
})


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
        if isinstance(e, A.Become):
            # Roadmap S3.3: a typestate transition is identity at
            # runtime; only the state-type changes (a compile-time
            # property). Lower to the value operand directly.
            return self._lower_expr(e.value)
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
        # Snapshot ``_live_locals`` the same way ``_params`` is
        # snapshotted: the copy keeps the enclosing scope's live locals
        # visible inside the lambda body (so a captured enclosing local
        # still resolves ``kind="local"``), and the restore below drops
        # the lambda's OWN binds from the enclosing resolution while
        # leaving their types in the shared ``_locals`` map for the
        # closure emitter.
        outer_live = self._live_locals
        self._instrs = []
        self._params = dict(outer_params)
        self._cap_params = dict(outer_caps)
        self._live_locals = set(outer_live)
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
        # Capa's implicit-result-block semantics - the tail
        # expression is the lambda's return value (matches
        # ``_lower_match_expr``'s arm-body handling at
        # _lower_expr.py:174-185). Otherwise the block lowers
        # as plain statements with the analyzer-enforced
        # explicit ``return``, or fall-through for Unit lambdas.
        # Audit slice 24 (2026-05-30): pre-fix the Block branch
        # always fell through, so a non-Unit lambda like
        # ``fun (x) -> Int => { let y = x*2; y + 1 }`` returned
        # None on Python and trapped on Wasm - silent divergence
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
                v = self._retype_lambda_result(v, ret_ty_name)
                self._instrs.append(Return(value=v))
            else:
                self._lower_block(e.body)
        else:
            v = self._lower_expr(e.body)
            ret_ty_name = _type_name(e.return_type) if e.return_type else ""
            v = self._retype_lambda_result(v, ret_ty_name)
            self._instrs.append(Return(value=v))
        self._exit_scope()
        body = self._instrs
        # Restore outer state and emit the MakeLambda instruction.
        self._instrs = outer_instrs
        self._params = outer_params
        self._cap_params = outer_caps
        self._live_locals = outer_live
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

    def _retype_lambda_result(self, v: Value, ret_ty: str) -> Value:
        """A lambda's implicit tail expression IS the lambda's
        return value, so its static type is the lambda's declared
        return type. When every arm of a tail match exits via an
        explicit ``return``, the analyzer types the match
        expression ``?`` (no arm yields a value), the lowerer's
        result temp inherits that, and the Wasm backend then
        declares the temp with the default i64 shape -- so the
        (unreachable but still validated) trailing ``Return``
        pushes the wrong shape for a String / Float / pointer
        result ("type mismatch: expected i32, found i64" at
        wasmtime compile). Re-typing the temp from the declared
        return type gives every backend a consistent shape.

        On the all-arms-return path the temp is dead, so the
        re-typed value never flows. But the temp is NOT universally
        dead: when the tail match has expression-body arms (each arm
        ``AssignConst``s its value into the temp and the trailing
        ``Return`` reads it back), the temp is live, and a guarded
        arm of that shape (``Some(n) if n > 5 -> "..."``) keeps it
        live too. In the live case the analyzer already types the
        match from its arm values, so the re-type is a no-op there;
        the guarded-lambda shape mismatch that case once tripped
        lived in the closure-lifting locals sweep
        (``_emit_wasm/_closures.py``, which now sweeps each arm's
        ``guard_setup`` temporaries), not here."""
        if not ret_ty or ret_ty in ("Unit", "Unknown"):
            return v
        cur = v.ty or ""
        if cur not in ("", "?", "Unknown", "Any") and not cur.startswith("?"):
            return v
        if v.kind == "local" and v.name:
            rec = self._locals.get(v.name, "")
            if rec in ("", "?", "Unknown", "Any") or rec.startswith("?"):
                self._locals[v.name] = ret_ty
                # A nested tail match feeds its own (equally
                # never-typed) result temp into this one via a dead
                # ``AssignConst`` inside an arm body; retype the
                # whole chain so e.g. a match-inside-a-match arm
                # doesn't leave an i64-shaped temp assigned into a
                # String (ptr, len) pair.
                self._retype_chained_unknowns(
                    self._instrs, v.name, ret_ty, {v.name},
                )
        from dataclasses import replace
        return replace(v, ty=ret_ty)

    def _retype_chained_unknowns(
        self, instrs, name: str, ret_ty: str, seen: set,
    ) -> None:
        """Follow ``AssignConst`` writes into ``name`` (anywhere in
        the instruction tree -- match arms included) and retype any
        unknown-typed source local to ``ret_ty``, recursively. Only
        fully-unknown locals are touched, and an unknown source
        local can only be another diverging match / if temp on the
        same dead path, so the retype never changes a reachable
        value's shape."""
        from ._walk import walk_instrs
        for instr in walk_instrs(instrs):
            if not isinstance(instr, AssignConst) or instr.dst != name:
                continue
            src = instr.src
            if src.kind != "local" or not src.name or src.name in seen:
                continue
            rec = self._locals.get(src.name, "")
            if rec in ("", "?", "Unknown", "Any") or rec.startswith("?"):
                self._locals[src.name] = ret_ty
                seen.add(src.name)
                self._retype_chained_unknowns(
                    instrs, src.name, ret_ty, seen,
                )

    def _lower_try(self, e: A.Try) -> Value:
        # Three-address IR uses a single TryUnwrap instruction for
        # every ``?`` site, regardless of whether the source-level
        # context was a statement-top position or a sub-expression.
        # The Python emitter expands TryUnwrap into the inline
        # isinstance / is-None_ check + early return; no exception
        # path is involved.
        inner = self._lower_expr(e.expr)
        # The unwrapped type is the inner's type-arg if known.
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        # When the analyzer left the ``Try`` node untyped, recover the
        # payload from the operand's ``Result<T, E>`` / ``Option<T>``
        # type by stripping the Ok / Some arm. Otherwise the payload
        # defaults to ``Unknown``, which flows into ``_lower_let`` and
        # makes a destructured ``let (m, s) = f()?`` binder lose its
        # element type; the Wasm tuple emitter then sizes a pointer-
        # shaped element (Map / List / Set) as an i64 slot and the
        # module fails the Wasm validator.
        if result_ty in ("Unknown", "") or result_ty.startswith("?"):
            recovered = _unwrap_try_payload_ty(inner.ty or "")
            if recovered:
                result_ty = recovered
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
        if resolved in self._live_locals:
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
        # Constant-fold ``-<int literal>`` written in source into a
        # single negative ``lit_int``. This matters for ``i64::MIN``
        # (``-9223372036854775808``): the parser emits it as
        # ``UnaryOp('-', IntLit(9223372036854775808))``, and routing
        # that through the runtime negation (``0 - x``) would push the
        # operand as ``i64.const 9223372036854775808`` -- already the
        # i64::MIN bit pattern -- and the Wasm backend's overflow guard
        # would trap on it, even though the *literal* is a valid value
        # (the Python backend folds with bignums and prints it fine).
        # Folding here emits ``i64.const -9223372036854775808``
        # directly. Crucially this only fires for a literal operand:
        # negating a runtime value that happens to equal i64::MIN still
        # goes through the guard and traps in both backends.
        if e.op == "-" and isinstance(e.operand, A.IntLit):
            return Value(
                kind="lit_int", literal=-e.operand.value, ty="Int",
            )
        operand = self._lower_expr(e.operand)
        result_ty = operand.ty
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(UnaryOp(dst=dst, op=e.op, operand=operand))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_call(self, e: A.Call) -> Value:
        # Phase 1: direct identifier-callee calls resolve by source
        # name. A callee that is an *expression* (``fs[0](x)``,
        # ``getf()(x)``, ``s.op(x)``) is supported when that
        # expression's type is ``Fun(...)``: lower it to a Value,
        # materialise it into a named local, and emit the same
        # closure-call IR that ``let f = <expr>; f(x)`` produces --
        # a Call whose ``callee_name`` is the temp local. The Wasm
        # backend recognises a local of Fun type as a closure callee
        # and routes through ``call_indirect``. Any other callee
        # shape (a non-Fun expression) stays unsupported.
        if not isinstance(e.callee, A.Ident):
            return self._lower_call_expr_callee(e)
        callee_name = e.callee.name
        # Resolve the callee through the alpha-renaming alias stack,
        # exactly like ``_lower_ident`` does for value positions. A
        # lambda body that shadows the very local the closure is
        # bound to (``let f = fun ... => { let f = ...; ... }``)
        # makes the lowerer rename the OUTER binding (the lambda
        # body lowers first and claims the bare name in the flat
        # locals map), so a later call ``f()`` must follow the
        # rename to the closure local -- otherwise the Call carries
        # the source name, the emitter sees a non-Fun local of that
        # name, and falls through to ``call $f`` against a function
        # that does not exist ("unknown func" at wasm-tools parse).
        resolved_callee = self._resolve_name(callee_name)
        if resolved_callee != callee_name and resolved_callee in self._locals:
            callee_name = resolved_callee
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
        #
        # The gate keys on the callee's BINDING identity, not its name:
        # a user-defined ``fun declassify(value, reason)`` shadows the
        # built-in and must be lowered as an ordinary call and actually
        # invoked. ``is_declassify_call`` is the one predicate the
        # analyzer and the manifest already share; with the analyzer's
        # bindings threaded in (``self._bindings``) it resolves the
        # built-in by ``BUILTIN_POS`` and rejects the shadow. Without
        # bindings (internal ceiling lowerings) it falls back to the
        # name-only floor, matching the prior behaviour. The extra
        # arity guard preserves the historical name-only path exactly
        # (a genuine built-in call is always two-argument).
        if is_declassify_call(e, self._bindings) and len(e.args) == 2:
            return self._lower_expr(e.args[0])
        args = [self._lower_expr(arg) for arg in e.args]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        # ``IoError(msg)`` / ``IoError(msg, cause)`` is the one built-in
        # value type Capa constructs with call syntax (structs use brace
        # literals). The analyzer does not type the constructor result --
        # it falls through to ``?`` -- so pin it to ``IoError`` here.
        # Without this the lowerer leaves the dst local unresolved (``?``),
        # the Wasm backend declares it i64 instead of the i32 record
        # pointer, and the Err-payload store treats it as a scalar rather
        # than a pointer-shaped value. The Python backend is unaffected
        # (its Call rendering does not consult the dst type).
        if callee_name == "IoError" and (
            not result_ty
            or result_ty in ("Unknown", "?")
            or result_ty.startswith("?")
        ):
            result_ty = "IoError"
        route = self._classify_call_route(e.callee.name, resolved_callee)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(
            Call(dst=dst, callee_name=callee_name, args=args, route=route)
        )
        return Value(kind="local", name=dst, ty=result_ty)

    def _classify_call_route(self, orig_name: str, resolved: str):
        """Decide direct-vs-closure routing for a call at LOWERING time,
        recorded on the ``Call`` node so both Wasm emitter sites honour
        the decision instead of re-guessing from the flat
        ``Function.locals`` type map (which intentionally keeps a dead
        lambda-body local's ``Fun`` type for the closure emitter, and so
        would mis-route a same-named enclosing call).

        Classification ORDER is load-bearing. A callee that resolves to a
        live local, a Fun-typed parameter, or a captured Fun value (both
        of the latter reachable through the lambda's snapshotted
        ``_params`` / ``_live_locals``) is a CLOSURE call; ONLY a callee
        that is none of those and is a module-level symbol is a DIRECT
        ``call $name``. The order matters: a callee that is BOTH a
        module-function name AND a Fun parameter must route to the
        parameter, not to the module function.

        Returns ``"closure"`` / ``"direct"``, or ``None`` for a callee
        that is neither (a built-in / intrinsic / variant constructor);
        the emitter's earlier branches handle those before any routing
        decision, and its ``Function.locals`` fallback covers the rest.
        """
        # CLOSURE: a live local shadows any same-named module symbol, so
        # the callee is the local (its type is Fun, the analyzer having
        # vetted it callable). This also covers the alpha-renamed outer
        # binding and, inside a lambda body, a captured enclosing local.
        if resolved in self._live_locals:
            return "closure"
        # CLOSURE: a Fun-typed parameter (covers a captured enclosing
        # parameter too, since the lambda snapshots ``_params``). Checked
        # BEFORE the module rule so a Fun param that shares a module
        # function's name routes to the parameter.
        pty = self._params.get(orig_name)
        if pty is not None and pty.startswith("Fun"):
            return "closure"
        # DIRECT: a module-level symbol (function or const) that is none
        # of the above.
        # known-open: a module const whose value is a Fun classifies
        # DIRECT here and emits ``call $const`` -- there is no such
        # function, so it fails loud with "unknown func", identically to
        # the shadow-free form of the same program. Making a const-of-Fun
        # callee callable is a separate open gap; it is intentionally left
        # to fail loud rather than silently produce a value.
        if orig_name in self._module_names:
            return "direct"
        return None

    def _lower_call_expr_callee(self, e: A.Call) -> Value:
        """Lower a call whose callee is an expression, not a bare
        identifier (``fs[0](x)``, ``getf()(x)``, ``s.op(x)``). Only
        a callee whose type is ``Fun(...)`` is supported: the value
        is materialised into a named local so the backend's closure-
        call path (a local of Fun type -> ``call_indirect``) applies,
        exactly as it does for ``let f = <expr>; f(x)``."""
        callee_val = self._lower_expr(e.callee)
        callee_ty = callee_val.ty or ""
        if not callee_ty.startswith("Fun"):
            raise UnsupportedInIR(
                f"call with callee {type(e.callee).__name__}"
            )
        # ``_lower_expr`` of an Index / FieldAccess / Call already
        # binds a fresh local; reuse it. A non-local Value (rare for
        # a Fun-typed callee) is copied into a temp so the Call can
        # reference it by name.
        if callee_val.kind == "local":
            callee_name = callee_val.name
        else:
            callee_name = fresh_local(self._counter)
            self._locals[callee_name] = callee_ty
            self._instrs.append(
                AssignConst(dst=callee_name, src=callee_val)
            )
        args = [self._lower_expr(arg) for arg in e.args]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        # The callee is the result of an expression of ``Fun(...)`` type
        # (``make()(5)``, ``fs[0](x)``): a closure call by construction,
        # and never a module name, so tag it CLOSURE unconditionally.
        self._instrs.append(
            Call(
                dst=dst, callee_name=callee_name, args=args,
                route="closure",
            )
        )
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
        # Feature #4 (F2a): a call to a typed foreign component,
        # ``Bureau.submit(net, x)``. The receiver is a bare Ident naming
        # an ``extern component`` declaration -- a callable namespace,
        # not a value -- so it is intercepted BEFORE ``_lower_expr(
        # e.receiver)`` (which would try to lower ``Bureau`` as a value
        # and fail). Produces a ForeignCall the Wasm backend lowers to a
        # sandboxed sub-component dispatch.
        if (
            isinstance(e.receiver, A.Ident)
            and e.receiver.name in getattr(self, "_foreign_components", {})
        ):
            return self._lower_foreign_call(e)
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
        # Range transform / indexed-query methods desugar to
        # ``range.to_list().<method>(...)``. The teaching material's
        # promise is that "a range is just a List", so these carry the
        # exact List semantics. The Wasm backend has no native Range
        # HOF emitter; materialising first and routing through the
        # List method emitters keeps that backend untouched while
        # guaranteeing ``r.map(f)`` == ``r.to_list().map(f)``.
        if (
            (receiver.ty or "").startswith("Range")
            and e.method in _RANGE_DESUGAR_METHODS
        ):
            list_dst = fresh_local(self._counter)
            list_ty = "List<Int>"
            self._locals[list_dst] = list_ty
            self._instrs.append(
                MethodCall(
                    dst=list_dst, receiver=receiver, method="to_list",
                    args=[], cap_used=None, attenuations=None,
                )
            )
            receiver = Value(kind="local", name=list_dst, ty=list_ty)
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

    def _lower_foreign_call(self, e: A.MethodCall) -> Value:
        """Lower ``Bureau.submit(net, x)`` to a :class:`ForeignCall`
        (feature #4, F2a). The declared method signature (from the
        ``extern component`` declaration) fixes the parameter order and
        each parameter's kind (capability vs scalar); the arguments are
        lowered and rearranged into that order so the emitter can pair
        each operand with its declared kind."""
        from ..foreign import (
            method_param_kinds, method_return_root,
        )
        from ..foreign_schema import crossing_kind
        from ..manifest._strings import _ty_text
        comp = self._foreign_components[e.receiver.name]
        method_sig = next(
            (m for m in comp.methods if m.name == e.method), None,
        )
        if method_sig is None:
            # The analyzer already rejected an unknown foreign method;
            # defensively lower to a discarded unit so a mis-shaped tree
            # does not crash the lowerer.
            return Value(kind="lit_unit", ty="Unit")
        param_names = [p.name for p in method_sig.params if p.name != "self"]
        # Reorder named arguments into declared-parameter order (the
        # analyzer already validated well-formedness); a plain positional
        # call is the identity permutation.
        arg_names = getattr(e, "arg_names", [None] * len(e.args))
        order = list(range(len(e.args)))
        if any(n is not None for n in arg_names):
            name_to_pos = {n: i for i, n in enumerate(param_names)}
            slot: list = [None] * len(param_names)
            cursor = 0
            for i, n in enumerate(arg_names):
                if n is None:
                    slot[cursor] = i
                    cursor += 1
                else:
                    idx = name_to_pos.get(n)
                    if idx is not None:
                        slot[idx] = i
            order = [i for i in slot if i is not None]
        args = [self._lower_expr(e.args[i]) for i in order]
        param_kinds = method_param_kinds(method_sig)
        return_root = method_return_root(method_sig)
        # The ForeignCall's ``return_type`` is the scalar / String root for
        # a scalar-ish return (Int / Bool / Float / String / Unit), but the
        # FULL type text for an AGGREGATE return (feature #4 F2c) so the
        # emitter can tell an aggregate return from a scalar one -- a tuple
        # return has no root name at all (``_root_type_name`` -> None).
        ret_expr = method_sig.return_type
        if ret_expr is None:
            return_type = "Unit"
        elif crossing_kind(ret_expr) == "aggregate":
            return_type = _ty_text(ret_expr)
        else:
            return_type = return_root
        result_ty = return_root
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = None
        if return_type != "Unit":
            dst = fresh_local(self._counter)
            self._locals[dst] = result_ty
        self._instrs.append(
            ForeignCall(
                dst=dst,
                component=e.receiver.name,
                method=e.method,
                artifact=comp.artifact,
                args=args,
                param_kinds=param_kinds,
                return_type=return_type,
            )
        )
        if dst is None:
            return Value(kind="lit_unit", ty="Unit")
        return Value(kind="local", name=dst, ty=result_ty)


# ----------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------


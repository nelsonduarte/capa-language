"""Statement-level AST -> CIR lowering.

The bulk of the lowerer's by-AST-shape dispatch lives here:
``_lower_let`` / ``_lower_var`` for bindings, ``_lower_if`` /
``_lower_while`` / ``_lower_for`` / ``_lower_match_stmt`` for
control flow, ``_lower_return`` / ``_lower_expr_stmt`` /
``_lower_assign`` for value-producing tails. Each method
appends to ``self._instrs`` (the current function's
instruction list) and returns ``None``; expressions return
``Value``-s and live in ``_lower_expr.py``.

Audit P1 refactor: split per AST family.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._lower_helpers import (
    _type_name, _ty_to_str, _split_tuple_elem_types, UnsupportedInIR,
)
from ._nodes import (
    AssignConst, Reassign, BinOp, Call, MethodCall,
    Break, Continue, For, If, Match, MatchArm, Return, TryUnwrap,
    FieldAccess, FieldStore, Index, Instr, Value, While, fresh_local,
)


class _LowerStmtMixin:
    def _lower_block(self, block: A.Block) -> None:
        for stmt in block.stmts:
            self._lower_stmt(stmt)

    def _lower_stmt(self, s: A.Stmt) -> None:
        if isinstance(s, A.LetStmt):
            return self._lower_let(s)
        if isinstance(s, A.VarStmt):
            return self._lower_var(s)
        if isinstance(s, A.AssignStmt):
            return self._lower_assign(s)
        if isinstance(s, A.IfStmt):
            return self._lower_if(s)
        if isinstance(s, A.WhileStmt):
            return self._lower_while(s)
        if isinstance(s, A.BreakStmt):
            self._instrs.append(Break())
            return
        if isinstance(s, A.ContinueStmt):
            self._instrs.append(Continue())
            return
        if isinstance(s, A.ForStmt):
            return self._lower_for(s)
        if isinstance(s, A.ReturnStmt):
            return self._lower_return(s)
        if isinstance(s, A.ExprStmt):
            return self._lower_expr_stmt(s)
        raise UnsupportedInIR(f"statement {type(s).__name__}")

    def _binding_local_ty(self, expr, ann_ty, value):
        """Pick the recorded type for a ``let``/``var`` binding.

        A concrete annotation wins; otherwise the initializer's
        inferred ``value.ty``; and when that is still ``Unknown``/
        ``?`` (an unannotated copy of ``self``, whose IR param carries
        no concrete impl type, is the motivating case) fall back to the
        analyzer's recorded type for the initializer expression. This
        mirrors what ``_lower_ident`` already does for module globals
        and keeps the "a concrete annotation beats value.ty" precedence
        intact."""
        if ann_ty and ann_ty != "Unknown":
            return ann_ty
        if value.ty not in ("Unknown", "?"):
            return value.ty
        if self.types:
            t = self.types.get(id(expr))
            if t is not None:
                recovered = _ty_to_str(t)
                if recovered and recovered not in ("Unknown", "?"):
                    return recovered
        return value.ty

    def _lower_let(self, s: A.LetStmt) -> None:
        # Ident pattern: ``let x = expr``. Tuple pattern:
        # ``let (a, b) = expr`` destructures positionally. Wildcard
        # ``let _ = expr`` lowers to an evaluate-and-discard (binds a
        # throwaway local so RHS side effects still happen). Other
        # pattern shapes (Variant, Struct, Or) on the LHS of a let
        # are still deferred (they would need a one-arm match
        # lowering with an exhaustiveness check the analyzer has
        # already done).
        if isinstance(s.pattern, A.WildcardPat):
            # ``let _ = expr``: evaluate the RHS for its effects (or
            # for its types, in ``reserved for future`` placeholders
            # like render.capa's ``let _ = sbom``) and drop the value
            # into a fresh local that nothing reads. Binding into the
            # locals map keeps the emitter's type-aware dispatch
            # consistent with how ``let x = expr`` would have been
            # treated, even though no source name resolves here.
            value = self._lower_expr(s.value)
            ann_ty = _type_name(s.type_expr) if s.type_expr else None
            local_ty = (
                ann_ty if ann_ty and ann_ty != "Unknown"
                else value.ty
            )
            wild = fresh_local(self._counter, prefix="wild")
            self._locals[wild] = local_ty
            self._instrs.append(AssignConst(dst=wild, src=value))
            return
        if isinstance(s.pattern, A.IdentPat):
            value = self._lower_expr(s.value)
            # Prefer the explicit type annotation when present and
            # concrete (see _lower_var for the rationale -- the
            # RHS expression's inferred type may be less specific
            # than the user's annotation, particularly for
            # ``new_map()`` / ``new_set()`` calls).
            ann_ty = _type_name(s.type_expr) if s.type_expr else None
            local_ty = self._binding_local_ty(s.value, ann_ty, value)
            bound = self._bind_local(s.pattern.name, local_ty)
            self._instrs.append(AssignConst(dst=bound, src=value))
            return
        if isinstance(s.pattern, A.TuplePat):
            value = self._lower_expr(s.value)
            # Parse element types from the tuple's type string so
            # the binders carry precise types rather than Unknown.
            # ``(String, Int)`` -> ["String", "Int"]. When the type
            # string isn't a tuple shape (e.g. analyser couldn't
            # narrow it), fall back to ``Unknown`` per element.
            elem_types = _split_tuple_elem_types(value.ty)
            for idx, sub in enumerate(s.pattern.elements):
                # ``let (a, _) = pair``: skip the wildcard slot, no
                # binding emitted.
                if isinstance(sub, A.WildcardPat):
                    continue
                if not isinstance(sub, A.IdentPat):
                    raise UnsupportedInIR(
                        f"nested let-pattern {type(sub).__name__}"
                    )
                # Index into the tuple positionally; the IR's Index
                # instruction is the same one ``xs[i]`` uses, so the
                # emitter renders ``a = pair[0]`` etc.
                idx_v = Value(kind="lit_int", literal=idx, ty="Int")
                bind_ty = elem_types[idx] if idx < len(elem_types) else "Unknown"
                bound = self._bind_local(sub.name, bind_ty)
                self._instrs.append(
                    Index(dst=bound, receiver=value, index=idx_v)
                )
            return
        if isinstance(s.pattern, A.StructPat):
            # ``let Point { x, y } = p`` binds each named field to a
            # local read off the struct value. This mirrors the tuple
            # path but reads fields by name (FieldAccess) rather than by
            # position (Index); both backends already lower FieldAccess
            # for ``p.x``, so no IR-node or emitter change is needed.
            value = self._lower_expr(s.value)
            field_types = self._struct_field_types.get(s.pattern.type_name, {})
            elem_v = value
            for fname, fpat in s.pattern.fields:
                # ``let Point { x: _ } = p``: an explicit wildcard
                # sub-pattern reads nothing and binds nothing.
                if isinstance(fpat, A.WildcardPat):
                    continue
                # Only shorthand (``x``) and rename-to-ident
                # (``x: a``) are supported here; nested destructuring
                # in a let struct-pattern is rejected loudly, matching
                # the tuple path's nested-pattern guard.
                if fpat is None:
                    bind_name = fname
                elif isinstance(fpat, A.IdentPat):
                    bind_name = fpat.name
                else:
                    raise UnsupportedInIR(
                        f"nested let struct-pattern {type(fpat).__name__}"
                    )
                bind_ty = field_types.get(fname, "Unknown")
                bound = self._bind_local(bind_name, bind_ty)
                self._instrs.append(
                    FieldAccess(dst=bound, receiver=elem_v, field=fname)
                )
            return
        raise UnsupportedInIR(
            f"let-pattern {type(s.pattern).__name__}"
        )

    def _lower_var(self, s: A.VarStmt) -> None:
        # ``var x = expr``: same Python emission as ``let``, but the
        # IR records both kinds so future backends can enforce
        # immutability of let-bindings. Phase 2 collapses both to
        # AssignConst for simplicity; a follow-up may add a
        # ``mutable`` flag to AssignConst when a Wasm or LLVM target
        # cares.
        #
        # Prefer the explicit type annotation when present and
        # concrete: ``var m: Map<String, String> = new_map()`` has
        # a typed annotation but the RHS expression's inferred type
        # may be a less-specific ``Map<?, ?>`` (since ``new_map``
        # returns fresh type variables that the analyzer unifies
        # later). Using the annotation directly keeps downstream
        # dispatch (Map value-shape selection in particular)
        # working on the concrete shape the user wrote.
        value = self._lower_expr(s.value)
        ann_ty = _type_name(s.type_expr) if s.type_expr else None
        local_ty = self._binding_local_ty(s.value, ann_ty, value)
        bound = self._bind_local(s.name, local_ty)
        self._instrs.append(AssignConst(dst=bound, src=value))

    def _lower_assign(self, s: A.AssignStmt) -> None:
        # Plain ``x = expr`` lowers directly; compound assignments
        # (``+=``, ``-=``, ``*=``, ``/=``, ``%=``) rewrite to
        # ``x = x <op> expr`` at the IR level. A FieldAccess target
        # (``obj.field = expr``) lowers to a FieldStore; the analyzer
        # has already vetted that the field may be mutated. Index
        # targets are still deferred.
        if isinstance(s.target, A.FieldAccess):
            return self._lower_field_assign(s)
        if not isinstance(s.target, A.Ident):
            raise UnsupportedInIR(
                f"assignment target {type(s.target).__name__}"
            )
        target = self._resolve_name(s.target.name)
        if s.op == "=":
            value = self._lower_expr(s.value)
            self._instrs.append(Reassign(dst=target, src=value))
            return
        compound_ops = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}
        if s.op not in compound_ops:
            raise UnsupportedInIR(
                f"compound assignment operator {s.op!r}"
            )
        # Compound: lower the current ident value, the RHS value, then
        # a BinOp, then a Reassign.
        op = compound_ops[s.op]
        cur_ty = self._params.get(target) or self._locals.get(target, "Unknown")
        if target in self._params:
            left = Value(kind="param", name=target, ty=cur_ty)
        else:
            left = Value(kind="local", name=target, ty=cur_ty)
        right = self._lower_expr(s.value)
        dst = fresh_local(self._counter)
        self._locals[dst] = cur_ty
        self._instrs.append(BinOp(dst=dst, op=op, left=left, right=right))
        self._instrs.append(
            Reassign(
                dst=target,
                src=Value(kind="local", name=dst, ty=cur_ty),
            )
        )

    def _lower_field_assign(self, s: A.AssignStmt) -> None:
        # ``recv.field = expr`` (and compound forms). The receiver is
        # lowered to a struct-pointer Value; the RHS lands in a
        # FieldStore that writes the field slot in place. For compound
        # ops, read the current field value first, combine, then store.
        from ._lower_helpers import _ty_to_str
        target = s.target
        recv = self._lower_expr(target.receiver)
        # Field type from the analyzer (keyed by the FieldAccess node
        # id), so the read-modify-write intermediate and the store
        # carry a concrete type.
        field_ty = "Unknown"
        if self.types:
            t = self.types.get(id(target))
            if t is not None:
                field_ty = _ty_to_str(t)
        if s.op == "=":
            value = self._lower_expr(s.value)
            self._instrs.append(
                FieldStore(receiver=recv, field=target.field_name, src=value)
            )
            return
        compound_ops = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}
        if s.op not in compound_ops:
            raise UnsupportedInIR(
                f"compound assignment operator {s.op!r}"
            )
        op = compound_ops[s.op]
        # Read the current field value into a fresh local.
        cur = fresh_local(self._counter)
        self._locals[cur] = field_ty
        self._instrs.append(
            FieldAccess(dst=cur, receiver=recv, field=target.field_name)
        )
        left = Value(kind="local", name=cur, ty=field_ty)
        right = self._lower_expr(s.value)
        combined = fresh_local(self._counter)
        self._locals[combined] = field_ty
        self._instrs.append(
            BinOp(dst=combined, op=op, left=left, right=right)
        )
        self._instrs.append(
            FieldStore(
                receiver=recv,
                field=target.field_name,
                src=Value(kind="local", name=combined, ty=field_ty),
            )
        )

    def _lower_if(self, s: A.IfStmt) -> None:
        # Lower ``if cond { then } elif c1 { b1 } ... else { e }`` by
        # nesting elif chains in the else branch. The IR's ``If`` is
        # strictly binary (then / else). The condition's intermediate
        # instructions (e.g., method calls that build a Bool) need to
        # be emitted before the ``If`` itself; we capture them by
        # snapshotting the current instruction list, lowering the
        # condition, then splicing.
        outer_instrs = self._instrs

        # Condition: lower into a side buffer, then move into the
        # main instruction list before the ``If``.
        self._instrs = []
        cond_value = self._lower_expr(s.cond)
        cond_setup = self._instrs
        outer_instrs.extend(cond_setup)

        # Then body.
        self._instrs = []
        self._enter_scope()
        self._lower_block(s.then_block)
        self._exit_scope()
        then_body = self._instrs

        # Else chain: fold elifs into nested ifs, terminating with
        # the actual else block (or empty list if none).
        else_body: list[Instr] = self._fold_elif_chain(
            s.elif_arms, s.else_block,
        )

        self._instrs = outer_instrs
        self._instrs.append(
            If(cond=cond_value, then_body=then_body, else_body=else_body)
        )

    def _fold_elif_chain(self, elif_arms, else_block) -> list[Instr]:
        if not elif_arms:
            if else_block is None:
                return []
            buf = self._instrs
            self._instrs = []
            self._enter_scope()
            self._lower_block(else_block)
            self._exit_scope()
            out = self._instrs
            self._instrs = buf
            return out
        # First elif becomes ``if`` at this nesting level; remaining
        # elifs + the original else become its else-body.
        cond_expr, body = elif_arms[0]
        rest = elif_arms[1:]

        # Lower condition into a side buffer; its setup instructions
        # need to precede the nested ``If`` in the else_body.
        outer = self._instrs
        self._instrs = []
        cond_value = self._lower_expr(cond_expr)
        cond_setup = self._instrs

        self._instrs = []
        self._enter_scope()
        self._lower_block(body)
        self._exit_scope()
        then_body = self._instrs

        nested_else = self._fold_elif_chain(rest, else_block)

        self._instrs = outer
        return cond_setup + [
            If(cond=cond_value, then_body=then_body, else_body=nested_else)
        ]

    def _lower_while(self, s: A.WhileStmt) -> None:
        outer = self._instrs

        # Lower the condition into a setup buffer + a final Value.
        self._instrs = []
        cond_value = self._lower_expr(s.cond)
        cond_setup = self._instrs

        # Body.
        self._instrs = []
        self._enter_scope()
        self._lower_block(s.body)
        self._exit_scope()
        body = self._instrs

        self._instrs = outer
        self._instrs.append(
            While(cond_setup=cond_setup, cond=cond_value, body=body)
        )

    def _lower_for(self, s: A.ForStmt) -> None:
        # Four for-pattern shapes are supported: a single ``IdentPat``
        # (``for x in xs``), a wildcard ``WildcardPat`` (``for _ in xs``)
        # that iterates without binding a visible name, a ``TuplePat``
        # (``for (a, b) in pairs``) that destructures each element
        # positionally, and a ``StructPat`` (``for P { a, b } in xs``)
        # that destructures each struct element by field name. Any other
        # pattern shape is rejected loudly rather than miscompiled.
        if not isinstance(
            s.pattern, (A.IdentPat, A.WildcardPat, A.TuplePat, A.StructPat)
        ):
            raise UnsupportedInIR(
                f"for-pattern {type(s.pattern).__name__}"
            )
        iter_value = self._lower_expr(s.iter)
        # Extract the element type so the bound name carries enough
        # info for downstream method dispatch (``for t in xs: t.is_empty()``
        # must dispatch on the element type, not on ``Unknown``).
        bind_ty = "Unknown"
        if iter_value.ty.startswith("List<") and iter_value.ty.endswith(">"):
            bind_ty = iter_value.ty[5:-1]
        elif iter_value.ty.startswith("Set<") and iter_value.ty.endswith(">"):
            # A Set shares the List in-memory layout and yields its
            # single type argument per iteration, exactly like a List.
            # Without this branch the loop variable (and any tuple-
            # destructured component) stayed ``Unknown``, so the Wasm
            # emitter defaulted every component to an i64 scalar load:
            # a ``Set<(Int, String)>`` element's String component was
            # decoded as a raw packed i64 and printed as a garbage
            # integer instead of as (ptr, len). Stripping the element
            # type here matches the List path and the analyzer (which
            # already binds the Set's element type to the pattern).
            bind_ty = iter_value.ty[4:-1]
        elif iter_value.ty.startswith("Range"):
            bind_ty = "Int"
        elif iter_value.ty == "String":
            # Iterating a String yields each Unicode code point bound
            # as a one-codepoint String per iteration (Capa models a
            # Char as a one-codepoint String). The element is a String
            # so the body can use String methods / interpolation on it,
            # matching the Python backend which yields one-character
            # strings.
            bind_ty = "String"
        # A tuple-destructuring for-pattern over a String has no tuple
        # element to destructure (each element is a one-codepoint
        # String, not a tuple). Reject it loudly here rather than let
        # the destructure path Index into a String receiver and emit a
        # silent miscompile.
        if isinstance(s.pattern, A.TuplePat) and bind_ty == "String":
            raise UnsupportedInIR(
                "tuple-destructuring for-pattern over a String "
                "(a String element is a one-codepoint String, not a tuple)"
            )
        self._enter_scope()
        if isinstance(s.pattern, A.IdentPat):
            bound = self._bind_local(s.pattern.name, bind_ty)
            destructure: list[Instr] = []
        elif isinstance(s.pattern, A.WildcardPat):
            # ``for _ in xs``: the loop must still bind an induction
            # local for the emitter to consume (the Wasm emitter reads
            # the For's ``name`` as a local whether or not the body
            # references it), but no source name resolves here. Bind a
            # fresh throwaway local carrying the element type, mirroring
            # the ``let _ = expr`` and tuple ``forelem`` discardable-
            # local patterns, so the body iterates with nothing visible.
            bound = fresh_local(self._counter, prefix="wildfor")
            self._locals[bound] = bind_ty
            destructure = []
        elif isinstance(s.pattern, A.StructPat):
            # Struct-destructuring for-pattern. Bind each iteration's
            # element to a fresh temporary carrying the struct type,
            # then read the named fields off it (FieldAccess) into the
            # bound locals. Mirrors the tuple branch below, swapping the
            # positional Index for a by-name FieldAccess; both backends
            # already lower FieldAccess for ``p.x``.
            bound = fresh_local(self._counter, prefix="forelem")
            self._locals[bound] = bind_ty
            field_types = self._struct_field_types.get(
                s.pattern.type_name, {}
            )
            elem_v = Value(kind="local", name=bound, ty=bind_ty)
            destructure = []
            for fname, fpat in s.pattern.fields:
                if isinstance(fpat, A.WildcardPat):
                    continue
                if fpat is None:
                    bind_name = fname
                elif isinstance(fpat, A.IdentPat):
                    bind_name = fpat.name
                else:
                    raise UnsupportedInIR(
                        f"nested for struct-pattern {type(fpat).__name__}"
                    )
                sub_ty = field_types.get(fname, "Unknown")
                sub_bound = self._bind_local(bind_name, sub_ty)
                destructure.append(
                    FieldAccess(dst=sub_bound, receiver=elem_v, field=fname)
                )
        else:
            # Tuple-destructuring for-pattern. Bind each iteration's
            # element to a fresh temporary carrying the tuple type,
            # then destructure that temporary into the named
            # components positionally. This reuses the exact ``Index``
            # path that powers ``let (a, b) = t`` and ``t[i]``: each
            # backend already lowers ``Index`` on a tuple receiver, so
            # no IR-node or emitter change is needed. The temporary is
            # the ``For`` loop's single bind name; the destructure
            # instructions are prepended to the loop body so they run
            # once per iteration with the components in scope.
            bound = fresh_local(self._counter, prefix="forelem")
            self._locals[bound] = bind_ty
            elem_types = _split_tuple_elem_types(bind_ty)
            elem_v = Value(kind="local", name=bound, ty=bind_ty)
            destructure = []
            for idx, sub in enumerate(s.pattern.elements):
                # ``for (a, _) in pairs``: skip the wildcard slot.
                if isinstance(sub, A.WildcardPat):
                    continue
                if not isinstance(sub, A.IdentPat):
                    raise UnsupportedInIR(
                        f"nested for-pattern {type(sub).__name__}"
                    )
                idx_v = Value(kind="lit_int", literal=idx, ty="Int")
                sub_ty = (
                    elem_types[idx] if idx < len(elem_types) else "Unknown"
                )
                sub_bound = self._bind_local(sub.name, sub_ty)
                destructure.append(
                    Index(dst=sub_bound, receiver=elem_v, index=idx_v)
                )
        outer = self._instrs
        self._instrs = list(destructure)
        self._lower_block(s.body)
        body = self._instrs
        self._instrs = outer
        self._exit_scope()
        self._instrs.append(
            For(name=bound, iter=iter_value, body=body)
        )

    def _lower_return(self, s: A.ReturnStmt) -> None:
        if s.value is None:
            self._instrs.append(Return(value=None))
            return
        v = self._lower_expr(s.value)
        self._instrs.append(Return(value=v))

    def _lower_expr_stmt(self, s: A.ExprStmt) -> None:
        # Special case: a bare ``match`` used as a statement (value
        # discarded). The lowerer emits a Match instruction directly
        # rather than going through _lower_expr (which would force a
        # result Value the caller would then discard).
        if isinstance(s.expr, A.MatchExpr):
            return self._lower_match_stmt(s.expr)
        # Discard the value of the expression; the side-effecting work
        # has already been emitted by ``_lower_expr``. For a call /
        # method-call we rewrite the last emitted instruction to drop
        # its ``dst`` so the emitter does not bind a useless local.
        v = self._lower_expr(s.expr)
        if self._instrs and isinstance(self._instrs[-1], (Call, MethodCall)):
            last = self._instrs[-1]
            if isinstance(v, Value) and v.kind == "local" and v.name == last.dst:
                last.dst = None
                self._locals.pop(v.name, None)
                return
        # No instruction-level rewrite possible (e.g., a bare literal
        # used as a statement). Just drop it; the emitter has nothing
        # to write.

    def _lower_match_stmt(self, m: A.MatchExpr) -> None:
        """Lower a match-as-statement. The expression-position form
        (``let x = match ...``) is deferred until a later phase."""
        scrut = self._lower_expr(m.scrutinee)
        arms: list[MatchArm] = []
        for arm in m.arms:
            self._enter_scope()
            self._refine_pattern_binds(arm.pattern, scrut.ty)
            pat = self._lower_pattern(arm.pattern)
            # Lower the guard FIRST -- inside the arm's scope so
            # pattern binders resolve, but BEFORE the body so its
            # ANF setup lands ahead of the body in the arm's
            # instruction list. ``case PAT if EXPR:`` in Python
            # requires EXPR to be a single expression, so for the
            # Python emitter we accept only guards whose lowered
            # form has empty setup; the Wasm emitter (which has
            # arbitrary control flow) tolerates richer guards but
            # we restrict the surface to the common shape.
            guard_value = None
            guard_setup: list = []
            if arm.guard is not None:
                guard_value, guard_setup = self._lower_guard(arm.guard)
            outer = self._instrs
            self._instrs = []
            if isinstance(arm.body, A.Block):
                self._lower_block(arm.body)
            else:
                # Expression body used as a statement: lower the
                # expression for side effects and drop the value.
                self._lower_expr_stmt(A.ExprStmt(pos=m.pos, expr=arm.body))
            body = self._instrs
            self._instrs = outer
            self._exit_scope()
            arms.append(MatchArm(
                pattern=pat, body=body,
                guard=guard_value, guard_setup=guard_setup,
            ))
        self._instrs.append(Match(scrutinee=scrut, arms=arms, result_dst=None))

    def _lower_guard(self, guard_expr: A.Expr) -> tuple[Value, list]:
        """Lower a match-arm guard.

        The guard is an AST expression the source-level
        ``case PAT if EXPR:`` carries. Returns ``(value, prelude)``:
        ``value`` is the final Value the emitter tests, and
        ``prelude`` is the list of ANF instructions that produce
        any intermediate locals the Value references.

        Emitters consume the pair differently:
        - The Python emitter substitutes prelude instructions back
          into the guard's expression form so ``case PAT if EXPR:``
          stays a single expression (a guard like ``not t.done``
          lowers to a FieldAccess + UnaryOp pair that the emitter
          collapses back to ``(not t.done)``). Prelude shapes the
          emitter cannot inline (a free-function call with side
          effects, a MakeLambda, ...) trip
          ``UnsupportedInIR`` at emit time so the caller can fall
          back to the legacy direct-to-Python transpiler.
        - The Wasm emitter would emit prelude as a fall-through
          control-flow block before testing the guard Value, but
          that restructure has not landed; see
          ``capa/ir/_emit_wasm/_match.py``.

        Pre-2026-05-24 this raised ``UnsupportedInIR`` whenever
        prelude was non-empty, blocking ``examples/tasks.capa``
        (the ``High if not t.done`` arm) and any program with
        comparable guards from the CIR path. The IR now carries
        the prelude through; rejection moves to the emitter that
        actually cannot handle it."""
        outer = self._instrs
        self._instrs = []
        v = self._lower_expr(guard_expr)
        prelude = self._instrs
        self._instrs = outer
        return v, prelude


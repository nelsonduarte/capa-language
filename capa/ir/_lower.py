"""AST -> CIR lowering pass (Phase 1).

Walks a typed AST module and produces a CIR module covering the
subset listed in ``capa/ir/__init__.py``. Any construct outside the
subset raises ``UnsupportedInIR`` so the caller can fall back to the
legacy transpiler path.

The lowerer is ANF-flavoured: every sub-expression is bound to a
fresh local before its parent uses it. The Python emitter could
fold these back into nested expressions if it wanted; the cost of
the extra locals is one ``x = ...`` line per intermediate, which
Python's optimiser absorbs.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return,
    MakeStruct, MakeList, MakeTuple, MakeMap, MakeSet,
    FieldAccess, Index, FormatStr, For,
    TryUnwrap, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, PatTuple,
    MatchArm, Match,
    StructDecl, StructField, SumDecl, SumVariant, ImplBlock,
    TraitDecl, MethodSig, ConstDecl, ImportDecl,
    fresh_local,
)


# Built-in capabilities the analyzer recognises by type name. Used
# to set ``Param.is_capability``. Kept in sync with capa/builtins.py
# capability class list.
_BUILTIN_CAPS = {
    "Stdio", "Fs", "Net", "Env", "Clock", "Random", "Proc", "Db", "Unsafe",
}


class UnsupportedInIR(Exception):
    """Raised when the lowerer hits an AST node it does not yet
    handle. The caller (typically ``capa.ir.compile`` or a test) is
    expected to catch this and fall back to the legacy transpiler.
    The message identifies the unsupported shape so coverage can be
    extended incrementally."""

    def __init__(self, shape: str):
        super().__init__(f"CIR lowering does not yet support: {shape}")
        self.shape = shape


class Lowerer:
    def __init__(self, types: Optional[dict] = None):
        self.types = types or {}
        # Per-function state, reset on entry to each FunDecl.
        self._counter: dict = {"n": 0}
        self._instrs: list[Instr] = []
        self._locals: dict[str, str] = {}
        # Parameters of the function currently being lowered, used by
        # ``_lower_ident`` to decide between ``kind="param"`` and
        # ``kind="local"``. Stored as a name->ty mapping so the
        # emitter can resolve per-receiver method dispatch (a
        # parameter ``s: String`` must dispatch ``s.length()`` to
        # ``len(s)`` via the type).
        self._params: dict[str, str] = {}
        # Capability classes declared in the current function's
        # signature, used by ``_lower_method_call`` to flag
        # ``cap_used``. The set tracks parameter names that are
        # capability-typed (built-in caps for now; user-defined caps
        # are added in a later phase).
        self._cap_params: dict[str, str] = {}
        # Module-level identifiers (top-level consts and function
        # names). Populated by ``lower_module`` before any function is
        # lowered so that references to them inside function bodies
        # resolve to ``Value(kind="global")``.
        self._module_names: set[str] = set()
        # Payload-less sum-type variants. When the source uses one as
        # a bare value (``return Excellent``), the Python emitter must
        # construct it (``Excellent()``); ordinary identifier
        # resolution would produce just ``Excellent`` which is a class
        # object, not an instance.
        self._payloadless_variants: set[str] = set()
        # User-defined variant name -> ordered payload type names.
        # Populated by ``lower_module`` from every ``TypeSum`` in the
        # module so ``_refine_pattern_binds`` can recover the payload
        # types for non-built-in sums.
        self._user_variants: dict[str, list[str]] = {}
        # Lexical alpha-renaming. ``_locals`` is flat per function (a
        # Wasm function declares each local exactly once with one
        # type), but Capa source allows the same name to be bound in
        # sibling scopes with incompatible types (e.g. ``for c in
        # classified_txs`` then later ``Some(c) -> c`` in a match arm
        # where ``c: String``). Without alpha-renaming those two ``c``
        # bindings collide on a single Wasm local with conflicting
        # shapes. ``_alias_stack`` is a list of frames; each frame
        # maps source-level names to the renamed binding used in IR.
        # A binding that shadows an outer scope gets a fresh suffix
        # (``c__s17``) recorded in the current frame; ``_resolve_name``
        # walks the stack innermost-first so identifier references
        # inside the shadowing scope resolve to the fresh name.
        self._alias_stack: list[dict[str, str]] = [{}]

    # ------------------------------------------------------------
    # Module / function entry points.
    # ------------------------------------------------------------

    def lower_module(self, module: A.Module) -> Module:
        functions: list[Function] = []
        types: list = []
        impls: list = []
        traits: list = []
        consts: list = []
        imports: list = []
        # Pre-scan: collect every top-level identifier (const names and
        # function names) so that intra-module references resolve to a
        # module-scope global rather than tripping the unknown-ident
        # branch in ``_lower_ident``.
        self._module_names = {
            item.name
            for item in module.items
            if isinstance(item, (A.ConstDecl, A.FunDecl))
        }
        # Pre-scan: collect payload-less variant names from every
        # sum-type declaration. References to these as bare values
        # must construct the variant (``Excellent`` -> ``Excellent()``)
        # because the runtime class is not its own instance.
        # Also collect each variant's payload type names so pattern
        # lowering can thread types into bound identifiers.
        self._payloadless_variants = set()
        self._user_variants = {}
        # Seed payloadless built-in variants so the lowerer accepts
        # bare references like ``return Ok(JNull)`` or ``Some(None)``
        # without the user having to wrap them as ``JNull()``. The
        # analyzer-side ``VARIANTS`` table is the source of truth;
        # this list mirrors its payloadless rows.
        for v_name in ("None", "JNull"):
            self._payloadless_variants.add(v_name)
        for item in module.items:
            if isinstance(item, A.TypeSum):
                for v in item.variants:
                    if not v.payloads:
                        self._payloadless_variants.add(v.name)
                    self._user_variants[v.name] = [
                        _type_name(p) for p in v.payloads
                    ]
        for item in module.items:
            if isinstance(item, A.FunDecl):
                functions.append(self.lower_function(item))
            elif isinstance(item, A.TypeStruct):
                types.append(self._lower_struct_decl(item))
            elif isinstance(item, A.TypeSum):
                types.append(self._lower_sum_decl(item))
            elif isinstance(item, A.ImplBlock):
                impls.append(self._lower_impl_block(item))
            elif isinstance(item, A.TraitDecl):
                traits.append(self._lower_trait_decl(item))
            elif isinstance(item, A.ConstDecl):
                consts.append(self._lower_const_decl(item))
            elif isinstance(item, A.Import):
                imports.append(
                    ImportDecl(path=list(item.path), alias=item.alias)
                )
            else:
                raise UnsupportedInIR(
                    f"top-level item {type(item).__name__}"
                )
        return Module(
            functions=functions, types=types, impls=impls,
            traits=traits, consts=consts, imports=imports,
            ast_module=module,
        )

    def _lower_const_decl(self, c: A.ConstDecl) -> ConstDecl:
        # Constants live at module scope but their RHS uses the same
        # expression machinery as a function body. We reset per-
        # function state so the lowering's locals, counter, and
        # instruction buffer are scoped to this constant's body
        # alone. The emitted prelude (intermediate locals if the
        # expression has sub-computations) is bundled into ``body``;
        # the emitter renders the prelude as ordinary statements
        # before the final binding.
        outer_counter = self._counter
        outer_instrs = self._instrs
        outer_locals = self._locals
        outer_params = self._params
        outer_caps = self._cap_params
        outer_alias = self._alias_stack
        self._counter = {"n": 0}
        self._instrs = []
        self._locals = {}
        self._params = {}
        self._cap_params = {}
        self._alias_stack = [{}]
        value = self._lower_expr(c.value)
        # Final binding: ``name = value``. Reuse AssignConst so the
        # emitter can render it without a special case.
        self._instrs.append(AssignConst(dst=c.name, src=value))
        body = self._instrs
        ty = _type_name(c.type_expr) if c.type_expr else _ty_to_str(
            self.types.get(id(c.value), "Unknown") if self.types else "Unknown"
        )
        self._counter = outer_counter
        self._instrs = outer_instrs
        self._locals = outer_locals
        self._params = outer_params
        self._cap_params = outer_caps
        self._alias_stack = outer_alias
        return ConstDecl(name=c.name, ty=ty, body=body)

    def _lower_trait_decl(self, t: A.TraitDecl) -> TraitDecl:
        methods: list[MethodSig] = []
        for m in t.methods:
            ms_params = [
                Param(
                    name=p.name,
                    ty=_type_name(p.type_expr) if p.type_expr else "Unknown",
                    is_capability=(
                        _type_name(p.type_expr) in _BUILTIN_CAPS
                        if p.type_expr else False
                    ),
                )
                for p in m.params
            ]
            ret_ty = _type_name(m.return_type) if m.return_type else "Unit"
            methods.append(
                MethodSig(name=m.name, params=ms_params, return_type=ret_ty)
            )
        return TraitDecl(
            name=t.name, methods=methods, is_capability=t.is_capability,
        )

    def _lower_impl_block(self, impl: A.ImplBlock) -> ImplBlock:
        # Each method is lowered with the same machinery as a top-level
        # FunDecl. ``self`` becomes a regular parameter (the analyzer
        # has already typed it as the impl's target type).
        methods = [self.lower_function(m) for m in impl.methods]
        return ImplBlock(
            type_name=impl.type_name,
            trait_name=impl.trait_name,
            methods=methods,
        )

    def _lower_struct_decl(self, t: A.TypeStruct) -> StructDecl:
        fields = [
            StructField(name=f.name, ty=_type_name(f.type_expr))
            for f in t.fields
        ]
        return StructDecl(name=t.name, fields=fields)

    def _lower_sum_decl(self, t: A.TypeSum) -> SumDecl:
        variants = [
            SumVariant(
                name=v.name,
                payload_tys=[_type_name(p) for p in v.payloads],
            )
            for v in t.variants
        ]
        return SumDecl(name=t.name, variants=variants)

    # ------------------------------------------------------------
    # Lexical scope + alpha-renaming helpers.
    # ------------------------------------------------------------

    def _enter_scope(self) -> None:
        self._alias_stack.append({})

    def _exit_scope(self) -> None:
        self._alias_stack.pop()

    def _resolve_name(self, name: str) -> str:
        """Resolve a source-level identifier to its IR binding name,
        walking the alias stack innermost-first. Returns the original
        name when no alias is recorded (parameters, module-level
        identifiers, fresh ANF temporaries)."""
        for frame in reversed(self._alias_stack):
            if name in frame:
                return frame[name]
        return name

    def _bind_local(self, name: str, ty: str) -> str:
        """Bind ``name`` with type ``ty`` in the current scope.

        Three cases:
        - Same-scope rebinding (name already in current frame): reuse
          the same binding name; refine the recorded type when the new
          one is more specific than the existing one. Covers the
          ``_refine_pattern_binds`` -> ``_lower_pattern`` IdentPat
          handoff where two binding writes target the same scope.
        - Shadowing (name lives in ``_params`` or in ``_locals`` from
          an outer/sibling scope): generate a fresh ``name__sN`` binding
          and record the alias in the current frame.
        - Fresh binding: install ``name`` directly.

        Returns the binding name to use in the IR."""
        cur_frame = self._alias_stack[-1]
        if name in cur_frame:
            bound = cur_frame[name]
            existing = self._locals.get(bound, "Unknown")
            if existing == "Unknown" and ty != "Unknown":
                self._locals[bound] = ty
            return bound
        if name in self._params or name in self._locals:
            fresh = self._fresh_shadow(name)
            cur_frame[name] = fresh
            self._locals[fresh] = ty
            return fresh
        cur_frame[name] = name
        self._locals[name] = ty
        return name

    def _fresh_shadow(self, name: str) -> str:
        n = self._counter["n"]
        self._counter["n"] = n + 1
        return f"{name}__s{n}"

    def lower_function(self, fn: A.FunDecl) -> Function:
        # Reset per-function state.
        self._counter = {"n": 0}
        self._instrs = []
        self._locals = {}
        self._params = {}
        self._cap_params = {}
        self._alias_stack = [{}]

        params: list[Param] = []
        for p in fn.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in _BUILTIN_CAPS
            params.append(Param(name=p.name, ty=ty_name, is_capability=is_cap))
            self._params[p.name] = ty_name
            if is_cap:
                self._cap_params[p.name] = ty_name

        ret_ty = _type_name(fn.return_type) if fn.return_type else "Unit"
        declared_caps = sorted(set(self._cap_params.values()))

        self._lower_block(fn.body)

        return Function(
            name=fn.name,
            params=params,
            return_type=ret_ty,
            declared_caps=declared_caps,
            body=self._instrs,
            locals=dict(self._locals),
            type_params=list(fn.type_params),
        )

    # ------------------------------------------------------------
    # Blocks and statements.
    # ------------------------------------------------------------

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

    def _lower_let(self, s: A.LetStmt) -> None:
        # Ident pattern: ``let x = expr``. Tuple pattern:
        # ``let (a, b) = expr`` destructures positionally. Other
        # pattern shapes (Variant, Struct, Or) on the LHS of a let
        # are still deferred (they would need a one-arm match
        # lowering with an exhaustiveness check the analyzer has
        # already done).
        if isinstance(s.pattern, A.IdentPat):
            value = self._lower_expr(s.value)
            # Prefer the explicit type annotation when present and
            # concrete (see _lower_var for the rationale -- the
            # RHS expression's inferred type may be less specific
            # than the user's annotation, particularly for
            # ``new_map()`` / ``new_set()`` calls).
            ann_ty = _type_name(s.type_expr) if s.type_expr else None
            local_ty = (
                ann_ty if ann_ty and ann_ty != "Unknown"
                else value.ty
            )
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
        local_ty = (
            ann_ty if ann_ty and ann_ty != "Unknown"
            else value.ty
        )
        bound = self._bind_local(s.name, local_ty)
        self._instrs.append(AssignConst(dst=bound, src=value))

    def _lower_assign(self, s: A.AssignStmt) -> None:
        # Plain ``x = expr`` lowers directly; compound assignments
        # (``+=``, ``-=``, ``*=``, ``/=``, ``%=``) rewrite to
        # ``x = x <op> expr`` at the IR level. LHS-as-FieldAccess /
        # Index targets are still deferred.
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
        # Phase 2 only supports Ident patterns. Tuple destructuring
        # (``for (a, b) in pairs``) is deferred.
        if not isinstance(s.pattern, A.IdentPat):
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
        elif iter_value.ty.startswith("Range"):
            bind_ty = "Int"
        self._enter_scope()
        bound = self._bind_local(s.pattern.name, bind_ty)
        outer = self._instrs
        self._instrs = []
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

    def _refine_pattern_binds(self, p: A.Pattern, scrut_ty: str) -> None:
        """Best-effort: thread the scrutinee's type into pattern-bound
        identifier locals so downstream method dispatch sees the
        right receiver type. Without this, ``Some(m) -> m.get(k)``
        sees ``m: Unknown`` and skips the type-aware Map/List/String
        rewrite. We handle Option, Result, and user-defined sum
        types where the lowerer has the variant decl's payload types
        in scope. Tuple patterns recurse element-by-element using
        the per-position types parsed out of the scrutinee's tuple
        type string. A top-level IdentPat catch-all binds the whole
        scrutinee, so the binder takes the scrutinee's type directly;
        without this the Wasm backend declared the local as the
        Unknown-default ``i64`` and the assignment from an i32
        scrutinee (Bool, tuple pointer) tripped the validator."""
        if isinstance(p, A.IdentPat):
            self._bind_local(p.name, scrut_ty)
            return
        if isinstance(p, A.TuplePat):
            elem_tys = _split_tuple_elem_types(scrut_ty)
            for idx, sub in enumerate(p.elements):
                ety = elem_tys[idx] if idx < len(elem_tys) else "Unknown"
                if isinstance(sub, A.IdentPat):
                    self._bind_local(sub.name, ety)
                else:
                    self._refine_pattern_binds(sub, ety)
            return
        if not isinstance(p, A.VariantPat) or not p.payloads:
            return
        payload_tys = self._variant_payload_tys(p.name, scrut_ty)
        if payload_tys is None or len(payload_tys) != len(p.payloads):
            return
        for sub, ty in zip(p.payloads, payload_tys):
            if isinstance(sub, A.IdentPat):
                self._bind_local(sub.name, ty)
            else:
                # Nested patterns share the same refinement rule.
                self._refine_pattern_binds(sub, ty)

    def _variant_payload_tys(
        self, variant_name: str, scrut_ty: str,
    ) -> Optional[list[str]]:
        """Return the payload type(s) bound by ``Variant(...)`` when
        the scrutinee has type ``scrut_ty``. Handles the built-in
        ``Option<T>`` / ``Result<T, E>`` shapes via string parsing,
        and user-defined sums via the pre-collected ``_user_variants``
        table populated by ``lower_module``."""
        if scrut_ty.startswith("Option<") and scrut_ty.endswith(">"):
            inner = scrut_ty[7:-1]
            if variant_name == "Some":
                return [inner]
            if variant_name == "None":
                return []
        if scrut_ty.startswith("Result<") and scrut_ty.endswith(">"):
            inner = scrut_ty[7:-1]
            t, e = _split_top_level_comma(inner)
            if variant_name == "Ok":
                return [t]
            if variant_name == "Err":
                return [e]
        if variant_name in self._user_variants:
            return list(self._user_variants[variant_name])
        return None

    def _lower_pattern(self, p: A.Pattern) -> Pattern:
        """Translate an AST pattern to its IR shape. Phase 2D supports
        Wildcard, Ident, Literal (Int / String / Bool / Unit), and
        Variant (with payloads). Other shapes (Struct, Tuple, Or)
        raise UnsupportedInIR until a later phase handles them."""
        if isinstance(p, A.WildcardPat):
            return PatWildcard()
        if isinstance(p, A.IdentPat):
            # Track the binding name as a local in the arm scope so
            # that the arm body can reference it. ``_bind_local``
            # preserves any refinement that ``_refine_pattern_binds``
            # may have written before us (same-frame rebinding keeps
            # the more specific type); when the name shadows an outer
            # binding it gets a fresh alpha-renamed identifier so the
            # two Wasm locals don't collide on incompatible shapes.
            bound = self._bind_local(p.name, "Unknown")
            return PatIdent(name=bound)
        if isinstance(p, A.LiteralPat):
            return self._lower_literal_pattern(p)
        if isinstance(p, A.VariantPat):
            payloads = [self._lower_pattern(sub) for sub in p.payloads]
            return PatVariant(name=p.name, payloads=payloads)
        if isinstance(p, A.TuplePat):
            elements = [self._lower_pattern(sub) for sub in p.elements]
            return PatTuple(elements=elements)
        raise UnsupportedInIR(f"match pattern {type(p).__name__}")

    def _lower_literal_pattern(self, p: A.LiteralPat) -> Pattern:
        v = p.value
        if isinstance(v, A.IntLit):
            return PatLiteral(kind="int", value=v.value)
        if isinstance(v, A.StringLit):
            return PatLiteral(kind="str", value=v.value)
        if isinstance(v, A.BoolLit):
            return PatLiteral(kind="bool", value=v.value)
        if isinstance(v, A.UnitLit):
            return PatLiteral(kind="unit", value=None)
        raise UnsupportedInIR(
            f"literal pattern of kind {type(v).__name__}"
        )

    # ------------------------------------------------------------
    # Expressions: each returns a Value.
    # ------------------------------------------------------------

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
        raise UnsupportedInIR(f"expression {type(e).__name__}")

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
            is_cap = ty_name in _BUILTIN_CAPS
            lambda_params.append(
                Param(name=p.name, ty=ty_name, is_capability=is_cap)
            )
            self._params[p.name] = ty_name
            if is_cap:
                self._cap_params[p.name] = ty_name
        # Body: an expression body produces a value the lambda must
        # ``return``; a block body lowers as a sequence of statements
        # with explicit ``return`` (the analyzer guarantees a Unit
        # return for fall-off cases, which our emitter matches via the
        # natural fall-through).
        self._enter_scope()
        if isinstance(e.body, A_local.Block):
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
        if e.name in _BUILTIN_CAPS:
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
        receiver = self._lower_expr(e.receiver)
        args = [self._lower_expr(arg) for arg in e.args]
        cap_used: Optional[str] = None
        # If the receiver is a capability-typed parameter, record the
        # capability class so the manifest builder can attribute this
        # method invocation.
        if receiver.kind == "param" and receiver.name in self._cap_params:
            cap_used = self._cap_params[receiver.name]
        elif (receiver.ty or "").split("<", 1)[0] in _BUILTIN_CAPS:
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
                args=args, cap_used=cap_used,
            )
        )
        return Value(kind="local", name=dst, ty=result_ty)


# ----------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------

def _type_name(te: object) -> str:
    """Best-effort name for a TypeExpr or Ty. Phase 1 only needs the
    string form for the Python emitter; structured Ty access can come
    later via the type map. ``FunType`` is rendered as
    ``Fun(P1, P2) -> R`` so backends that pattern-match the type
    string (the Wasm closure-signature lookup, for instance) can
    recognise it."""
    if te is None:
        return "Unknown"
    if isinstance(te, str):
        return te
    # FunType: render as ``Fun(P1, P2) -> R`` to match the canonical
    # Capa source syntax and the Wasm emitter's sig-key parser.
    if te.__class__.__name__ == "FunType":
        params = ", ".join(_type_name(p) for p in te.param_types)
        ret = _type_name(te.return_type)
        return f"Fun({params}) -> {ret}"
    # TupleType: render as ``(T1, T2, ...)`` to match the Capa
    # source syntax. Empty tuple renders as ``()`` (i.e., Unit
    # alias). Without this branch the fall-through to ``repr(te)``
    # would put the raw AST node text into a ``ty`` string, which
    # tripped the Wasm emitter with "Capa type '<AST repr>' has no
    # Wasm encoding" -- visible only on bare tuple parameters
    # (``cand: (String, Int)``); wrapped forms like
    # ``List<(String, Int)>`` short-circuited via the
    # ``head in ("List", ...)`` check in ``_wasm_type``.
    if te.__class__.__name__ == "TupleType":
        inner = ", ".join(_type_name(e) for e in te.elements)
        return f"({inner})"
    if hasattr(te, "name"):
        # Parametric types (List<T>, Map<K, V>, Option<T>, user-
        # defined generics) carry their args in ``te.args``; render
        # them in the canonical ``Name<A, B>`` form so downstream
        # consumers (for-iter element extraction, method dispatch
        # on receiver type, Wasm size_of) can parse them back.
        args = getattr(te, "args", None) or []
        if args:
            inner = ", ".join(_type_name(a) for a in args)
            return f"{te.name}<{inner}>"
        return te.name
    return _ty_to_str(te)


def _split_tuple_elem_types(ty: str) -> list[str]:
    """``(String, Int)`` -> ``['String', 'Int']``. Returns an empty
    list when ``ty`` isn't shaped like a parenthesised tuple, so
    callers can fall back to per-element ``Unknown``."""
    if not ty.startswith("(") or not ty.endswith(")"):
        return []
    inner = ty[1:-1].strip()
    if not inner:
        return []
    out: list[str] = []
    buf = ""
    depth = 0
    for ch in inner:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(buf.strip())
            buf = ""
            continue
        buf += ch
    if buf.strip():
        out.append(buf.strip())
    return out


def _split_top_level_comma(s: str) -> tuple[str, str]:
    """Split ``"T, Map<K, V>"`` into ``("T", "Map<K, V>")`` by
    counting angle brackets AND parentheses so commas inside
    nested ``<...>`` or tuple ``(...)`` shapes don't split. For
    example ``"(JsonValue, Int), String"`` splits into
    ``("(JsonValue, Int)", "String")``. Returns the whole string
    and an empty string if there is no comma at depth zero, which
    matches Result with a single generic arg (unusual but
    possible)."""
    depth = 0
    for i, ch in enumerate(s):
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        elif ch == "," and depth == 0:
            return s[:i].strip(), s[i + 1:].strip()
    return s.strip(), ""


def _ty_to_str(t: object) -> str:
    """Convert a typesys Ty to a string. Falls back to ``repr`` for
    unknown shapes; the Python emitter does not consume this string.

    Capa's analyzer renders function types as ``fun(...) -> R``
    (lowercase). The IR's downstream consumers (Wasm emitter
    closure machinery, in particular) match against the
    ``Fun(...)`` form used by the AST-side rendering, so we
    normalise the prefix here to keep the two paths in lockstep.
    """
    try:
        from ..typesys import ty_str
        s = ty_str(t)
    except Exception:
        return repr(t)
    if s.startswith("fun("):
        return "Fun" + s[3:]
    return s

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
    MakeStruct, MakeList, MakeTuple, FieldAccess, Index, FormatStr, For,
    TryUnwrap, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant,
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
        # ``kind="local"``.
        self._params: set[str] = set()
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
        self._counter = {"n": 0}
        self._instrs = []
        self._locals = {}
        self._params = set()
        self._cap_params = {}
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

    def lower_function(self, fn: A.FunDecl) -> Function:
        # Reset per-function state.
        self._counter = {"n": 0}
        self._instrs = []
        self._locals = {}
        self._params = set()
        self._cap_params = {}

        params: list[Param] = []
        for p in fn.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in _BUILTIN_CAPS
            params.append(Param(name=p.name, ty=ty_name, is_capability=is_cap))
            self._params.add(p.name)
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
        # Phase 1 supports only Ident patterns on the left side.
        if not isinstance(s.pattern, A.IdentPat):
            raise UnsupportedInIR(
                f"let-pattern {type(s.pattern).__name__}"
            )
        name = s.pattern.name
        value = self._lower_expr(s.value)
        # If the source value is already a single Value, bind directly.
        # Otherwise the expression lowering will have produced
        # instructions that ended with the result in a temp; chain
        # an extra AssignConst to give that result the user's name.
        self._locals[name] = value.ty
        self._instrs.append(AssignConst(dst=name, src=value))

    def _lower_var(self, s: A.VarStmt) -> None:
        # ``var x = expr``: same Python emission as ``let``, but the
        # IR records both kinds so future backends can enforce
        # immutability of let-bindings. Phase 2 collapses both to
        # AssignConst for simplicity; a follow-up may add a
        # ``mutable`` flag to AssignConst when a Wasm or LLVM target
        # cares.
        value = self._lower_expr(s.value)
        self._locals[s.name] = value.ty
        self._instrs.append(AssignConst(dst=s.name, src=value))

    def _lower_assign(self, s: A.AssignStmt) -> None:
        # Phase 2 only handles plain ``x = expr`` on a bare ident.
        # Compound assignment (``x += y``) and lhs-as-FieldAccess /
        # Index targets are deferred.
        if s.op != "=":
            raise UnsupportedInIR(
                f"compound assignment operator {s.op!r}"
            )
        if not isinstance(s.target, A.Ident):
            raise UnsupportedInIR(
                f"assignment target {type(s.target).__name__}"
            )
        value = self._lower_expr(s.value)
        self._instrs.append(Reassign(dst=s.target.name, src=value))

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
        self._lower_block(s.then_block)
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
            self._lower_block(else_block)
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
        self._lower_block(body)
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
        self._lower_block(s.body)
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
        self._locals[s.pattern.name] = "Unknown"
        outer = self._instrs
        self._instrs = []
        self._lower_block(s.body)
        body = self._instrs
        self._instrs = outer
        self._instrs.append(
            For(name=s.pattern.name, iter=iter_value, body=body)
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
            if arm.guard is not None:
                raise UnsupportedInIR("match arm with guard")
            pat = self._lower_pattern(arm.pattern)
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
            arms.append(MatchArm(pattern=pat, body=body, guard=None))
        self._instrs.append(Match(scrutinee=scrut, arms=arms, result_dst=None))

    def _lower_pattern(self, p: A.Pattern) -> Pattern:
        """Translate an AST pattern to its IR shape. Phase 2D supports
        Wildcard, Ident, Literal (Int / String / Bool / Unit), and
        Variant (with payloads). Other shapes (Struct, Tuple, Or)
        raise UnsupportedInIR until a later phase handles them."""
        if isinstance(p, A.WildcardPat):
            return PatWildcard()
        if isinstance(p, A.IdentPat):
            # Track the binding name as a local in the arm scope so
            # that the arm body can reference it. The type is left
            # Unknown because the analyzer's pattern-binding type is
            # not carried through the AST node we have here.
            self._locals[p.name] = "Unknown"
            return PatIdent(name=p.name)
        if isinstance(p, A.LiteralPat):
            return self._lower_literal_pattern(p)
        if isinstance(p, A.VariantPat):
            payloads = [self._lower_pattern(sub) for sub in p.payloads]
            return PatVariant(name=p.name, payloads=payloads)
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
        raise UnsupportedInIR(f"expression {type(e).__name__}")

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
        self._params = set(outer_params)
        self._cap_params = dict(outer_caps)
        lambda_params: list[Param] = []
        for p in e.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in _BUILTIN_CAPS
            lambda_params.append(
                Param(name=p.name, ty=ty_name, is_capability=is_cap)
            )
            self._params.add(p.name)
            if is_cap:
                self._cap_params[p.name] = ty_name
        # Body: an expression body produces a value the lambda must
        # ``return``; a block body lowers as a sequence of statements
        # with explicit ``return`` (the analyzer guarantees a Unit
        # return for fall-off cases, which our emitter matches via the
        # natural fall-through).
        if isinstance(e.body, A_local.Block):
            self._lower_block(e.body)
        else:
            v = self._lower_expr(e.body)
            self._instrs.append(Return(value=v))
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
        if e.name in self._params:
            ty = self._cap_params.get(e.name) or self._locals.get(e.name) or "Unknown"
            return Value(kind="param", name=e.name, ty=ty)
        if e.name in self._locals:
            return Value(kind="local", name=e.name, ty=self._locals[e.name])
        if e.name in self._module_names:
            # A reference to a top-level constant or a function name
            # used as a value (e.g. higher-order use). Treated as a
            # Python-level global; the emitter renders ``Value`` as
            # the bare name.
            return Value(kind="global", name=e.name, ty="Unknown")
        if e.name in _BUILTIN_CAPS:
            return Value(kind="cap_const", name=e.name, ty=e.name)
        raise UnsupportedInIR(f"identifier reference {e.name!r}")

    def _lower_binop(self, e: A.BinOp) -> Value:
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
        result_ty = "Tuple"
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
    later via the type map."""
    if te is None:
        return "Unknown"
    if isinstance(te, str):
        return te
    if hasattr(te, "name"):
        return getattr(te, "name")
    return _ty_to_str(te)


def _ty_to_str(t: object) -> str:
    """Convert a typesys Ty to a string. Falls back to ``repr`` for
    unknown shapes; the Python emitter does not consume this string."""
    try:
        from ..typesys import ty_str
        return ty_str(t)
    except Exception:
        return repr(t)

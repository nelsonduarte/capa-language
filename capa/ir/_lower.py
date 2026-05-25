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


from ._capa_types import BUILTIN_CAPS
from ._lower_expr import _LowerExprMixin
from ._lower_helpers import (
    _type_name, _split_tuple_elem_types, _split_top_level_comma, _ty_to_str,
)
from ._lower_pattern import _LowerPatternMixin
from ._lower_stmt import _LowerStmtMixin


class UnsupportedInIR(Exception):
    """Raised when the lowerer hits an AST node it does not yet
    handle. The caller (typically ``capa.ir.compile`` or a test) is
    expected to catch this and fall back to the legacy transpiler.
    The message identifies the unsupported shape so coverage can be
    extended incrementally."""

    def __init__(self, shape: str):
        super().__init__(f"CIR lowering does not yet support: {shape}")
        self.shape = shape


class Lowerer(
    _LowerExprMixin,
    _LowerStmtMixin,
    _LowerPatternMixin,
):
    def __init__(self, types: Optional[dict] = None):
        self.types = types or {}
        # Per-function state, reset on entry to each FunDecl.
        self._counter: dict = {"n": 0}
        self._instrs: list[Instr] = []
        self._locals: dict[str, str] = {}
        # Per-function attenuation map produced by
        # ``_build_attenuation_map`` (intra-function flow of
        # ``restrict_to`` / ``restrict_to_keys`` /
        # ``restrict_to_after`` / ``with_seed`` chains). Keyed by
        # source-level binding name; consulted in
        # ``_lower_method_call`` to tag privileged-op MethodCalls
        # with their effective attenuation list, which the Wasm
        # backend turns into inline runtime checks.
        self._attenuation_map: dict[str, list] = {}
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
                        _type_name(p.type_expr) in BUILTIN_CAPS
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
        # Build the intra-function attenuation map from the AST
        # body before lowering. Keyed by source-level binding name;
        # populated by ``_lower_method_call`` into IR MethodCall's
        # ``attenuations`` field whenever a privileged op is dispatched
        # on a tracked binding. Manifests / Wasm backend share the
        # same flow analyser (see ``capa.manifest._flow``).
        from ..manifest._flow import _build_attenuation_map
        self._attenuation_map = _build_attenuation_map(fn.body)

        params: list[Param] = []
        for p in fn.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in BUILTIN_CAPS
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

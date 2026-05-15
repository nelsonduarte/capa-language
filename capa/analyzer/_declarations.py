"""Phase-1 global-declarations mixin.

Six methods, run before any expression is type-checked:

- ``_collect_globals``: walk the module, register every
  top-level name as a Symbol, and resolve struct fields, sum
  variant payloads, constant types, function signatures, and
  trait method signatures into actual ``Ty`` values.
- ``_register_impl_methods``: attach impl-block methods to the
  target type's Symbol; record the trait/capability the type
  implements.
- ``_method_type_from_decl``: compute a method's TyFun
  (excluding ``self``).
- ``_fun_type_from_decl``: compute a function's TyFun.
- ``_declare_global``: add a Symbol to the global scope,
  rejecting duplicates (with built-ins exempted).
- ``_resolve_type``: convert an AST ``TypeExpr`` into the
  analyzer's runtime ``Ty`` representation.

The mixin assumes ``self`` has the state set up by
``Analyzer.__init__`` (``global_scope``, ``self_type``, the
type-param stack, ``errors`` via ``_err``) and pulls helpers
from other mixins (``_check_no_capability``,
``_check_no_builtin_capability``, ``_is_user_capability``,
``_hint_did_you_mean``, ``_type_names``, ``_push_type_params``,
``_pop_type_params``, ``_is_type_param_in_scope``).
"""

from __future__ import annotations

from .. import capa_ast as A
from ..builtins import BUILTIN_POS as _BUILTIN_POS
from ..typesys import (
    Ty, TyFun, TyName, TyTuple, TyUnit, TyUnknown, TyVar,
)


class _DeclarationsMixin:
    def _collect_globals(self, module: A.Module) -> None:
        from . import Symbol, SymbolKind

        for item in module.items:
            if isinstance(item, A.Import):
                # ``import`` is resolved by ``capa.loader.ModuleLoader``
                # before the module reaches the analyzer: imported
                # files are merged in-place and the original Import
                # nodes are stripped. If we still see one here, the
                # analyzer was called directly on a parsed (not
                # linked) module; that path is fine for unit tests
                # of the analyzer itself, but emit no error and no
                # symbol so the analyzer just ignores the directive.
                continue
            elif isinstance(item, A.ConstDecl):
                # Type resolved in the next sub-pass once all
                # top-level decls are registered.
                self._declare_global(
                    Symbol(
                        name=item.name, kind=SymbolKind.CONSTANT,
                        pos=item.pos,
                    )
                )
            elif isinstance(item, A.TypeStruct):
                sym = Symbol(
                    name=item.name, kind=SymbolKind.TYPE_STRUCT,
                    pos=item.pos, type_params=list(item.type_params),
                )
                self._declare_global(sym)
            elif isinstance(item, A.TypeSum):
                sym = Symbol(
                    name=item.name, kind=SymbolKind.TYPE_SUM,
                    pos=item.pos, type_params=list(item.type_params),
                )
                self._declare_global(sym)
                for v in item.variants:
                    if v.name in self.global_scope.symbols:
                        existing = self.global_scope.symbols[v.name]
                        # Collisions with built-ins are silently
                        # ignored (a user variant named ``None``
                        # is fine as long as it is not used in
                        # the same context); collisions between
                        # user types are reported.
                        if existing.pos is not _BUILTIN_POS:
                            self._err(
                                f"variant {v.name!r} conflicts with another "
                                f"declaration at {existing.pos}",
                                v.pos,
                            )
                            continue
                    vsym = Symbol(
                        name=v.name, kind=SymbolKind.VARIANT, pos=v.pos,
                        variant_owner=sym,
                    )
                    sym.sum_variants[v.name] = vsym
                    self.global_scope.define(vsym)
            elif isinstance(item, A.TraitDecl):
                # ``capability X`` lands as SymbolKind.CAPABILITY
                # so the discipline checks treat it identically
                # to a built-in cap. ``trait X`` lands as
                # SymbolKind.TRAIT. Method dispatch and impl
                # checking are the same in both cases.
                kind = (
                    SymbolKind.CAPABILITY if item.is_capability
                    else SymbolKind.TRAIT
                )
                sym = Symbol(
                    name=item.name, kind=kind, pos=item.pos,
                    type_params=list(item.type_params),
                    trait_methods={m.name for m in item.methods},
                )
                self._declare_global(sym)
            elif isinstance(item, A.FunDecl):
                self._declare_global(
                    Symbol(
                        name=item.name, kind=SymbolKind.FUNCTION,
                        pos=item.pos, type_params=list(item.type_params),
                    )
                )
            elif isinstance(item, A.ImplBlock):
                pass  # impls only add methods to the target type

        # Intermediate sub-pass: identify structs that implement
        # a user-defined capability. They are exempt from the
        # "no capability as struct field" rule so they can
        # encapsulate built-in caps (the user-defined-cap
        # implementor pattern).
        self._cap_bearing_structs: set[str] = set()
        for item in module.items:
            if not isinstance(item, A.ImplBlock):
                continue
            if item.trait_name is None:
                continue
            if self._is_user_capability(item.trait_name):
                self._cap_bearing_structs.add(item.type_name)

        # Second sub-pass: with all type names in scope, resolve
        # struct field types, variant payloads, constants,
        # function signatures, and trait method signatures.
        for item in module.items:
            if isinstance(item, A.TypeStruct):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                self._push_type_params(item.type_params)
                is_cap_bearing = item.name in self._cap_bearing_structs
                for fld in item.fields:
                    fty = self._resolve_type(fld.type_expr)
                    if not is_cap_bearing:
                        self._check_no_capability(
                            fty, fld.pos, f"struct field {fld.name!r}",
                        )
                    sym.struct_fields[fld.name] = fty
                self._pop_type_params()
            elif isinstance(item, A.TypeSum):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                self._push_type_params(item.type_params)
                for v in item.variants:
                    vsym = sym.sum_variants.get(v.name)
                    if vsym is None:
                        continue
                    if v.payload is not None:
                        pty = self._resolve_type(v.payload)
                        self._check_no_capability(
                            pty, v.pos,
                            f"payload of variant {v.name!r}",
                        )
                        vsym.variant_payload_ty = pty
                self._pop_type_params()
            elif isinstance(item, A.ConstDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is not None:
                    sym.ty = self._resolve_type(item.type_expr)
                    self._check_no_capability(
                        sym.ty, item.pos, f"constant {item.name!r}",
                    )
            elif isinstance(item, A.FunDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is not None:
                    sym.ty = self._fun_type_from_decl(item)
                    sym.consuming_params = [
                        p.consuming for p in item.params if p.name != "self"
                    ]
                    sym.param_names = [
                        p.name for p in item.params if p.name != "self"
                    ]
                    if isinstance(sym.ty, TyFun):
                        # Only built-in capabilities are
                        # forbidden as return types. User-defined
                        # caps can be returned by factories.
                        self._check_no_builtin_capability(
                            sym.ty.ret, item.pos,
                            f"return type of function {item.name!r}",
                        )
            elif isinstance(item, A.TraitDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                self._push_type_params(item.type_params)
                prev_self = self.self_type
                self.self_type = TyName("Self")
                for method in item.methods:
                    fty = self._method_type_from_decl(method)
                    if isinstance(fty, TyFun):
                        sym.trait_method_sigs[method.name] = fty
                self.self_type = prev_self
                self._pop_type_params()

        # Third sub-pass: register impl methods on the target
        # type symbols. Must come after the second sub-pass
        # because method-type computation may depend on fully
        # resolved types.
        for item in module.items:
            if isinstance(item, A.ImplBlock):
                self._register_impl_methods(item)

    def _register_impl_methods(self, impl: A.ImplBlock) -> None:
        """Attach impl-block methods to the target type's Symbol.
        Records the implemented trait/capability on
        ``target.implements`` so the compatibility check accepts
        the target where the trait/cap is expected."""
        from . import Symbol, SymbolKind

        target = self.global_scope.lookup(impl.type_name)
        if target is None or target.kind not in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
        ):
            return
        if impl.trait_name is not None:
            target.implements.add(impl.trait_name)
        self_args = tuple(TyVar(p) for p in target.type_params)
        prev_self = self.self_type
        self.self_type = TyName(impl.type_name, self_args)
        self._push_type_params(target.type_params)

        for method in impl.methods:
            if method.name in target.methods:
                self._err(
                    f"duplicate method {method.name!r} in impl of "
                    f"{impl.type_name!r}",
                    method.pos,
                )
                continue
            fty = self._method_type_from_decl(method)
            m_sym = Symbol(
                name=method.name, kind=SymbolKind.FUNCTION,
                pos=method.pos, ty=fty,
                type_params=list(method.type_params),
                consuming_params=[
                    p.consuming for p in method.params if p.name != "self"
                ],
                param_names=[
                    p.name for p in method.params if p.name != "self"
                ],
            )
            target.methods[method.name] = m_sym

        self._pop_type_params()
        self.self_type = prev_self

    def _method_type_from_decl(self, method: A.FunDecl) -> Ty:
        """Compute the ``TyFun`` of a method, **excluding** the
        ``self`` parameter; the receiver is handled separately
        in :meth:`_check_method_call`."""
        self._push_type_params(method.type_params)
        params: list[Ty] = []
        for p in method.params:
            if p.name == "self":
                continue
            if p.type_expr is None:
                params.append(TyUnknown)
            else:
                params.append(self._resolve_type(p.type_expr))
        ret = (
            self._resolve_type(method.return_type)
            if method.return_type else TyUnit
        )
        self._pop_type_params()
        return TyFun(tuple(params), ret)

    def _declare_global(self, sym) -> None:
        """Define a Symbol in the global scope, rejecting
        duplicates. Built-in Symbols (``pos == _BUILTIN_POS``)
        are exempted so user code can shadow primitives without
        a spurious error."""
        existing = self.global_scope.lookup_local(sym.name)
        if existing is not None and existing.pos is not _BUILTIN_POS:
            self._err(
                f"duplicate top-level declaration {sym.name!r}; previously "
                f"declared at {existing.pos}",
                sym.pos,
            )
            return
        self.global_scope.define(sym)

    def _fun_type_from_decl(self, fn: A.FunDecl) -> Ty:
        """Compute a function's ``TyFun``."""
        self._push_type_params(fn.type_params)
        params: list[Ty] = []
        for p in fn.params:
            if p.name == "self" and p.type_expr is None:
                params.append(TyUnknown)
            elif p.type_expr is None:
                params.append(TyUnknown)
            else:
                params.append(self._resolve_type(p.type_expr))
        ret = (
            self._resolve_type(fn.return_type)
            if fn.return_type else TyUnit
        )
        self._pop_type_params()
        return TyFun(tuple(params), ret)

    def _resolve_type(self, te: A.TypeExpr) -> Ty:
        """Convert an AST ``TypeExpr`` into the analyzer's
        runtime ``Ty`` representation. Handles primitives, the
        ``Self`` keyword, generic type params in scope, and
        nominal type lookups in the global scope."""
        from . import SymbolKind

        if isinstance(te, A.UnitType):
            return TyUnit
        if isinstance(te, A.TupleType):
            return TyTuple(tuple(
                self._resolve_type(e) for e in te.elements
            ))
        if isinstance(te, A.FunType):
            return TyFun(
                tuple(self._resolve_type(p) for p in te.param_types),
                self._resolve_type(te.return_type),
            )
        if isinstance(te, A.TypeName):
            name = te.name
            if name == "Unit" and not te.args:
                return TyUnit
            if name == "Self":
                if self.self_type is None:
                    self._err(
                        "'Self' is only valid inside an impl or trait",
                        te.pos,
                    )
                    return TyUnknown
                return self.self_type
            if self._is_type_param_in_scope(name):
                if te.args:
                    self._err(
                        f"type parameter {name!r} cannot have type arguments",
                        te.pos,
                    )
                return TyVar(name)
            sym = self.global_scope.lookup(name)
            if sym is None:
                hint = self._hint_did_you_mean(name, self._type_names())
                self._err(f"undefined type {name!r}{hint}", te.pos)
                return TyUnknown
            if sym.kind not in (
                SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
                SymbolKind.TRAIT, SymbolKind.CAPABILITY,
            ):
                self._err(
                    f"{name!r} is not a type "
                    f"(it is a {sym.kind.name.lower().replace('_', ' ')})",
                    te.pos,
                )
                return TyUnknown
            args = tuple(self._resolve_type(a) for a in te.args)
            return TyName(name, args)
        return TyUnknown

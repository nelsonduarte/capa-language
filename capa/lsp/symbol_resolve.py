"""Resolution helpers for decl-site cursor positions.

A reference Ident resolves to a Symbol via ``result.bindings``.
A *declaration* site has no Ident in the AST (declared names
live as strings on their decl node), so the LSP fakes one via
:class:`DeclSite` and resolves to a Symbol through tables on the
analysis result: ``global_symbols`` for top-level names,
``sum_variants`` for sum-type variants, ``trait_method_sigs`` for
trait method signatures, ``struct_fields`` for struct fields.
Parameters require walking the enclosing function's body
bindings (the analyzer does not expose function-local scopes).
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..analyzer import AnalysisResult, Symbol, SymbolKind
from .context import DeclSite, walk


def resolve_decl_symbol(
    site: DeclSite, result: AnalysisResult, module: A.Module,
) -> Optional[Symbol]:
    """Find the Symbol for a declaration site.

    Returns a real Symbol from the analysis result when the
    declaration kind is backed by one (globals, variants). Returns
    a synthetic Symbol carrying the right type / kind for kinds
    that the analyzer does not file as first-class symbols
    (trait method signatures, struct fields, parameters).
    """
    if site.decl_kind == "global":
        if site.container_name is None:
            return result.global_symbols.get(site.ident.name)
        # Impl method: look it up on the target type's methods.
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        return owner.methods.get(site.ident.name)

    if site.decl_kind == "variant":
        for s in result.global_symbols.values():
            if s.kind == SymbolKind.TYPE_SUM:
                v = s.sum_variants.get(site.ident.name)
                if v is not None:
                    return v
        return None

    if site.decl_kind == "method_sig":
        if site.container_name is None:
            return None
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        ty = owner.trait_method_sigs.get(site.ident.name)
        if ty is None:
            return None
        return Symbol(
            name=site.ident.name, kind=SymbolKind.FUNCTION,
            pos=site.ident.pos, ty=ty,
        )

    if site.decl_kind == "field":
        if site.container_name is None:
            return None
        owner = result.global_symbols.get(site.container_name)
        if owner is None:
            return None
        fty = owner.struct_fields.get(site.ident.name)
        if fty is None:
            return None
        return Symbol(
            name=site.ident.name, kind=SymbolKind.LOCAL,
            pos=site.ident.pos, ty=fty,
        )

    if site.decl_kind == "param":
        if site.container_name is None:
            return None
        target_fn = find_fundecl(module, site.container_name)
        if target_fn is None:
            return None
        # Find any use of the param inside the body that resolves
        # to a PARAM symbol with this name. That gives us the
        # real Symbol the analyzer interned for the parameter.
        body_idents = [
            n for n in walk(target_fn.body) if isinstance(n, A.Ident)
        ]
        for ident in body_idents:
            sym = result.bindings.get(id(ident))
            if (
                sym is not None
                and sym.kind == SymbolKind.PARAM
                and sym.name == site.ident.name
            ):
                return sym
        # Param exists in the parameter list but is unused inside
        # the body. Synthesise a stand-in so hover etc. still work.
        for p in target_fn.params:
            if p.name == site.ident.name and p.type_expr is not None:
                return Symbol(
                    name=p.name, kind=SymbolKind.PARAM,
                    pos=site.ident.pos,
                )
        return None

    return None


def find_fundecl(
    module: A.Module, name: str,
) -> Optional[A.FunDecl]:
    """Locate a FunDecl by name across top-level items and impl
    blocks. Returns the first match; method names are not unique
    across impls but the LSP use cases only care about which
    function scope to search."""
    for item in module.items:
        if isinstance(item, A.FunDecl) and item.name == name:
            return item
        if isinstance(item, A.ImplBlock):
            for m in item.methods:
                if m.name == name:
                    return m
    return None

"""``textDocument/hover`` implementation."""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..analyzer import Symbol, SymbolKind
from ..typesys import Ty, TyFun, ty_str
from .context import LspContext, find_decl_site_at, find_ident_at
from .symbol_resolve import resolve_decl_symbol


def compute_hover(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[str, A.Ident]]:
    """Compute the hover content (Markdown) and the source range
    to highlight when the cursor sits at the 1-based
    ``(line, col)`` position. Returns ``None`` when the position
    is not inside a recognised identifier or the analyzer has no
    binding to report (the file may have parse errors).

    The returned tuple is ``(markdown, ident)``: the ident is
    surfaced so the caller can build an LSP range from its span.
    """
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None

    # 1) Try a reference Ident at the cursor.
    ident = find_ident_at(ctx.idents, line, col)
    if ident is not None:
        sym = ctx.result.bindings.get(id(ident))
        if sym is not None:
            ident_ty = ctx.result.types.get(id(ident))
            return _format_symbol_for_hover(sym, ident_ty), ident

    # 2) Fall back to a declaration site.
    site = find_decl_site_at(ctx.decl_sites, line, col)
    if site is not None:
        sym = resolve_decl_symbol(site, ctx.result, ctx.module)
        if sym is not None:
            return _format_symbol_for_hover(sym, None), site.ident
    return None


def _format_symbol_for_hover(
    sym: Symbol, ident_ty: Optional[Ty],
) -> str:
    """Render a Capa Symbol as the Markdown body of a hover
    response. Falls back to a generic ``name: T`` shape when the
    Symbol kind has no specialised rendering.

    ``ident_ty`` is the inferred type recorded for the Ident
    itself (from ``AnalysisResult.types``); it can be more
    specific than ``sym.ty`` when type inference filled in a
    generic. When available, prefer it for the display.
    """
    name = sym.name
    if sym.kind == SymbolKind.FUNCTION and isinstance(sym.ty, TyFun):
        param_names = sym.param_names or [
            f"arg{i + 1}" for i in range(len(sym.ty.params))
        ]
        params = ", ".join(
            f"{pn}: {ty_str(pt)}"
            for pn, pt in zip(param_names, sym.ty.params)
        )
        return f"```capa\nfun {name}({params}) -> {ty_str(sym.ty.ret)}\n```"
    if sym.kind == SymbolKind.PARAM:
        ty = ident_ty if ident_ty is not None else sym.ty
        if ty is not None:
            return f"```capa\n{name}: {ty_str(ty)}\n```\n\n*parameter*"
        return f"`{name}` (parameter)"
    if sym.kind in (SymbolKind.LOCAL_VAR, SymbolKind.LOCAL):
        ty = ident_ty if ident_ty is not None else sym.ty
        kind_label = (
            "mutable variable" if sym.kind == SymbolKind.LOCAL_VAR
            else "binding"
        )
        if ty is not None:
            return f"```capa\n{name}: {ty_str(ty)}\n```\n\n*{kind_label}*"
        return f"`{name}` ({kind_label})"
    if sym.kind == SymbolKind.CONSTANT:
        head = "const " + name
        if sym.ty is not None:
            head += f": {ty_str(sym.ty)}"
        return f"```capa\n{head}\n```\n\n*constant*"
    if sym.kind == SymbolKind.VARIANT:
        owner = sym.variant_owner.name if sym.variant_owner else "?"
        head = name
        if sym.variant_payload_ty is not None:
            head += f"({ty_str(sym.variant_payload_ty)})"
        return f"```capa\n{head}\n```\n\n*variant of `{owner}`*"
    if sym.kind == SymbolKind.CAPABILITY:
        return (
            f"```capa\ncapability {name}\n```"
            f"\n\n*user-defined capability*"
        )
    if sym.kind in (SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM):
        kind = "struct" if sym.kind == SymbolKind.TYPE_STRUCT else "sum type"
        return f"```capa\ntype {name}\n```\n\n*{kind}*"
    if sym.ty is not None:
        return f"```capa\n{name}: {ty_str(sym.ty)}\n```"
    return f"`{name}`"

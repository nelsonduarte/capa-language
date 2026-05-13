"""``textDocument/references`` implementation."""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..analyzer import Symbol
from ..tokens import Pos
from .context import LspContext, find_decl_site_at, find_ident_at
from .symbol_resolve import resolve_decl_symbol


def compute_references(
    source: str, filename: str, line: int, col: int,
    *,
    include_declaration: bool = True,
) -> Optional[list[A.Ident]]:
    """Resolve the identifier at ``(line, col)`` and return every
    other identifier in the module that resolves to the same
    symbol. Returns ``None`` when the cursor is not on an
    identifier or has no resolved binding.

    The result is sorted by source position. When
    ``include_declaration`` is ``True`` and the declaring symbol
    has a real source origin, a synthetic entry at the
    declaration's name position is appended.
    """
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None

    # The pivot can be either a reference Ident or a declaration
    # site. Either way we end up with a Symbol and the position
    # of the matching declaration's name.
    target_sym: Optional[Symbol] = None
    decl_name_pos: Optional[Pos] = None
    decl_name: Optional[str] = None

    pivot = find_ident_at(ctx.idents, line, col)
    if pivot is not None:
        target_sym = ctx.result.bindings.get(id(pivot))
        if target_sym is not None:
            for s in ctx.decl_sites:
                cand = resolve_decl_symbol(s, ctx.result, ctx.module)
                if cand is target_sym:
                    decl_name_pos = s.ident.pos
                    decl_name = s.ident.name
                    break

    if target_sym is None:
        site = find_decl_site_at(ctx.decl_sites, line, col)
        if site is not None:
            target_sym = resolve_decl_symbol(site, ctx.result, ctx.module)
            if target_sym is not None:
                decl_name_pos = site.ident.pos
                decl_name = site.ident.name

    if target_sym is None:
        return None

    refs: list[A.Ident] = [
        ident for ident in ctx.idents
        if ctx.result.bindings.get(id(ident)) is target_sym
    ]

    if include_declaration and not (
        target_sym.pos.line == 0 and target_sym.pos.col == 0
    ):
        if decl_name_pos is not None and decl_name is not None:
            dpos, dname = decl_name_pos, decl_name
        else:
            dpos, dname = target_sym.pos, target_sym.name
        already_there = any(
            r.pos.line == dpos.line and r.pos.col == dpos.col
            for r in refs
        )
        if not already_there:
            refs.append(A.Ident(pos=dpos, name=dname))

    refs.sort(key=lambda i: (i.pos.line, i.pos.col))
    return refs

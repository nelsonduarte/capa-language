"""``textDocument/definition`` implementation."""

from __future__ import annotations

from typing import Optional

from ..analyzer import Symbol
from ..tokens import Pos
from .context import LspContext, find_decl_site_at, find_ident_at
from .symbol_resolve import resolve_decl_symbol


def compute_definition(
    source: str, filename: str, line: int, col: int,
) -> Optional[Pos]:
    """Resolve the identifier at ``(line, col)`` to the source
    position where its symbol is declared.

    Returns ``None`` when the cursor is not on a recognised
    identifier, the buffer has parse errors, the symbol has no
    resolved binding (typo at the cursor), or the symbol is a
    built-in (``Pos(0, 0, 0)`` sentinel, which would jump the
    editor to the top of a non-existent file).

    Positions returned use Capa's 1-based convention; the LSP
    server converts to LSP's 0-based form at the boundary.
    """
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None

    ident = find_ident_at(ctx.idents, line, col)
    sym: Optional[Symbol] = None
    if ident is not None:
        sym = ctx.result.bindings.get(id(ident))
    if sym is None:
        site = find_decl_site_at(ctx.decl_sites, line, col)
        if site is not None:
            sym = resolve_decl_symbol(site, ctx.result, ctx.module)
            if sym is not None:
                # On a declaration site, go-to-definition is a
                # no-op: jump to the name itself. Use the site
                # position rather than Symbol.pos so the editor
                # lands on the token even when Symbol.pos points
                # at the start of the enclosing construct
                # (e.g. ``fun``).
                return site.ident.pos
    if sym is None:
        return None
    if sym.pos.line == 0 and sym.pos.col == 0:
        return None  # built-in: no source origin to jump to
    return sym.pos

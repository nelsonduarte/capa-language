"""``textDocument/rename`` and ``textDocument/prepareRename``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..tokens import KEYWORDS, Pos
from .context import LspContext, find_decl_site_at, find_ident_at
from .references import compute_references
from .symbol_resolve import resolve_decl_symbol


@dataclass
class RenameEdit:
    """A single position to rewrite. Line / col are 1-based;
    the LSP server converts to 0-based before emitting the
    ``TextEdit``."""
    line: int
    col_start: int
    col_end: int


@dataclass
class RenameResult:
    """Outcome of a rename request."""
    edits: list[RenameEdit] = field(default_factory=list)
    error: Optional[str] = None


def is_valid_capa_identifier(name: str) -> bool:
    """``True`` iff ``name`` matches the lexer's IDENT pattern
    and is not a reserved keyword."""
    if not name:
        return False
    if not name.isidentifier():
        return False
    if name in KEYWORDS:
        return False
    return True


def compute_prepare_rename(
    source: str, filename: str, line: int, col: int,
) -> Optional[tuple[Pos, str]]:
    """Pre-flight check: is the cursor on a renameable symbol?
    Returns ``(name_pos, name)`` on success, ``None`` otherwise
    (built-in, no symbol, parse error)."""
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None

    ident = find_ident_at(ctx.idents, line, col)
    if ident is not None:
        sym = ctx.result.bindings.get(id(ident))
        if sym is not None and not (sym.pos.line == 0 and sym.pos.col == 0):
            return ident.pos, ident.name

    site = find_decl_site_at(ctx.decl_sites, line, col)
    if site is not None:
        sym = resolve_decl_symbol(site, ctx.result, ctx.module)
        if sym is not None and not (sym.pos.line == 0 and sym.pos.col == 0):
            return site.ident.pos, site.ident.name

    return None


def compute_rename(
    source: str, filename: str, line: int, col: int, new_name: str,
) -> RenameResult:
    """Compute the set of edits needed to rename the symbol
    under the cursor to ``new_name``. Errors are returned in the
    ``error`` field rather than raised so the LSP handler can
    surface them to the editor as a notification."""
    if not is_valid_capa_identifier(new_name):
        return RenameResult(
            error=(
                f"{new_name!r} is not a valid Capa identifier; "
                f"identifiers start with a letter or underscore "
                f"and must not be a reserved keyword"
            ),
        )

    refs = compute_references(
        source, filename, line, col, include_declaration=True,
    )
    if refs is None:
        return RenameResult(
            error="no renameable symbol at the cursor position",
        )

    edits = [
        RenameEdit(
            line=r.pos.line,
            col_start=r.pos.col,
            col_end=r.pos.col + len(r.name),
        )
        for r in refs
    ]
    return RenameResult(edits=edits)

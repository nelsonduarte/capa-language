"""``workspace/symbol`` implementation.

Project-wide symbol search. Where ``textDocument/documentSymbol``
outlines a single file, this spans every ``.capa`` file under the
workspace and returns the top-level declarations whose name
matches a query string: functions, structs, sums, traits,
capabilities, and constants.

The match is a case-insensitive substring test, ranked so that an
exact (case-insensitive) name comes first, then a prefix match,
then any other substring; ties break alphabetically. An empty
query returns every top-level symbol (capped by the caller's
result handling), which is the conventional "show me everything"
behaviour editors expect when the symbol box is first opened.

A file that fails to lex or parse is skipped, never fatal: the
search degrades to the files that do parse rather than returning
nothing because one buffer is mid-edit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .. import capa_ast as A
from ..errors import LexerError
from ..lexer import Lexer
from ..parser import Parser, ParserError
from ..tokens import Pos


@dataclass
class WorkspaceSymbol:
    """Capa-native workspace-symbol entry. ``filename`` is the
    file the symbol was declared in; ``pos`` is its 1-based
    declaration position; ``kind`` is one of the tags the server
    maps onto ``lsp.SymbolKind``."""
    name: str
    kind: str   # constant | function | struct | sum | trait | capability
    filename: str
    pos: Pos


def compute_workspace_symbols(
    query: str, files: Iterable[tuple[str, str]],
) -> list[WorkspaceSymbol]:
    """Search ``files`` (an iterable of ``(filename, source)``
    pairs) for top-level symbols whose name matches ``query``.

    Results are ranked exact-then-prefix-then-substring, ties
    alphabetical. Files that fail to lex / parse are skipped."""
    needle = query.strip().lower()
    matches: list[WorkspaceSymbol] = []
    for filename, source in files:
        for sym in _symbols_in_file(filename, source):
            if needle and needle not in sym.name.lower():
                continue
            matches.append(sym)
    matches.sort(key=lambda s: _rank(s.name, needle))
    return matches


def _rank(name: str, needle: str) -> tuple[int, str]:
    """Sort key: lower tier sorts first. 0 = exact (ci),
    1 = prefix, 2 = other substring; ties alphabetical (ci)."""
    low = name.lower()
    if needle and low == needle:
        tier = 0
    elif needle and low.startswith(needle):
        tier = 1
    else:
        tier = 2
    return (tier, low)


def _symbols_in_file(
    filename: str, source: str,
) -> list[WorkspaceSymbol]:
    """Parse one file and return its top-level declarations.
    Returns an empty list on lexer / parser failure (skip, do not
    crash)."""
    try:
        tokens = Lexer(source, filename=filename).lex()
        module = Parser(
            tokens, source=source, filename=filename,
        ).parse_module()
    except (LexerError, ParserError, RecursionError):
        return []

    out: list[WorkspaceSymbol] = []
    for item in module.items:
        entry = _item_to_symbol(item, filename)
        if entry is not None:
            out.append(entry)
    return out


def _item_to_symbol(
    item: A.Item, filename: str,
) -> "WorkspaceSymbol | None":
    """Map a top-level item to a workspace symbol, anchoring at the
    declared name's position when the parser recorded it (so the
    editor lands on the name, not the ``fun`` / ``type`` keyword)."""
    if isinstance(item, A.ConstDecl):
        return _mk(item.name, "constant", filename, item.name_pos, item.pos)
    if isinstance(item, A.TypeStruct):
        return _mk(item.name, "struct", filename, item.name_pos, item.pos)
    if isinstance(item, A.TypeSum):
        return _mk(item.name, "sum", filename, item.name_pos, item.pos)
    if isinstance(item, A.TraitDecl):
        kind = "capability" if item.is_capability else "trait"
        return _mk(item.name, kind, filename, item.name_pos, item.pos)
    if isinstance(item, A.FunDecl):
        return _mk(item.name, "function", filename, item.name_pos, item.pos)
    return None


def _mk(
    name: str, kind: str, filename: str,
    name_pos: "Pos | None", fallback: Pos,
) -> WorkspaceSymbol:
    return WorkspaceSymbol(
        name=name, kind=kind, filename=filename,
        pos=name_pos if name_pos is not None else fallback,
    )

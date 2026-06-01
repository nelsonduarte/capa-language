"""``textDocument/semanticTokens/full`` implementation.

Server-driven highlighting beyond what the TextMate grammar
delivers. The legend uses LSP-standard token types plus three
modifiers (``defaultLibrary``, ``declaration``, ``readonly``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import capa_ast as A
from ..analyzer import AnalysisResult, Symbol, SymbolKind
from .context import LspContext, walk
from .symbol_resolve import resolve_decl_symbol


# Legend, in the order indices will reference them. ``interface``
# is the LSP-standard name we use for "capability".
TOKEN_TYPES: list[str] = [
    "function",     # 0
    "parameter",    # 1
    "variable",     # 2
    "interface",    # 3
    "type",         # 4
    "enumMember",   # 5
    "property",     # 6
]


TOKEN_MODIFIERS: list[str] = [
    "defaultLibrary",   # bit 0
    "declaration",      # bit 1
    "readonly",         # bit 2
]


@dataclass(frozen=True)
class _SemToken:
    """Absolute (1-based) coordinates; the encoder converts to
    LSP's 0-based relative form."""
    line: int
    col: int
    length: int
    type_index: int
    modifiers_mask: int


def compute_semantic_tokens(
    source: str, filename: str,
) -> tuple[list[str], list[str], list[int]]:
    """Compute the semantic-tokens response.

    Returns ``(token_types, token_modifiers, data)`` where
    ``data`` is the flat relative-encoded array of
    ``[deltaLine, deltaStart, length, tokenType, tokenModifiers]``
    quintuples. A buffer that fails to lex / parse returns the
    legend with an empty data array.
    """
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return TOKEN_TYPES, TOKEN_MODIFIERS, []

    sem_tokens: list[_SemToken] = []

    # Reference idents.
    for ident in ctx.idents:
        sym = ctx.result.bindings.get(id(ident))
        if sym is None:
            continue
        pair = _symbol_to_token_type(sym)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(_SemToken(
            line=ident.pos.line, col=ident.pos.col,
            length=len(ident.name),
            type_index=type_index,
            modifiers_mask=_mods_mask(mods),
        ))

    # Declaration sites.
    for site in ctx.decl_sites:
        pair = _decl_site_to_token_type(site, ctx.result, ctx.module)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(_SemToken(
            line=site.ident.pos.line, col=site.ident.pos.col,
            length=len(site.ident.name),
            type_index=type_index,
            modifiers_mask=_mods_mask(mods),
        ))

    # TypeName references inside type annotations.
    for n in walk(ctx.module):
        if not isinstance(n, A.TypeName):
            continue
        sym = ctx.result.global_symbols.get(n.name)
        if sym is None:
            continue
        pair = _symbol_to_token_type(sym)
        if pair is None:
            continue
        type_index, mods = pair
        sem_tokens.append(_SemToken(
            line=n.pos.line, col=n.pos.col, length=len(n.name),
            type_index=type_index,
            modifiers_mask=_mods_mask(mods),
        ))

    # let / var bindings inside function bodies.
    var_idx = TOKEN_TYPES.index("variable")
    for n in walk(ctx.module):
        if isinstance(n, A.LetStmt):
            for pat in walk(n.pattern):
                if isinstance(pat, A.IdentPat):
                    sem_tokens.append(_SemToken(
                        line=pat.pos.line, col=pat.pos.col,
                        length=len(pat.name),
                        type_index=var_idx,
                        modifiers_mask=_mods_mask(
                            {"readonly", "declaration"}
                        ),
                    ))
        elif isinstance(n, A.VarStmt) and n.name_pos is not None:
            sem_tokens.append(_SemToken(
                line=n.name_pos.line, col=n.name_pos.col,
                length=len(n.name),
                type_index=var_idx,
                modifiers_mask=_mods_mask({"declaration"}),
            ))

    return TOKEN_TYPES, TOKEN_MODIFIERS, _encode(sem_tokens, source)


def _utf16_len(s: str) -> int:
    """Number of UTF-16 code units in ``s``. A BMP char is 1 unit; a
    supplementary-plane char (emoji, ...) is a surrogate pair = 2.
    Audit slice 28 P3 (2026-06-01): the LSP wire protocol counts
    columns + token lengths in UTF-16 units (pygls advertises Utf16),
    but the lexer's columns and ``len(name)`` are codepoints. They
    agree for ASCII; they diverge once an astral char sits earlier on
    the line. Kept dependency-free (no pygls import) to match the
    rest of this module; the byte count over utf-16-le / 2 is the
    code-unit count."""
    return len(s.encode("utf-16-le")) // 2


def _encode(sem_tokens: list[_SemToken], source: str) -> list[int]:
    """Sort, deduplicate, and relative-encode the tokens.

    Columns and lengths are converted from the lexer's codepoint
    coordinates to the UTF-16 code units the LSP wire protocol uses
    (slice 28 P3). For an all-ASCII document this is the identity, so
    existing behaviour is unchanged; it only shifts when an astral
    char precedes a token on the same line.
    """
    sem_tokens.sort(key=lambda t: (t.line, t.col))
    seen: set[tuple[int, int]] = set()
    deduped: list[_SemToken] = []
    for t in sem_tokens:
        key = (t.line, t.col)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)

    # Index source lines so we can convert a codepoint column to its
    # UTF-16 column (count UTF-16 units in the line prefix before the
    # token) and the token's codepoint length to its UTF-16 length.
    lines = source.splitlines()

    def _utf16_col0(line_1: int, col_1: int) -> int:
        idx = line_1 - 1
        if 0 <= idx < len(lines):
            return _utf16_len(lines[idx][: col_1 - 1])
        return col_1 - 1  # out of range: fall back to codepoint col

    def _utf16_tok_len(line_1: int, col_1: int, cp_len: int) -> int:
        idx = line_1 - 1
        if 0 <= idx < len(lines):
            cp0 = col_1 - 1
            return _utf16_len(lines[idx][cp0: cp0 + cp_len])
        return cp_len

    data: list[int] = []
    prev_line_0 = 0
    prev_col_0 = 0
    for t in deduped:
        line_0 = t.line - 1
        col_0 = _utf16_col0(t.line, t.col)
        length = _utf16_tok_len(t.line, t.col, t.length)
        if line_0 == prev_line_0:
            delta_line = 0
            delta_start = col_0 - prev_col_0
        else:
            delta_line = line_0 - prev_line_0
            delta_start = col_0
        data.extend([
            delta_line, delta_start, length,
            t.type_index, t.modifiers_mask,
        ])
        prev_line_0 = line_0
        prev_col_0 = col_0
    return data


def _mods_mask(modifiers: set[str]) -> int:
    """Encode a set of modifier names as a bitmask."""
    out = 0
    for m in modifiers:
        if m in TOKEN_MODIFIERS:
            out |= 1 << TOKEN_MODIFIERS.index(m)
    return out


def _symbol_to_token_type(
    sym: Symbol,
) -> Optional[tuple[int, set[str]]]:
    """Map a Capa Symbol to a (type_index, modifier_set) pair."""
    is_builtin = sym.pos.line == 0 and sym.pos.col == 0
    mods: set[str] = set()
    if is_builtin:
        mods.add("defaultLibrary")
    if sym.kind == SymbolKind.FUNCTION:
        return TOKEN_TYPES.index("function"), mods
    if sym.kind == SymbolKind.PARAM:
        return TOKEN_TYPES.index("parameter"), mods
    if sym.kind == SymbolKind.LOCAL:
        mods.add("readonly")
        return TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.LOCAL_VAR:
        return TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.CONSTANT:
        mods.add("readonly")
        return TOKEN_TYPES.index("variable"), mods
    if sym.kind == SymbolKind.CAPABILITY:
        return TOKEN_TYPES.index("interface"), mods
    if sym.kind in (
        SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM, SymbolKind.TRAIT,
    ):
        return TOKEN_TYPES.index("type"), mods
    if sym.kind == SymbolKind.VARIANT:
        return TOKEN_TYPES.index("enumMember"), mods
    return None


def _decl_site_to_token_type(
    site, result: AnalysisResult, module: A.Module,
) -> Optional[tuple[int, set[str]]]:
    """Tag a declaration site. Fields use the ``property`` type;
    the rest defer to :func:`_symbol_to_token_type` with a
    ``declaration`` modifier layered on top."""
    mods = {"declaration"}
    if site.decl_kind == "field":
        return TOKEN_TYPES.index("property"), mods
    sym = resolve_decl_symbol(site, result, module)
    if sym is None:
        return None
    pair = _symbol_to_token_type(sym)
    if pair is None:
        return None
    type_index, sym_mods = pair
    return type_index, sym_mods | mods

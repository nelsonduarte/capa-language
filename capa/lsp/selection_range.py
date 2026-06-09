"""``textDocument/selectionRange`` implementation (smart-select).

Given a cursor position, return the chain of enclosing source
ranges from innermost to outermost: the smallest AST node covering
the position, then each larger ancestor, so the editor's
"expand selection" command grows the selection one syntactic level
at a time (identifier -> sub-expression -> full expression ->
statement -> block -> function).

The request takes a list of positions; each yields its own
independent chain.

Capa AST nodes carry only a *start* :class:`Pos`. A node's full
span is therefore reconstructed as the bounding box of the node's
own start offset and every descendant's span: the minimum start
offset and the maximum end offset reached anywhere in the subtree.
This guarantees the structural property selection-range needs - a
parent range always contains its child range - even though it is a
conservative (sometimes slightly wide) approximation of the exact
syntactic extent. Leaf tokens whose text length is known from the
node (identifiers, keyword/operator-free literals) extend the end
offset past their starting column so a single identifier selects
the whole identifier rather than one character.

Offsets are translated to 1-based (line, col) against the source
once, at the end, so the hierarchy is built in the cheap offset
space.

Returns an empty list on lex / parse failure: a mid-edit buffer
shows no smart-select rather than crashing the request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import capa_ast as A
from ..errors import LexerError
from ..lexer import Lexer
from ..parser import Parser, ParserError


@dataclass
class SelectionRange:
    """One link in a smart-select chain. ``start`` / ``end`` are
    1-based (line, col) tuples, half-open at ``end`` (the column
    just past the last selected character). ``parent`` is the next
    larger enclosing range, or ``None`` at the top of the chain."""
    start: tuple[int, int]
    end: tuple[int, int]
    parent: Optional["SelectionRange"] = None


def compute_selection_ranges(
    source: str, positions: list[tuple[int, int]],
) -> list[Optional[SelectionRange]]:
    """For each (1-based line, col) position in ``positions`` return
    the innermost :class:`SelectionRange` of its enclosing-node
    chain (follow ``.parent`` for the outer links), or ``None`` when
    no node covers the position.

    The returned list is positional: result ``i`` corresponds to
    ``positions[i]``. Returns an all-``None`` list (one per input)
    on lex / parse failure so the editor degrades gracefully."""
    try:
        tokens = Lexer(source, filename="<lsp>").lex()
        module = Parser(
            tokens, source=source, filename="<lsp>",
        ).parse_module()
    except (LexerError, ParserError, RecursionError):
        return [None for _ in positions]

    spans = _Spans(source)
    spans.compute(module)
    return [
        _chain_for_position(module, spans, line, col)
        for (line, col) in positions
    ]


def _chain_for_position(
    module: A.Module, spans: "_Spans", line: int, col: int,
) -> Optional[SelectionRange]:
    """Build the innermost-to-outermost selection-range chain for
    one position, or ``None`` if nothing covers it."""
    target = _offset_of(spans.source, line, col)
    if target is None:
        return None

    # Every node whose span covers the offset, ordered largest span
    # first so we can thread parents top-down and dedup adjacent
    # identical / zero-width spans.
    covering = [
        n for n in _walk_nodes(module)
        if _covers(spans.get(n), target)
    ]
    if not covering:
        return None
    covering.sort(key=lambda n: _span_size(spans.get(n)), reverse=True)

    chain: Optional[SelectionRange] = None
    last_span: Optional[tuple[int, int]] = None
    for node in covering:
        span = spans.get(node)
        if span is None:
            continue
        s_off, e_off = span
        if e_off <= s_off:
            continue  # zero-width, nothing to select
        if last_span is not None and span == last_span:
            continue  # dedup identical spans (e.g. wrapper == child)
        link = SelectionRange(
            start=_line_col(spans.source, s_off),
            end=_line_col(spans.source, e_off),
            parent=chain,
        )
        chain = link
        last_span = span
    return chain


def _covers(span: Optional[tuple[int, int]], offset: int) -> bool:
    if span is None:
        return False
    s_off, e_off = span
    return s_off <= offset <= e_off


def _span_size(span: Optional[tuple[int, int]]) -> int:
    if span is None:
        return -1
    return span[1] - span[0]


# ---------------------------------------------------------------
# Span reconstruction
# ---------------------------------------------------------------


class _Spans:
    """Memoised (start_offset, end_offset) bounding box for every
    node, computed bottom-up over the dataclass tree."""

    def __init__(self, source: str) -> None:
        self.source = source
        self._cache: dict[int, Optional[tuple[int, int]]] = {}

    def compute(self, node) -> None:
        self.get(node)

    def get(self, node) -> Optional[tuple[int, int]]:
        if not isinstance(node, A.Node):
            return None
        key = id(node)
        if key in self._cache:
            return self._cache[key]
        # Guard against the rare shared/cyclic reference: seed with
        # None so a re-entrant lookup terminates.
        self._cache[key] = None
        span = self._compute(node)
        self._cache[key] = span
        return span

    def _compute(self, node) -> Optional[tuple[int, int]]:
        pos = getattr(node, "pos", None)
        starts: list[int] = []
        ends: list[int] = []
        if pos is not None and pos.offset >= 0:
            starts.append(pos.offset)
            ends.append(pos.offset + _leaf_len(node))
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            self._collect_value(getattr(node, f.name, None), starts, ends)
        if not starts:
            return None
        return (min(starts), max(ends))

    def _collect_value(self, v, starts: list[int], ends: list[int]) -> None:
        if isinstance(v, A.Node):
            span = self.get(v)
            if span is not None:
                starts.append(span[0])
                ends.append(span[1])
        elif isinstance(v, (list, tuple)):
            for item in v:
                self._collect_value(item, starts, ends)


def _leaf_len(node) -> int:
    """Source length of a leaf node's own token, so its end offset
    reaches past the starting column. Container nodes (whose span is
    driven by descendants) contribute their start as a 1-char floor;
    descendants then widen the box."""
    if isinstance(node, A.Ident):
        return len(node.name)
    if isinstance(node, A.IntLit):
        return len(str(node.value))
    if isinstance(node, A.FloatLit):
        return len(repr(node.value))
    if isinstance(node, A.BoolLit):
        return len("true") if node.value else len("false")
    if isinstance(node, A.StringLit):
        # Quotes + content; a lower bound is fine since descendants
        # of a plain StringLit do not exist to widen it.
        return len(node.value) + 2
    if isinstance(node, A.CharLit):
        return len(node.value) + 2
    return 1


# ---------------------------------------------------------------
# Offset <-> (line, col) translation
# ---------------------------------------------------------------


def _line_starts(source: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _offset_of(source: str, line: int, col: int) -> Optional[int]:
    """1-based (line, col) -> 0-based offset, or ``None`` when out
    of range."""
    starts = _line_starts(source)
    if line < 1 or line > len(starts):
        return None
    base = starts[line - 1]
    off = base + (col - 1)
    if off < 0 or off > len(source):
        return None
    return off


def _line_col(source: str, offset: int) -> tuple[int, int]:
    """0-based offset -> 1-based (line, col)."""
    starts = _line_starts(source)
    # Largest line start <= offset.
    lo, hi = 0, len(starts) - 1
    line_idx = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if starts[mid] <= offset:
            line_idx = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return (line_idx + 1, offset - starts[line_idx] + 1)


def _walk_nodes(node):
    """Yield every AST node reachable from ``node``. Mirrors
    ``context.walk`` but kept local so this module has no import
    cycle with the parse-context layer."""
    if isinstance(node, A.Node):
        yield node
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            yield from _walk_nodes(getattr(node, f.name, None))
    elif isinstance(node, (list, tuple)):
        for x in node:
            yield from _walk_nodes(x)

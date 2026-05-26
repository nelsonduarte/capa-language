"""CommentMap attachment pass (formatter v3 phase 2).

Phase 1 gave the lexer a sidecar ``Lexer.comments`` of every plain
``//`` and ``/* */`` comment with start+end positions and text. Doc
comments (``///``, ``/**``) flow as ``DOC_COMMENT`` tokens and are
attached to items by the parser, so they are NOT in scope here.

This module ties each plain comment to exactly one AST node so the
phase-3 pretty-printer can re-emit it in the right place during an
AST round-trip. The design is locked in
``docs/formatter-v3-comment-map-design.md``.

Public surface:

- :class:`AttachedComments` - per-node bucket with four slots:
  ``leading`` / ``trailing`` / ``trailing_header`` / ``interior``.
- :class:`CommentMap` - side-table keyed by ``id(node)`` (mirroring
  the ``analyzer.types: dict[int, Ty]`` / ``transpiler.types``
  convention; deliberately NOT a field on :class:`Node` to keep
  AST equality and the dump format untouched).
- :func:`build_comment_map` - one-shot builder; the only public
  construction path.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Optional

from .. import capa_ast as A
from ..tokens import Comment, Token, TokenKind


# Recognises a "section divider" line comment: an optional space
# after ``//`` followed by three or more ``=`` / ``-`` / ``*`` /
# ``#`` characters (plus optional trailing whitespace). Used to
# decide that a comment at the very top of a file, immediately
# above ``fun`` / ``type`` / etc., is a divider for the following
# item rather than a file-header for the Module. See the design
# note in section 2 of the spec, "section-divider // ===== blocks
# attach as leading on the following FunDecl".
_SECTION_DIVIDER_RE = re.compile(r"^//\s*[=\-*#]{3,}\s*$")


# Tokens whose presence on a line does NOT count as "code before the
# comment" for the trailing-vs-standalone test.
_LAYOUT_KINDS = {
    TokenKind.NEWLINE,
    TokenKind.INDENT,
    TokenKind.DEDENT,
    TokenKind.EOF,
}

# Compound nodes whose comment-on-the-header-line lands in the
# ``trailing_header`` slot (not as leading on the first child).
_COMPOUND_HEADER_TYPES: tuple[type, ...] = (
    A.IfStmt,
    A.WhileStmt,
    A.ForStmt,
    A.FunDecl,
    A.TypeStruct,
    A.TypeSum,
    A.TraitDecl,
    A.ImplBlock,
    A.MatchExpr,
)


@dataclass
class AttachedComments:
    """Comments attached to a single AST node, by slot."""
    leading: list[Comment] = field(default_factory=list)
    trailing: list[Comment] = field(default_factory=list)
    trailing_header: list[Comment] = field(default_factory=list)
    interior: list[Comment] = field(default_factory=list)


class CommentMap:
    """Side-table tying plain comments to AST nodes for the
    formatter's AST round-trip. Doc comments (``///`` and ``/**``)
    are stored on AST items directly by the parser and do NOT
    appear here."""

    def __init__(self) -> None:
        self._by_id: dict[int, AttachedComments] = {}

    def get(self, node: A.Node) -> Optional[AttachedComments]:
        return self._by_id.get(id(node))

    def attach(self, node: A.Node, slot: str, comment: Comment) -> None:
        """Append ``comment`` to ``node``'s ``slot`` list (one of
        ``'leading'``, ``'trailing'``, ``'trailing_header'``,
        ``'interior'``)."""
        entry = self._by_id.setdefault(id(node), AttachedComments())
        getattr(entry, slot).append(comment)

    def __contains__(self, node: A.Node) -> bool:
        return id(node) in self._by_id

    def __iter__(self):
        return iter(self._by_id.values())

    def __len__(self) -> int:
        return sum(
            len(e.leading) + len(e.trailing)
            + len(e.trailing_header) + len(e.interior)
            for e in self._by_id.values()
        )


# -----------------------------------------------------------
# NodeIndex: flat, source-ordered view of the AST.
# -----------------------------------------------------------


@dataclass
class _NodeEntry:
    """One entry in the source-ordered NodeIndex."""
    start: int          # node.pos.offset
    end: int            # max(start, recursive max of children's ends)
    node: A.Node
    parent: Optional[A.Node]
    depth: int          # 0 for Module, 1 for top-level items, ...


def _iter_children(node: A.Node):
    """Yield direct child :class:`A.Node` instances of ``node``.

    Walks the dataclass fields and unwraps lists / tuples (the AST
    uses tuples in a few places: ``IfStmt.elif_arms``,
    ``StructLit.fields``, ``StructPat.fields``).
    """
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name, None)
        if v is None:
            continue
        if isinstance(v, A.Node):
            yield v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, A.Node):
                    yield item
                elif isinstance(item, tuple):
                    for sub in item:
                        if isinstance(sub, A.Node):
                            yield sub
        elif isinstance(v, tuple):
            for sub in v:
                if isinstance(sub, A.Node):
                    yield sub


def _build_node_index(module: A.Module) -> list[_NodeEntry]:
    """Walk the module, returning a flat list of node entries
    sorted by ``start`` offset (stable, so ties preserve source
    order).

    End offsets are computed bottom-up as ``max(start, recursive
    max of children's ends)``. This is an approximation: it does
    not account for the closing token after the last child (e.g.
    the ``)`` of a call), but it is correct for the only thing
    we need it for: the smallest-containing-node lookup, which
    only requires that a node's [start, end] interval cover its
    children.
    """
    entries: list[_NodeEntry] = []
    # Bottom-up end-offset memo, keyed by id(node).
    ends: dict[int, int] = {}

    def visit(node: A.Node, parent: Optional[A.Node], depth: int) -> int:
        if not isinstance(node, A.Node):
            return -1
        pos = getattr(node, "pos", None)
        start = pos.offset if pos is not None else 0
        end = start
        children: list[A.Node] = list(_iter_children(node))
        for child in children:
            child_end = visit(child, node, depth + 1)
            if child_end > end:
                end = child_end
        ends[id(node)] = end
        entries.append(_NodeEntry(
            start=start, end=end, node=node, parent=parent, depth=depth,
        ))
        return end

    visit(module, None, 0)
    entries.sort(key=lambda e: e.start)
    return entries


# -----------------------------------------------------------
# Token / node lookups.
# -----------------------------------------------------------


def _find_prev_token(tokens: list[Token], offset: int) -> Optional[Token]:
    """Largest token T with ``T.end.offset <= offset``.

    Binary search on a list pre-sorted by ``token.end.offset``
    (tokens are emitted in source order, so ``end.offset`` is
    non-decreasing and ``bisect_right`` over ``end.offset`` keys
    is valid).
    """
    if not tokens:
        return None
    end_offsets = [t.end.offset for t in tokens]
    i = bisect_right(end_offsets, offset)
    if i == 0:
        return None
    return tokens[i - 1]


def _smallest_containing_node(
    entries: list[_NodeEntry], offset: int,
) -> Optional[_NodeEntry]:
    """Smallest (deepest) node entry whose [start, end] contains
    ``offset``. Ties on ``start`` are broken by depth (deeper
    wins). Returns ``None`` if no node contains the offset.
    """
    best: Optional[_NodeEntry] = None
    # Linear scan over candidates whose start <= offset; binary
    # search on starts to bound the prefix.
    starts = [e.start for e in entries]
    upper = bisect_right(starts, offset)
    for i in range(upper):
        e = entries[i]
        if e.start <= offset <= e.end:
            if best is None or e.depth > best.depth:
                best = e
            elif e.depth == best.depth and e.start > best.start:
                # Deeper start at same depth (rare with the tree's
                # depth bookkeeping, but defended for robustness).
                best = e
    return best


def _smallest_node_after(
    entries: list[_NodeEntry], offset: int,
) -> Optional[_NodeEntry]:
    """Smallest entry (by source position) whose ``start > offset``,
    excluding the Module itself (which always starts at 0). Returns
    ``None`` at end-of-file."""
    starts = [e.start for e in entries]
    i = bisect_right(starts, offset)
    while i < len(entries):
        e = entries[i]
        if not isinstance(e.node, A.Module):
            return e
        i += 1
    return None


def _enclosing_stmt_or_item(
    entries_by_id: dict[int, _NodeEntry],
    entry: _NodeEntry,
) -> _NodeEntry:
    """Walk up parent links until an :class:`A.Stmt`, :class:`A.Item`
    or :class:`A.Module` is reached. Used to find the owner of a
    trailing comment that landed on a leaf expression.
    """
    cur = entry
    while cur.parent is not None:
        if isinstance(cur.node, (A.Stmt, A.Item, A.Module)):
            return cur
        parent_entry = entries_by_id.get(id(cur.parent))
        if parent_entry is None:
            return cur
        cur = parent_entry
    return cur


def _enclosing_expr(
    entries_by_id: dict[int, _NodeEntry],
    entry: _NodeEntry,
) -> _NodeEntry:
    """Walk up to the smallest enclosing :class:`A.Expr`. Used for
    interior block comments. Falls back to the input ``entry``
    if no Expr ancestor exists.
    """
    cur = entry
    while cur is not None:
        if isinstance(cur.node, A.Expr):
            return cur
        if cur.parent is None:
            return entry
        cur = entries_by_id.get(id(cur.parent))  # type: ignore[assignment]
        if cur is None:
            return entry
    return entry


def _enclosing_block_or_module(
    entries_by_id: dict[int, _NodeEntry],
    entry: _NodeEntry,
) -> _NodeEntry:
    """Walk up to the smallest enclosing :class:`A.Block` or
    :class:`A.Module`. Used for floating standalone comments at the
    end of a block / file.
    """
    cur = entry
    while cur is not None:
        if isinstance(cur.node, (A.Block, A.Module)):
            return cur
        if cur.parent is None:
            return cur
        nxt = entries_by_id.get(id(cur.parent))
        if nxt is None:
            return cur
        cur = nxt
    return entry


def _header_line(node: A.Node) -> int:
    """The line where the compound node's *header* sits. For most
    compound nodes that is ``node.pos.line``; for :class:`A.FunDecl`
    that has been positioned at an attribute (so ``pos.line`` is the
    attribute's line, not ``fun``), we use ``name_pos.line`` when
    available.
    """
    if isinstance(node, A.FunDecl) and node.name_pos is not None:
        return node.name_pos.line
    return node.pos.line


# -----------------------------------------------------------
# Public builder.
# -----------------------------------------------------------


def build_comment_map(
    module: A.Module,
    tokens: list[Token],
    comments: list[Comment],
) -> CommentMap:
    """Attach every plain comment in ``comments`` to an AST node
    in ``module``.

    See ``docs/formatter-v3-comment-map-design.md`` for the rules.
    Algorithm in three passes:

    1. Build a source-ordered flat NodeIndex.
    2. For each comment, classify as trailing / standalone /
       interior and find its owner node + slot.
    3. Store in a :class:`CommentMap`.

    The function is pure; it does not mutate ``module`` or any
    of its descendants.
    """
    cmap = CommentMap()
    if not comments:
        return cmap

    entries = _build_node_index(module)
    entries_by_id = {id(e.node): e for e in entries}

    for c in comments:
        prev = _find_prev_token(tokens, c.start.offset)
        is_trailing = (
            prev is not None
            and prev.kind not in _LAYOUT_KINDS
            and prev.end.line == c.start.line
        )

        if is_trailing:
            _attach_trailing(cmap, entries, entries_by_id, c, prev, tokens)
        else:
            _attach_standalone(
                cmap, entries, entries_by_id, c, tokens, module,
            )

    return cmap


def _attach_trailing(
    cmap: CommentMap,
    entries: list[_NodeEntry],
    entries_by_id: dict[int, _NodeEntry],
    c: Comment,
    prev: Token,
    tokens: list[Token],
) -> None:
    """Place a trailing-classified comment.

    Three sub-cases:

    - Mid-expression block comment (``let x = 1 /* aside */ + 2``):
      there is code on the same line *after* the comment as well.
      The owner is the smallest enclosing :class:`A.Expr`, slot
      ``interior``.
    - Trailing on a compound header (``if cond  // checked``,
      ``fun foo()  // exposed``): owner is the compound node,
      slot ``trailing_header``.
    - Otherwise: owner is the enclosing Stmt / Item, slot
      ``trailing``.
    """
    # Locate the node prev_token belongs to.
    inner = _smallest_containing_node(entries, prev.end.offset - 1)
    if inner is None:
        # Unanchored trailing comment (e.g. on a structural-only
        # token before any node was built). Attach to Module.
        inner = entries[0]  # the Module entry (depth 0, start 0)

    # Mid-expression block comment: look at the next non-layout
    # token after the comment. If it sits on the same line as the
    # comment, the comment is wedged inside an expression.
    next_tok = _next_non_layout_token(tokens, c.end.offset)
    if (
        c.kind.name == "BLOCK"
        and next_tok is not None
        and next_tok.start.line == c.start.line
        and next_tok.kind not in _LAYOUT_KINDS
    ):
        owner = _enclosing_expr(entries_by_id, inner)
        cmap.attach(owner.node, "interior", c)
        return

    owner = _enclosing_stmt_or_item(entries_by_id, inner)
    if (
        isinstance(owner.node, _COMPOUND_HEADER_TYPES)
        and _header_line(owner.node) == c.start.line
    ):
        cmap.attach(owner.node, "trailing_header", c)
    else:
        cmap.attach(owner.node, "trailing", c)


def _attach_standalone(
    cmap: CommentMap,
    entries: list[_NodeEntry],
    entries_by_id: dict[int, _NodeEntry],
    c: Comment,
    tokens: list[Token],
    module: A.Module,
) -> None:
    """Place a standalone comment.

    Floating (no following AST node at any scope): walk up using
    the comment's column to choose the right enclosing container.
    Comments at column 1 land on the Module ``trailing``; comments
    indented to the column of a function body land on that body
    ``Block`` ``trailing``.

    Standalone with a follower: usually ``leading`` on the
    follower, with two exceptions for top-of-file comments. A
    plain narrative comment immediately above the FIRST item of a
    Module (no preceding AST node at all, no doc comment between
    the comment and the item, and the comment is not a section
    divider) attaches to the ``Module`` ``leading`` (the
    "file-header" case). Section dividers (``// =====``) and any
    comment immediately followed by a ``/// doc`` for the same
    item always attach to the item.
    """
    follower = _smallest_node_after(entries, c.end.offset)
    if follower is None:
        # Floating: pick Block.trailing if the comment is indented
        # inside one, else Module.trailing.
        cmap.attach(
            _floating_owner(module, entries, c).node, "trailing", c,
        )
        return

    # Risk-mitigation (design section 7): a plain comment with a
    # doc comment immediately following always binds to the
    # doc-bearing item, even when the comment would otherwise be
    # classified as a Module file-header.
    doc_bound = _follower_has_preceding_doc(follower.node, c, tokens)

    # File-header case: a comment that lives strictly before the
    # first item, is not a section divider, and is not followed
    # by a doc comment, binds to the Module. The first-item check
    # is "no AST node ends before this comment starts" (i.e. the
    # comment really is at the top of the file).
    if (
        not doc_bound
        and not _is_section_divider(c)
        and _is_before_first_item(entries, c)
    ):
        cmap.attach(module, "leading", c)
        return

    cmap.attach(follower.node, "leading", c)


def _is_section_divider(c: Comment) -> bool:
    """``// ====``, ``// ----``, ``// ****``, ``// ####`` (3+
    chars) are dividers. Block comments are never dividers in
    this sense."""
    if c.kind != type(c.kind).LINE:  # CommentKind.LINE
        return False
    return bool(_SECTION_DIVIDER_RE.match(c.text))


def _is_before_first_item(
    entries: list[_NodeEntry], c: Comment,
) -> bool:
    """True iff no non-Module AST node lives strictly before the
    comment's start offset (i.e. the comment is at the very top
    of the source)."""
    for e in entries:
        if isinstance(e.node, A.Module):
            continue
        if e.start < c.start.offset:
            return False
    return True


def _floating_owner(
    module: A.Module,
    entries: list[_NodeEntry],
    c: Comment,
) -> _NodeEntry:
    """Owner for a floating comment (no AST node follows).

    Picks the smallest enclosing :class:`A.Block` whose body
    indentation level is ``<=`` the comment's column. Falls back
    to the Module entry when the comment sits at column 1.
    """
    # Comments at column 1 always belong to the Module.
    module_entry = next(e for e in entries if e.node is module)
    if c.start.col <= 1:
        return module_entry
    # Find the deepest Block whose body indent <= comment.col.
    # The body indent is the column of the Block's first
    # statement's first token (which equals ``stmt.pos.col``).
    best: Optional[_NodeEntry] = None
    for e in entries:
        if not isinstance(e.node, A.Block):
            continue
        body_col = _block_body_col(e.node)
        if body_col is None:
            continue
        if body_col <= c.start.col and e.start < c.start.offset:
            if best is None or e.start > best.start:
                best = e
    return best if best is not None else module_entry


def _block_body_col(block: A.Block) -> Optional[int]:
    """Column of the first body statement (1-indexed). ``None`` for
    empty blocks (degenerate; the parser does not produce them in
    well-formed source)."""
    if not block.stmts:
        return None
    return block.stmts[0].pos.col


def _next_non_layout_token(
    tokens: list[Token], offset: int,
) -> Optional[Token]:
    """First token T with ``T.start.offset >= offset`` and
    ``T.kind`` not in the layout set. ``None`` at end of file.
    """
    starts = [t.start.offset for t in tokens]
    i = bisect_right(starts, offset - 1)
    while i < len(tokens):
        if tokens[i].kind not in _LAYOUT_KINDS:
            return tokens[i]
        i += 1
    return None


def _follower_has_preceding_doc(
    node: A.Node, c: Comment, tokens: list[Token],
) -> bool:
    """True iff the AST item ``node`` is one of the doc-bearing item
    kinds AND there is at least one DOC_COMMENT token in the
    [c.end.offset, node.pos.offset) range. Pure look-up; no
    mutation. See :func:`_attach_standalone` for why this matters.
    """
    if not isinstance(node, (A.FunDecl, A.TypeStruct, A.TypeSum, A.TraitDecl)):
        return False
    lo = c.end.offset
    hi = node.pos.offset
    if lo >= hi:
        return False
    # Bounded by item.pos so the scan is O(small).
    starts = [t.start.offset for t in tokens]
    i = bisect_right(starts, lo - 1)
    while i < len(tokens) and tokens[i].start.offset < hi:
        if tokens[i].kind == TokenKind.DOC_COMMENT:
            return True
        i += 1
    return False

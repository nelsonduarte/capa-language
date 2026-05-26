"""``textDocument/foldingRange`` handler.

Editor gutter +/- regions for collapsible blocks. Each region is
a half-open ``[start_line, end_line]`` span in 1-based line
numbers; the editor stores them as 0-based when serialised to the
LSP wire format (the ``server.py`` wrapper does that translation).

What folds:

- Function bodies (``fun foo() ... <body>``)
- Type body of ``TypeStruct`` and ``TypeSum`` (the ``{ ... }`` /
  ``= ...`` block)
- ``ImplBlock`` body
- ``TraitDecl`` body
- ``IfStmt`` / ``ForStmt`` / ``WhileStmt`` body blocks (each
  branch separately for ``IfStmt``'s elif chain + else)
- ``MatchExpr`` arm list (one fold for the whole arm list)
- Block-bodied lambdas (``|x| { ... }``)

What does NOT fold (out of scope for v1):

- import groups
- region markers (``// region: foo`` / ``// endregion``)
- multi-line doc comments / comment runs
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import capa_ast as A
from ..errors import LexerError
from ..lexer import Lexer
from ..parser import Parser, ParserError


@dataclass
class FoldingRange:
    """Capa-native folding range. 1-based line numbers.

    ``kind`` is one of ``"region"``, ``"comment"``, ``"imports"``;
    the LSP server translates to the wire enum.
    """
    start_line: int
    end_line: int
    kind: str = "region"


# AST node types that fold as a single region from ``node.pos.line``
# to the deepest descendant's line.
_FOLDABLE = (
    A.FunDecl,
    A.TypeStruct,
    A.TypeSum,
    A.ImplBlock,
    A.TraitDecl,
    A.MatchExpr,
    A.IfStmt,
    A.ForStmt,
    A.WhileStmt,
    A.LambdaExpr,
)


def compute_folding_ranges(source: str) -> list[FoldingRange]:
    """Parse ``source`` and return every collapsible region.

    Returns an empty list on lexer / parser failure: the editor
    will just show no folds for a broken file, which is the right
    UX (no spurious folds while the user is mid-edit).
    """
    try:
        tokens = Lexer(source, filename="<lsp>").lex()
    except LexerError:
        return []
    try:
        module = Parser(
            tokens, source=source, filename="<lsp>",
        ).parse_module()
    except (LexerError, ParserError):
        return []
    ranges: list[FoldingRange] = []
    _collect(module, ranges)
    return ranges


def _collect(node, out: list[FoldingRange]) -> None:
    """Recursive walk. For each foldable container node emit a
    ``FoldingRange`` covering ``node.pos.line`` through the line
    of its deepest descendant; skip single-line constructs since
    they cannot be folded."""
    if not isinstance(node, A.Node):
        return
    if isinstance(node, _FOLDABLE):
        start = node.pos.line
        end = _last_line(node)
        if end > start:
            out.append(FoldingRange(
                start_line=start, end_line=end, kind="region",
            ))
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name, None)
        _recurse_value(v, out)


def _recurse_value(v, out: list[FoldingRange]) -> None:
    if isinstance(v, A.Node):
        _collect(v, out)
    elif isinstance(v, list):
        for item in v:
            _recurse_value(item, out)
    elif isinstance(v, tuple):
        for sub in v:
            _recurse_value(sub, out)


def _last_line(node) -> int:
    """Largest line number reached by ``node`` or any
    descendant."""
    if not isinstance(node, A.Node):
        return 0
    pos = getattr(node, "pos", None)
    last = pos.line if pos is not None else 0
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name, None)
        cand = _last_line_value(v)
        if cand > last:
            last = cand
    return last


def _last_line_value(v) -> int:
    if isinstance(v, A.Node):
        return _last_line(v)
    if isinstance(v, list):
        best = 0
        for item in v:
            cand = _last_line_value(item)
            if cand > best:
                best = cand
        return best
    if isinstance(v, tuple):
        best = 0
        for sub in v:
            cand = _last_line_value(sub)
            if cand > best:
                best = cand
        return best
    return 0

"""AST-based pretty-printer (Phase 3 of formatter v3).

Walks a parsed Capa AST and emits canonical Capa source.

Public entry point: :func:`format_source_emit`. Composes the
:class:`Lexer` + :class:`Parser` and then runs an :class:`_Emitter`
over the resulting :class:`A.Module`. The emitter accepts an
optional :class:`CommentMap`; when present, leading / trailing /
trailing-header comments are re-emitted in the right slots so an
AST round-trip preserves source comments.

The emission logic is split across three mixins:

- :mod:`._emit_items` - top-level items (``import``, ``const``,
  ``type``, ``trait``, ``impl``, ``fun``) and the ``Module``
  entry.
- :mod:`._emit_stmts` - statements and patterns.
- :mod:`._emit_exprs` - expressions and type expressions.

The shared :class:`_Emitter` class owns the output buffer,
indentation depth, optional :class:`CommentMap`, and the helpers
the per-node methods call (``_write``, ``_newline``, ``_indent``,
``_push_indent`` / ``_pop_indent``).

Scope cuts documented at the top of this module:

- Interior block-comment placement is deferred; an ``interior``
  comment is hoisted to a trailing comment on the parent
  statement. Round-trip parse equality is unaffected.
- Multi-line doc comments emit as ``/// line`` per source line;
  the ``/** */`` block form is not reconstructed (the line form
  is canonical).
- Blank-line preservation is item-level only: exactly one blank
  line between every top-level item. Blank lines inside function
  bodies have no AST representation and are not preserved.
- Trailing commas are omitted; the canonical form has none.
- Match expressions are always emitted in the multi-line form,
  even when the source used the inline ``{ p -> e, p -> e }``
  shape. Both forms produce the same AST.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..lexer import Lexer
from ..parser import Parser

from ._emit_exprs import _ExprsEmitterMixin
from ._emit_items import _ItemsEmitterMixin
from ._emit_stmts import _StmtsEmitterMixin


def format_source_emit(
    source: str,
    *,
    cmap: Optional["object"] = None,
) -> str:
    """Format ``source`` via parse + AST round-trip.

    Raises ``LexerError`` / ``ParserError`` if ``source`` does not
    lex or parse; the caller (the top-level ``format_source``
    wrapper in Phase 4) is responsible for catching and falling
    back to the line-level pipeline on failure.

    When ``cmap`` is None, the emitter tries to build one from the
    lexer's comment sidecar. If the Phase-2 ``_comments`` module
    has not landed (``ImportError``), the emitter proceeds without
    comments; the output structure is identical, only the comment
    text is missing.
    """
    lexer = Lexer(source)
    tokens = lexer.lex()
    parser = Parser(tokens, source=source, filename="<fmt>")
    module = parser.parse_module()
    if cmap is None:
        try:
            from ._comments import build_comment_map  # type: ignore
            cmap = build_comment_map(module, tokens, lexer.comments)
        except ImportError:
            cmap = None
    emitter = _Emitter(cmap=cmap)
    emitter.emit_module(module)
    return emitter.text()


class _Emitter(
    _ItemsEmitterMixin,
    _StmtsEmitterMixin,
    _ExprsEmitterMixin,
):
    """Accumulator + dispatcher used by the three per-category mixins.

    The buffer is a ``list[str]`` of chunks; :meth:`text` joins it
    and ensures exactly one trailing ``\\n``. Indentation is tracked
    as a depth counter; each ``_indent()`` writes ``depth * 4``
    spaces.

    The optional ``cmap`` argument is a ``CommentMap``-shaped
    object. The mixins consult it through :meth:`_emit_leading`,
    :meth:`_emit_trailing_header`, :meth:`_emit_trailing`, none of
    which fail if ``cmap`` is None.
    """

    INDENT_UNIT: str = "    "

    def __init__(self, *, cmap: Optional["object"] = None) -> None:
        self._buf: list[str] = []
        self._depth: int = 0
        self._cmap = cmap
        # Track whether the buffer currently ends at a fresh line
        # (i.e. the last chunk written ended with ``\n`` or the
        # buffer is empty). Used by ``_indent`` to avoid double-
        # indenting when the caller is mid-line.
        self._at_line_start: bool = True

    # ------------------------------------------------------------
    # Buffer mechanics
    # ------------------------------------------------------------
    def text(self) -> str:
        """Return the accumulated output with exactly one final newline.

        The buffer is allowed to end with zero, one, or multiple
        trailing newlines during emission; we normalise at the
        boundary so callers do not have to police every code path.
        """
        s = "".join(self._buf)
        # Strip any trailing whitespace newlines and re-add exactly
        # one. ``rstrip("\n")`` would leave trailing spaces; we want
        # the canonical "no trailing whitespace, one final newline".
        while s.endswith("\n"):
            s = s[:-1]
        # Also strip trailing spaces on the last line, in case some
        # comment-emission path left one.
        # (Cheap: lines split + last line strip.)
        if s:
            lines = s.split("\n")
            lines[-1] = lines[-1].rstrip()
            s = "\n".join(lines)
            return s + "\n"
        return ""

    def _write(self, s: str) -> None:
        if not s:
            return
        self._buf.append(s)
        self._at_line_start = s.endswith("\n")

    def _newline(self) -> None:
        self._buf.append("\n")
        self._at_line_start = True

    def _indent(self) -> None:
        """Write the current indentation prefix if we are at line start."""
        if self._at_line_start:
            self._buf.append(self.INDENT_UNIT * self._depth)
            self._at_line_start = False

    def _push_indent(self) -> None:
        self._depth += 1

    def _pop_indent(self) -> None:
        assert self._depth > 0, "indent underflow"
        self._depth -= 1

    # ------------------------------------------------------------
    # Comment hooks
    # ------------------------------------------------------------
    def _attached(self, node: A.Node):
        """Return the AttachedComments for ``node`` or None.

        The CommentMap shape (see Phase-2 design doc): ``get(node)``
        returns an object with ``leading``, ``trailing``,
        ``trailing_header``, ``interior`` list attributes, or None
        when the node has no attached comments.
        """
        if self._cmap is None:
            return None
        return self._cmap.get(node)

    def _emit_leading(self, node: A.Node) -> None:
        att = self._attached(node)
        if att is None:
            return
        for c in getattr(att, "leading", []) or []:
            self._indent()
            self._write(c.text)
            self._newline()

    def _emit_trailing_header(self, node: A.Node) -> None:
        """Emit comments that should land at the END of a header line.

        Must be called AFTER the header text but BEFORE the closing
        newline. Adds a two-space gap before the comment marker, the
        idiomatic spacing in the example corpus.
        """
        att = self._attached(node)
        if att is None:
            return
        comments = getattr(att, "trailing_header", []) or []
        if not comments:
            return
        text = " ".join(c.text for c in comments)
        self._write("  " + text)

    def _emit_trailing(self, node: A.Node) -> None:
        """Emit trailing comments (statement-line, same as header).

        Like ``_emit_trailing_header`` but for non-compound nodes
        whose entire emission is one line. By construction a
        ``trailing`` comment in Phase-2 sits on the same source
        line as its owner; we emit it before the newline that
        ends that line.
        """
        att = self._attached(node)
        if att is None:
            return
        comments = getattr(att, "trailing", []) or []
        if not comments:
            return
        text = " ".join(c.text for c in comments)
        self._write("  " + text)

    def _emit_block_trailing(self, block: A.Block) -> None:
        """Emit trailing (floating) comments at the end of a Block.

        These are comments whose source position was inside the
        block but after the last statement (e.g. a section divider
        with no following statement, or a final ``// end`` note).
        Emitted at the current indentation level, one per line.
        """
        att = self._attached(block)
        if att is None:
            return
        for c in getattr(att, "trailing", []) or []:
            self._indent()
            self._write(c.text)
            self._newline()


__all__ = ["format_source_emit", "_Emitter"]

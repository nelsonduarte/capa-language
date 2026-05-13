"""Comment-lexing mixin.

Handles both plain comments (``//`` line, ``/* */`` block) and doc
comments (``///`` line, ``/** */`` block). Plain comments are
silently consumed; doc comments emit a ``DOC_COMMENT`` token with
its text content as ``value``.

- ``_skip_line_comment``: ``// ...`` up to the newline.
- ``_lex_doc_line_comment``: emit ``DOC_COMMENT`` for ``/// text``,
  stripping one leading space.
- ``_lex_doc_block_comment``: emit ``DOC_COMMENT`` for
  ``/** ... */``, supporting nesting and stripping the Javadoc-style
  ``*`` left-margin decoration.
- ``_skip_block_comment``: ``/* ... */``, supporting nesting.
"""

from __future__ import annotations

from ..tokens import TokenKind


class _CommentsMixin:
    def _skip_line_comment(self) -> None:
        """Skips // ... until the newline (without consuming the newline)."""
        # We are already at '/'; the second '/' is at peek(1).
        self._advance()  # /
        self._advance()  # /
        while not self._at_end() and self._peek() != "\n":
            self._advance()

    def _lex_doc_line_comment(self) -> None:
        """Emits a DOC_COMMENT token for ``/// text...`` up to (but not
        consuming) the newline. The token's ``value`` is the text
        content with one leading space stripped (the convention is
        ``/// text``, not ``///text``).
        """
        start = self._pos()
        self._advance()  # /
        self._advance()  # /
        self._advance()  # /
        text_start = self.offset
        while not self._at_end() and self._peek() != "\n":
            self._advance()
        body = self.source[text_start:self.offset]
        # Strip one leading space if present (idiomatic spacing).
        if body.startswith(" "):
            body = body[1:]
        # Strip trailing whitespace (but keep meaningful content).
        body = body.rstrip()
        self._emit(
            TokenKind.DOC_COMMENT,
            self.source[start.offset:self.offset],
            start,
            value=body,
        )

    def _lex_doc_block_comment(self) -> None:
        """Emits a DOC_COMMENT token for ``/** ... */``. Supports
        nesting on the outer ``/* ... */`` pair (matching
        ``_skip_block_comment``). The token's ``value`` is the inner
        text with the typical Javadoc-style ``*`` left-margin
        decoration stripped, so ``/** line1\\n * line2 */`` reads as
        ``line1\\nline2``.
        """
        from . import _strip_block_doc_margins
        start = self._pos()
        self._advance()  # /
        self._advance()  # *
        self._advance()  # *  (second star, makes it a doc comment)
        text_start = self.offset
        depth = 1
        while depth > 0:
            if self._at_end():
                raise self._error("unterminated doc block comment", start)
            if self._peek() == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                depth += 1
            elif self._peek() == "*" and self._peek(1) == "/":
                end_inner = self.offset
                self._advance()
                self._advance()
                depth -= 1
                if depth == 0:
                    raw = self.source[text_start:end_inner]
                    body = _strip_block_doc_margins(raw)
                    self._emit(
                        TokenKind.DOC_COMMENT,
                        self.source[start.offset:self.offset],
                        start,
                        value=body,
                    )
                    return
            else:
                self._advance()

    def _skip_block_comment(self) -> None:
        """Skips /* ... */, supporting nesting."""
        start = self._pos()
        self._advance()  # /
        self._advance()  # *
        depth = 1
        while depth > 0:
            if self._at_end():
                raise self._error("unterminated block comment", start)
            if self._peek() == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                depth += 1
            elif self._peek() == "*" and self._peek(1) == "/":
                self._advance()
                self._advance()
                depth -= 1
            else:
                self._advance()

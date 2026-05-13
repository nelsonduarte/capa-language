"""Hand-written lexer for the Capa language.

This implementation follows the specification of chapters 3 and 4 of
the EBNF document: tokens recognized with the maximal munch rule,
significant indentation managed by a level stack that emits
NEWLINE/INDENT/DEDENT, tabs forbidden at the start of a line, and
implicit line continuation inside parentheses (any of the three
kinds).

Notes on the scope of version 1.0:
- String interpolation (``${...}`` syntax) is recognized syntactically
  but not tokenized recursively: the expression inside the braces is
  kept as literal part of the string value. This limitation is
  deliberate to keep the lexer simple; the parser can re-lex the
  contents if needed.
- Raw strings (``r"..."``) are recognised. No escape processing
  applies inside them: every character up to the next unescaped
  quote is taken literally (no ``\\n``, no ``${}`` interpolation).
  This means a raw string cannot itself contain ``"``; for those
  cases use a regular string with ``\"``. The intended use is
  Windows paths and regular-expression patterns where backslashes
  would otherwise need to be doubled.

The lexer is split across four mixins:

- :mod:`._indent` - ``_process_line_start`` and the indent-stack
  bookkeeping.
- :mod:`._comments` - line and block comments (regular and doc).
- :mod:`._literals` - numbers, strings (regular + raw), characters,
  and escape sequences.
- :mod:`._tokens` - the per-token dispatcher plus identifiers and
  punctuation (with maximal-munch lookahead).

This module hosts the :class:`Lexer` composition, the cursor
helpers shared by every mixin, the main ``lex()`` loop, and the
small ``_strip_block_doc_margins`` helper used by the doc-block
lexer.
"""

from typing import Optional

from ..errors import LexerError
from ..tokens import KEYWORDS, Pos, Token, TokenKind

from ._comments import _CommentsMixin
from ._indent import _IndentMixin
from ._literals import _LiteralsMixin
from ._tokens import _TokensMixin


def _strip_block_doc_margins(raw: str) -> str:
    """Normalise the body of a ``/** ... */`` doc block.

    Strips one leading space at the very start (idiomatic spacing),
    and on every continuation line removes leading whitespace
    followed by an optional ``*`` and one space, so that

        /** line1
         * line2
         */

    yields ``line1\\nline2`` and not ``line1\\n * line2``. The result
    has trailing whitespace stripped.
    """
    lines = raw.splitlines()
    if not lines:
        return ""
    out = []
    for i, line in enumerate(lines):
        if i == 0:
            # First line: strip one leading space.
            out.append(line[1:] if line.startswith(" ") else line)
            continue
        stripped = line.lstrip()
        if stripped.startswith("* "):
            out.append(stripped[2:])
        elif stripped == "*":
            out.append("")
        else:
            out.append(stripped)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out).rstrip()


class Lexer(
    _IndentMixin,
    _CommentsMixin,
    _LiteralsMixin,
    _TokensMixin,
):
    """Recursive descent lexer for Capa.

    Typical use:

        lexer = Lexer(source, filename="file.capa")
        tokens = lexer.lex()

    A Lexer is not reusable: create a new one for each analysis.
    """

    def __init__(self, source: str, filename: str = "<input>"):
        self.source = source
        self.filename = filename

        # Cursor into the source
        self.offset = 0
        self.line = 1
        self.col = 1

        # Stack of indentation levels. Always starts with 0 (top of program).
        self.indent_stack: list[int] = [0]

        # Depth of open parentheses. Newlines inside parentheses do not
        # terminate the logical line (implicit continuation).
        self.paren_depth = 0

        # Stack of open parentheses, for better error messages when
        # there is an unmatched closer.
        self.paren_stack: list[tuple[str, Pos]] = []

        # Token accumulator.
        self.tokens: list[Token] = []

    # ===========================================================
    # Cursor helpers
    # ===========================================================

    def _at_end(self) -> bool:
        return self.offset >= len(self.source)

    def _peek(self, n: int = 0) -> str:
        i = self.offset + n
        if i >= len(self.source):
            return ""
        return self.source[i]

    def _pos(self) -> Pos:
        return Pos(self.line, self.col, self.offset)

    def _advance(self) -> str:
        c = self.source[self.offset]
        self.offset += 1
        if c == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return c

    def _next_non_blank_line_starts_with_dot(self) -> bool:
        """Lookahead starting from the current ``\\n``: skips blank
        lines (whitespace only or comment lines) and returns True if
        the next content line begins with ``.``.

        Used for multi-line method chaining: ``xs\\n  .map(f)`` is
        treated as a single logical line.
        """
        i = self.offset
        # Skip the current '\\n'.
        if i < len(self.source) and self.source[i] == "\n":
            i += 1
        while i < len(self.source):
            # Skip horizontal whitespace at the start.
            while i < len(self.source) and self.source[i] in (" ", "\t"):
                i += 1
            if i >= len(self.source):
                return False
            c = self.source[i]
            if c == "\n":
                # Blank line - keep searching.
                i += 1
                continue
            if c == "/" and i + 1 < len(self.source) and self.source[i + 1] == "/":
                # Line comment - skip to the end.
                while i < len(self.source) and self.source[i] != "\n":
                    i += 1
                continue
            return c == "."
        return False

    def _skip_blank_lines_and_indent(self) -> None:
        """Advances the cursor through blank lines and the indent of
        the next content line, stopping before the first non-whitespace
        character (which will be the ``.``).

        Does not update ``self.indent_stack`` - this function is only
        called when we are doing implicit continuation, where indent
        does not count.
        """
        while not self._at_end():
            c = self._peek()
            if c == "\n":
                self._advance()
                continue
            if c == " " or c == "\t":
                self._advance()
                continue
            if c == "/" and self._peek(1) == "/":
                while not self._at_end() and self._peek() != "\n":
                    self._advance()
                continue
            return

    def _consume(self, expected: str) -> bool:
        if self._peek() == expected:
            self._advance()
            return True
        return False

    def _error(self, msg: str, pos: Optional[Pos] = None) -> "LexerError":
        return LexerError(msg, pos or self._pos(), self.source, self.filename)

    # ===========================================================
    # Main entry point
    # ===========================================================

    def lex(self) -> list[Token]:
        # The first line of the file also goes through
        # _process_line_start, even though there is typically no initial
        # indentation.
        self._process_line_start()

        while not self._at_end():
            c = self._peek()

            # Newline: ends the logical line if we are outside parentheses.
            if c == "\n":
                if self.paren_depth == 0:
                    # Lookahead for multi-line method chaining: if the
                    # next content line begins with '.', suppress the
                    # NEWLINE and indent tracking. This allows:
                    #     let r = xs
                    #         .filter(...)
                    #         .map(...)
                    # without the parser seeing separate statements.
                    if self._next_non_blank_line_starts_with_dot():
                        # Skip the \n and all whitespace on the next
                        # line, leaving the cursor at the '.'.
                        self._advance()
                        self._skip_blank_lines_and_indent()
                        continue
                    start = self._pos()
                    self._advance()
                    self._emit(TokenKind.NEWLINE, "\n", start, value=None)
                    self._process_line_start()
                else:
                    # Inside parentheses: newline is just whitespace.
                    self._advance()
                continue

            # Horizontal whitespace (mid-line): consumed silently.
            if c == " " or c == "\t":
                self._advance()
                continue

            # Explicit continuation via backslash: \\ \n discards the break.
            if c == "\\" and self._peek(1) == "\n":
                self._advance()  # \\
                self._advance()  # \n
                continue

            # Comments. Doc comments (/// or /**) emit a token; plain
            # comments are dropped on the floor.
            if c == "/" and self._peek(1) == "/":
                if self._peek(2) == "/" and self._peek(3) != "/":
                    self._lex_doc_line_comment()
                else:
                    self._skip_line_comment()
                continue
            if c == "/" and self._peek(1) == "*":
                if self._peek(2) == "*" and self._peek(3) != "/":
                    self._lex_doc_block_comment()
                else:
                    self._skip_block_comment()
                continue

            # Real token
            self._lex_token()

        # End of file: emit final NEWLINE (if missing), DEDENTs, EOF.
        end = self._pos()

        # Check for unclosed open parentheses.
        if self.paren_stack:
            opener, opener_pos = self.paren_stack[-1]
            raise self._error(
                f"Unclosed {opener!r} (opened at line {opener_pos.line}, col {opener_pos.col})",
                opener_pos,
            )

        if self.tokens and self.tokens[-1].kind not in (
            TokenKind.NEWLINE,
            TokenKind.INDENT,
            TokenKind.DEDENT,
        ):
            self._emit(TokenKind.NEWLINE, "", end, value=None)

        while len(self.indent_stack) > 1:
            self.indent_stack.pop()
            self._emit(TokenKind.DEDENT, "", end, value=None)

        self._emit(TokenKind.EOF, "", end, value=None)
        return self.tokens

    def _emit(
        self,
        kind: TokenKind,
        text: str,
        start: Pos,
        value=None,
    ) -> None:
        self.tokens.append(Token(kind, text, value, start, self._pos()))

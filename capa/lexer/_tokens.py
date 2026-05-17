"""Per-token lexing mixin: the dispatcher, identifiers, and punctuation.

``_lex_token`` is the per-token entry point invoked from the main
loop in :meth:`Lexer.lex`. It peeks one character and routes to one
of the literal lexers (in :mod:`._literals`), the identifier lexer
here, or the punctuation lexer here.

- ``_lex_token``: top-level dispatch.
- ``_lex_identifier``: bare identifiers and keywords (looked up in
  the ``KEYWORDS`` table). A lone ``_`` becomes ``UNDERSCORE``.
- ``_lex_punct``: operators and punctuation, including the maximal-
  munch lookahead for compound operators (``==``, ``=>``, ``+=``,
  ``->``, ``..``, ``..=``, etc.) and the paren-stack bookkeeping for
  implicit line continuation.
"""

from __future__ import annotations

from ..tokens import KEYWORDS, Pos, TokenKind


_SINGLE_CHAR_TOKENS: dict[str, TokenKind] = {
    ",": TokenKind.COMMA,
    ":": TokenKind.COLON,
    ";": TokenKind.SEMI,
    "?": TokenKind.QUESTION,
    "|": TokenKind.PIPE,
    "@": TokenKind.AT,
    "(": TokenKind.LPAREN,
    ")": TokenKind.RPAREN,
    "[": TokenKind.LBRACKET,
    "]": TokenKind.RBRACKET,
    "{": TokenKind.LBRACE,
    "}": TokenKind.RBRACE,
}

_OPEN_PAREN = "([{"
_CLOSE_PAREN = ")]}"
_MATCHING_PAREN = {")": "(", "]": "[", "}": "{"}


class _TokensMixin:
    def _lex_token(self) -> None:
        start = self._pos()
        c = self._peek()

        # Raw string literal: r"..."
        # Recognised only when "r" is immediately followed by a double
        # quote; the bare identifier "r" is still a valid identifier.
        if c == "r" and self._peek(1) == '"':
            self._advance()  # 'r' prefix
            self._lex_raw_string(start)
            return

        # Identifier / keyword
        if c.isalpha() or c == "_":
            self._lex_identifier(start)
            return

        # Numeric literal
        if c.isdigit():
            self._lex_number(start)
            return

        # String literal
        if c == '"':
            self._lex_string(start)
            return

        # Character literal
        if c == "'":
            self._lex_char(start)
            return

        # Operator / punctuation
        self._lex_punct(start)

    def _lex_identifier(self, start: Pos) -> None:
        while not self._at_end():
            c = self._peek()
            if c.isalnum() or c == "_":
                self._advance()
            else:
                break
        text = self._slice_from(start)

        # Special case: a lone '_' is wildcard, not identifier.
        if text == "_":
            self._emit(TokenKind.UNDERSCORE, "_", start)
            return

        if text in KEYWORDS:
            self._emit(KEYWORDS[text], text, start)
        else:
            self._emit(TokenKind.IDENT, text, start, value=text)

    def _lex_punct(self, start: Pos) -> None:
        c = self._peek()

        # Operators with lookahead (maximal munch)
        if c == "=":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.EQ_EQ, "==", start)
            elif self._consume(">"):
                self._emit(TokenKind.FAT_ARROW, "=>", start)
            else:
                self._emit(TokenKind.EQ, "=", start)
            return

        if c == "!":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.BANG_EQ, "!=", start)
                return
            else:
                raise self._error(
                    "unexpected '!'; for logical negation, use 'not'; "
                    "for inequality, use '!='",
                    start,
                )

        if c == "<":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.LT_EQ, "<=", start)
            else:
                self._emit(TokenKind.LT, "<", start)
            return

        if c == ">":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.GT_EQ, ">=", start)
            else:
                self._emit(TokenKind.GT, ">", start)
            return

        if c == "+":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.PLUS_EQ, "+=", start)
            else:
                self._emit(TokenKind.PLUS, "+", start)
            return

        if c == "-":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.MINUS_EQ, "-=", start)
            elif self._consume(">"):
                self._emit(TokenKind.ARROW, "->", start)
            else:
                self._emit(TokenKind.MINUS, "-", start)
            return

        if c == "*":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.STAR_EQ, "*=", start)
            else:
                self._emit(TokenKind.STAR, "*", start)
            return

        if c == "/":
            # Comments are already handled by the main loop; here only
            # / or /= can appear.
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.SLASH_EQ, "/=", start)
            else:
                self._emit(TokenKind.SLASH, "/", start)
            return

        if c == "%":
            self._advance()
            if self._consume("="):
                self._emit(TokenKind.PERCENT_EQ, "%=", start)
            else:
                self._emit(TokenKind.PERCENT, "%", start)
            return

        if c == ".":
            self._advance()
            if self._consume("."):
                if self._consume("="):
                    self._emit(TokenKind.DOT_DOT_EQ, "..=", start)
                else:
                    self._emit(TokenKind.DOT_DOT, "..", start)
            else:
                self._emit(TokenKind.DOT, ".", start)
            return

        # Single-character tokens
        if c in _SINGLE_CHAR_TOKENS:
            kind = _SINGLE_CHAR_TOKENS[c]
            self._advance()
            if c in _OPEN_PAREN:
                self.paren_depth += 1
                self.paren_stack.append((c, start))
            elif c in _CLOSE_PAREN:
                expected = _MATCHING_PAREN[c]
                if not self.paren_stack:
                    raise self._error(
                        f"unmatched closing {c!r} (no matching opener)",
                        start,
                    )
                opener, _ = self.paren_stack[-1]
                if opener != expected:
                    raise self._error(
                        f"mismatched delimiter: expected closing match for "
                        f"{opener!r}, got {c!r}",
                        start,
                    )
                self.paren_stack.pop()
                self.paren_depth -= 1
            self._emit(kind, c, start)
            return

        raise self._error(f"unexpected character: {c!r}", start)

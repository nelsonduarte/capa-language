"""Literal-lexing mixin: numbers, strings (regular + raw), characters.

Each method assumes the relevant opener has been peeked but not
consumed; the method itself advances past it.

- ``_lex_number``: ints (binary / octal / decimal / hex), floats,
  with exponent and underscore separators.
- ``_consume_digits``: shared helper that drives the digit consumer
  with the underscore-separator rules.
- ``_lex_string``: regular ``"..."`` literals with escape sequences
  and ``${...}`` recognition (kept as literal text in v1).
- ``_lex_raw_string``: ``r"..."`` with no escapes and no
  interpolation; the ``r`` prefix has already been consumed by the
  caller.
- ``_read_escape``: the escape-sequence DFA, including the ``\\u{...}``
  Unicode form.
- ``_lex_char``: ``'c'`` literals; a single character or one escape
  sequence.
"""

from __future__ import annotations

from ..tokens import Pos, TokenKind


_DEC_DIGITS = "0123456789"
_HEX_DIGITS = "0123456789abcdefABCDEF"
_OCT_DIGITS = "01234567"
_BIN_DIGITS = "01"


class _LiteralsMixin:
    def _lex_number(self, start: Pos) -> None:
        # Detect non-decimal base prefixes: 0x, 0o, 0b.
        if self._peek() == "0" and self._peek(1) in ("x", "X", "o", "O", "b", "B"):
            self._advance()  # 0
            base_char = self._advance().lower()
            if base_char == "x":
                self._consume_digits(_HEX_DIGITS, "hexadecimal", start)
                base = 16
            elif base_char == "o":
                self._consume_digits(_OCT_DIGITS, "octal", start)
                base = 8
            else:
                self._consume_digits(_BIN_DIGITS, "binary", start)
                base = 2
            text = self.source[start.offset : self.offset]
            value = int(text[2:].replace("_", ""), base)
            self._emit(TokenKind.INT_LIT, text, start, value=value)
            return

        # Decimal - may be INT or FLOAT.
        self._consume_digits(_DEC_DIGITS, "decimal", start)
        is_float = False

        # Fractional part: '.' followed by a digit (do not consume if it
        # is the '.' operator applied to an integer, e.g., 5.method()).
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            self._advance()
            self._consume_digits(_DEC_DIGITS, "fractional part of float", start)

        # Exponent.
        if self._peek() in ("e", "E"):
            is_float = True
            self._advance()
            if self._peek() in ("+", "-"):
                self._advance()
            if not self._peek().isdigit():
                raise self._error("expected digit in exponent")
            self._consume_digits(_DEC_DIGITS, "exponent", start)

        text = self.source[start.offset : self.offset]
        if is_float:
            value = float(text.replace("_", ""))
            self._emit(TokenKind.FLOAT_LIT, text, start, value=value)
        else:
            value = int(text.replace("_", ""))
            self._emit(TokenKind.INT_LIT, text, start, value=value)

    def _consume_digits(self, valid: str, what: str, start: Pos) -> None:
        """Consumes a sequence of digits in the given base, with
        underscores allowed as visual separators, but not at the start
        or end, nor two consecutive.
        """
        # Careful: in Python, '' in 'abc' is True (empty subsequence).
        # So we explicitly check for EOF before testing `in`.
        if self._at_end() or self._peek() not in valid:
            raise self._error(f"expected {what} digit", self._pos())
        last_was_underscore = False
        consumed = 0
        while not self._at_end():
            c = self._peek()
            if c in valid:
                self._advance()
                last_was_underscore = False
                consumed += 1
            elif c == "_":
                if last_was_underscore:
                    raise self._error(
                        "consecutive underscores in numeric literal"
                    )
                if consumed == 0:
                    raise self._error(
                        "numeric literal cannot start with underscore"
                    )
                self._advance()
                last_was_underscore = True
            else:
                break
        if last_was_underscore:
            raise self._error("numeric literal cannot end with underscore")

    def _lex_string(self, start: Pos) -> None:
        self._advance()  # opening quote
        buf: list[str] = []
        while not self._at_end():
            c = self._peek()
            if c == '"':
                self._advance()
                text = self.source[start.offset : self.offset]
                self._emit(TokenKind.STRING_LIT, text, start, value="".join(buf))
                return
            if c == "\n":
                raise self._error(
                    "unterminated string literal (newline before closing quote)",
                    start,
                )
            if c == "\\":
                self._advance()
                buf.append(self._read_escape())
                continue
            if c == "$" and self._peek(1) == "{":
                # Interpolation recognized but not tokenized in v1.0.
                # The content between ${ and } is kept as literal part
                # of the value.
                # TODO(v1.1): emit STRING_PART / sub-tokens / STRING_PART.
                buf.append(c)
                self._advance()
                continue
            buf.append(c)
            self._advance()
        raise self._error("unterminated string literal", start)

    def _lex_raw_string(self, start: Pos) -> None:
        """Lexes a raw string literal ``r"..."``.

        The opening ``r`` has already been consumed by the caller.
        Inside a raw string, backslashes are literal and ``${...}``
        interpolation is not recognised. The closing ``"`` cannot
        therefore be escaped: include none, or use a regular string.
        """
        self._advance()  # opening quote
        buf: list[str] = []
        while not self._at_end():
            c = self._peek()
            if c == '"':
                self._advance()
                text = self.source[start.offset : self.offset]
                self._emit(TokenKind.STRING_LIT, text, start, value="".join(buf))
                return
            if c == "\n":
                raise self._error(
                    "unterminated raw string literal "
                    "(newline before closing quote)",
                    start,
                )
            buf.append(c)
            self._advance()
        raise self._error("unterminated raw string literal", start)

    def _read_escape(self) -> str:
        """Reads an escape sequence after '\\\\' has been consumed."""
        if self._at_end():
            raise self._error("unterminated escape sequence")
        c = self._peek()
        simple = {
            "n": "\n", "r": "\r", "t": "\t",
            "\\": "\\", '"': '"', "'": "'",
            "0": "\0",
        }
        if c in simple:
            self._advance()
            return simple[c]
        if c == "u":
            self._advance()
            if self._peek() != "{":
                raise self._error(
                    "expected '{' after \\u in unicode escape sequence"
                )
            self._advance()
            hex_str = ""
            while self._peek() != "}" and not self._at_end():
                ch = self._peek()
                if ch in _HEX_DIGITS:
                    hex_str += ch
                    self._advance()
                else:
                    raise self._error(
                        f"invalid hex digit in unicode escape: {ch!r}"
                    )
            if self._peek() != "}":
                raise self._error("unterminated unicode escape sequence")
            self._advance()  # }
            if not hex_str:
                raise self._error("empty unicode escape sequence")
            if len(hex_str) > 6:
                raise self._error(
                    "unicode escape sequence too long (max 6 hex digits)"
                )
            codepoint = int(hex_str, 16)
            if codepoint > 0x10FFFF:
                raise self._error(
                    f"unicode escape U+{codepoint:X} out of range "
                    "(max U+10FFFF)"
                )
            return chr(codepoint)
        raise self._error(f"unknown escape sequence: \\{c}")

    def _lex_char(self, start: Pos) -> None:
        self._advance()  # opening quote
        if self._at_end():
            raise self._error("unterminated character literal", start)
        c = self._peek()
        if c == "'":
            raise self._error("empty character literal", start)
        if c == "\n":
            raise self._error(
                "unterminated character literal (newline before closing quote)",
                start,
            )
        if c == "\\":
            self._advance()
            ch = self._read_escape()
        else:
            ch = c
            self._advance()
        if self._peek() != "'":
            raise self._error(
                "expected closing quote in character literal "
                "(character literals contain a single character)"
            )
        self._advance()
        text = self.source[start.offset : self.offset]
        self._emit(TokenKind.CHAR_LIT, text, start, value=ch)

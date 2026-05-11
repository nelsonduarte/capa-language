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
- Raw strings (r"...") are not yet implemented.
"""

from typing import Optional

from .errors import LexerError
from .tokens import KEYWORDS, Pos, Token, TokenKind


# Characters that form digits in each base
_DEC_DIGITS = "0123456789"
_HEX_DIGITS = "0123456789abcdefABCDEF"
_OCT_DIGITS = "01234567"
_BIN_DIGITS = "01"

# Map of single-character tokens (excluding those that need lookahead)
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


class Lexer:
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

            # Comments
            if c == "/" and self._peek(1) == "/":
                self._skip_line_comment()
                continue
            if c == "/" and self._peek(1) == "*":
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

    # ===========================================================
    # Start of line (indentation)
    # ===========================================================

    def _process_line_start(self) -> None:
        """Processes the indentation at the start of a logical line.

        Skips blank lines and lines that contain only comments, without
        emitting INDENT/DEDENT for them. When the first line with real
        content is found, computes the indentation level and emits the
        necessary INDENT or DEDENT tokens.
        """
        while not self._at_end():
            line_start_pos = self._pos()

            # Tabs forbidden at the start of a line (design decision,
            # documented in section 4.1 of the spec).
            if self._peek() == "\t":
                raise self._error(
                    "tabs are not allowed at the start of a line; "
                    "use spaces only (4 by convention)",
                )

            # Count indentation spaces.
            indent = 0
            while self._peek() == " ":
                self._advance()
                indent += 1

            # A tab after spaces is still a tab at the start of the
            # line (because no non-space content has appeared yet).
            if self._peek() == "\t":
                raise self._error(
                    "tabs are not allowed at the start of a line; "
                    "use spaces only (4 by convention)",
                )

            c = self._peek()

            # End of file: nothing to do.
            if c == "":
                return

            # Blank line: skip with no effect.
            if c == "\n":
                self._advance()
                continue

            # Line comment: skip the whole line.
            if c == "/" and self._peek(1) == "/":
                self._skip_line_comment()
                if self._peek() == "\n":
                    self._advance()
                continue

            # Block comment at the start of the line: skip it and
            # re-evaluate the start of line from where we left off.
            if c == "/" and self._peek(1) == "*":
                self._skip_block_comment()
                # If it ended in the middle of a line with content, we
                # stop here and use the indentation we already counted.
                # If it ended on a blank line or at the end of file, we
                # continue the loop. To detect, we peek without
                # consuming. Without consuming anything else from the
                # current line, check whether there is only whitespace
                # until the newline.
                save = self.offset
                save_line, save_col = self.line, self.col
                while self._peek() == " " or self._peek() == "\t":
                    self._advance()
                tail = self._peek()
                if tail == "" or tail == "\n":
                    # The comment was all there was; continue the loop.
                    if tail == "\n":
                        self._advance()
                    continue
                if tail == "/" and self._peek(1) == "/":
                    # Another comment follows on the same line.
                    self._skip_line_comment()
                    if self._peek() == "\n":
                        self._advance()
                    continue
                # There is real content after the comment; restore the
                # cursor to right after the comment so that content is
                # lexed by the main loop, and use the indentation
                # counted before the comment.
                self.offset, self.line, self.col = save, save_line, save_col
                break

            # Real content found.
            break
        else:
            return

        # Apply the indentation change.
        current = self.indent_stack[-1]
        if indent > current:
            self.indent_stack.append(indent)
            self._emit(
                TokenKind.INDENT, " " * indent, line_start_pos, value=None
            )
        elif indent < current:
            while len(self.indent_stack) > 1 and self.indent_stack[-1] > indent:
                self.indent_stack.pop()
                self._emit(TokenKind.DEDENT, "", line_start_pos, value=None)
            if self.indent_stack[-1] != indent:
                raise self._error(
                    "inconsistent indentation: indent does not match any "
                    "outer level",
                    line_start_pos,
                )
        # If indent == current, no tokens to emit.

    # ===========================================================
    # Comments
    # ===========================================================

    def _skip_line_comment(self) -> None:
        """Skips // ... until the newline (without consuming the newline)."""
        # We are already at '/'; the second '/' is at peek(1).
        self._advance()  # /
        self._advance()  # /
        while not self._at_end() and self._peek() != "\n":
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

    # ===========================================================
    # Tokens
    # ===========================================================

    def _emit(
        self,
        kind: TokenKind,
        text: str,
        start: Pos,
        value=None,
    ) -> None:
        self.tokens.append(Token(kind, text, value, start, self._pos()))

    def _lex_token(self) -> None:
        start = self._pos()
        c = self._peek()

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

    # -------- Identifiers and keywords --------

    def _lex_identifier(self, start: Pos) -> None:
        while not self._at_end():
            c = self._peek()
            if c.isalnum() or c == "_":
                self._advance()
            else:
                break
        text = self.source[start.offset : self.offset]

        # Special case: a lone '_' is wildcard, not identifier.
        if text == "_":
            self._emit(TokenKind.UNDERSCORE, "_", start)
            return

        if text in KEYWORDS:
            self._emit(KEYWORDS[text], text, start)
        else:
            self._emit(TokenKind.IDENT, text, start, value=text)

    # -------- Numeric literals --------

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

    # -------- String literals --------

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

    # -------- Character literals --------

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

    # -------- Operators and punctuation --------

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

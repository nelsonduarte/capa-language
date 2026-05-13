"""Significant-indentation handling.

Each logical line begins with ``_process_line_start``, which counts
leading spaces, skips blank-and-comment-only lines, rejects tabs at
the start of a line, and emits :data:`TokenKind.INDENT` or one or
more :data:`TokenKind.DEDENT` tokens against the indent stack.

The indent stack itself lives on the ``Lexer`` instance
(``self.indent_stack``), as do the source cursor and the token
accumulator.

The decision to forbid tabs at line start is documented in section
4.1 of the specification; this mixin enforces it.
"""

from __future__ import annotations

from ..tokens import TokenKind


class _IndentMixin:
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

            # Doc line comment at line start: treat as real content
            # for the purposes of indentation. The main loop will
            # then emit the DOC_COMMENT token.
            if (
                c == "/" and self._peek(1) == "/" and self._peek(2) == "/"
                and self._peek(3) != "/"
            ):
                break

            # Line comment (regular): skip the whole line.
            if c == "/" and self._peek(1) == "/":
                self._skip_line_comment()
                if self._peek() == "\n":
                    self._advance()
                continue

            # Doc block comment at line start: same treatment as
            # doc line comments. Fall through to indent emit + return.
            if (
                c == "/" and self._peek(1) == "*" and self._peek(2) == "*"
                and self._peek(3) != "/"
            ):
                break

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

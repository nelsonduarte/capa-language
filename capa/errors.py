"""Lexer errors with pedagogical formatting.

The error message formatting follows a principle stated in the
white paper: messages should teach. To that end, we show the offending
line and a caret pointing at the exact position of the error, in the
style of Rust and Elm.
"""

from .tokens import Pos


class LexerError(Exception):
    """Error detected by the lexer.

    Includes the exact position in the source, a descriptive message, and -
    when the source is supplied, formats a multi-line message with the
    context line and a caret pointing at the position.
    """

    def __init__(
        self,
        message: str,
        pos: Pos,
        source: str = "",
        filename: str = "<input>",
    ):
        self.message = message
        self.pos = pos
        self.source = source
        self.filename = filename
        super().__init__(self.format())

    def format(self) -> str:
        header = f"{self.filename}:{self.pos.line}:{self.pos.col}: error: {self.message}"
        if not self.source:
            return header
        lines = self.source.split("\n")
        if not (1 <= self.pos.line <= len(lines)):
            return header
        line_text = lines[self.pos.line - 1]
        gutter = f"{self.pos.line:>4} | "
        caret_pad = " " * (len(gutter) + max(0, self.pos.col - 1))
        return (
            f"{header}\n"
            f"{gutter}{line_text}\n"
            f"{caret_pad}^"
        )

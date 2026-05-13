"""``textDocument/publishDiagnostics`` computation.

Unlike the other LSP features, diagnostics intentionally do
*not* use :class:`LspContext`: when the lexer or parser fails,
we still want the failure surfaced to the editor (that is the
whole point of the diagnostic), not silently dropped. This
module therefore drives its own parse and produces a Capa-native
``Diagnostic`` list; the server layer wraps each entry into the
LSP wire format.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..analyzer import analyze
from ..errors import LexerError
from ..lexer import Lexer
from ..parser import Parser, ParserError
from ..tokens import Pos


@dataclass(frozen=True)
class Diagnostic:
    """One diagnostic in Capa-native form."""
    pos: Pos
    message: str
    severity: str = "error"   # always "error" in v1
    source: str = "capa-lsp"


def compute_diagnostics(source: str, filename: str) -> list[Diagnostic]:
    """Run the pipeline and return one diagnostic per error.

    Errors from the lexer and parser short-circuit (consistent
    with the CLI); analyzer errors are collected and returned
    together. A clean buffer returns an empty list.
    """
    out: list[Diagnostic] = []
    fallback_pos = Pos(line=1, col=1, offset=0)

    try:
        tokens = Lexer(source, filename=filename).lex()
    except LexerError as e:
        out.append(Diagnostic(pos=e.pos or fallback_pos, message=e.message))
        return out

    try:
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except ParserError as e:
        out.append(Diagnostic(pos=e.pos or fallback_pos, message=e.message))
        return out

    result = analyze(module, source=source, filename=filename)
    for err in result.errors:
        out.append(Diagnostic(pos=err.pos, message=err.message))
    return out

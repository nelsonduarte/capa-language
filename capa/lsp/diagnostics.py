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
    severity: str = "error"   # "error" | "warning"
    source: str = "capa-lsp"


def compute_diagnostics(source: str, filename: str) -> list[Diagnostic]:
    """Run the pipeline and return one diagnostic per error or warning.

    Errors from the lexer and parser short-circuit (consistent
    with the CLI); analyzer errors are collected and returned
    together, followed by the analyzer's non-fatal warnings (the
    dead-Unsafe nudge, IFC warn-then-enforce) with severity
    ``"warning"``. A clean buffer returns an empty list.
    """
    out: list[Diagnostic] = []
    fallback_pos = Pos(line=1, col=1, offset=0)

    try:
        tokens = Lexer(source, filename=filename).lex()
    except LexerError as e:
        out.append(Diagnostic(pos=e.pos or fallback_pos, message=e.message))
        return out
    except RecursionError:
        # Robustness guard: deeply nested input can overflow the lexer.
        # Degrade to no diagnostics rather than crashing the request.
        return out

    try:
        module = Parser(tokens, source=source, filename=filename).parse_module()
    except ParserError as e:
        out.append(Diagnostic(pos=e.pos or fallback_pos, message=e.message))
        return out
    except RecursionError:
        # Robustness guard: a deeply nested expression overflows the
        # recursive-descent parser. Degrade to no diagnostics.
        return out

    try:
        result = analyze(module, source=source, filename=filename)
    except RecursionError:
        # Robustness guard: a deeply nested AST can overflow the
        # analyzer's recursive walk. Degrade to no diagnostics.
        return out
    for err in result.errors:
        out.append(Diagnostic(pos=err.pos, message=err.message))
    for warn in result.warnings:
        out.append(
            Diagnostic(pos=warn.pos, message=warn.message, severity="warning")
        )
    return out

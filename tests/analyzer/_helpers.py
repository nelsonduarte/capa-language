"""Shared helpers for the tests/analyzer/ package.

check() and errors_of() are the two helpers every analyzer test module
imports; this module is their single source. Do not re-export capa types from
here: a module that needs Ty*/ty_str imports them directly from capa.
"""
from capa import Lexer, Parser, analyze, AnalysisResult


def check(source: str) -> AnalysisResult:
    """Lex + parse + analyze. Returns the AnalysisResult."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return analyze(module, source=source)


def errors_of(source: str) -> list[str]:
    """List of error messages (just the message part, without position)."""
    result = check(source)
    return [e.message for e in result.errors]

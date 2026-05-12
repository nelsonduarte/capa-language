"""capa, front-end for the Capa programming language.

This package contains the lexer, parser, AST, type system, semantic
analyzer, transpiler, and runtime for Capa.

Example usage:

    from capa import Lexer, Parser, LexerError

    source = open("program.capa", encoding="utf-8").read()
    try:
        tokens = Lexer(source, filename="program.capa").lex()
        ast = Parser(tokens, source=source, filename="program.capa").parse_module()
    except LexerError as e:
        print(e.format())
"""

from . import capa_ast as ast
from .analyzer import Analyzer, AnalysisError, AnalysisResult, Symbol, SymbolKind, analyze
from .capa_ast import dump as ast_dump
from .errors import LexerError
from .lexer import Lexer
from .parser import Parser, ParserError
from .tokens import KEYWORDS, Pos, Token, TokenKind
from .transpiler import Transpiler, TranspilerError, transpile
from .typesys import Ty, TyName, TyFun, TyTuple, TyVar, TyUnit, TyUnknown, ty_str

__all__ = [
    "analyze",
    "Analyzer",
    "AnalysisError",
    "AnalysisResult",
    "ast",
    "ast_dump",
    "KEYWORDS",
    "Lexer",
    "LexerError",
    "Parser",
    "ParserError",
    "Pos",
    "Symbol",
    "SymbolKind",
    "Token",
    "TokenKind",
    "transpile",
    "Transpiler",
    "TranspilerError",
    "Ty",
    "TyName",
    "TyFun",
    "TyTuple",
    "TyVar",
    "TyUnit",
    "TyUnknown",
    "ty_str",
]

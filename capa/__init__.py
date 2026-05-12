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

# Single source of truth for the package version. Bump here when
# cutting a release; consumers (the manifest builder, the docs
# tooling, the egg-info / wheel metadata) read this value rather
# than hard-coding a string.
__version__ = "0.5.0"

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
    "__version__",
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

"""Token definitions for the Capa language.

This module defines the lexer's vocabulary: the TokenKind enum with all
token types recognized by the language, the Token dataclass which represents
a concrete token produced by the lexer, and the KEYWORDS table that maps
reserved identifiers to their corresponding TokenKind.

The separation between per-keyword TokenKinds (KW_FUN, KW_TYPE, etc.) and
the generic IDENT lets the parser pattern-match directly on the token type,
without having to inspect text.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class TokenKind(Enum):
    # Layout (synthesized by the lexer based on indentation)
    NEWLINE = auto()
    INDENT = auto()
    DEDENT = auto()
    EOF = auto()

    # Doc comments: /// or /** ... */ (outer doc, attached to the
    # next declaration by the parser). Distinct from regular // and
    # /* comments which the lexer drops on the floor.
    DOC_COMMENT = auto()

    # Literals
    INT_LIT = auto()
    FLOAT_LIT = auto()
    STRING_LIT = auto()
    CHAR_LIT = auto()

    # Identifier (non-keyword)
    IDENT = auto()

    # Keywords - declarations
    KW_FUN = auto()
    KW_TYPE = auto()
    KW_TRAIT = auto()
    KW_IMPL = auto()
    KW_CAPABILITY = auto()
    KW_CONST = auto()
    KW_PUB = auto()
    KW_IMPORT = auto()
    KW_AS = auto()

    # Keywords - variable binding
    KW_LET = auto()
    KW_VAR = auto()

    # Keywords - control flow
    KW_IF = auto()
    KW_THEN = auto()
    KW_ELIF = auto()
    KW_ELSE = auto()
    KW_MATCH = auto()
    KW_WHILE = auto()
    KW_FOR = auto()
    KW_IN = auto()
    KW_BREAK = auto()
    KW_CONTINUE = auto()
    KW_RETURN = auto()

    # Keywords - special literals
    KW_TRUE = auto()
    KW_FALSE = auto()

    # Keywords - logical operators
    KW_AND = auto()
    KW_OR = auto()
    KW_NOT = auto()

    # Keywords - self
    KW_SELF = auto()
    KW_BIG_SELF = auto()

    # Keywords - reserved for future use (lexer recognizes, parser rejects)
    KW_ASYNC = auto()
    KW_AWAIT = auto()
    KW_YIELD = auto()
    KW_DEFER = auto()
    KW_WHERE = auto()
    KW_MUT = auto()
    KW_CONSUME = auto()

    # Arithmetic operators
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    PERCENT = auto()

    # Comparison operators
    EQ_EQ = auto()
    BANG_EQ = auto()
    LT = auto()
    LT_EQ = auto()
    GT = auto()
    GT_EQ = auto()

    # Assignment operators
    EQ = auto()
    PLUS_EQ = auto()
    MINUS_EQ = auto()
    STAR_EQ = auto()
    SLASH_EQ = auto()
    PERCENT_EQ = auto()

    # Structural
    AT = auto()           # @ (attribute prefix)
    ARROW = auto()        # ->
    FAT_ARROW = auto()    # =>  (reserved for future use)
    QUESTION = auto()     # ?
    DOT_DOT = auto()      # ..   (exclusive-end range)
    DOT_DOT_EQ = auto()   # ..=  (inclusive-end range)
    DOT = auto()          # .
    COMMA = auto()        # ,
    COLON = auto()        # :
    SEMI = auto()         # ;  (reserved)
    UNDERSCORE = auto()   # _ (only when isolated; used as wildcard)
    PIPE = auto()         # |

    # Delimiters
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    LBRACE = auto()
    RBRACE = auto()


# Map from reserved words to their corresponding TokenKind.
# The lexer consults this table after recognizing an identifier to decide
# whether it is a keyword or a genuine IDENT.
KEYWORDS: dict[str, TokenKind] = {
    "fun":        TokenKind.KW_FUN,
    "type":       TokenKind.KW_TYPE,
    "trait":      TokenKind.KW_TRAIT,
    "impl":       TokenKind.KW_IMPL,
    "capability": TokenKind.KW_CAPABILITY,
    "const":      TokenKind.KW_CONST,
    "pub":        TokenKind.KW_PUB,
    "import":     TokenKind.KW_IMPORT,
    "as":         TokenKind.KW_AS,
    "let":        TokenKind.KW_LET,
    "var":        TokenKind.KW_VAR,
    "if":         TokenKind.KW_IF,
    "then":       TokenKind.KW_THEN,
    "elif":       TokenKind.KW_ELIF,
    "else":       TokenKind.KW_ELSE,
    "match":      TokenKind.KW_MATCH,
    "while":      TokenKind.KW_WHILE,
    "for":        TokenKind.KW_FOR,
    "in":         TokenKind.KW_IN,
    "break":      TokenKind.KW_BREAK,
    "continue":   TokenKind.KW_CONTINUE,
    "return":     TokenKind.KW_RETURN,
    "true":       TokenKind.KW_TRUE,
    "false":      TokenKind.KW_FALSE,
    "and":        TokenKind.KW_AND,
    "or":         TokenKind.KW_OR,
    "not":        TokenKind.KW_NOT,
    "self":       TokenKind.KW_SELF,
    "Self":       TokenKind.KW_BIG_SELF,
    # Reserved for future use
    "async":      TokenKind.KW_ASYNC,
    "await":      TokenKind.KW_AWAIT,
    "yield":      TokenKind.KW_YIELD,
    "defer":      TokenKind.KW_DEFER,
    "where":      TokenKind.KW_WHERE,
    "mut":        TokenKind.KW_MUT,
    "consume":    TokenKind.KW_CONSUME,
}


@dataclass(frozen=True)
class Pos:
    """Absolute position in the source file.

    line and col are 1-indexed (universal convention in error messages);
    offset is 0-indexed (convenient for source slicing).

    ``filename`` is set by the lexer; AST nodes inherit it via their
    tokens. The error renderer uses it to pick the right source when
    rendering snippets for errors that originate in an imported
    module (the analyzer is given a ``sources`` map by the CLI).
    Empty string is the default for synthetic positions (built-ins,
    fallbacks).
    """
    line: int
    col: int
    offset: int
    filename: str = ""

    def __str__(self) -> str:
        return f"{self.line}:{self.col}"


@dataclass
class Token:
    """A token produced by the lexer.

    - kind: the syntactic category (TokenKind).
    - text: the exact source text that produced the token.
    - value: for literals, the already-processed value (int, float, str, char).
             None for structural tokens and identifiers.
    - start, end: delimiting positions in the source.
    - interp_positions: for STRING_LIT tokens that contain ``${...}``
      interpolations, the source position of the first character
      inside each interpolation (immediately after the ``${``). Empty
      for plain strings. The parser uses these to keep diagnostics on
      typos inside ``${...}`` pointing at the actual source location.
    """
    kind: TokenKind
    text: str
    value: Any
    start: Pos
    end: Pos
    interp_positions: list[Pos] = field(default_factory=list)

    def __repr__(self) -> str:
        if self.value is not None and self.value != self.text:
            return f"Token({self.kind.name}, {self.text!r}, value={self.value!r}, {self.start})"
        return f"Token({self.kind.name}, {self.text!r}, {self.start})"

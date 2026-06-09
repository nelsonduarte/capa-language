"""Recursive descent parser for the Capa language.

Implements the grammar defined in the EBNF document (chapter 5). The
strategy is pure recursive descent, with precedence climbing for binary
expressions. The lexer handles significant indentation: the parser only
consumes NEWLINE / INDENT / DEDENT as structural tokens.

The :class:`Parser` here owns the cursor state, string-literal
construction (including interpolation), and the public
``parse_module`` entry point. The grammar rules are split across
five mixins, each living in its own module:

- :mod:`._types` - type expressions.
- :mod:`._patterns` - patterns (let/for/var/match).
- :mod:`._statements` - statements and block-shaped expressions.
- :mod:`._expressions` - precedence-climbing expression parser.
- :mod:`._items` - top-level declarations (import / const / type /
  trait / capability / impl / fun) and their support helpers
  (doc-comments, attributes, parameter lists).

Design decisions:
- Errors are detected as early as possible and propagated with precise
  position info.
- ``self._error`` produces a :class:`ParserError` with caret-style
  formatting.
- Comparison operators are parsed as NON-associative: ``1 < x < 10``
  is a syntax error.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..errors import LexerError
from ..tokens import Token, TokenKind as T

from ._expressions import _ExpressionsMixin
from ._items import _ItemsMixin
from ._patterns import _PatternsMixin
from ._statements import _StatementsMixin
from ._types import _TypesMixin


class ParserError(LexerError):
    """Error detected by the parser. Reuses LexerError's formatting."""
    pass


class Parser(
    _TypesMixin,
    _PatternsMixin,
    _StatementsMixin,
    _ExpressionsMixin,
    _ItemsMixin,
):
    """Recursive descent parser.

    Usage:
        from capa import Lexer, Parser
        tokens = Lexer(source).lex()
        ast = Parser(tokens, source=source, filename="x.capa").parse_module()
    """

    def __init__(
        self,
        tokens: list[Token],
        source: str = "",
        filename: str = "<input>",
    ):
        # Shallow-copy the token list so the parser owns its own
        # stream: ``_close_type_args`` rewrites the ``>>`` slot when
        # splitting nested generics, and that write must not reach a
        # caller that shares this list (an LSP caching tokens, the
        # comment sidecar, a re-parse of the same stream). Audit
        # slice 26 P3-2 (2026-06-01). The Token objects themselves
        # are never mutated in place (see ``_close_type_args``); the
        # split produces a fresh Token via ``dataclasses.replace``.
        self.tokens = list(tokens)
        self.idx = 0
        self.source = source
        self.filename = filename
        # When True, suppresses the "PascalCase IDENT followed by `{`"
        # heuristic that parses a struct literal. Used while parsing the
        # scrutinee of `match`, so `match SomeVariant { ... }` is read as
        # inline match arms rather than `match (SomeVariant { ... })`.
        # To use a struct literal as scrutinee, wrap it in parentheses.
        self._no_struct_lit = False
        # Current expression-nesting depth, guarded by MAX_EXPR_DEPTH
        # in the expressions mixin so adversarial ``((((...))))`` input
        # yields a clean parse diagnostic rather than a raw
        # ``RecursionError`` (audit 2026-05-25 M2).
        self._expr_depth = 0

    def _build_string_lit(self, value: str, pos, interp_positions=None) -> A.Expr:
        """Builds a string literal. If it contains ``${...}``, returns
        an ``InterpolatedString`` with each interpolation parsed as a
        Capa expression. Otherwise, returns a plain ``StringLit``.

        ``$$`` is a literal escape for ``$``. Literal text and
        expressions alternate inside ``parts``.

        ``interp_positions`` (optional) carries the source Pos of each
        top-level ``${...}`` interpolation's content as emitted by the
        lexer; when present, each sub-Lexer is started at the
        corresponding Pos so diagnostics from inside ``${...}`` point
        at the actual source location rather than the string's opening
        quote.
        """
        if "${" not in value:
            return A.StringLit(pos=pos, value=value)
        interp_positions = interp_positions or []
        interp_idx = 0
        parts: list = []
        buf: list[str] = []
        i = 0
        while i < len(value):
            c = value[i]
            if c == "$" and i + 1 < len(value) and value[i + 1] == "$":
                # Literal $ escape.
                buf.append("$")
                i += 2
                continue
            if c == "$" and i + 1 < len(value) and value[i + 1] == "{":
                # End accumulated literal text.
                parts.append("".join(buf))
                buf.clear()
                # Find the matching `}`, counting depth (to support
                # `${ {x: 1} }` in the future, although today such
                # cases are uncommon).
                depth = 1
                j = i + 2
                while j < len(value) and depth > 0:
                    if value[j] == "{":
                        depth += 1
                    elif value[j] == "}":
                        depth -= 1
                    if depth > 0:
                        j += 1
                if depth != 0:
                    raise self._error(
                        f"unterminated interpolation in string literal: {value!r}"
                    )
                expr_text = value[i + 2 : j]
                # Mini-lex + mini-parse of the expression. The lexer
                # recorded the source Pos of every top-level ``${...}``
                # opener; if we have one for this interpolation, pass
                # it through so sub-diagnostics keep correct positions.
                sub_pos = (
                    interp_positions[interp_idx]
                    if interp_idx < len(interp_positions)
                    else pos
                )
                interp_idx += 1
                expr = self._parse_interpolation(expr_text, sub_pos)
                parts.append(expr)
                i = j + 1
                continue
            buf.append(c)
            i += 1
        # Remaining text after the last interpolation.
        parts.append("".join(buf))
        return A.InterpolatedString(pos=pos, parts=parts)

    def _parse_interpolation(self, expr_text: str, pos) -> A.Expr:
        """Parses ``expr_text`` (the content between ``${`` and ``}``)
        as a Capa expression.

        Creates a local Lexer and Parser for the sub-string. The
        sub-Lexer is started at ``pos`` (the position of the first
        character of ``expr_text`` in the outer source), so every
        token, AST node, and diagnostic produced from inside the
        interpolation reports a position valid in the outer source.
        """
        from ..lexer import Lexer
        try:
            sub_tokens = Lexer(
                expr_text,
                filename=self.filename,
                start_line=pos.line,
                start_col=pos.col,
                start_offset=pos.offset,
            ).lex()
            sub_parser = Parser(
                sub_tokens, source=expr_text, filename=self.filename,
            )
            expr = sub_parser._parse_expr()
        except (LexerError, ParserError) as e:
            # Re-raise as an error of the outer literal, with position.
            raise self._error(
                f"error parsing interpolation: {e.message}"
            )
        return expr

    # ===========================================================
    # Cursor helpers
    # ===========================================================

    def _peek(self, n: int = 0) -> Token:
        i = self.idx + n
        if i >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[i]

    def _at_end(self) -> bool:
        return self._peek().kind == T.EOF

    def _advance(self) -> Token:
        t = self.tokens[self.idx]
        if not self._at_end():
            self.idx += 1
        return t

    def _check(self, *kinds: T) -> bool:
        return self._peek().kind in kinds

    def _match(self, *kinds: T) -> Optional[Token]:
        if self._peek().kind in kinds:
            return self._advance()
        return None

    def _expect(self, kind: T, message: str) -> Token:
        if self._peek().kind == kind:
            return self._advance()
        got = self._peek()
        raise self._error(
            f"{message}; got {got.kind.name}"
            + (f" {got.text!r}" if got.text else ""),
            got,
        )

    def _error(self, message: str, tok: Optional[Token] = None) -> ParserError:
        tok = tok or self._peek()
        return ParserError(message, tok.start, self.source, self.filename)

    def _skip_newlines(self) -> None:
        while self._check(T.NEWLINE):
            self._advance()

    # ===========================================================
    # Main entry point
    # ===========================================================

    @staticmethod
    def _stack_depth() -> int:
        """Number of frames currently on the call stack. Used to size
        the recursion-limit bump from the current depth (the limit is
        an absolute interpreter-wide value)."""
        import sys

        depth = 0
        frame = sys._getframe()
        while frame is not None:
            depth += 1
            frame = frame.f_back
        return depth

    def parse_module(self) -> A.Module:
        # Raise the interpreter recursion limit for the duration of the
        # parse so the MAX_EXPR_DEPTH cap (a clean diagnostic) fires
        # before Python's RecursionError on pathological nesting. Each
        # expression-nesting level costs ~17 Python frames in the
        # precedence-climbing descent; budget 25/level plus headroom,
        # measured from the current depth so a deep caller stack still
        # leaves room. Restored in ``finally`` to avoid leaking the
        # raised limit to the rest of the process. Audit 2026-05-25 M2.
        import sys
        from ._expressions import MAX_EXPR_DEPTH

        prev_limit = sys.getrecursionlimit()
        # Bump the ceiling relative to the frames already on the stack:
        # parsing may be invoked from deep within a caller (LSP, REPL,
        # nested string interpolation), and the limit is an absolute
        # interpreter-wide value. ``_stack_depth`` walks the current
        # frame chain so the headroom is measured from here, not zero.
        floor = self._stack_depth() + MAX_EXPR_DEPTH * 25 + 2000
        raised = False
        if prev_limit < floor:
            sys.setrecursionlimit(floor)
            raised = True
        try:
            start = self._peek().start
            self._skip_newlines()
            items: list[A.Item] = []
            while not self._at_end():
                items.append(self._parse_item())
                self._skip_newlines()
            return A.Module(pos=start, items=items)
        finally:
            if raised:
                sys.setrecursionlimit(prev_limit)

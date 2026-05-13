"""Type-expression parsing mixin.

Handles the grammar rules that produce :class:`A.TypeExpr` nodes:

- ``_parse_type``: dispatches between named types, ``Self``, function
  types (``Fun(...) -> Ret``), and parenthesised / tuple types.
- ``_parse_tuple_or_paren_type``: continues a parse that already
  saw ``(`` and needs to decide tuple-vs-grouped.
- ``_parse_type_args``: ``<T, U, ...>`` generic argument lists.

These helpers are used both from the items mixin (parameter and
return types, struct fields, trait method signatures) and from the
expression mixin (turbofish-style type arguments on calls).
"""

from __future__ import annotations

from .. import capa_ast as A
from ..tokens import TokenKind as T


class _TypesMixin:
    def _parse_type(self) -> A.TypeExpr:
        # Special case: () = UnitType
        if self._check(T.LPAREN):
            start = self._peek().start
            save = self.idx
            self._advance()
            if self._match(T.RPAREN):
                return A.UnitType(pos=start)
            # Tuple of types (T, U, V) - restore and parse
            self.idx = save
            return self._parse_tuple_or_paren_type()
        # Named type, with possible generic args. Also accepts Self.
        start = self._peek().start
        if self._check(T.KW_BIG_SELF):
            self._advance()
            name = "Self"
        else:
            name = self._expect(T.IDENT, "expected type name").text
        # Function type: 'Fun' followed by '('. Syntax:
        #   Fun(T1, T2, ...) -> Ret
        # Ambiguity with the outer function's return type: to return
        # a function, wrap it in parentheses or a tuple:
        # '(Fun(Int) -> Int)'.
        if name == "Fun" and self._check(T.LPAREN):
            self._advance()
            param_types: list[A.TypeExpr] = []
            if not self._check(T.RPAREN):
                param_types.append(self._parse_type())
                while self._match(T.COMMA):
                    param_types.append(self._parse_type())
            self._expect(T.RPAREN, "expected ')' to close 'Fun(...)'")
            self._expect(T.ARROW, "expected '->' after 'Fun(...)'")
            ret = self._parse_type()
            return A.FunType(pos=start, param_types=param_types, return_type=ret)
        args: list[A.TypeExpr] = []
        if self._check(T.LT):
            args = self._parse_type_args()
        return A.TypeName(pos=start, name=name, args=args)

    def _parse_tuple_or_paren_type(self) -> A.TypeExpr:
        start = self._peek().start
        self._expect(T.LPAREN, "expected '('")
        first = self._parse_type()
        if self._match(T.COMMA):
            elements = [first]
            while not self._check(T.RPAREN):
                elements.append(self._parse_type())
                if not self._match(T.COMMA):
                    break
            self._expect(T.RPAREN, "expected ')' to close tuple type")
            return A.TupleType(pos=start, elements=elements)
        self._expect(T.RPAREN, "expected ')' or ',' in type")
        return first

    def _parse_type_args(self) -> list[A.TypeExpr]:
        self._expect(T.LT, "expected '<'")
        args = [self._parse_type()]
        while self._match(T.COMMA):
            args.append(self._parse_type())
        self._expect(T.GT, "expected '>' to close type argument list")
        return args

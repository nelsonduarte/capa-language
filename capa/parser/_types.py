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
from ..tokens import Pos, TokenKind as T


class _TypesMixin:
    def _parse_type(self) -> A.TypeExpr:
        # Optional security label before the type (roadmap S2):
        # ``@secret String`` / ``@public Int``. Distinct from a
        # function attribute ``@name(...)`` -- a label is ``@`` + a
        # bare ``secret``/``public`` identifier NOT followed by ``(``.
        # The label attaches to whatever TypeExpr follows.
        label: "str | None" = None
        if self._check(T.AT):
            nxt = self._peek(1)
            after = self._peek(2)
            from .._labels import VALID_LABELS
            if (
                nxt.kind == T.IDENT
                and nxt.text in VALID_LABELS
                and after.kind != T.LPAREN
            ):
                self._advance()  # '@'
                label = self._advance().text  # 'secret' / 'public'
        ty = self._parse_type_unlabelled()
        if label is not None:
            ty.label = label
        return ty

    def _parse_type_unlabelled(self) -> A.TypeExpr:
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
        self._close_type_args()
        return args

    def _close_type_args(self) -> None:
        """Consume the closing ``>`` of a type-argument list.

        Maximal-munch lexing fuses two consecutive ``>>`` into a single
        RSHIFT token (needed so expression-level ``a >> b`` is one
        token). In a nested generic context like ``List<List<Int>>``
        the inner ``_parse_type_args`` therefore meets RSHIFT, not GT,
        when it tries to close. We split it in place: consume one
        ``>`` and rewrite the slot to a fresh GT positioned one column
        to the right, leaving the outer ``_parse_type_args`` to close
        normally. The same split applies to ``>=``: a future
        ``List<List<Int>>=`` would need similar handling, but ``>=``
        cannot appear as a type-arg closer today (the grammar has no
        type-arg = production), so we restrict the split to RSHIFT.
        """
        tok = self._peek()
        if tok.kind == T.GT:
            self._advance()
            return
        if tok.kind == T.RSHIFT:
            # Split the ``>>`` into a single ``>`` so the outer closer
            # sees one ``>`` at the right position. Audit slice 26
            # P3-2 (2026-06-01): write a FRESH Token into the stream
            # slot via ``dataclasses.replace`` rather than mutating
            # the shared Token object in place -- the original token
            # may be referenced by a caller (LSP token cache, comment
            # sidecar) that must not observe the rewrite. The parser
            # owns its own list copy (see ``Parser.__init__``), so
            # overwriting the slot is local; only the in-place object
            # mutation was the leak.
            import dataclasses
            new_start = Pos(
                line=tok.start.line,
                col=tok.start.col + 1,
                offset=tok.start.offset + 1,
                filename=tok.start.filename,
            )
            self.tokens[self.idx] = dataclasses.replace(
                tok, kind=T.GT, text=">", start=new_start,
            )
            return
        # Reuse the standard "expected" diagnostic for anything else.
        self._expect(T.GT, "expected '>' to close type argument list")

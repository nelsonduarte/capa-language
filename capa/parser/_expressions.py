"""Expression-parsing mixin.

Implements the precedence-climbing parser for the expression
grammar. From lowest to highest precedence:

``expr -> or -> and -> not -> comparison -> range -> additive ->
multiplicative -> unary -> postfix -> primary``

- ``_parse_if_expr``: ``if cond then e1 else e2`` (note the
  required ``then`` keyword; without it ``if`` parses as a
  statement).
- ``_parse_postfix``: field access, method/function calls,
  indexing, and the ``?`` (Try) operator.
- ``_parse_call_args`` / ``_parse_one_call_arg``: positional and
  named arguments. The analyzer enforces positional-before-named.
- ``_parse_primary``: literals, parens/tuples, list literals,
  identifiers / struct literals, ``self``, embedded ``match`` and
  lambda forms.
- ``_parse_ident_or_struct_lit``: applies the PascalCase + ``{``
  heuristic for struct literals, respecting ``_no_struct_lit``.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import TokenKind as T

# Token-set constants used by precedence-climbing levels. Local to
# the mixin so the file is self-contained.
_COMPARISON_OPS = {
    T.EQ_EQ:  "==",
    T.BANG_EQ: "!=",
    T.LT:     "<",
    T.LT_EQ:  "<=",
    T.GT:     ">",
    T.GT_EQ:  ">=",
}
_ADDITIVE_OPS = {T.PLUS: "+", T.MINUS: "-"}
_MULTIPLICATIVE_OPS = {T.STAR: "*", T.SLASH: "/", T.PERCENT: "%"}


class _ExpressionsMixin:
    def _parse_expr(self) -> A.Expr:
        # if-expression: ``if cond then e1 else e2``. The ``then`` is
        # the discriminator - without it, ``if`` is a statement
        # elsewhere in the parser and this path is not taken.
        if self._check(T.KW_IF):
            return self._parse_if_expr()
        # match was already parsed as an expression via _parse_match_expr
        # when it appears on the RHS of let/var/return; this branch is
        # reached if the user writes `let x = match e ...`.
        if self._check(T.KW_MATCH):
            return self._parse_match_expr()
        return self._parse_or()

    def _parse_if_expr(self) -> A.Expr:
        """Parses ``if cond then e1 else e2`` as an IfExpr.

        Note: ``then`` is required in expression form. Without ``then``,
        ``if`` is interpreted as a statement (parsed in another path).
        """
        start = self._expect(T.KW_IF, "expected 'if'").start
        cond = self._parse_or()
        self._expect(T.KW_THEN, "expected 'then' in if-expression")
        then_expr = self._parse_expr()
        self._expect(T.KW_ELSE, "expected 'else' in if-expression")
        else_expr = self._parse_expr()
        return A.IfExpr(
            pos=start, cond=cond,
            then_expr=then_expr, else_expr=else_expr,
        )

    def _parse_or(self) -> A.Expr:
        left = self._parse_and()
        while self._match(T.KW_OR):
            right = self._parse_and()
            left = A.BinOp(pos=left.pos, op="or", left=left, right=right)
        return left

    def _parse_and(self) -> A.Expr:
        left = self._parse_not()
        while self._match(T.KW_AND):
            right = self._parse_not()
            left = A.BinOp(pos=left.pos, op="and", left=left, right=right)
        return left

    def _parse_not(self) -> A.Expr:
        if self._check(T.KW_NOT):
            start = self._advance().start
            operand = self._parse_not()
            return A.UnaryOp(pos=start, op="not", operand=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> A.Expr:
        left = self._parse_range()
        if self._peek().kind in _COMPARISON_OPS:
            op_tok = self._advance()
            op = _COMPARISON_OPS[op_tok.kind]
            right = self._parse_range()
            # Non-associative: reject if another comparison operator follows.
            if self._peek().kind in _COMPARISON_OPS:
                next_tok = self._peek()
                raise self._error(
                    "comparison operators are non-associative; "
                    "use parentheses or boolean operators to combine",
                    next_tok,
                )
            return A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_range(self) -> A.Expr:
        """Range expression: ``start..end`` (exclusive) or
        ``start..=end`` (inclusive). Non-associative, chained ranges
        like ``a..b..c`` are not allowed and would be a syntax error.
        Sits between comparison and addition in the precedence ladder,
        so ``1+2..5+3`` parses as ``(1+2)..(5+3)``.
        """
        left = self._parse_additive()
        if self._check(T.DOT_DOT):
            start_tok = self._advance()
            end = self._parse_additive()
            return A.RangeExpr(
                pos=start_tok.start, start=left, end=end, inclusive=False,
            )
        if self._check(T.DOT_DOT_EQ):
            start_tok = self._advance()
            end = self._parse_additive()
            return A.RangeExpr(
                pos=start_tok.start, start=left, end=end, inclusive=True,
            )
        return left

    def _parse_additive(self) -> A.Expr:
        left = self._parse_multiplicative()
        while self._peek().kind in _ADDITIVE_OPS:
            op_tok = self._advance()
            op = _ADDITIVE_OPS[op_tok.kind]
            right = self._parse_multiplicative()
            left = A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_multiplicative(self) -> A.Expr:
        left = self._parse_unary()
        while self._peek().kind in _MULTIPLICATIVE_OPS:
            op_tok = self._advance()
            op = _MULTIPLICATIVE_OPS[op_tok.kind]
            right = self._parse_unary()
            left = A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_unary(self) -> A.Expr:
        if self._check(T.MINUS):
            start = self._advance().start
            operand = self._parse_unary()
            return A.UnaryOp(pos=start, op="-", operand=operand)
        return self._parse_postfix()

    def _parse_postfix(self) -> A.Expr:
        expr = self._parse_primary()
        while True:
            if self._match(T.DOT):
                name_tok = self._expect(T.IDENT, "expected field or method name")
                # Method call if followed by '(' or turbofish '::<'.
                if self._check(T.LPAREN):
                    args, arg_names = self._parse_call_args()
                    expr = A.MethodCall(
                        pos=expr.pos,
                        receiver=expr,
                        method=name_tok.text,
                        args=args,
                        arg_names=arg_names,
                    )
                else:
                    expr = A.FieldAccess(
                        pos=expr.pos, receiver=expr, field_name=name_tok.text
                    )
                continue
            if self._check(T.LPAREN):
                # Function call
                args, arg_names = self._parse_call_args()
                expr = A.Call(
                    pos=expr.pos, callee=expr, args=args, arg_names=arg_names,
                )
                continue
            if self._check(T.LBRACKET):
                self._advance()
                idx = self._parse_expr()
                self._expect(T.RBRACKET, "expected ']' after index expression")
                expr = A.Index(pos=expr.pos, receiver=expr, index=idx)
                continue
            if self._match(T.QUESTION):
                expr = A.Try(pos=expr.pos, expr=expr)
                continue
            break
        return expr

    def _parse_call_args(self) -> tuple[list[A.Expr], list[Optional[str]]]:
        """Parse ``( arg [, arg]* [,]? )`` where each ``arg`` is either
        an expression (positional) or ``IDENT ":" expression`` (named).

        Returns two parallel lists: the argument expressions and, for
        each one, either the parameter name it targets or ``None`` if
        it is positional. The analyzer checks that positional comes
        before named and that names match a real parameter.
        """
        self._expect(T.LPAREN, "expected '('")
        args: list[A.Expr] = []
        names: list[Optional[str]] = []
        if not self._check(T.RPAREN):
            self._parse_one_call_arg(args, names)
            while self._match(T.COMMA):
                if self._check(T.RPAREN):  # trailing comma
                    break
                self._parse_one_call_arg(args, names)
        self._expect(T.RPAREN, "expected ')' to close call argument list")
        return args, names

    def _parse_one_call_arg(
        self, args: list[A.Expr], names: list[Optional[str]],
    ) -> None:
        # Named argument: IDENT ":" expr. Only commit to this branch
        # when we are certain (two-token lookahead), so identifiers
        # involved in other expressions (e.g. struct literals via
        # `Point { x: 1, y: 2 }`) are not misparsed here.
        if (
            self._peek().kind == T.IDENT
            and self._peek(1).kind == T.COLON
        ):
            name_tok = self._advance()
            self._advance()  # consume ':'
            names.append(name_tok.value)
            args.append(self._parse_expr())
        else:
            names.append(None)
            args.append(self._parse_expr())

    def _parse_primary(self) -> A.Expr:
        tok = self._peek()

        if tok.kind == T.INT_LIT:
            self._advance()
            return A.IntLit(pos=tok.start, value=tok.value)
        if tok.kind == T.FLOAT_LIT:
            self._advance()
            return A.FloatLit(pos=tok.start, value=tok.value)
        if tok.kind == T.STRING_LIT:
            self._advance()
            return self._build_string_lit(tok.value, tok.start, tok.interp_positions)
        if tok.kind == T.CHAR_LIT:
            self._advance()
            return A.CharLit(pos=tok.start, value=tok.value)
        if tok.kind == T.KW_TRUE:
            self._advance()
            return A.BoolLit(pos=tok.start, value=True)
        if tok.kind == T.KW_FALSE:
            self._advance()
            return A.BoolLit(pos=tok.start, value=False)

        if tok.kind == T.LPAREN:
            return self._parse_paren_or_tuple()

        if tok.kind == T.LBRACKET:
            return self._parse_list_literal()

        if tok.kind == T.IDENT:
            return self._parse_ident_or_struct_lit()

        if tok.kind == T.KW_SELF:
            self._advance()
            return A.Ident(pos=tok.start, name="self")

        if tok.kind == T.KW_MATCH:
            return self._parse_match_expr()

        if tok.kind == T.KW_FUN:
            return self._parse_lambda_expr()

        raise self._error(
            f"expected expression, got {tok.kind.name}"
            + (f" {tok.text!r}" if tok.text else "")
        )

    def _parse_paren_or_tuple(self) -> A.Expr:
        start = self._peek().start
        self._expect(T.LPAREN, "expected '('")
        # () = unit
        if self._match(T.RPAREN):
            return A.UnitLit(pos=start)
        first = self._parse_expr()
        if self._match(T.COMMA):
            elements = [first]
            while not self._check(T.RPAREN):
                elements.append(self._parse_expr())
                if not self._match(T.COMMA):
                    break
            self._expect(T.RPAREN, "expected ')' to close tuple")
            return A.TupleLit(pos=start, elements=elements)
        self._expect(T.RPAREN, "expected ')' or ',' in parenthesized expression")
        return first

    def _parse_list_literal(self) -> A.ListLit:
        start = self._peek().start
        self._expect(T.LBRACKET, "expected '['")
        elements: list[A.Expr] = []
        self._skip_newlines()
        if not self._check(T.RBRACKET):
            elements.append(self._parse_expr())
            self._skip_newlines()
            while self._match(T.COMMA):
                self._skip_newlines()
                if self._check(T.RBRACKET):
                    break
                elements.append(self._parse_expr())
                self._skip_newlines()
        self._expect(T.RBRACKET, "expected ']' to close list literal")
        return A.ListLit(pos=start, elements=elements)

    def _parse_ident_or_struct_lit(self) -> A.Expr:
        """Identifier, possibly followed by '{' (struct literal).

        The heuristic: if it is an IDENT directly followed by '{' (with
        no newline between them), treat it as a struct literal.
        Otherwise, it is a plain reference. We use the PascalCase
        heuristic as additional confirmation to avoid ambiguity in
        statements like `if x { ... }` (not Capa, but avoids surprises).

        The ``_no_struct_lit`` flag overrides the heuristic, used when
        parsing the scrutinee of ``match`` so that ``match X { ... }``
        is the inline-arm form, not a struct literal as the scrutinee.
        """
        tok = self._advance()
        # Struct literal: Type { field: value, ... }
        # Convention: name starts with an uppercase letter.
        if (
            tok.text and tok.text[0].isupper()
            and self._check(T.LBRACE)
            and not self._no_struct_lit
        ):
            self._advance()  # {
            fields = self._parse_struct_lit_fields()
            return A.StructLit(
                pos=tok.start,
                type_name=tok.text,
                fields=fields,
            )
        return A.Ident(pos=tok.start, name=tok.text)

    def _parse_struct_lit_fields(self) -> list[tuple[str, A.Expr]]:
        fields: list[tuple[str, A.Expr]] = []
        self._skip_newlines()
        while not self._check(T.RBRACE):
            fname = self._expect(T.IDENT, "expected field name").text
            self._expect(T.COLON, "expected ':' in struct literal field")
            value = self._parse_expr()
            fields.append((fname, value))
            self._skip_newlines()
            if self._match(T.COMMA):
                self._skip_newlines()
                continue
            break
        self._expect(T.RBRACE, "expected '}' to close struct literal")
        return fields

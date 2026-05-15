"""Statement-parsing mixin.

Owns everything that produces an :class:`A.Stmt` or one of the
statement-like expression forms (``match``, lambda block bodies):

- ``_parse_block`` / ``_parse_stmt``: dispatch and indentation
  bookkeeping.
- ``_parse_let_stmt`` / ``_parse_var_stmt``: bindings.
- ``_parse_if_stmt`` / ``_parse_while_stmt`` / ``_parse_for_stmt``:
  control flow with block bodies.
- ``_parse_lambda_expr``: ``fun (...) => body`` with optional block
  body, including the diagnostic for block-body lambdas inside
  parenthesised contexts (where the lexer suppresses NEWLINE).
- ``_parse_match_expr`` / ``_parse_match_inline_arms`` /
  ``_parse_match_arm`` / ``_parse_inline_match_arm``: both the
  multi-line and inline forms.
- ``_parse_return_stmt`` / ``_parse_expr_or_assign_stmt``: the two
  expression-shaped statements.
- ``_expect_eos``: shared end-of-statement helper.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import TokenKind as T

# Re-imported here so ``_parse_expr_or_assign_stmt`` keeps the same
# mapping the rest of the parser uses.
_ASSIGN_OPS = {
    T.EQ:        "=",
    T.PLUS_EQ:   "+=",
    T.MINUS_EQ:  "-=",
    T.STAR_EQ:   "*=",
    T.SLASH_EQ:  "/=",
    T.PERCENT_EQ: "%=",
}


class _StatementsMixin:
    def _parse_block(self) -> A.Block:
        """NEWLINE INDENT stmt+ DEDENT"""
        start = self._peek().start
        self._expect(T.NEWLINE, "expected newline before block")
        self._expect(T.INDENT, "expected indented block")
        stmts: list[A.Stmt] = []
        while not self._check(T.DEDENT) and not self._at_end():
            stmts.append(self._parse_stmt())
            self._skip_newlines()
        self._expect(T.DEDENT, "expected dedent at end of block")
        return A.Block(pos=start, stmts=stmts)

    def _parse_stmt(self) -> A.Stmt:
        if self._check(T.KW_LET):
            return self._parse_let_stmt()
        if self._check(T.KW_VAR):
            return self._parse_var_stmt()
        if self._check(T.KW_IF):
            return self._parse_if_stmt()
        if self._check(T.KW_WHILE):
            return self._parse_while_stmt()
        if self._check(T.KW_FOR):
            return self._parse_for_stmt()
        if self._check(T.KW_MATCH):
            start = self._peek().start
            expr = self._parse_match_expr()
            return A.ExprStmt(pos=start, expr=expr)
        if self._check(T.KW_RETURN):
            return self._parse_return_stmt()
        if self._check(T.KW_BREAK):
            start = self._advance().start
            self._expect_eos("after 'break'")
            return A.BreakStmt(pos=start)
        if self._check(T.KW_CONTINUE):
            start = self._advance().start
            self._expect_eos("after 'continue'")
            return A.ContinueStmt(pos=start)
        # Expression or assignment
        return self._parse_expr_or_assign_stmt()

    def _parse_let_stmt(self) -> A.LetStmt:
        start = self._peek().start
        self._expect(T.KW_LET, "expected 'let'")
        pattern = self._parse_pattern()
        type_expr: Optional[A.TypeExpr] = None
        if self._match(T.COLON):
            type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in let binding")
        value = self._parse_expr()
        self._expect_eos("after let binding")
        return A.LetStmt(
            pos=start, pattern=pattern, type_expr=type_expr, value=value
        )

    def _parse_var_stmt(self) -> A.VarStmt:
        start = self._peek().start
        self._expect(T.KW_VAR, "expected 'var'")
        name_tok = self._expect(T.IDENT, "expected variable name")
        type_expr: Optional[A.TypeExpr] = None
        if self._match(T.COLON):
            type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in var declaration")
        value = self._parse_expr()
        self._expect_eos("after var declaration")
        return A.VarStmt(
            pos=start, name=name_tok.text, name_pos=name_tok.start,
            type_expr=type_expr, value=value,
        )

    def _parse_if_stmt(self) -> A.IfStmt:
        start = self._peek().start
        self._expect(T.KW_IF, "expected 'if'")
        cond = self._parse_expr()
        then_block = self._parse_block()
        elif_arms: list[tuple[A.Expr, A.Block]] = []
        else_block: Optional[A.Block] = None
        # elif/else are only recognized immediately after the if's block;
        # the block parser has already consumed the DEDENT, so we are
        # already at the right level.
        while self._check(T.KW_ELIF):
            self._advance()
            elif_cond = self._parse_expr()
            elif_block = self._parse_block()
            elif_arms.append((elif_cond, elif_block))
        if self._match(T.KW_ELSE):
            else_block = self._parse_block()
        return A.IfStmt(
            pos=start,
            cond=cond,
            then_block=then_block,
            elif_arms=elif_arms,
            else_block=else_block,
        )

    def _parse_while_stmt(self) -> A.WhileStmt:
        start = self._peek().start
        self._expect(T.KW_WHILE, "expected 'while'")
        cond = self._parse_expr()
        body = self._parse_block()
        return A.WhileStmt(pos=start, cond=cond, body=body)

    def _parse_for_stmt(self) -> A.ForStmt:
        start = self._peek().start
        self._expect(T.KW_FOR, "expected 'for'")
        pattern = self._parse_pattern()
        self._expect(T.KW_IN, "expected 'in' in for loop")
        it = self._parse_expr()
        body = self._parse_block()
        return A.ForStmt(pos=start, pattern=pattern, iter=it, body=body)

    def _parse_lambda_expr(self) -> A.LambdaExpr:
        """Parses ``fun (params) -> Ret => body``. Body is a single
        expression or an indented block. Return type is optional.

        Block body: if ``=>`` is followed by NEWLINE, parses as a block
        (NEWLINE INDENT stmts DEDENT) - useful for lambdas with multiple
        statements, explicit returns, etc.

        Inside ``(...)``, the lexer suppresses NEWLINE/INDENT/DEDENT
        for implicit line continuation, so a block-body lambda cannot
        be written there: we detect that case (a statement-starter
        keyword appears immediately after ``=>``) and report a
        targeted error pointing at the recommended workaround.
        """
        start = self._peek().start
        self._expect(T.KW_FUN, "expected 'fun'")
        self._expect(T.LPAREN, "expected '(' for lambda parameters")
        params: list[A.Param] = []
        if not self._check(T.RPAREN):
            params.append(self._parse_param())
            while self._match(T.COMMA):
                params.append(self._parse_param())
        self._expect(T.RPAREN, "expected ')' after lambda parameters")
        return_type: Optional[A.TypeExpr] = None
        if self._match(T.ARROW):
            return_type = self._parse_type()
        self._expect(T.FAT_ARROW, "expected '=>' before lambda body")
        # Block body: NEWLINE followed by INDENT.
        # Single-expr body: everything else.
        body: A.Expr | A.Block
        if self._check(T.NEWLINE):
            body = self._parse_block()
        else:
            # Detect the block-body-inside-parens case: any of these
            # tokens unambiguously starts a statement, not an
            # expression. When we see one here, the user almost
            # certainly wrote a block-body lambda inside a paren
            # context where the lexer suppressed the NEWLINE that
            # would have triggered the block branch above.
            stmt_starters = (
                T.KW_LET, T.KW_VAR, T.KW_RETURN,
                T.KW_BREAK, T.KW_CONTINUE,
            )
            if self._peek().kind in stmt_starters:
                raise self._error(
                    "a block-body lambda cannot appear directly inside "
                    "parentheses; bind it to a `let` first and pass the "
                    "name, or use a single-expression body"
                )
            body = self._parse_expr()
        return A.LambdaExpr(
            pos=start, params=params, return_type=return_type, body=body,
        )

    def _parse_match_expr(self) -> A.MatchExpr:
        start = self._peek().start
        self._expect(T.KW_MATCH, "expected 'match'")
        # Suppress the struct-literal heuristic while reading the
        # scrutinee, so that `match X { ... }` parses as an inline match
        # rather than `match (X { ... })`. Wrap the scrutinee in parens
        # if you really want a struct literal there.
        prev = self._no_struct_lit
        self._no_struct_lit = True
        try:
            scrutinee = self._parse_expr()
        finally:
            self._no_struct_lit = prev

        # Inline form: `match s { p -> e [, p -> e ]* [,] }`
        if self._check(T.LBRACE):
            return self._parse_match_inline_arms(start, scrutinee)

        # Multi-line form: NEWLINE INDENT arms DEDENT
        self._expect(
            T.NEWLINE,
            "expected newline or '{' after match scrutinee",
        )
        self._expect(T.INDENT, "expected indented match arms")
        arms: list[A.MatchArm] = []
        while not self._check(T.DEDENT) and not self._at_end():
            arms.append(self._parse_match_arm())
            self._skip_newlines()
        self._expect(T.DEDENT, "expected dedent at end of match")
        if not arms:
            raise self._error("match must have at least one arm")
        return A.MatchExpr(pos=start, scrutinee=scrutinee, arms=arms)

    def _parse_match_inline_arms(
        self, start, scrutinee: A.Expr,
    ) -> A.MatchExpr:
        """Parses inline match arms: ``{ p -> e, p -> e [, ...] }``.

        Each arm body is a single expression (no block bodies in the
        inline form). Or-patterns and guards are supported.
        """
        self._expect(T.LBRACE, "expected '{' for inline match arms")
        arms: list[A.MatchArm] = []
        if not self._check(T.RBRACE):
            arms.append(self._parse_inline_match_arm())
            while self._match(T.COMMA):
                if self._check(T.RBRACE):  # trailing comma
                    break
                arms.append(self._parse_inline_match_arm())
        self._expect(T.RBRACE, "expected '}' to close inline match arms")
        if not arms:
            raise self._error("inline match must have at least one arm")
        return A.MatchExpr(pos=start, scrutinee=scrutinee, arms=arms)

    def _parse_inline_match_arm(self) -> A.MatchArm:
        """Parses one arm of an inline match: ``pat [if guard] -> expr``.

        Or-patterns (``a | b | c``) are accepted at the arm level.
        """
        start = self._peek().start
        pattern = self._parse_pattern(in_match=True)
        if self._check(T.PIPE):
            alternatives: list[A.Pattern] = [pattern]
            while self._match(T.PIPE):
                alternatives.append(self._parse_pattern(in_match=True))
            pattern = A.OrPat(pos=start, alternatives=alternatives)
        guard: Optional[A.Expr] = None
        if self._match(T.KW_IF):
            guard = self._parse_expr()
        self._expect(T.ARROW, "expected '->' in inline match arm")
        body = self._parse_expr()
        return A.MatchArm(pos=start, pattern=pattern, guard=guard, body=body)

    def _parse_match_arm(self) -> A.MatchArm:
        start = self._peek().start
        pattern = self._parse_pattern(in_match=True)
        # Or-patterns: ``pat1 | pat2 | ...``. We keep parsing while we
        # see PIPE. This is only interpreted as an or-pattern in match
        # context (not in let/for/var).
        if self._check(T.PIPE):
            alternatives: list[A.Pattern] = [pattern]
            while self._match(T.PIPE):
                alternatives.append(self._parse_pattern(in_match=True))
            pattern = A.OrPat(pos=start, alternatives=alternatives)
        guard: Optional[A.Expr] = None
        if self._match(T.KW_IF):
            guard = self._parse_expr()
        self._expect(T.ARROW, "expected '->' in match arm")
        # Body: an indented block (NEWLINE INDENT stmts DEDENT), a
        # single divergent statement (return / break / continue,
        # promoted to a one-statement block so the analyzer treats
        # the arm as divergent and its type does not constrain the
        # match's result type), or a single expression terminated
        # by NEWLINE.
        if self._check(T.NEWLINE):
            body: A.Block | A.Expr = self._parse_block()
        elif self._check(T.KW_RETURN):
            stmt_start = self._peek().start
            ret_stmt = self._parse_return_stmt()
            body = A.Block(pos=stmt_start, stmts=[ret_stmt])
        elif self._check(T.KW_BREAK):
            stmt_start = self._advance().start
            self._expect_eos("after 'break' in match arm")
            body = A.Block(
                pos=stmt_start, stmts=[A.BreakStmt(pos=stmt_start)]
            )
        elif self._check(T.KW_CONTINUE):
            stmt_start = self._advance().start
            self._expect_eos("after 'continue' in match arm")
            body = A.Block(
                pos=stmt_start, stmts=[A.ContinueStmt(pos=stmt_start)]
            )
        else:
            stmt_start = self._peek().start
            expr = self._parse_expr()
            if self._peek().kind in _ASSIGN_OPS:
                # Single-line arm body is an assignment statement,
                # not a plain expression. Promote to a one-statement
                # block so the analyzer treats the arm as side-
                # effectful with Unit result type.
                op_tok = self._advance()
                op = _ASSIGN_OPS[op_tok.kind]
                value = self._parse_expr()
                self._expect_eos(f"after assignment '{op}' in match arm")
                if not isinstance(expr, (A.Ident, A.FieldAccess, A.Index)):
                    raise self._error(
                        "invalid assignment target in match arm "
                        "(must be name, field, or index)",
                        self.tokens[self.idx - 1] if self.idx > 0 else None,
                    )
                body = A.Block(pos=stmt_start, stmts=[
                    A.AssignStmt(pos=stmt_start, target=expr, op=op, value=value),
                ])
            else:
                self._expect_eos("after match arm body")
                body = expr
        return A.MatchArm(pos=start, pattern=pattern, guard=guard, body=body)

    def _parse_return_stmt(self) -> A.ReturnStmt:
        start = self._peek().start
        self._expect(T.KW_RETURN, "expected 'return'")
        value: Optional[A.Expr] = None
        if not self._check(T.NEWLINE) and not self._at_end():
            value = self._parse_expr()
        self._expect_eos("after return statement")
        return A.ReturnStmt(pos=start, value=value)

    def _parse_expr_or_assign_stmt(self) -> A.Stmt:
        start = self._peek().start
        expr = self._parse_expr()
        if self._peek().kind in _ASSIGN_OPS:
            op_tok = self._advance()
            op = _ASSIGN_OPS[op_tok.kind]
            value = self._parse_expr()
            self._expect_eos(f"after assignment '{op}'")
            # Validate: target can only be an ident, field access, or index.
            if not isinstance(expr, (A.Ident, A.FieldAccess, A.Index)):
                raise self._error(
                    "invalid assignment target (must be name, field, or index)",
                    self.tokens[self.idx - 1] if self.idx > 0 else None,
                )
            return A.AssignStmt(pos=start, target=expr, op=op, value=value)
        self._expect_eos("after expression statement")
        return A.ExprStmt(pos=start, expr=expr)

    def _expect_eos(self, where: str) -> None:
        """End-of-statement: NEWLINE or EOF."""
        if self._check(T.NEWLINE):
            self._advance()
            return
        if self._at_end():
            return
        # In some cases, end-of-block (DEDENT) also counts as an
        # implicit end of statement - but the lexer emits NEWLINE
        # before DEDENT.
        if self._check(T.DEDENT):
            return
        # If the last consumed token was a NEWLINE or DEDENT, the
        # logical line has already ended - this typically happens when
        # a complex expression (match-expr) ends with a DEDENT that
        # closes its own block. We do not need to require another
        # NEWLINE.
        if self.idx > 0 and self.tokens[self.idx - 1].kind in (
            T.NEWLINE, T.DEDENT,
        ):
            return
        raise self._error(f"expected newline {where}")

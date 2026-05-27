"""Statement and pattern emission for the AST pretty-printer.

Handles every ``Stmt`` shape plus the pattern-as-l-value (in
``let`` / ``for``) and pattern-in-match emissions.

Key style rules applied here:

- Block-bodied compound statements (``if``, ``while``, ``for``,
  match arms) use Capa's indent-based syntax: a header line,
  newline, indented body.
- ``let`` / ``var`` / assignment / return / expression
  statements each occupy a single header line.
- A multi-line match arm whose body is a single statement that
  the parser promoted into a one-statement block (return /
  break / continue) is emitted as a single-line arm
  ``Pattern -> return value``, restoring the canonical form.
- A multi-line match arm whose body is an ``Expr`` (recorded as
  ``A.MatchArm(body=Expr)``) is emitted as a single-line arm
  ``Pattern -> Expr``.
- A multi-line match arm whose body is a true multi-statement
  ``Block`` is emitted as ``Pattern ->`` followed by an indented
  block of statements.
"""

from __future__ import annotations

from .. import capa_ast as A


class _StmtsEmitterMixin:
    # ------------------------------------------------------------
    # Block body
    # ------------------------------------------------------------
    def _emit_block_body(self, block: A.Block) -> None:
        """Emit the statements inside a block. Each statement begins
        on its own line at the current indent level.
        """
        if not block.stmts:
            # Empty block: the source must have had something, but
            # synthetic ASTs can produce empty blocks. Emit a unit
            # expression so the result re-parses.
            self._indent()
            self._write("()")
            self._newline()
            self._emit_block_trailing(block)
            return
        for stmt in block.stmts:
            self._emit_leading(stmt)
            self._emit_stmt(stmt)
        self._emit_block_trailing(block)

    def _emit_stmt(self, s: A.Stmt) -> None:
        if isinstance(s, A.LetStmt):
            self._emit_let(s)
        elif isinstance(s, A.VarStmt):
            self._emit_var(s)
        elif isinstance(s, A.AssignStmt):
            self._emit_assign(s)
        elif isinstance(s, A.IfStmt):
            self._emit_if(s)
        elif isinstance(s, A.WhileStmt):
            self._emit_while(s)
        elif isinstance(s, A.ForStmt):
            self._emit_for(s)
        elif isinstance(s, A.ReturnStmt):
            self._emit_return(s)
        elif isinstance(s, A.BreakStmt):
            self._indent()
            self._write("break")
            self._emit_trailing(s)
            self._newline()
        elif isinstance(s, A.ContinueStmt):
            self._indent()
            self._write("continue")
            self._emit_trailing(s)
            self._newline()
        elif isinstance(s, A.ExprStmt):
            self._emit_expr_stmt(s)
        else:
            raise AssertionError(
                f"unsupported statement: {type(s).__name__}"
            )

    # ------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------
    def _emit_let(self, s: A.LetStmt) -> None:
        self._indent()
        self._write("let ")
        self._write(self._emit_pattern_lvalue(s.pattern))
        if s.type_expr is not None:
            self._write(f": {self._emit_type(s.type_expr)}")
        self._write(" = ")
        self._emit_rhs_expr(s.value)
        self._emit_trailing(s)
        self._newline()

    def _emit_var(self, s: A.VarStmt) -> None:
        self._indent()
        self._write(f"var {s.name}")
        if s.type_expr is not None:
            self._write(f": {self._emit_type(s.type_expr)}")
        self._write(" = ")
        self._emit_rhs_expr(s.value)
        self._emit_trailing(s)
        self._newline()

    def _emit_assign(self, s: A.AssignStmt) -> None:
        self._indent()
        self._write(self._emit_expr(s.target))
        self._write(f" {s.op} ")
        self._emit_rhs_expr(s.value)
        self._emit_trailing(s)
        self._newline()

    def _emit_rhs_expr(self, value: A.Expr) -> None:
        """Emit an expression in RHS position.

        Special case: a multi-line ``match`` on the RHS of ``let``
        / ``var`` / ``return`` / assign uses the indented form
        whose ``match`` keyword sits on the assignment line, then
        each arm on a new line at the next indent level. Same for
        a top-level ``IfExpr`` is fine to emit inline (it is a
        ternary, no newlines).
        """
        if isinstance(value, A.MatchExpr):
            # Emit ``match scrut`` then a newline + indented arms.
            self._write(f"match {self._emit_expr(value.scrutinee)}")
            self._newline()
            self._push_indent()
            for arm in value.arms:
                self._emit_match_arm(arm)
            self._pop_indent()
            # No final newline; the caller will not add one because
            # the arms already ended on a newline. We need to swallow
            # the caller's _newline by leaving the buffer line-start.
            # Detect by setting a flag the let/var/return emitters
            # check via `_at_line_start`.
            return
        self._write(self._emit_expr(value))

    # ------------------------------------------------------------
    # Return / expression statement
    # ------------------------------------------------------------
    def _emit_return(self, s: A.ReturnStmt) -> None:
        self._indent()
        if s.value is None:
            self._write("return")
            self._emit_trailing(s)
            self._newline()
            return
        self._write("return ")
        if isinstance(s.value, A.MatchExpr):
            self._emit_rhs_expr(s.value)
            # The match arms already emitted newlines.
            return
        self._write(self._emit_expr(s.value))
        self._emit_trailing(s)
        self._newline()

    def _emit_expr_stmt(self, s: A.ExprStmt) -> None:
        # A match used as a statement is emitted as a multi-line
        # match block. Other expressions emit on a single line.
        if isinstance(s.expr, A.MatchExpr):
            self._indent()
            self._write(f"match {self._emit_expr(s.expr.scrutinee)}")
            self._newline()
            self._push_indent()
            for arm in s.expr.arms:
                self._emit_match_arm(arm)
            self._pop_indent()
            return
        self._indent()
        self._write(self._emit_expr(s.expr))
        self._emit_trailing(s)
        self._newline()

    # ------------------------------------------------------------
    # Control flow
    # ------------------------------------------------------------
    def _emit_if(self, s: A.IfStmt) -> None:
        self._indent()
        self._write(f"if {self._emit_expr(s.cond)}")
        self._emit_trailing_header(s)
        self._newline()
        self._push_indent()
        self._emit_block_body(s.then_block)
        self._pop_indent()
        for cond, blk in s.elif_arms:
            self._indent()
            self._write(f"elif {self._emit_expr(cond)}")
            self._newline()
            self._push_indent()
            self._emit_block_body(blk)
            self._pop_indent()
        if s.else_block is not None:
            self._indent()
            self._write("else")
            self._newline()
            self._push_indent()
            self._emit_block_body(s.else_block)
            self._pop_indent()

    def _emit_while(self, s: A.WhileStmt) -> None:
        self._indent()
        self._write(f"while {self._emit_expr(s.cond)}")
        self._emit_trailing_header(s)
        self._newline()
        self._push_indent()
        self._emit_block_body(s.body)
        self._pop_indent()

    def _emit_for(self, s: A.ForStmt) -> None:
        self._indent()
        self._write(
            f"for {self._emit_pattern_lvalue(s.pattern)} "
            f"in {self._emit_expr(s.iter)}"
        )
        self._emit_trailing_header(s)
        self._newline()
        self._push_indent()
        self._emit_block_body(s.body)
        self._pop_indent()

    # ------------------------------------------------------------
    # Match arms
    # ------------------------------------------------------------
    def _emit_match_arm(self, arm: A.MatchArm) -> None:
        """Emit a single match arm at the current indent level.

        Four shapes for ``arm.body``:

        - ``Expr`` that is a ``MatchExpr`` containing block arms:
          emit ``pat [if guard] -> match scrut`` on one line, then
          the inner match's arms one indent level deeper. This is
          the only round-trippable shape for a nested match whose
          inner arms cannot be inlined.
        - Other ``Expr``: ``pat [if guard] -> expr`` on one line.
        - ``Block`` of one statement (``ReturnStmt`` / ``BreakStmt`` /
          ``ContinueStmt`` promoted by the parser from a single-line
          divergent arm): emit single-line ``pat -> return value``.
        - General ``Block``: ``pat [if guard] ->`` then newline +
          indented block.
        """
        self._indent()
        self._write(self._emit_pattern_match(arm.pattern))
        if arm.guard is not None:
            self._write(f" if {self._emit_expr(arm.guard)}")
        if isinstance(arm.body, A.Block):
            stmts = arm.body.stmts
            if len(stmts) == 1 and isinstance(
                stmts[0], (A.ReturnStmt, A.BreakStmt, A.ContinueStmt),
            ):
                # Single-line divergent arm: keep on one line.
                self._write(" -> ")
                self._write(_render_divergent_stmt_inline(self, stmts[0]))
                self._emit_trailing(arm)
                self._newline()
                return
            # Multi-statement (or other) block: header + indented body.
            self._write(" ->")
            self._newline()
            self._push_indent()
            self._emit_block_body(arm.body)
            self._pop_indent()
            return
        # Single-expression body. Special case: nested match whose
        # inner arms contain blocks cannot live in the inline form
        # ``{ p -> e, p -> e }``; the inline form is expression-only.
        # Re-emit as a header line ``pat -> match scrut`` followed
        # by indented arms.
        if isinstance(arm.body, A.MatchExpr) and _match_has_block_arms(arm.body):
            inner = arm.body
            self._write(f" -> match {self._emit_expr(inner.scrutinee)}")
            self._newline()
            self._push_indent()
            for inner_arm in inner.arms:
                self._emit_match_arm(inner_arm)
            self._pop_indent()
            return
        self._write(f" -> {self._emit_expr(arm.body)}")
        self._emit_trailing(arm)
        self._newline()

    # ------------------------------------------------------------
    # Patterns
    # ------------------------------------------------------------
    def _emit_pattern_lvalue(self, p: A.Pattern) -> str:
        """Emit a pattern as it appears in let / var / for (l-value
        position).

        let/for/var accept Wildcard, Ident, Tuple, and Struct
        patterns. Or-patterns and Variant-with-payload patterns are
        rejected by the parser in that context. We delegate to the
        match-style emitter for the structural cases (TuplePat,
        StructPat) and special-case Wildcard / Ident so the output
        does not invent unwanted shape.
        """
        if isinstance(p, A.WildcardPat):
            return "_"
        if isinstance(p, A.IdentPat):
            return p.name
        if isinstance(p, A.TuplePat):
            if not p.elements:
                return "()"
            inner = ", ".join(
                self._emit_pattern_lvalue(sub) for sub in p.elements
            )
            if len(p.elements) == 1:
                return f"({inner},)"
            return f"({inner})"
        if isinstance(p, A.StructPat):
            return self._emit_pattern_match(p)
        # Fallback: shouldn't be reachable for valid l-value patterns.
        return self._emit_pattern_match(p)

    def _emit_pattern_match(self, p: A.Pattern) -> str:
        """Emit a pattern as it appears in a match arm."""
        if isinstance(p, A.WildcardPat):
            return "_"
        if isinstance(p, A.IdentPat):
            return p.name
        if isinstance(p, A.LiteralPat):
            return self._emit_expr(p.value)
        if isinstance(p, A.VariantPat):
            if not p.payloads:
                return p.name
            inner = ", ".join(self._emit_pattern_match(sub) for sub in p.payloads)
            return f"{p.name}({inner})"
        if isinstance(p, A.StructPat):
            parts: list[str] = []
            for fname, fpat in p.fields:
                if fpat is None:
                    parts.append(fname)
                else:
                    parts.append(f"{fname}: {self._emit_pattern_match(fpat)}")
            return f"{p.type_name} {{ {', '.join(parts)} }}"
        if isinstance(p, A.TuplePat):
            if not p.elements:
                return "()"
            inner = ", ".join(self._emit_pattern_match(sub) for sub in p.elements)
            if len(p.elements) == 1:
                return f"({inner},)"
            return f"({inner})"
        if isinstance(p, A.OrPat):
            return " | ".join(self._emit_pattern_match(a) for a in p.alternatives)
        raise AssertionError(f"unsupported pattern: {type(p).__name__}")


# ----------------------------------------------------------------
# Helpers (free functions, used only by this mixin)
# ----------------------------------------------------------------
def _match_has_block_arms(m: A.MatchExpr) -> bool:
    """True iff any arm of ``m`` has a ``Block`` body that cannot
    be expressed inline. A single-statement divergent arm body
    (return / break / continue) is wrapped in a Block by the
    parser but represents a single line of source, so we still
    treat the match as inline-emittable.
    """
    for arm in m.arms:
        body = arm.body
        if isinstance(body, A.Block):
            stmts = body.stmts
            if not (
                len(stmts) == 1
                and isinstance(
                    stmts[0],
                    (A.ReturnStmt, A.BreakStmt, A.ContinueStmt),
                )
            ):
                return True
        if isinstance(body, A.MatchExpr) and _match_has_block_arms(body):
            return True
    return False


def _render_divergent_stmt_inline(emitter, stmt: A.Stmt) -> str:
    """Render a return / break / continue statement as one line of text.

    Used for single-statement match arm bodies that the parser
    promoted to a Block (so the analyzer treats the arm as
    divergent). Re-emitting them inline restores the user-facing
    ``Pattern -> return value`` shape.
    """
    if isinstance(stmt, A.ReturnStmt):
        if stmt.value is None:
            return "return"
        return f"return {emitter._emit_expr(stmt.value)}"
    if isinstance(stmt, A.BreakStmt):
        return "break"
    if isinstance(stmt, A.ContinueStmt):
        return "continue"
    # Unexpected; fall back to a safe representation.
    raise AssertionError(
        f"_render_divergent_stmt_inline: unexpected stmt {type(stmt).__name__}"
    )

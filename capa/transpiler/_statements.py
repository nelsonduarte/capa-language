"""Statement and pattern emission mixin.

Lowers Capa statements to Python equivalents, plus the pattern
translation used in both ``let`` / ``for`` (as an l-value) and
``match`` (as a Python ``case`` pattern).

- ``_emit_block_body`` / ``_emit_stmt``: block entry and per-stmt
  dispatch.
- ``_emit_match_stmt``: ``match`` used as a statement (value
  discarded), emitting Python ``match/case`` directly.
- ``_emit_let``: bindings, delegating l-value rendering to
  ``_emit_pattern_lvalue``.
- ``_emit_pattern_lvalue``: emit a pattern as an assignment target
  (only simple ones - wildcard / ident / tuple - are supported here;
  destructuring beyond that raises).
- ``_emit_if`` / ``_emit_while`` / ``_emit_for``: control flow.
- ``_emit_pattern_match``: render any pattern as a Python ``case``
  pattern, including the ``None`` -> ``_NoneType()`` special case.
"""

from __future__ import annotations

from .. import capa_ast as A


class _StatementsMixin:
    def _emit_block_body(self, block: A.Block) -> None:
        if not block.stmts:
            self.em.write("pass")
            return
        for stmt in block.stmts:
            self._emit_stmt(stmt)

    def _emit_stmt(self, s: A.Stmt) -> None:
        from . import _safe_ident, TranspilerError
        if isinstance(s, A.LetStmt):
            self._emit_let(s)
        elif isinstance(s, A.VarStmt):
            value = self._emit_expr(s.value)
            self.em.write(f"{_safe_ident(s.name)} = {value}")
        elif isinstance(s, A.AssignStmt):
            target = self._emit_expr(s.target)
            value = self._emit_expr(s.value)
            self.em.write(f"{target} {s.op} {value}")
        elif isinstance(s, A.IfStmt):
            self._emit_if(s)
        elif isinstance(s, A.WhileStmt):
            self._emit_while(s)
        elif isinstance(s, A.ForStmt):
            self._emit_for(s)
        elif isinstance(s, A.ReturnStmt):
            if s.value is None:
                self.em.write("return")
            elif isinstance(s.value, A.Try):
                # ``return expr?`` lowers inline: hoist expr to a
                # temp, return the temp on Err / None_, return the
                # unwrapped payload on Ok / Some. Avoids the
                # exception path entirely.
                tmp = self._emit_try_check(s.value.expr)
                self.em.write(f"return {tmp}.value")
            else:
                self.em.write(f"return {self._emit_expr(s.value)}")
        elif isinstance(s, A.BreakStmt):
            self.em.write("break")
        elif isinstance(s, A.ContinueStmt):
            self.em.write("continue")
        elif isinstance(s, A.ExprStmt):
            # Special case: ExprStmt(MatchExpr) emits match/case directly
            # without needing a temporary variable - the value is discarded.
            if isinstance(s.expr, A.MatchExpr):
                self._emit_match_stmt(s.expr)
            elif isinstance(s.expr, A.Try):
                # ``expr?`` as a discarded statement: still propagate
                # Err / None_ early. The unwrapped payload is dropped.
                self._emit_try_check(s.expr.expr)
            else:
                self.em.write(self._emit_expr(s.expr))
        else:
            raise TranspilerError(f"unsupported statement: {type(s).__name__}")

    def _emit_try_check(self, inner: A.Expr) -> str:
        """Lower ``inner?`` inline: emit a fresh ``__capa_try_N``
        temp, an ``isinstance(..., Err) or ... is None_`` guard that
        ``return``s the temp on the failure path, and leave the
        caller to use ``<tmp>.value`` (or discard it). Returns the
        temp name so the caller can read ``.value`` from it.

        Replaces the slower ``_capa_try`` path for the three
        positions the transpiler can hoist statically: ``LetStmt``
        value, ``ReturnStmt`` value, ``ExprStmt`` expression.
        """
        inner_code = self._emit_expr(inner)
        tmp = f"__capa_try_{self._tmp_counter}"
        self._tmp_counter += 1
        self.em.write(f"{tmp} = {inner_code}")
        self.em.write(f"if isinstance({tmp}, Err) or {tmp} is None_:")
        self.em.indent()
        self.em.write(f"return {tmp}")
        self.em.dedent()
        return tmp

    def _emit_match_stmt(self, m: A.MatchExpr) -> None:
        """Emits a MatchExpr whose value is discarded (used as a statement).

        Each arm body emits its statements directly - without capturing
        the value in a temporary.
        """
        scrut = self._emit_expr(m.scrutinee)
        self.em.write(f"match {scrut}:")
        self.em.indent()
        for arm in m.arms:
            pat = self._emit_pattern_match(arm.pattern)
            if arm.guard is not None:
                guard = self._emit_expr(arm.guard)
                self.em.write(f"case {pat} if {guard}:")
            else:
                self.em.write(f"case {pat}:")
            self.em.indent()
            if isinstance(arm.body, A.Block):
                self._emit_block_body(arm.body)
            else:
                # Body is a single expression used as a statement: emit
                # as a line that evaluates the expression and discards it.
                self.em.write(self._emit_expr(arm.body))
            self.em.dedent()
        self.em.dedent()

    def _emit_let(self, s: A.LetStmt) -> None:
        if isinstance(s.value, A.Try):
            # ``let pat = expr?`` lowers inline: hoist expr to a
            # temp, return early on Err / None_, bind the
            # unwrapped payload to the pattern. No exception, no
            # @_capa_wrap unless something else in the function
            # still needs it.
            tmp = self._emit_try_check(s.value.expr)
            target = self._emit_pattern_lvalue(s.pattern)
            self.em.write(f"{target} = {tmp}.value")
            return
        value = self._emit_expr(s.value)
        target = self._emit_pattern_lvalue(s.pattern)
        self.em.write(f"{target} = {value}")

    def _emit_pattern_lvalue(self, p: A.Pattern) -> str:
        """Emits a pattern as an assignment target (let/for).

        For simple patterns (Wildcard, Ident), returns the name or ``_``
        directly. Tuples are supported: ``(a, b)`` in Capa becomes
        ``(a, b)`` in Python, valid as an assignment target.
        More complex patterns are not supported in let/for.
        """
        from . import _safe_ident, TranspilerError
        if isinstance(p, A.WildcardPat):
            return "_"
        if isinstance(p, A.IdentPat):
            return _safe_ident(p.name)
        if isinstance(p, A.TuplePat):
            if not p.elements:
                # () as assignment target: ignore the value (let the
                # right-hand side evaluate to Unit).
                return "_"
            subs = [self._emit_pattern_lvalue(sub) for sub in p.elements]
            if len(subs) == 1:
                return f"({subs[0]},)"
            return f"({', '.join(subs)})"
        raise TranspilerError(
            f"complex pattern in let/for not yet supported: {type(p).__name__}"
        )

    def _emit_if(self, s: A.IfStmt) -> None:
        self.em.write(f"if {self._emit_expr(s.cond)}:")
        self.em.indent()
        self._emit_block_body(s.then_block)
        self.em.dedent()
        for cond, blk in s.elif_arms:
            self.em.write(f"elif {self._emit_expr(cond)}:")
            self.em.indent()
            self._emit_block_body(blk)
            self.em.dedent()
        if s.else_block is not None:
            self.em.write("else:")
            self.em.indent()
            self._emit_block_body(s.else_block)
            self.em.dedent()

    def _emit_while(self, s: A.WhileStmt) -> None:
        self.em.write(f"while {self._emit_expr(s.cond)}:")
        self.em.indent()
        self._emit_block_body(s.body)
        self.em.dedent()

    def _emit_for(self, s: A.ForStmt) -> None:
        target = self._emit_pattern_lvalue(s.pattern)
        # Special case: `for x in a..b` and `for x in a..=b` iterate
        # over Python's lazy `range()` directly, without materialising
        # a CapaList. A bare RangeExpr in this position is the common
        # case (`for i in 0..1_000_000`) and previously allocated the
        # full list (28 bytes per int in CPython, gigabytes for large
        # ranges). Bound ranges (`let xs = 0..n; for x in xs`) still
        # materialise via the standard `_emit_expr(RangeExpr)` path
        # because the user asked for the list by binding it.
        if isinstance(s.iter, A.RangeExpr):
            start = self._emit_expr(s.iter.start)
            end = self._emit_expr(s.iter.end)
            stop = f"({end}) + 1" if s.iter.inclusive else end
            self.em.write(f"for {target} in range({start}, {stop}):")
        else:
            iter_code = self._emit_expr(s.iter)
            self.em.write(f"for {target} in {iter_code}:")
        self.em.indent()
        self._emit_block_body(s.body)
        self.em.dedent()

    def _emit_pattern_match(self, p: A.Pattern) -> str:
        """Emits a pattern for use inside a Python ``case``."""
        from . import _safe_ident, TranspilerError
        if isinstance(p, A.WildcardPat):
            return "_"
        if isinstance(p, A.IdentPat):
            # In Python, a bare name in a case is a binding.
            return _safe_ident(p.name)
        if isinstance(p, A.LiteralPat):
            return self._emit_expr(p.value)
        if isinstance(p, A.VariantPat):
            # Special case: Option's None is a singleton (None_) at
            # runtime, an instance of _NoneType. Python match requires
            # a class - we use _NoneType().
            if p.name == "None":
                if p.payload is not None:
                    raise TranspilerError("'None' takes no payload")
                return "_NoneType()"
            if p.payload is None:
                return f"{p.name}()"
            sub = self._emit_pattern_match(p.payload)
            return f"{p.name}({sub})"
        if isinstance(p, A.StructPat):
            parts = []
            for fname, fpat in p.fields:
                if fpat is None:
                    parts.append(f"{_safe_ident(fname)}={_safe_ident(fname)}")
                else:
                    parts.append(f"{_safe_ident(fname)}={self._emit_pattern_match(fpat)}")
            return f"{p.type_name}({', '.join(parts)})"
        if isinstance(p, A.TuplePat):
            # () in Python match is not valid as a pattern - use _.
            # But an empty Capa tuple = Unit, and a Unit scrutinee is rare
            # in match. For other sizes, emit (p1, p2, ...).
            if not p.elements:
                return "()"
            subs = [self._emit_pattern_match(sub) for sub in p.elements]
            if len(subs) == 1:
                return f"({subs[0]},)"
            return f"({', '.join(subs)})"
        if isinstance(p, A.OrPat):
            # Python match accepts ``a | b | c`` directly.
            alts = [self._emit_pattern_match(a) for a in p.alternatives]
            return " | ".join(alts)
        raise TranspilerError(f"unsupported pattern in match: {type(p).__name__}")

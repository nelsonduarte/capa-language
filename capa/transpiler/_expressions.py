"""Expression emission mixin.

Lowers Capa expressions into Python source fragments. The
expression mixin produces *strings* (the fragment of Python code
that represents the expression) and may also write supporting
statements through ``self.em.write`` when an expression has no
Python-expression equivalent (block-body lambdas, ``match`` in
expression position).

- ``_emit_expr``: top-level dispatcher over the ``Expr`` shapes.
- ``_emit_lambda``: handles both the simple ``lambda`` form and the
  block-body case (hoisted as a nested ``def``).
- ``_emit_match_expr``: emits a Python ``match/case`` that assigns
  to a fresh temporary and returns that temporary's name.
- ``_emit_ident``: applies the PascalCase-is-variant heuristic and
  the ``None`` / ``None_`` mapping.
- ``_emit_call`` / ``_emit_call_arg_list`` / ``_emit_call_callee``:
  function calls and the positional + named argument lowering.
- ``_emit_try``: the ``?`` operator (delegates to ``_capa_try``).
- ``_emit_interpolated_string`` / ``_emit_string_lit``: string and
  f-string lowering, including ``$$`` escapes.
"""

from __future__ import annotations

from .. import capa_ast as A


class _ExpressionsMixin:
    def _emit_expr(self, e: A.Expr) -> str:
        from . import _safe_ident, _BINOP_MAP, _UNARY_MAP, TranspilerError
        if isinstance(e, A.IntLit):
            return repr(e.value)
        if isinstance(e, A.FloatLit):
            return repr(e.value)
        if isinstance(e, A.StringLit):
            return self._emit_string_lit(e.value)
        if isinstance(e, A.InterpolatedString):
            return self._emit_interpolated_string(e)
        if isinstance(e, A.CharLit):
            # Capa Char -> length-1 str in Python (Python has no char).
            return repr(e.value)
        if isinstance(e, A.BoolLit):
            return "True" if e.value else "False"
        if isinstance(e, A.UnitLit):
            return "None"
        if isinstance(e, A.Ident):
            return self._emit_ident(e.name)
        if isinstance(e, A.BinOp):
            l = self._emit_expr(e.left)
            r = self._emit_expr(e.right)
            op = _BINOP_MAP.get(e.op)
            if op is None:
                raise TranspilerError(f"unsupported binop: {e.op}")
            return f"({l} {op} {r})"
        if isinstance(e, A.UnaryOp):
            op = _UNARY_MAP.get(e.op)
            if op is None:
                raise TranspilerError(f"unsupported unary: {e.op}")
            inner = self._emit_expr(e.operand)
            return f"({op}{inner})"
        if isinstance(e, A.Call):
            return self._emit_call(e)
        if isinstance(e, A.MethodCall):
            return self._emit_method_call(e)
        if isinstance(e, A.FieldAccess):
            recv = self._emit_expr(e.receiver)
            return f"{recv}.{_safe_ident(e.field_name)}"
        if isinstance(e, A.Index):
            recv = self._emit_expr(e.receiver)
            idx = self._emit_expr(e.index)
            return f"{recv}[{idx}]"
        if isinstance(e, A.Try):
            return self._emit_try(e)
        if isinstance(e, A.StructLit):
            parts = []
            for fname, fexpr in e.fields:
                parts.append(f"{_safe_ident(fname)}={self._emit_expr(fexpr)}")
            return f"{e.type_name}({', '.join(parts)})"
        if isinstance(e, A.ListLit):
            els = ", ".join(self._emit_expr(x) for x in e.elements)
            return f"CapaList([{els}])"
        if isinstance(e, A.TupleLit):
            if not e.elements:
                return "()"
            if len(e.elements) == 1:
                return f"({self._emit_expr(e.elements[0])},)"
            els = ", ".join(self._emit_expr(x) for x in e.elements)
            return f"({els})"
        if isinstance(e, A.MatchExpr):
            return self._emit_match_expr(e)
        if isinstance(e, A.IfExpr):
            cond = self._emit_expr(e.cond)
            then_e = self._emit_expr(e.then_expr)
            else_e = self._emit_expr(e.else_expr)
            return f"({then_e} if {cond} else {else_e})"
        if isinstance(e, A.LambdaExpr):
            return self._emit_lambda(e)
        if isinstance(e, A.RangeExpr):
            start = self._emit_expr(e.start)
            end = self._emit_expr(e.end)
            # ``a..=b`` is inclusive; Python's range stops one before
            # the second argument, so we add 1. The Capa source type
            # is ``Range<Int>`` (distinct from ``List<Int>``), so we
            # emit a lazy ``CapaRange`` wrapper rather than
            # materialising. A bound range that is later iterated
            # over goes through ``CapaRange.__iter__``; the
            # for-loop fast path in ``_emit_for`` bypasses
            # ``CapaRange`` entirely and emits a bare Python
            # ``range(...)``.
            stop = f"({end}) + 1" if e.inclusive else end
            return f"CapaRange({start}, {stop})"
        raise TranspilerError(f"unsupported expression: {type(e).__name__}")

    def _emit_lambda(self, e: A.LambdaExpr) -> str:
        """Emits a lambda as Python.

        - Single-expr body: ``(lambda x: body)`` (a Python expression).
        - Block body: generates a nested function with a unique name
          before the current line (hoisting), and returns that name.
          The Emitter is already in statement-producing mode, and the
          nested function's stmts appear at the correct indentation
          level.
        """
        from . import _safe_ident
        if isinstance(e.body, A.Block):
            name = f"_lambda_{self._tmp_counter}"
            self._tmp_counter += 1
            params = ", ".join(_safe_ident(p.name) for p in e.params)
            self.em.write(f"def {name}({params}):")
            self.em.indent()
            self._emit_block_body(e.body)
            self.em.dedent()
            return name
        param_names = ", ".join(_safe_ident(p.name) for p in e.params)
        body = self._emit_expr(e.body)
        return f"(lambda {param_names}: {body})"

    def _emit_match_expr(self, m: A.MatchExpr) -> str:
        """Emits a MatchExpr used in expression position.

        Strategy: generates a Python match/case that assigns to a
        temporary variable, and returns the variable's name. The
        match/case lines are emitted to the Emitter *before* the current
        line (because they are prelude to the statement the caller is
        building).

        Caveat: this does not work if the caller has already emitted
        part of the current line. In the current design, ``_emit_expr``
        is always called *before* ``em.write`` for the statement where
        it appears, so the prelude lands in the right place.

        For an arm body that is an expression, the expression's value
        is the match's value. For a block body, we assign None to the
        temporary - the caller is responsible for using ``return``
        inside the block if it wants to exit with a different value.

        Fast path: when every arm is a payload-less variant check
        (e.g. ``BrowserChrome``), a wildcard, or an or-pattern of
        those, the match lowers to an ``if isinstance(...)`` chain
        instead of Python's ``match`` / ``case``. The semantics are
        identical (each ``case Variant():`` is isinstance-checked
        anyway) and the overhead is materially lower on hot paths
        like enum dispatch inside an inner loop.
        """
        tmp = f"_m{self._tmp_counter}"
        self._tmp_counter += 1
        if self._is_simple_variant_dispatch(m):
            self._emit_match_expr_isinstance(m, tmp)
            return tmp
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
                # For v1, blocks as arm body in expression context
                # produce None. If the user wants a concrete value,
                # they must use a single-line expr or an explicit return.
                self._emit_block_body(arm.body)
                self.em.write(f"{tmp} = None")
            else:
                body_code = self._emit_expr(arm.body)
                self.em.write(f"{tmp} = {body_code}")
            self.em.dedent()
        self.em.dedent()
        return tmp

    def _is_simple_variant_dispatch(self, m: A.MatchExpr) -> bool:
        """Returns True iff every arm in the match qualifies for the
        ``isinstance`` fast path: a payload-less variant pattern, a
        wildcard, or an or-pattern of those, with no guard. Literal
        patterns and patterns with destructured payloads stay on the
        general ``match`` / ``case`` path.
        """
        for arm in m.arms:
            if arm.guard is not None:
                return False
            if not self._is_simple_dispatch_pattern(arm.pattern):
                return False
        return True

    def _is_simple_dispatch_pattern(self, p) -> bool:
        if isinstance(p, A.WildcardPat):
            return True
        if isinstance(p, A.VariantPat):
            return p.payload is None
        if isinstance(p, A.OrPat):
            return all(self._is_simple_dispatch_pattern(a) for a in p.alternatives)
        return False

    def _emit_match_expr_isinstance(self, m: A.MatchExpr, tmp: str) -> None:
        """Fast path of ``_emit_match_expr``: lowers a payload-less
        variant dispatch to ``if isinstance(...)`` / ``elif`` /
        ``else``. The scrutinee is bound to a temporary so it is
        evaluated exactly once even when it has a non-trivial
        expression shape (e.g. ``parsed.browser``).
        """
        scrut_code = self._emit_expr(m.scrutinee)
        scrut_tmp = f"_ms{self._tmp_counter}"
        self._tmp_counter += 1
        self.em.write(f"{scrut_tmp} = {scrut_code}")
        first = True
        emitted_else = False
        for arm in m.arms:
            keyword = "if" if first else "elif"
            first = False
            classes = self._variant_classes_in_pattern(arm.pattern)
            if classes is None:
                # Wildcard arm: emit as ``else:`` and stop (any
                # subsequent arms are unreachable; the analyser
                # already validates exhaustiveness).
                self.em.write("else:")
                emitted_else = True
            else:
                check = self._isinstance_check(scrut_tmp, classes)
                self.em.write(f"{keyword} {check}:")
            self.em.indent()
            if isinstance(arm.body, A.Block):
                self._emit_block_body(arm.body)
                self.em.write(f"{tmp} = None")
            else:
                body_code = self._emit_expr(arm.body)
                self.em.write(f"{tmp} = {body_code}")
            self.em.dedent()
            if emitted_else:
                break

    def _variant_classes_in_pattern(self, p):
        """Returns a list of Python class names (as strings) the
        pattern checks for via isinstance, or ``None`` for a wildcard.
        Only called on patterns that passed
        ``_is_simple_dispatch_pattern``.
        """
        if isinstance(p, A.WildcardPat):
            return None
        if isinstance(p, A.VariantPat):
            return [self._variant_class_name(p.name)]
        if isinstance(p, A.OrPat):
            classes: list[str] = []
            for alt in p.alternatives:
                inner = self._variant_classes_in_pattern(alt)
                if inner is None:
                    return None
                classes.extend(inner)
            return classes
        raise AssertionError(
            f"unexpected pattern in isinstance lowering: {type(p).__name__}"
        )

    def _variant_class_name(self, name: str) -> str:
        # Mirrors the special case in ``_emit_pattern_match`` for the
        # ``None`` Option singleton, whose runtime class is
        # ``_NoneType``.
        if name == "None":
            return "_NoneType"
        return name

    def _isinstance_check(self, scrut: str, classes: list[str]) -> str:
        if len(classes) == 1:
            return f"isinstance({scrut}, {classes[0]})"
        return f"isinstance({scrut}, ({', '.join(classes)}))"

    def _emit_ident(self, name: str) -> str:
        from . import _safe_ident
        # Constant variants (PascalCase, no calls after) are
        # instantiated. This is already handled by the fact that emit of
        # Call/MethodCall produces `{name}(...)` separately. Here we only
        # emit the bare name; if it is a payload-less variant used as a
        # value (e.g., `return Red`), it needs to become `Red()`.
        # Special case: ``None`` is a runtime singleton, not an
        # instantiable class. Map it directly to the ``None_`` singleton.
        if name == "None":
            return "None_"
        if name and name[0].isupper() and name not in (
            # Capabilities, Result variants, Option variants - these are
            # not "simple variants" because they are classes that must
            # be explicitly instantiated (and usually already are via Call).
        ):
            # Heuristic: if it is a bare Ident with a PascalCase name,
            # it is probably a variant being used as a value - emit it
            # as `Name()`. Cases that need the raw type (e.g., passing
            # a class) are rare in Capa.
            return f"{name}()"
        return _safe_ident(name)

    def _emit_call(self, e: A.Call) -> str:
        # Special case: callee is an IDENT that is a variant with payload.
        # Already handled naturally - `Some(x)` in Capa becomes `Some(x)`
        # in Python because Some is a class.
        # Builtin collection-creation functions: emit Python literals.
        if isinstance(e.callee, A.Ident):
            if e.callee.name == "new_map" and not e.args:
                return "{}"
            if e.callee.name == "new_set" and not e.args:
                return "set()"
        callee = self._emit_call_callee(e.callee)
        args = self._emit_call_arg_list(e.args, e.arg_names)
        return f"{callee}({args})"

    def _emit_call_arg_list(
        self, args: list[A.Expr], arg_names: list,
    ) -> str:
        """Render a call argument list, including any named arguments
        as Python keyword arguments (``name=value``). Capa parameter
        names are mapped through ``_safe_ident`` because they may
        collide with Python reserved words.
        """
        from . import _safe_ident
        parts: list[str] = []
        for i, a in enumerate(args):
            name = arg_names[i] if i < len(arg_names) else None
            code = self._emit_expr(a)
            if name is None:
                parts.append(code)
            else:
                parts.append(f"{_safe_ident(name)}={code}")
        return ", ".join(parts)

    def _emit_call_callee(self, e: A.Expr) -> str:
        from . import _safe_ident
        # When emitting a Call, the callee is a concrete call;
        # we avoid the "constant variant = `()`" heuristic here.
        if isinstance(e, A.Ident):
            return _safe_ident(e.name)
        if isinstance(e, A.FieldAccess):
            recv = self._emit_expr(e.receiver)
            return f"{recv}.{_safe_ident(e.field_name)}"
        return self._emit_expr(e)

    def _emit_try(self, e: A.Try) -> str:
        """``?`` operator: propagates ``Err`` early by returning.

        Strategy: generates code that evaluates the expression into a
        temporary, and if it is Err, returns it. Otherwise, returns the
        ``.value``.

        To do this with expressions, we would use a walrus expression
        inside a lambda trick. But that is fragile - we prefer the `?`
        to appear in statements where we can *hoist* the temporary onto
        a previous line.

        For v1, we use an approach that requires co-writing with the
        statement emitter: emit `(tmp := <expr>).value if isinstance(tmp, Ok) else (return tmp)`
        - but Python does not allow return in an expression.

        Pragmatic solution: we emit a call to `_capa_try` that raises a
        special exception; the caller (the function where the ? appears)
        must catch it. This loosens the "pure early return" semantics
        but works transparently.
        """
        # For v1, we use a helper that raises a special exception
        # and is caught at the function boundary. Not ideal
        # performance-wise, but correct.
        inner = self._emit_expr(e.expr)
        return f"_capa_try({inner})"

    def _emit_interpolated_string(self, e: A.InterpolatedString) -> str:
        """Emits a string with interpolations as a Python f-string.

        Each Expr part is processed via ``_emit_expr`` (with correct
        type dispatch, e.g., ``s.length()`` -> ``len(s)``). Literal
        text between interpolations is escaped so it does not interfere
        with f-string syntax.
        """
        parts: list[str] = []
        for part in e.parts:
            if isinstance(part, str):
                # Escape f-string special characters: { } and \
                escaped = (
                    part.replace("\\", "\\\\")
                    .replace('"', '\\"')
                    .replace("{", "{{")
                    .replace("}", "}}")
                    .replace("\n", "\\n")
                    .replace("\t", "\\t")
                    .replace("\r", "\\r")
                )
                parts.append(escaped)
            else:
                expr_code = self._emit_expr(part)
                parts.append("{" + expr_code + "}")
        return 'f"' + "".join(parts) + '"'

    def _emit_string_lit(self, value: str) -> str:
        """Converts a Capa literal to Python.

        If the literal contains ``${expr}``, emits an f-string.
        Otherwise, emits with ``repr``.

        ``$$`` escapes a literal ``$``.
        """
        from . import TranspilerError
        if "${" not in value:
            return repr(value)
        # Build an f-string. We must escape literal { and }.
        parts: list[str] = []
        i = 0
        while i < len(value):
            c = value[i]
            if c == "$" and i + 1 < len(value) and value[i + 1] == "$":
                parts.append("$")
                i += 2
                continue
            if c == "$" and i + 1 < len(value) and value[i + 1] == "{":
                # Find the matching `}`.
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
                    raise TranspilerError(
                        f"unterminated interpolation in string literal: {value!r}"
                    )
                expr_text = value[i + 2 : j]
                parts.append("{" + expr_text + "}")
                i = j + 1
                continue
            if c == "{":
                parts.append("{{")
                i += 1
                continue
            if c == "}":
                parts.append("}}")
                i += 1
                continue
            parts.append(c)
            i += 1
        body = "".join(parts)
        # Escape backslashes and quotes for safe f-string repr.
        # The simplest way: emit as f"..." with double quotes, escaping
        # only `\` and `"`.
        escaped = body.replace("\\", "\\\\").replace('"', '\\"')
        # Literal newlines must become \n to fit in a single-line f-string.
        escaped = escaped.replace("\n", "\\n").replace("\t", "\\t")
        return f'f"{escaped}"'

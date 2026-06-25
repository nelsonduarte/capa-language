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
            return self._emit_ident(e)
        if isinstance(e, A.BinOp):
            l = self._emit_expr(e.left)
            r = self._emit_expr(e.right)
            op = _BINOP_MAP.get(e.op)
            if op is None:
                raise TranspilerError(f"unsupported binop: {e.op}")
            from ..typesys import TyName
            lt = self.types.get(id(e.left))
            rt = self.types.get(id(e.right))
            lt_is_int = isinstance(lt, TyName) and lt.name == "Int"
            rt_is_int = isinstance(rt, TyName) and rt.name == "Int"
            # Safety (Bug #1): Int ``/`` is floor division (Python
            # ``//``), but plain ``//`` neither traps on ``MIN / -1``
            # (Python yields the bignum ``2**63``, escaping i64) nor on
            # division by zero in a way that matches the Wasm trap.
            # Route through ``_capa_idiv``, which floors AND traps on
            # ``b == 0`` (ZeroDivisionError) and ``MIN / -1``
            # (OverflowError), mirroring the Wasm backend.
            if e.op == "/" and lt_is_int and rt_is_int:
                return f"_capa_idiv({l}, {r})"
            # Safety: route Int +/-/* and <</>> through the
            # overflow-checking runtime helpers so the Python backend
            # raises ``OverflowError`` at the same input the Wasm
            # backend traps on (audit fixes C2 and C3). Float and
            # mixed-type arithmetic stays on the plain operator path.
            both_int = lt_is_int and rt_is_int
            if both_int and e.op in ("+", "-", "*"):
                helper = {
                    "+": "_capa_iadd",
                    "-": "_capa_isub",
                    "*": "_capa_imul",
                }[e.op]
                return f"{helper}({l}, {r})"
            if both_int and e.op in ("<<", ">>"):
                helper = "_capa_shl" if e.op == "<<" else "_capa_shr"
                return f"{helper}({l}, {r})"
            return f"({l} {op} {r})"
        if isinstance(e, A.UnaryOp):
            op = _UNARY_MAP.get(e.op)
            if op is None:
                raise TranspilerError(f"unsupported unary: {e.op}")
            inner = self._emit_expr(e.operand)
            # Safety (Bug #6): negating ``i64::MIN`` overflows i64
            # (``-(MIN) == 2**63``). Plain Python ``-x`` yields the
            # bignum ``2**63`` (escaping i64) while the Wasm ``0 - x``
            # wraps back to MIN; both are wrong. Route Int negation
            # through the checked subtract (``0 - x``) so the Python
            # backend raises ``OverflowError`` at the same input the
            # Wasm backend now traps on. Normal negation is unaffected.
            from ..typesys import TyName
            ot = self.types.get(id(e.operand))
            if e.op == "-" and isinstance(ot, TyName) and ot.name == "Int":
                return f"_capa_isub(0, {inner})"
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
            # Safety (audit fix C1): List indexing routes through
            # ``_capa_list_get`` so the Python backend raises
            # ``IndexError`` at the same input the Wasm backend
            # traps on (negative index OR out-of-range). Tuple /
            # Map / String indexing falls through to native Python
            # ``[]``: tuples are statically arity-checked by the
            # analyzer, Map[key] raises KeyError natively, and
            # source-level String indexing is not surface syntax in
            # Capa (use ``s.substring(...)`` / ``s.char_at(...)``).
            from ..typesys import TyName
            recv_ty = self.types.get(id(e.receiver))
            if isinstance(recv_ty, TyName) and recv_ty.name == "List":
                return f"_capa_list_get({recv}, {idx})"
            return f"{recv}[{idx}]"
        if isinstance(e, A.Try):
            return self._emit_try(e)
        if isinstance(e, A.Become):
            # Roadmap S3.2: a transition is identity at runtime; only the
            # state-type changes (a compile-time property). The value
            # flows through unchanged.
            return self._emit_expr(e.value)
        if isinstance(e, A.StructLit):
            # Roadmap S3.4: a typestate construction ``Name[State] {...}``
            # builds the same struct class as an ordinary literal (the
            # state is compile-time-only); a fieldless one is ``Name()``.
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

        Captures are bound by VALUE at lambda-definition time
        (audit slice 19, 2026-05-29). Without this, Python's
        late-binding closure semantics make
        ``for i in 0..3: handlers.push(fun () => i)`` produce
        three lambdas that all return ``2`` (the loop var's
        final value), while the Wasm backend captures each
        iteration's ``i`` at ``MakeLambda`` time and produces
        ``[0, 1, 2]``. The fix emits captures as Python default
        arguments (``lambda x, _i=i: ...``) which binds the
        value at the lambda's creation site, matching Wasm.
        Reference-typed captures (lists, maps, strings) still
        share the same object - default args bind the reference,
        not a copy, which is also what the Wasm side does (it
        captures the i32 pointer to the heap record, not a
        deep copy).

        Lambdas whose body contains ``?`` get the ``@_capa_wrap``
        decorator (block-bodied) or are wrapped via ``_capa_wrap(...)``
        (expression-bodied) so that ``_CapaTryEarlyReturn`` raised by
        ``_capa_try`` is caught at the lambda's own boundary. Without
        this, the exception would escape past the lambda's caller,
        which has no decorator of its own to catch it.
        """
        from . import _safe_ident, _uses_exception_try
        needs_wrap = _uses_exception_try(e.body)
        own_param_names = {p.name for p in e.params}
        captures = self._collect_lambda_captures(e.body, own_param_names)
        own_param_str = ", ".join(_safe_ident(p.name) for p in e.params)
        capture_param_str = ", ".join(
            f"{_safe_ident(name)}={_safe_ident(name)}"
            for name in captures
        )
        # Join own params + capture defaults with a single comma
        # when both are present; either alone needs no comma.
        if own_param_str and capture_param_str:
            full_params = f"{own_param_str}, {capture_param_str}"
        else:
            full_params = own_param_str or capture_param_str
        if isinstance(e.body, A.Block):
            name = f"_lambda_{self._tmp_counter}"
            self._tmp_counter += 1
            if needs_wrap:
                self.em.write("@_capa_wrap")
            self.em.write(f"def {name}({full_params}):")
            self.em.indent()
            # Audit slice 24 (2026-05-30): a block-body lambda with
            # a non-Unit return type uses Capa's implicit-result-
            # block semantics - the trailing ExprStmt is the
            # lambda's return value. Without this, Python emits the
            # expression as a discarded statement and the lambda
            # returns None, while the CIR-side fix wraps the tail
            # in ``Return(...)`` and Wasm returns the correct value.
            # Mirror the implicit-result rule at the transpiler
            # layer so the legacy oracle backend matches Wasm.
            returns_unit = (
                e.return_type is None
                or isinstance(e.return_type, A.UnitType)
            )
            stmts = e.body.stmts
            if (
                not returns_unit
                and stmts
                and isinstance(stmts[-1], A.ExprStmt)
            ):
                for s in stmts[:-1]:
                    self._emit_stmt(s)
                tail_value = self._emit_expr(stmts[-1].expr)
                self.em.write(f"return {tail_value}")
            else:
                self._emit_block_body(e.body)
            self.em.dedent()
            return name
        body = self._emit_expr(e.body)
        expr = f"(lambda {full_params}: {body})" if full_params else f"(lambda: {body})"
        if needs_wrap:
            expr = f"_capa_wrap({expr})"
        return expr

    def _collect_lambda_captures(
        self, body, own_param_names: set[str],
    ) -> list[str]:
        """Walk ``body`` and return the deduplicated list of names
        that are referenced inside but bound in an enclosing scope
        (parameter / let / var). Module-level symbols
        (FUNCTION, CONSTANT, VARIANT, TYPE_*, CAPABILITY, TRAIT)
        are excluded -- they would change semantics if rebound as
        default args (a top-level fn name would shadow).
        Capability params are included (Wasm captures the cap
        pointer). Identifiers we cannot resolve via
        ``self.bindings`` are skipped conservatively. Names
        bound INSIDE the body (let / var / for / match pattern)
        are also excluded -- they're locals of the lambda, not
        captures from the outer scope.
        """
        from ..analyzer import SymbolKind
        captures: dict[str, None] = {}  # insertion-ordered dedup
        # Pre-walk: collect names bound INSIDE the body so we
        # don't mis-attribute their use-sites as captures from the
        # outer scope. ``let x = ... ; ... x ...`` should not
        # capture x.
        inner_bound: set[str] = set()
        self._collect_body_bound_names(body, inner_bound)
        excludes = own_param_names | inner_bound

        _LOCAL_KINDS = {
            SymbolKind.PARAM, SymbolKind.LOCAL, SymbolKind.LOCAL_VAR,
        }

        def visit(node):
            if node is None:
                return
            if isinstance(node, A.Ident):
                if node.name in excludes:
                    return
                sym = self.bindings.get(id(node))
                if sym is None or sym.kind not in _LOCAL_KINDS:
                    return
                captures.setdefault(node.name, None)
                return
            if isinstance(node, A.LambdaExpr):
                # Nested lambda: its own captures get rebound at
                # ITS emit site. Free names in its body that ALSO
                # need to come from OUR outer scope must still
                # be captured here. Recurse with the inner
                # lambda's own params added to the exclude set so
                # the inner's params aren't reported as captures
                # of ours.
                inner_excludes = excludes | {p.name for p in node.params}
                inner_caps = self._collect_lambda_captures(
                    node.body, inner_excludes,
                )
                for c in inner_caps:
                    if c not in excludes:
                        captures.setdefault(c, None)
                return
            # Generic walk: visit every field that holds an Expr,
            # a Stmt, a Block, or a list of any of them.
            from dataclasses import fields as _fields
            if hasattr(node, "__dataclass_fields__"):
                for f in _fields(node):
                    val = getattr(node, f.name, None)
                    if isinstance(val, list):
                        for item in val:
                            visit(item)
                    elif isinstance(val, tuple):
                        for item in val:
                            visit(item)
                    else:
                        visit(val)
        visit(body)
        return list(captures.keys())

    def _collect_body_bound_names(self, node, out: set[str]) -> None:
        """Recursively collect every identifier the body binds via
        let / var / for-binder / match-pattern. Used by
        ``_collect_lambda_captures`` to exclude names that the
        lambda binds internally (so a ``let x = ...`` inside the
        body isn't mistaken for a capture of an outer ``x``).
        Names bound inside a NESTED lambda are NOT collected --
        each lambda has its own scope and that inner lambda
        handles its own captures on emit."""
        if node is None:
            return
        if isinstance(node, A.LambdaExpr):
            # Don't peek inside nested lambdas; their bound names
            # live in their own scope.
            return
        if isinstance(node, A.LetStmt):
            self._collect_pattern_names(node.pattern, out)
            self._collect_body_bound_names(node.value, out)
            return
        if isinstance(node, A.VarStmt):
            out.add(node.name)
            self._collect_body_bound_names(node.value, out)
            return
        if isinstance(node, A.ForStmt):
            out.add(node.name)
            self._collect_body_bound_names(node.iter, out)
            for s in node.body.stmts:
                self._collect_body_bound_names(s, out)
            return
        if isinstance(node, A.MatchExpr) or (
            hasattr(A, "MatchStmt") and isinstance(node, A.MatchStmt)
        ):
            self._collect_body_bound_names(node.scrutinee, out)
            for arm in node.arms:
                self._collect_pattern_names(arm.pattern, out)
                self._collect_body_bound_names(arm.body, out)
            return
        # Generic walk.
        from dataclasses import fields as _fields
        if hasattr(node, "__dataclass_fields__"):
            for f in _fields(node):
                val = getattr(node, f.name, None)
                if isinstance(val, list):
                    for item in val:
                        self._collect_body_bound_names(item, out)
                elif isinstance(val, tuple):
                    for item in val:
                        self._collect_body_bound_names(item, out)
                else:
                    self._collect_body_bound_names(val, out)

    def _collect_pattern_names(self, pat, out: set[str]) -> None:
        """Collect every name a pattern binds (IdentPat,
        VariantPat payloads, TuplePat elements). WildcardPat and
        LiteralPat bind nothing."""
        if pat is None:
            return
        if isinstance(pat, A.IdentPat):
            out.add(pat.name)
            return
        if hasattr(A, "VariantPat") and isinstance(pat, A.VariantPat):
            for sub in pat.payloads:
                self._collect_pattern_names(sub, out)
            return
        if hasattr(A, "TuplePat") and isinstance(pat, A.TuplePat):
            for sub in pat.elements:
                self._collect_pattern_names(sub, out)
            return

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
            self._emit_arm_body_to(arm.body, tmp)
            self.em.dedent()
        self.em.dedent()
        return tmp

    def _emit_arm_body_to(self, body, tmp: str) -> None:
        """Emit a match arm body, assigning its value to ``tmp``.

        Three shapes are handled:
          * single-expression body (``Some(x) -> x + 1``): emit
            ``tmp = <expr>``.
          * block body whose last statement is an ``ExprStmt``:
            emit the head statements, then assign the trailing
            expression to ``tmp`` (block-as-expression semantics).
          * other block body (ends in let, return, while, ...):
            emit the block, then assign ``tmp = None`` so the
            shape of the match expression stays well-formed.
        """
        if isinstance(body, A.Block):
            stmts = body.stmts
            if stmts and isinstance(stmts[-1], A.ExprStmt):
                for s in stmts[:-1]:
                    self._emit_stmt(s)
                last_expr = self._emit_expr(stmts[-1].expr)
                self.em.write(f"{tmp} = {last_expr}")
            else:
                self._emit_block_body(body)
                self.em.write(f"{tmp} = None")
        else:
            body_code = self._emit_expr(body)
            self.em.write(f"{tmp} = {body_code}")

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
            return not p.payloads
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
            self._emit_arm_body_to(arm.body, tmp)
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

    def _emit_ident(self, e: A.Ident) -> str:
        from . import _safe_ident
        from ..analyzer import SymbolKind
        name = e.name
        # Special case: ``None`` is a runtime singleton, not an
        # instantiable class. Map it directly to the ``None_`` singleton.
        if name == "None":
            return "None_"
        # If we have analyzer bindings, use them: a payload-less
        # variant used as a bare value (``return Red``) must be
        # constructed as ``Red()``. Anything else (CONSTANT,
        # FUNCTION, capability, etc.) is just the bare name.
        sym = self.bindings.get(id(e))
        if sym is not None:
            if sym.kind == SymbolKind.VARIANT and not sym.variant_payload_tys:
                return f"{name}()"
            return _safe_ident(name)
        # Fallback (no bindings provided, e.g., direct unit-test
        # invocation of the transpiler): use the old PascalCase
        # heuristic. This is wrong for UPPERCASE constants, but
        # the bindings path handles them correctly when the CLI is
        # the caller.
        if name and name[0].isupper():
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
                # CapaSet is an insertion-ordered set (dict-backed), not
                # a raw Python ``set`` (hash order); the latter would
                # diverge from the Wasm backend's linear element array.
                return "CapaSet()"
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

    def _interp_type(self, expr: A.Expr):
        """Resolves the static type of an interpolated sub-expression.

        Returns the analyzer-recorded type from ``self.types`` when one
        is present and concrete. The analyzer records ``TyUnknown`` for a
        tuple index (it only resolves the element type for ``List``
        receivers), so for an ``A.Index`` over a tuple with a constant
        integer index we derive the element type from the receiver's
        ``TyTuple``. This keeps display decisions (e.g. lowering a Bool to
        ``true`` / ``false`` in ``${...}``) keyed off the real element
        type regardless of the node shape, matching the Wasm backend.
        """
        from ..typesys import TyName, TyTuple, TyUnknown
        ty = self.types.get(id(expr))
        if isinstance(ty, TyName) or (
            ty is not None and ty is not TyUnknown
        ):
            return ty
        # Fall back: derive a tuple-index element type the analyzer left
        # as TyUnknown. Only constant int indices are statically known.
        if isinstance(expr, A.Index) and isinstance(expr.index, A.IntLit):
            recv_ty = self.types.get(id(expr.receiver))
            if isinstance(recv_ty, TyTuple):
                i = expr.index.value
                if 0 <= i < len(recv_ty.elements):
                    return recv_ty.elements[i]
        return ty

    def _emit_interpolated_string(self, e: A.InterpolatedString) -> str:
        """Emits a string with interpolations as a Python concatenation.

        Each Expr part is processed via ``_emit_expr`` (with correct
        type dispatch, e.g., ``s.length()`` -> ``len(s)``) and wrapped
        in ``str(...)``; each literal text part is emitted with
        ``repr``. The pieces are joined with ``+``.

        We deliberately avoid an f-string here. An interpolated
        expression can itself contain a string literal or a nested
        interpolation (e.g. ``"${greet("${y}")}"``), whose emitted
        Python reuses the ``"`` quote inside the field. Embedding that
        in an f-string only parses on Python >= 3.12 (PEP 701); on the
        3.10 / 3.11 interpreters our ``pyproject`` supports it is a
        ``SyntaxError``. A ``str(...) + repr(...)`` concatenation is a
        plain expression that parses on every supported version, keeps
        each sub-expression evaluated exactly once, and produces a
        byte-identical result (Capa interpolation has no format specs,
        so ``f"{x}"`` and ``str(x)`` always agree).

        Display protocol: when an interpolated expression's type
        declares a ``fun to_string(self) -> String`` method (tracked
        in ``self._display_types`` by the pre-pass in
        ``transpile()``), the emitter wraps the expression in a
        ``.to_string()`` call instead of leaving the formatter to
        fall through to dataclass repr. Mirrors the Wasm emitter's
        FormatStr Display branch in ``_strings._emit_format_part_stash``
        so ``${p}`` produces identical output on both backends for
        any struct that opted in.
        """
        from ..typesys import TyName
        pieces: list[str] = []
        for part in e.parts:
            if isinstance(part, str):
                if part:
                    pieces.append(repr(part))
            else:
                expr_code = self._emit_expr(part)
                ty = self._interp_type(part)
                if isinstance(ty, TyName) and ty.name == "Bool":
                    # Python's f-string formats a bool as ``True`` /
                    # ``False`` (capitalised); the Wasm backend uses
                    # ``true`` / ``false`` (lowercase, matching JSON and
                    # most modern languages). Force the lowercase form
                    # here so ``${flag}`` is parity-clean across
                    # backends.
                    pieces.append(f"('true' if ({expr_code}) else 'false')")
                elif (
                    isinstance(ty, TyName)
                    and ty.name in self._display_types
                ):
                    pieces.append(f"({expr_code}).to_string()")
                else:
                    pieces.append(f"str({expr_code})")
        if not pieces:
            return "''"
        return "(" + " + ".join(pieces) + ")"

    def _emit_string_lit(self, value: str) -> str:
        """Converts a plain Capa ``StringLit`` to Python via ``repr``.

        Strings containing ``${...}`` never reach here: the parser's
        ``_build_string_lit`` routes any value with ``${`` to an
        ``InterpolatedString`` node, which is emitted by
        ``_emit_interpolated_string`` (the only place that handles the
        Bool/Display formatting rules). The assertion below pins that
        invariant so a future parser change cannot silently diverge.
        """
        assert "${" not in value, (
            "interpolated strings must go through InterpolatedString / "
            "_emit_interpolated_string, not _emit_string_lit"
        )
        return repr(value)

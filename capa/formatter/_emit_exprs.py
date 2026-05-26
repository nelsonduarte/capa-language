"""Expression and type-expression emission for the pretty-printer.

Returns each expression as a single string of Capa source. The
caller (statement mixin) is responsible for placing that string
on a line and adding the newline.

Precedence parenthesisation: a child of a binary / unary operator
gets wrapped in parens iff its own operator binds less tightly
than the parent's. Atoms (literals, identifiers, calls, indexes,
field accesses) never need parens because they bind tighter than
any operator. Match expressions and lambdas (which are not really
expression-precedence-typed) keep their existing source-level
parenthesisation by being emitted with explicit parens when
nested inside another operator.

Precedence ladder (from tightest to loosest):

  9  postfix (call, index, field, ``?``)
  8  unary (``-``, ``not``)
  7  multiplicative (``*``, ``/``, ``%``)
  6  additive (``+``, ``-``)
  5  range (``..``, ``..=``)
  4  comparison (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``)
  3  ``and``
  2  ``or``
  1  if-expression / match / lambda (loosest)

A child at precedence P is parenthesised when the parent's
required minimum precedence is > P. For non-associative
operators (comparison, range) we use ``> P`` (left and right
same precedence both wrap); for left-associative operators the
left child does not need parens.
"""

from __future__ import annotations

from .. import capa_ast as A


# Precedence of each binary operator (higher = tighter).
_BINOP_PREC = {
    "*": 7, "/": 7, "%": 7,
    "+": 6, "-": 6,
    "==": 4, "!=": 4, "<": 4, "<=": 4, ">": 4, ">=": 4,
    "and": 3,
    "or": 2,
}
_RANGE_PREC = 5
_UNARY_PREC = 8
_POSTFIX_PREC = 9
# Loosest forms (no operator at all in the surface): match expr,
# if expr, lambda. They need parens when used as a binop / range
# operand, but never when sitting at top level.
_TOP_LEVEL_PREC = 1


class _ExprsEmitterMixin:
    # ------------------------------------------------------------
    # Expression dispatch
    # ------------------------------------------------------------
    def _emit_expr(self, e: A.Expr) -> str:
        return self._emit_expr_prec(e, 0)

    def _emit_expr_prec(self, e: A.Expr, parent_prec: int) -> str:
        """Emit ``e`` and wrap in parens iff ``e``'s own precedence
        is strictly less than ``parent_prec``.
        """
        if isinstance(e, A.IntLit):
            return repr(e.value)
        if isinstance(e, A.FloatLit):
            return self._emit_float(e.value)
        if isinstance(e, A.StringLit):
            return self._emit_string_lit(e.value)
        if isinstance(e, A.InterpolatedString):
            return self._emit_interpolated_string(e)
        if isinstance(e, A.CharLit):
            return self._emit_char_lit(e.value)
        if isinstance(e, A.BoolLit):
            return "true" if e.value else "false"
        if isinstance(e, A.UnitLit):
            return "()"
        if isinstance(e, A.Ident):
            return e.name
        if isinstance(e, A.BinOp):
            return self._emit_binop(e, parent_prec)
        if isinstance(e, A.UnaryOp):
            return self._emit_unary(e, parent_prec)
        if isinstance(e, A.Call):
            return self._emit_call(e)
        if isinstance(e, A.MethodCall):
            return self._emit_method_call(e)
        if isinstance(e, A.FieldAccess):
            return self._emit_field_access(e)
        if isinstance(e, A.Index):
            return self._emit_index(e)
        if isinstance(e, A.Try):
            return self._emit_try(e)
        if isinstance(e, A.StructLit):
            return self._emit_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._emit_list_lit(e)
        if isinstance(e, A.TupleLit):
            return self._emit_tuple_lit(e)
        if isinstance(e, A.RangeExpr):
            return self._emit_range(e, parent_prec)
        if isinstance(e, A.IfExpr):
            return self._emit_if_expr(e, parent_prec)
        if isinstance(e, A.MatchExpr):
            return self._emit_match_expr_inline(e, parent_prec)
        if isinstance(e, A.LambdaExpr):
            return self._emit_lambda(e, parent_prec)
        raise AssertionError(f"unsupported expression: {type(e).__name__}")

    # ------------------------------------------------------------
    # Operators
    # ------------------------------------------------------------
    def _emit_binop(self, e: A.BinOp, parent_prec: int) -> str:
        prec = _BINOP_PREC[e.op]
        # Left-associative: left child accepts the same precedence;
        # right child must be strictly tighter to avoid parens.
        left = self._emit_expr_prec(e.left, prec)
        right = self._emit_expr_prec(e.right, prec + 1)
        # Comparison and ``or``/``and`` are non-associative in source;
        # parenthesisation above already forces parens on equal-precedence
        # right children so the output round-trips.
        out = f"{left} {e.op} {right}"
        if prec < parent_prec:
            out = f"({out})"
        return out

    def _emit_unary(self, e: A.UnaryOp, parent_prec: int) -> str:
        operand = self._emit_expr_prec(e.operand, _UNARY_PREC)
        if e.op == "not":
            out = f"not {operand}"
        else:
            # Unary minus: no space between the operator and operand.
            out = f"-{operand}"
        if _UNARY_PREC < parent_prec:
            out = f"({out})"
        return out

    def _emit_range(self, e: A.RangeExpr, parent_prec: int) -> str:
        # Range operands sit at additive precedence (one above range).
        start = self._emit_expr_prec(e.start, _RANGE_PREC + 1)
        end = self._emit_expr_prec(e.end, _RANGE_PREC + 1)
        op = "..=" if e.inclusive else ".."
        out = f"{start}{op}{end}"
        if _RANGE_PREC < parent_prec:
            out = f"({out})"
        return out

    # ------------------------------------------------------------
    # Postfix forms
    # ------------------------------------------------------------
    def _emit_call(self, e: A.Call) -> str:
        callee = self._emit_expr_prec(e.callee, _POSTFIX_PREC)
        args = self._emit_call_args(e.args, e.arg_names)
        return f"{callee}({args})"

    def _emit_method_call(self, e: A.MethodCall) -> str:
        recv = self._emit_expr_prec(e.receiver, _POSTFIX_PREC)
        args = self._emit_call_args(e.args, e.arg_names)
        return f"{recv}.{e.method}({args})"

    def _emit_field_access(self, e: A.FieldAccess) -> str:
        recv = self._emit_expr_prec(e.receiver, _POSTFIX_PREC)
        return f"{recv}.{e.field_name}"

    def _emit_index(self, e: A.Index) -> str:
        recv = self._emit_expr_prec(e.receiver, _POSTFIX_PREC)
        idx = self._emit_expr(e.index)
        return f"{recv}[{idx}]"

    def _emit_try(self, e: A.Try) -> str:
        inner = self._emit_expr_prec(e.expr, _POSTFIX_PREC)
        return f"{inner}?"

    def _emit_call_args(self, args, arg_names) -> str:
        parts: list[str] = []
        for i, a in enumerate(args):
            name = arg_names[i] if i < len(arg_names) else None
            code = self._emit_expr(a)
            if name is None:
                parts.append(code)
            else:
                parts.append(f"{name}: {code}")
        return ", ".join(parts)

    # ------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------
    def _emit_struct_lit(self, e: A.StructLit) -> str:
        head = e.type_name
        if e.type_args:
            head += "<" + ", ".join(
                self._emit_type(t) for t in e.type_args
            ) + ">"
        if not e.fields:
            return f"{head} {{}}"
        parts = [f"{fname}: {self._emit_expr(fexpr)}" for (fname, fexpr) in e.fields]
        return f"{head} {{ {', '.join(parts)} }}"

    def _emit_list_lit(self, e: A.ListLit) -> str:
        return "[" + ", ".join(self._emit_expr(x) for x in e.elements) + "]"

    def _emit_tuple_lit(self, e: A.TupleLit) -> str:
        if not e.elements:
            return "()"
        if len(e.elements) == 1:
            return f"({self._emit_expr(e.elements[0])},)"
        return "(" + ", ".join(self._emit_expr(x) for x in e.elements) + ")"

    # ------------------------------------------------------------
    # Control-flow expressions
    # ------------------------------------------------------------
    def _emit_if_expr(self, e: A.IfExpr, parent_prec: int) -> str:
        cond = self._emit_expr_prec(e.cond, _TOP_LEVEL_PREC + 1)
        then_e = self._emit_expr_prec(e.then_expr, _TOP_LEVEL_PREC + 1)
        else_e = self._emit_expr_prec(e.else_expr, _TOP_LEVEL_PREC)
        out = f"if {cond} then {then_e} else {else_e}"
        if _TOP_LEVEL_PREC < parent_prec:
            out = f"({out})"
        return out

    def _emit_match_expr_inline(self, e: A.MatchExpr, parent_prec: int) -> str:
        """Emit a match expression as the inline form.

        Reached when ``match`` sits inside another expression
        (a binop operand, a struct-literal field value, a call
        arg). The multi-line form requires its own statement
        line and cannot be embedded; the inline form is the only
        survivable shape here.

        For arm bodies that are blocks (multi-statement), the
        inline form is not expressible; we fall back to a
        ``match`` expression but the result will be a parse
        error if the arm contains a block. In practice the
        parser only ever produces inline-shape match expressions
        for arms with single-expr bodies, so this branch is
        safe for inputs that originally parsed.
        """
        # Build inline arms: ``pat [if guard] -> expr``.
        arm_strs: list[str] = []
        for arm in e.arms:
            pat = self._emit_pattern_match(arm.pattern)
            head = pat
            if arm.guard is not None:
                head += f" if {self._emit_expr(arm.guard)}"
            if isinstance(arm.body, A.Block):
                # Block bodies are not expressible inline. The
                # nearest fallback is to wrap the block in a unit
                # expression so the output at least lexes. This
                # path is unreachable for inputs parsed from
                # source because the parser never produces an
                # inline match with a Block body.
                body_str = "()"
            else:
                body_str = self._emit_expr(arm.body)
            arm_strs.append(f"{head} -> {body_str}")
        scrut = self._emit_expr_prec(e.scrutinee, _POSTFIX_PREC)
        out = f"match {scrut} {{ {', '.join(arm_strs)} }}"
        if _TOP_LEVEL_PREC < parent_prec:
            out = f"({out})"
        return out

    def _emit_lambda(self, e: A.LambdaExpr, parent_prec: int) -> str:
        params = self._emit_lambda_params(e.params)
        head = f"fun ({params})"
        if e.return_type is not None:
            head += f" -> {self._emit_type(e.return_type)}"
        if isinstance(e.body, A.Block):
            # Block-body lambdas cannot appear inside ``(...)``
            # in the source language (the lexer suppresses
            # NEWLINE there). The parser still accepts them at
            # the statement level via an indented body. Emitting
            # the body would require multi-line output, but
            # ``_emit_expr`` returns a single string for use in
            # an expression position. The few real corpus uses
            # of block-body lambdas occur on the RHS of a `let`
            # at statement level; the statement-level let
            # emitter calls _emit_expr expecting a single string.
            # We render the body as a synthetic indented block
            # written by a sub-emitter and return the
            # multi-line text. The caller's ``_indent()`` has
            # already been written so the first line of our
            # output sits at the right column; subsequent lines
            # carry their own indentation prefix relative to the
            # block's start column.
            body_text = self._emit_lambda_block_body(e.body)
            out = f"{head} =>\n{body_text}"
        else:
            body_str = self._emit_expr(e.body)
            out = f"{head} => {body_str}"
        if _TOP_LEVEL_PREC < parent_prec:
            out = f"({out})"
        return out

    def _emit_lambda_params(self, params: list[A.Param]) -> str:
        out: list[str] = []
        for p in params:
            if p.name == "self" and p.type_expr is None:
                out.append("self")
                continue
            prefix = "consume " if p.consuming else ""
            if p.type_expr is None:
                out.append(f"{prefix}{p.name}")
            else:
                out.append(
                    f"{prefix}{p.name}: {self._emit_type(p.type_expr)}"
                )
        return ", ".join(out)

    def _emit_lambda_block_body(self, block: A.Block) -> str:
        """Render a lambda block body as multi-line text.

        Spawns a fresh emitter at the current indent depth + 1 so
        the block statements have the right leading whitespace.
        Returns the joined text (with a trailing newline absent),
        because the caller embeds it after ``=>\\n``.
        """
        from ._emit import _Emitter
        sub = _Emitter(cmap=self._cmap)
        sub._depth = self._depth + 1
        sub._emit_block_body(block)
        # The sub-emitter ends with a trailing newline; trim it so
        # the parent's `_newline()` does not produce a blank line.
        text = "".join(sub._buf)
        if text.endswith("\n"):
            text = text[:-1]
        return text

    # ------------------------------------------------------------
    # Literals
    # ------------------------------------------------------------
    def _emit_float(self, v: float) -> str:
        # repr() gives the shortest round-tripping form. For
        # values that print as integers (e.g. 1.0), Python's repr
        # already includes ".0", which is what Capa needs to keep
        # the float type (otherwise the lexer treats it as an
        # integer).
        s = repr(v)
        if "." not in s and "e" not in s and "E" not in s and "n" not in s:
            s += ".0"
        return s

    def _emit_char_lit(self, v: str) -> str:
        # Capa char literals are single-quoted, with the same
        # escape repertoire as string literals.
        ch = v
        if ch == "'":
            return "'\\''"
        if ch == "\\":
            return "'\\\\'"
        if ch == "\n":
            return "'\\n'"
        if ch == "\t":
            return "'\\t'"
        if ch == "\r":
            return "'\\r'"
        if ch == "\0":
            return "'\\0'"
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            return f"'\\u{{{ord(ch):x}}}'"
        return f"'{ch}'"

    def _emit_string_lit(self, value: str) -> str:
        """Emit a non-interpolated string literal."""
        return '"' + _escape_for_string(value) + '"'

    def _emit_interpolated_string(self, e: A.InterpolatedString) -> str:
        """Reconstruct a ``"text${expr}text"`` literal from the AST.

        ``e.parts`` alternates ``str`` (literal text) and ``Expr``
        (interpolation contents). We escape each literal segment
        the same way as for a plain string, then re-emit each
        expression segment via ``_emit_expr`` and wrap it in
        ``${...}``. Literal ``$`` inside a text segment is escaped
        as ``$$`` so it does not introduce a fake interpolation.

        The expression body inside ``${...}`` is parsed as Capa
        but copied verbatim back into the string literal during
        re-lexing; any ``"`` character it contains would
        therefore terminate the outer literal. To keep the round-
        trip honest, we escape ``"`` and ``\\`` inside the
        rendered expression too. The lexer, on re-reading,
        unescapes them before sub-lexing the interpolation, so
        the resulting AST sees the original expression text.
        """
        out = ['"']
        for part in e.parts:
            if isinstance(part, str):
                # Inside a string body, escape ``$`` so that a
                # literal ``$`` doesn't introduce a fake
                # interpolation when the result is re-lexed.
                out.append(_escape_for_string(part).replace("$", "$$"))
            else:
                inner = self._emit_expr(part)
                # Escape characters that would close the outer
                # string before the lexer reaches the matching
                # ``}``. Backslash MUST come first; doubling it
                # later would corrupt other escapes.
                inner = inner.replace("\\", "\\\\").replace('"', '\\"')
                out.append("${" + inner + "}")
        out.append('"')
        return "".join(out)

    # ------------------------------------------------------------
    # Type expressions
    # ------------------------------------------------------------
    def _emit_type(self, t: A.TypeExpr) -> str:
        if isinstance(t, A.TypeName):
            if not t.args:
                return t.name
            args = ", ".join(self._emit_type(a) for a in t.args)
            return f"{t.name}<{args}>"
        if isinstance(t, A.FunType):
            params = ", ".join(self._emit_type(p) for p in t.param_types)
            return f"Fun({params}) -> {self._emit_type(t.return_type)}"
        if isinstance(t, A.TupleType):
            inner = ", ".join(self._emit_type(p) for p in t.elements)
            # A tuple type with one element is not currently
            # produced by the parser (single-element parens are
            # treated as grouping); emit canonical form anyway.
            if len(t.elements) == 1:
                return f"({inner},)"
            return f"({inner})"
        if isinstance(t, A.UnitType):
            return "()"
        raise AssertionError(f"unsupported type expression: {type(t).__name__}")


# ----------------------------------------------------------------
# Free helpers
# ----------------------------------------------------------------
def _escape_for_string(value: str) -> str:
    """Escape ``value`` for inclusion in a Capa double-quoted string.

    Capa's escape repertoire (per ``capa/lexer/_literals.py``):
    ``\\n``, ``\\r``, ``\\t``, ``\\\\``, ``\\"``, ``\\'``, ``\\0``,
    and the generic ``\\u{HEX}``. The C-style octal ``\\033`` is
    NOT supported (the lexer rejects ``\\0`` followed by a digit),
    so for the ESC byte and any other control character outside
    the named set we use ``\\u{HEX}``.

    Non-ASCII characters are emitted as themselves (the source is
    UTF-8), matching the example corpus's convention.
    """
    out: list[str] = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\0":
            out.append("\\0")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    return "".join(out)

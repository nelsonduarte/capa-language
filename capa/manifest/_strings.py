"""AST-to-string helpers used by the manifest layers.

The manifest is meant for humans (and CI tooling that prints it),
not for round-tripping back into AST. These functions render an
``Expr`` or ``TypeExpr`` as a short source-like fragment, with
truncation on overly long results.

- ``_stringify_expr`` / ``_stringify_expr_full``: expression
  rendering, with truncation in the public ``_stringify_expr``.
- ``_quote_string``: Capa-style double-quoted literal with the
  obvious escape rules.
- ``_ty_text``: render a ``TypeExpr`` (kept aligned with
  ``typesys.ty_str`` for built-in cases).
- ``_root_type_name``: head name of a type, or ``None`` if the
  type is not a plain ``TypeName``.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A


# Maximum length for a stringified call-site argument before it gets
# truncated in the manifest. Pure aesthetics, avoids blowing up the
# JSON when a program passes a long string literal or a complex
# lambda as an argument. The truncated form ends with "..." so it is
# obvious to the reader that a manifest is not the source of truth.
_MAX_ARG_REPR = 80


def _stringify_expr(e) -> str:
    """Render an expression as a short source-like string for the
    manifest. Truncates at ``_MAX_ARG_REPR`` chars with an ellipsis.
    Designed for human-readable manifest output, not round-tripping.
    """
    s = _stringify_expr_full(e)
    if len(s) > _MAX_ARG_REPR:
        s = s[: _MAX_ARG_REPR - 3] + "..."
    return s


def _stringify_expr_full(e) -> str:
    if e is None:
        return ""
    if isinstance(e, A.Ident):
        return e.name
    if isinstance(e, A.IntLit):
        return str(e.value)
    if isinstance(e, A.FloatLit):
        return repr(e.value)
    if isinstance(e, A.StringLit):
        return _quote_string(e.value)
    if isinstance(e, A.InterpolatedString):
        # Approximate. The parts list alternates str literals and
        # expressions; show "${...}" for the expression slots so the
        # reader sees something interpolated without long bodies.
        out = []
        for p in e.parts:
            if isinstance(p, str):
                out.append(p)
            else:
                out.append("${...}")
        return _quote_string("".join(out))
    if isinstance(e, A.CharLit):
        return f"'{e.value}'"
    if isinstance(e, A.BoolLit):
        return "true" if e.value else "false"
    if isinstance(e, A.UnitLit):
        return "()"
    if isinstance(e, A.BinOp):
        return f"{_stringify_expr_full(e.left)} {e.op} {_stringify_expr_full(e.right)}"
    if isinstance(e, A.UnaryOp):
        sep = " " if e.op.isalpha() else ""
        return f"{e.op}{sep}{_stringify_expr_full(e.operand)}"
    if isinstance(e, A.Call):
        callee = _stringify_expr_full(e.callee)
        args = ", ".join(_stringify_expr_full(a) for a in e.args)
        return f"{callee}({args})"
    if isinstance(e, A.MethodCall):
        recv = _stringify_expr_full(e.receiver)
        args = ", ".join(_stringify_expr_full(a) for a in e.args)
        return f"{recv}.{e.method}({args})"
    if isinstance(e, A.FieldAccess):
        return f"{_stringify_expr_full(e.receiver)}.{e.field_name}"
    if isinstance(e, A.Index):
        return f"{_stringify_expr_full(e.receiver)}[{_stringify_expr_full(e.index)}]"
    if isinstance(e, A.Try):
        return f"{_stringify_expr_full(e.expr)}?"
    if isinstance(e, A.ListLit):
        return "[" + ", ".join(_stringify_expr_full(x) for x in e.elements) + "]"
    if isinstance(e, A.TupleLit):
        return "(" + ", ".join(_stringify_expr_full(x) for x in e.elements) + ")"
    if isinstance(e, A.StructLit):
        body = ", ".join(
            f"{k}: {_stringify_expr_full(v)}" for k, v in e.fields
        )
        return f"{e.type_name} {{ {body} }}"
    if isinstance(e, A.RangeExpr):
        op = "..=" if e.inclusive else ".."
        return f"{_stringify_expr_full(e.start)}{op}{_stringify_expr_full(e.end)}"
    if isinstance(e, A.LambdaExpr):
        return "fun(...) => ..."
    if isinstance(e, A.IfExpr):
        return f"if {_stringify_expr_full(e.cond)} then ... else ..."
    if isinstance(e, A.MatchExpr):
        return f"match {_stringify_expr_full(e.scrutinee)} {{ ... }}"
    return f"<{type(e).__name__}>"


def _quote_string(s: str) -> str:
    """Render a Python string as a Capa-style double-quoted literal,
    escaping the obvious problem characters. Used only for the
    manifest representation; we are not round-tripping source."""
    escaped = (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _ty_text(t: Optional[A.TypeExpr]) -> str:
    """Render a ``TypeExpr`` to source-style text.

    The manifest stores types as strings so that downstream consumers
    (CI gates, SBOM tooling, dashboards) do not need to know Capa's
    internal type representation. Keep this aligned with ``ty_str``
    in ``typesys.py`` for built-in cases.
    """
    if t is None:
        return "()"
    if isinstance(t, A.TypeName):
        if not t.args:
            return t.name
        return f"{t.name}<{', '.join(_ty_text(a) for a in t.args)}>"
    if isinstance(t, A.FunType):
        params = ", ".join(_ty_text(p) for p in t.param_types)
        return f"Fun({params}) -> {_ty_text(t.return_type)}"
    if isinstance(t, A.TupleType):
        return f"({', '.join(_ty_text(e) for e in t.elements)})"
    if isinstance(t, A.UnitType):
        return "()"
    return f"<{type(t).__name__}>"


def _root_type_name(t: Optional[A.TypeExpr]) -> Optional[str]:
    """Return the head name of a type, or None if it is not a TypeName."""
    if isinstance(t, A.TypeName):
        return t.name
    return None

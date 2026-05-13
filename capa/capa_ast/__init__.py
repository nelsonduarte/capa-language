"""Abstract syntax tree (AST) of the Capa language.

Each node has an associated position (the ``pos`` field) that
points to the start of the construct in the source, useful for
type-checker error messages and for IDE tooling.

Design conventions:

- All nodes inherit from :class:`Node` and use ``@dataclass(kw_only=True)``
  to avoid field-ordering issues with defaults across the hierarchy.
- Abstract categories (:class:`Item`, :class:`Stmt`, :class:`Expr`,
  :class:`Pattern`, :class:`TypeExpr`) are only for typing; they have
  no fields of their own beyond ``pos``.
- Empty lists are preferred over None for fields like type_params, args.
- None is used for genuine semantic optionality (no return type, no
  guard in a match arm, etc.).

The node classes are split across submodules by category:

- :mod:`._base` - the abstract category markers and :class:`Node`.
- :mod:`._items` - :class:`Module` and every top-level declaration.
- :mod:`._stmts` - :class:`Block` and every statement.
- :mod:`._exprs` - every expression form, including
  :class:`MatchArm`, :class:`MatchExpr`, :class:`IfExpr`,
  :class:`RangeExpr`, and :class:`LambdaExpr`.
- :mod:`._patterns` - every pattern.
- :mod:`._types` - every type expression.

The full set is re-exported here so that existing
``from capa import capa_ast as A`` users keep finding every name
(``A.FunDecl``, ``A.MatchExpr``, etc.) at the same place.
"""

from __future__ import annotations

from ._base import Expr, Item, Node, Pattern, Stmt, TypeExpr
from ._exprs import (
    BinOp,
    BoolLit,
    Call,
    CharLit,
    FieldAccess,
    FloatLit,
    Ident,
    IfExpr,
    Index,
    IntLit,
    InterpolatedString,
    LambdaExpr,
    ListLit,
    MatchArm,
    MatchExpr,
    MethodCall,
    RangeExpr,
    StringLit,
    StructLit,
    TupleLit,
    Try,
    UnaryOp,
    UnitLit,
)
from ._items import (
    Attribute,
    ConstDecl,
    Field,
    FunDecl,
    ImplBlock,
    Import,
    MethodSig,
    Module,
    Param,
    TraitDecl,
    TypeStruct,
    TypeSum,
    Variant,
)
from ._patterns import (
    IdentPat,
    LiteralPat,
    OrPat,
    Pattern,
    StructPat,
    TuplePat,
    VariantPat,
    WildcardPat,
)
from ._stmts import (
    AssignStmt,
    Block,
    BreakStmt,
    ContinueStmt,
    ExprStmt,
    ForStmt,
    IfStmt,
    LetStmt,
    ReturnStmt,
    VarStmt,
    WhileStmt,
)
from ._types import FunType, TupleType, TypeName, UnitType


# ===========================================================
# Pretty-printing utility (debug / CLI)
# ===========================================================


def dump(node, indent: int = 0) -> str:
    """Returns a multi-line representation of the AST, useful for debugging."""
    pad = "  " * indent
    if isinstance(node, list):
        if not node:
            return "[]"
        body = "\n".join(pad + "  - " + dump(n, indent + 1).lstrip() for n in node)
        return f"[\n{body}\n{pad}]"
    if not isinstance(node, Node):
        return repr(node)
    cls = type(node).__name__
    fields_repr = []
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name)
        if v is None or v == [] or v is False:
            # Omit empty defaults to avoid clutter.
            continue
        fields_repr.append((f.name, v))
    if not fields_repr:
        return f"{cls}"
    parts = []
    for name, v in fields_repr:
        if isinstance(v, list) and v and isinstance(v[0], Node):
            parts.append(f"{pad}  {name}={dump(v, indent + 1)}")
        elif isinstance(v, Node):
            parts.append(f"{pad}  {name}={dump(v, indent + 1)}")
        else:
            parts.append(f"{pad}  {name}={v!r}")
    return f"{cls}(\n" + "\n".join(parts) + f"\n{pad})"

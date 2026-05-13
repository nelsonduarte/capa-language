"""Expression AST nodes.

Grouped here regardless of precedence or surface category so that
all value-producing forms live in one file. The pattern matcher
(:class:`MatchArm`) is included because each arm is a Node that
combines a pattern with an expression or block body.

Subgroups:

- literals and identifiers (:class:`IntLit`, :class:`FloatLit`,
  :class:`StringLit`, :class:`InterpolatedString`, :class:`CharLit`,
  :class:`BoolLit`, :class:`UnitLit`, :class:`Ident`);
- operators (:class:`BinOp`, :class:`UnaryOp`);
- postfix forms (:class:`Call`, :class:`MethodCall`,
  :class:`FieldAccess`, :class:`Index`, :class:`Try`);
- aggregates (:class:`StructLit`, :class:`ListLit`,
  :class:`TupleLit`, :class:`LambdaExpr`);
- control-flow expressions (:class:`IfExpr`, :class:`MatchExpr`,
  :class:`MatchArm`, :class:`RangeExpr`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ._base import Expr, Node

if TYPE_CHECKING:
    from ._items import Param
    from ._patterns import Pattern
    from ._stmts import Block
    from ._types import TypeExpr


# -----------------------------------------------------------
# Literals and identifiers
# -----------------------------------------------------------


@dataclass(kw_only=True)
class IntLit(Expr):
    value: int


@dataclass(kw_only=True)
class FloatLit(Expr):
    value: float


@dataclass(kw_only=True)
class StringLit(Expr):
    value: str


@dataclass(kw_only=True)
class InterpolatedString(Expr):
    """String literal with ``${expr}`` interpolations.

    ``parts`` alternates literal text (``str``) and expressions (``Expr``).
    Empty text is allowed but redundant. For example,
    ``"a${x}b"`` produces ``parts=["a", Ident("x"), "b"]``;
    ``"${x}${y}"`` produces ``parts=["", Ident("x"), "", Ident("y"), ""]``.
    """
    parts: list  # list[str | Expr]


@dataclass(kw_only=True)
class CharLit(Expr):
    value: str


@dataclass(kw_only=True)
class BoolLit(Expr):
    value: bool


@dataclass(kw_only=True)
class UnitLit(Expr):
    """The () expression of type Unit."""
    pass


@dataclass(kw_only=True)
class Ident(Expr):
    name: str


# -----------------------------------------------------------
# Operators
# -----------------------------------------------------------


@dataclass(kw_only=True)
class BinOp(Expr):
    op: str
    left: Expr
    right: Expr


@dataclass(kw_only=True)
class UnaryOp(Expr):
    op: str  # 'not', '-'
    operand: Expr


# -----------------------------------------------------------
# Postfix forms
# -----------------------------------------------------------


@dataclass(kw_only=True)
class Call(Expr):
    callee: Expr
    type_args: list[TypeExpr] = field(default_factory=list)  # turbofish ::<T>
    args: list[Expr]
    # Parallel to `args`. None for positional arguments; the parameter
    # name (a str) for named arguments such as ``f(age: 30)``. All
    # None when no named arguments are used. Per the EBNF, positional
    # arguments must all come before any named argument.
    arg_names: list[Optional[str]] = field(default_factory=list)


@dataclass(kw_only=True)
class MethodCall(Expr):
    receiver: Expr
    method: str
    type_args: list[TypeExpr] = field(default_factory=list)
    args: list[Expr]
    arg_names: list[Optional[str]] = field(default_factory=list)


@dataclass(kw_only=True)
class FieldAccess(Expr):
    receiver: Expr
    field_name: str


@dataclass(kw_only=True)
class Index(Expr):
    receiver: Expr
    index: Expr


@dataclass(kw_only=True)
class Try(Expr):
    """expr?, propagates the error if it is Err."""
    expr: Expr


# -----------------------------------------------------------
# Aggregates
# -----------------------------------------------------------


@dataclass(kw_only=True)
class StructLit(Expr):
    """Type { field: value, ... }"""
    type_name: str
    type_args: list[TypeExpr] = field(default_factory=list)
    fields: list[tuple[str, Expr]]


@dataclass(kw_only=True)
class ListLit(Expr):
    elements: list[Expr]


@dataclass(kw_only=True)
class TupleLit(Expr):
    """Tuple with 0+ elements. (1,) is a 1-tuple, () is unit."""
    elements: list[Expr]


@dataclass(kw_only=True)
class LambdaExpr(Expr):
    """Closure (lambda expression): ``fun (params) -> Ret => body``.

    The body can be:
    - A single expression (single-expr): ``fun (x) => x + 1``
    - An indented block (multi-line): ``fun (x) =>\\n    ...\\n    return x``

    A block body allows multiple statements and explicit returns.
    Without ``return``, a block-body returns ``Unit``.
    """
    params: list[Param]
    return_type: Optional[TypeExpr] = None
    body: "Expr | Block"


# -----------------------------------------------------------
# Control-flow expressions
# -----------------------------------------------------------


@dataclass(kw_only=True)
class MatchArm(Node):
    """A match arm: pattern (if guard)? -> body

    body is an expression (common case, single-line) or a Block (multi-line).
    When match is used as an expression, an Expr body produces the value
    of the arm; a Block body produces Unit (unless it ends in return).
    """
    pattern: Pattern
    guard: Optional[Expr] = None
    body: "Block | Expr"  # Block for multi-line arms, Expr for single-line


@dataclass(kw_only=True)
class MatchExpr(Expr):
    """``match`` as an expression. In statement context, it is wrapped in
    ``ExprStmt``; in expression context (RHS of let/var, return, etc.),
    the value of each arm with an expression body becomes the match value."""
    scrutinee: Expr
    arms: list[MatchArm]


@dataclass(kw_only=True)
class IfExpr(Expr):
    """``if cond then e1 else e2``, Capa ternary operator.

    Inline syntax for choosing a value between two expressions. Useful
    in single-line closures and in the RHS of let/var. The two branches
    must have compatible types. ``elif`` is not supported in this form -
    use match or an if-statement instead.
    """
    cond: Expr
    then_expr: Expr
    else_expr: Expr


@dataclass(kw_only=True)
class RangeExpr(Expr):
    """A range expression: ``a..b`` (exclusive of ``b``) or ``a..=b``
    (inclusive of ``b``). v1 supports only integer endpoints; the value
    has type ``List<Int>`` (materialised) so all List methods apply.
    """
    start: Expr
    end: Expr
    inclusive: bool  # True for ..=, False for ..

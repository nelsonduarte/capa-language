"""Statement AST nodes plus the :class:`Block` wrapper.

A ``Block`` is the body of a function, an ``if`` / ``while`` /
``for`` branch, or a multi-line ``match`` arm.

Statement forms:

- bindings: :class:`LetStmt`, :class:`VarStmt`.
- assignment: :class:`AssignStmt` (with the operator on the field
  ``op``).
- control flow: :class:`IfStmt`, :class:`WhileStmt`, :class:`ForStmt`,
  :class:`BreakStmt`, :class:`ContinueStmt`, :class:`ReturnStmt`.
- :class:`ExprStmt` - an expression evaluated for effect (typically
  a call). Wrapping ``match`` in an ``ExprStmt`` is how a match used
  as a statement reaches the analyzer / transpiler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ..tokens import Pos
from ._base import Expr, Node, Stmt

if TYPE_CHECKING:
    from ._patterns import Pattern
    from ._types import TypeExpr


@dataclass(kw_only=True)
class Block(Node):
    """Indented sequence of statements."""
    stmts: list[Stmt]


@dataclass(kw_only=True)
class LetStmt(Stmt):
    """let pattern: T = value   (T optional)"""
    pattern: Pattern
    type_expr: Optional[TypeExpr] = None
    value: Expr


@dataclass(kw_only=True)
class VarStmt(Stmt):
    """var name: T = value   (mutable)"""
    name: str
    type_expr: Optional[TypeExpr] = None
    value: Expr
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class AssignStmt(Stmt):
    """target op= value, where target is ident, field access or index."""
    target: Expr
    op: str  # '=', '+=', '-=', '*=', '/=', '%='
    value: Expr


@dataclass(kw_only=True)
class IfStmt(Stmt):
    cond: Expr
    then_block: Block
    elif_arms: list[tuple[Expr, Block]] = field(default_factory=list)
    else_block: Optional[Block] = None


@dataclass(kw_only=True)
class WhileStmt(Stmt):
    cond: Expr
    body: Block


@dataclass(kw_only=True)
class ForStmt(Stmt):
    pattern: Pattern
    iter: Expr
    body: Block


@dataclass(kw_only=True)
class ReturnStmt(Stmt):
    value: Optional[Expr] = None


@dataclass(kw_only=True)
class BreakStmt(Stmt):
    pass


@dataclass(kw_only=True)
class ContinueStmt(Stmt):
    pass


@dataclass(kw_only=True)
class ExprStmt(Stmt):
    """Expression used as a statement (typically, a function call)."""
    expr: Expr

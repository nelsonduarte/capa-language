"""Base AST categories: :class:`Node` and the abstract category
markers (:class:`Item`, :class:`Stmt`, :class:`Expr`, :class:`Pattern`,
:class:`TypeExpr`).

Concrete node classes live in the per-category submodules; they
inherit from the markers here.

Every node carries a :class:`Pos` pointing at its starting token,
used by the type checker for error reporting and by the LSP layer
for IDE features.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..tokens import Pos


@dataclass(kw_only=True)
class Node:
    """Base of the entire AST hierarchy. `pos` points to the starting token."""
    pos: Pos


@dataclass(kw_only=True)
class Item(Node):
    """Top-level declaration: import, type, trait, impl, fun, const."""
    pass


@dataclass(kw_only=True)
class Stmt(Node):
    """Statement inside a block."""
    pass


@dataclass(kw_only=True)
class Expr(Node):
    """Value-producing expression."""
    pass


@dataclass(kw_only=True)
class Pattern(Node):
    """Pattern used in let, for and match arms."""
    pass


@dataclass(kw_only=True)
class TypeExpr(Node):
    """Type expression (annotations, returns, generic parameters)."""
    pass

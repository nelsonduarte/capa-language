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

from dataclasses import dataclass, field
from typing import Optional

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
class LinkedName:
    """The source name of a declaration the module loader may rename.

    Mixed into every node that declares a module-scope name (the named
    top-level items and the variants of a sum type). The loader sets these
    when it RENAMES such a declaration while linking (privacy mangling, a
    selective import hiding it or binding it under an ``as`` alias), so
    the analyzer still sees the names the author wrote:

    - ``declared_name``: the name at the declaration (``None`` while the
      node still carries it);
    - ``alias_pos``: the position of the ``as`` alias in the
      ``import ... (x as y)`` selector that bound the current name
      (``None`` when no alias did).

    Read by the reserved built-in name rule
    (``capa._builtin_identity.item_declarations``)."""
    declared_name: Optional[str] = field(
        default=None, repr=False, compare=False,
    )
    alias_pos: Optional[Pos] = field(default=None, repr=False, compare=False)


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
    """Type expression (annotations, returns, generic parameters).

    ``label`` carries an optional information-flow security label
    written before the type (``@secret String``, ``@public Int``) --
    roadmap S2. ``None`` means unlabelled, which the analyzer treats
    as ``@public`` (the lattice bottom). The label lives on the base
    so every type form (named, function, tuple, unit) can be
    labelled uniformly."""
    label: "str | None" = None

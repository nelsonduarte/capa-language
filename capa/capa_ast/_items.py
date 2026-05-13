"""Top-level item AST nodes and the :class:`Module` wrapper.

Items are anything that may appear at the top level of a Capa file:

- :class:`Module` - the file as a whole.
- :class:`Import` - currently parsed but rejected by the analyzer in
  v1 (kept here so future module-system work can flip on).
- :class:`ConstDecl` - a typed top-level constant.
- :class:`TypeStruct` / :class:`TypeSum` - the two ``type``
  flavours; sums also need :class:`Variant`.
- :class:`Field` - a struct member.
- :class:`TraitDecl` - both ``trait`` and ``capability`` (the
  ``is_capability`` flag distinguishes them). Method shape is
  declared by :class:`MethodSig`.
- :class:`Param` - parameter shared by ``FunDecl``, ``MethodSig``,
  and ``LambdaExpr``.
- :class:`Attribute` - ``@name(...)`` metadata attached to
  functions.
- :class:`FunDecl` - top-level or impl-method function definition.
- :class:`ImplBlock` - inherent or trait-implementing ``impl``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ..tokens import Pos
from ._base import Item, Node

if TYPE_CHECKING:
    from ._exprs import Expr
    from ._stmts import Block
    from ._types import TypeExpr


@dataclass(kw_only=True)
class Module(Node):
    """A Capa file is a Module."""
    items: list[Item]


@dataclass(kw_only=True)
class Import(Item):
    """import X            -> path=['X'], alias=None
    import X.Y          -> path=['X','Y'], alias=None
    import X as Z       -> path=['X'], alias='Z'
    """
    path: list[str]
    alias: Optional[str] = None


@dataclass(kw_only=True)
class ConstDecl(Item):
    name: str
    type_expr: TypeExpr
    value: Expr
    is_pub: bool = False
    # Position of the ``name`` IDENT token specifically (vs ``pos``
    # which points at the start of the declaration as a whole).
    # Used by LSP features (hover, definition, references, rename)
    # to identify the cursor's intent when it sits on a declaration
    # site, and to compute precise ranges for token-shaped fixes.
    # ``None`` means the parser did not record it (older code paths,
    # synthetic AST in tests).
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class Field(Node):
    """Field of a struct."""
    name: str
    type_expr: TypeExpr
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class TypeStruct(Item):
    """type Name { field: T, ... }"""
    name: str
    type_params: list[str] = field(default_factory=list)
    fields: list[Field]
    is_pub: bool = False
    doc: Optional[str] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class Variant(Node):
    """Variant of a sum type; payload optional."""
    name: str
    payload: Optional[TypeExpr] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class TypeSum(Item):
    """type Name =
        Variant1
        Variant2(T)
    """
    name: str
    type_params: list[str] = field(default_factory=list)
    variants: list[Variant]
    is_pub: bool = False
    doc: Optional[str] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class Param(Node):
    """Function or method parameter.

    For `self`, name='self' and type_expr=None.
    `consuming=True` indicates that the function consumes the argument (moves ownership).
    """
    name: str
    type_expr: Optional[TypeExpr] = None
    consuming: bool = False
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class MethodSig(Node):
    """Method signature inside a trait."""
    name: str
    type_params: list[str] = field(default_factory=list)
    params: list[Param]
    return_type: Optional[TypeExpr] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class TraitDecl(Item):
    """A trait declaration. If ``is_capability`` is True, the declaration
    used the ``capability`` keyword instead of ``trait``: the declared
    name is registered as a capability (subject to the capability
    discipline), and types that implement it can be used as receivers
    of capability-typed parameters.
    """
    name: str
    type_params: list[str] = field(default_factory=list)
    methods: list[MethodSig]
    is_pub: bool = False
    is_capability: bool = False
    doc: Optional[str] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class Attribute(Node):
    """A function attribute: ``@name(key: "value", key: "value")``.

    Attributes are static metadata, surfaced in machine-readable form
    by the ``--manifest`` output for CRA-style auditing. v1 attributes
    are limited to a fixed set of names (``security``, ``deprecated``,
    ``audited``) and their arguments must be string literals.
    """
    name: str
    args: list[tuple[str, str]] = field(default_factory=list)


@dataclass(kw_only=True)
class FunDecl(Item):
    """Function declaration (top-level or method inside an impl)."""
    name: str
    type_params: list[str] = field(default_factory=list)
    params: list[Param]
    return_type: Optional[TypeExpr] = None
    body: Block
    is_pub: bool = False
    attributes: list[Attribute] = field(default_factory=list)
    doc: Optional[str] = None
    name_pos: Optional[Pos] = None


@dataclass(kw_only=True)
class ImplBlock(Item):
    """impl Trait for Type<...>   or   impl Type<...>"""
    trait_name: Optional[str]   # None = inherent impl
    type_name: str
    type_args: list[TypeExpr] = field(default_factory=list)
    methods: list[FunDecl]

"""Type expressions used in annotations, return types, and generic
arguments.

- :class:`TypeName` - a named type with optional generic args
  (``List<Int>``, ``Result<T, E>``, ``Self``).
- :class:`FunType` - a function type (``Fun(T, U) -> R``).
- :class:`TupleType` - a tuple type (``(T, U)``).
- :class:`UnitType` - the ``()`` type, distinct from the empty tuple
  type even though they print the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import TypeExpr


@dataclass(kw_only=True)
class TypeName(TypeExpr):
    """Type name, possibly with generic arguments."""
    name: str
    args: list[TypeExpr] = field(default_factory=list)


@dataclass(kw_only=True)
class FunType(TypeExpr):
    """fun(T1, T2) -> T3"""
    param_types: list[TypeExpr]
    return_type: TypeExpr


@dataclass(kw_only=True)
class TupleType(TypeExpr):
    elements: list[TypeExpr]


@dataclass(kw_only=True)
class UnitType(TypeExpr):
    """The Unit type, written ()."""
    pass

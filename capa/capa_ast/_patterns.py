"""Pattern AST nodes used in ``let``, ``for``, ``var`` bindings and
``match`` arms.

- :class:`WildcardPat` - the ``_`` pattern.
- :class:`IdentPat` - binds the matched value to a name.
- :class:`LiteralPat` - matches a specific literal value.
- :class:`VariantPat` - sum-type variant, optionally with a nested
  payload pattern.
- :class:`StructPat` - struct deconstruction.
- :class:`TuplePat` - tuple deconstruction; ``()`` matches ``Unit``.
- :class:`OrPat` - alternative patterns; bindings inside alternatives
  are intentionally restricted in v0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ._base import Expr, Pattern


@dataclass(kw_only=True)
class WildcardPat(Pattern):
    """_"""
    pass


@dataclass(kw_only=True)
class IdentPat(Pattern):
    """Binds the value to a name."""
    name: str


@dataclass(kw_only=True)
class LiteralPat(Pattern):
    """Literal pattern (int, float, string, char, bool)."""
    value: Expr


@dataclass(kw_only=True)
class VariantPat(Pattern):
    """Sum-type variant with optional payload.

    Red             -> name='Red', payload=None
    Some(x)         -> name='Some', payload=IdentPat('x')
    Some(Red)       -> name='Some', payload=VariantPat('Red', None)
    """
    name: str
    payload: Optional[Pattern] = None


@dataclass(kw_only=True)
class StructPat(Pattern):
    """Type { field: pat, ... }   (just `field` is shorthand for `field: field`)"""
    type_name: str
    fields: list[tuple[str, Optional[Pattern]]]


@dataclass(kw_only=True)
class TuplePat(Pattern):
    """``(pat1, pat2, ...)``, deconstructs a tuple into its components.

    Each element is itself a pattern, allowing nesting such as
    ``(Some(x), y)``. Empty tuples ``()`` match the ``Unit`` type.
    """
    elements: list[Pattern]


@dataclass(kw_only=True)
class OrPat(Pattern):
    """``pat1 | pat2 | ... | patN``, pattern alternatives.

    Matches if *any* of the alternatives matches. For v0, we do not
    support bindings inside or-patterns (each alternative must be a
    pattern without bound variables: literal, wildcard, variant without
    payload). This restriction exists because allowing bindings would
    require ensuring that all alternatives bind the same names with the
    same types.
    """
    alternatives: list[Pattern]

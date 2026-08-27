"""Single source of truth for the linear must-consume OBLIGATION predicate.

A value carries a must-consume obligation iff its type is a
linear/typestate type (``owned_obligation`` returns True on the type's
own name), OR it is a struct that TRANSITIVELY OWNS a linear/typestate
field through its declared (non-container) struct fields -- a CARRIER
(``carries_linear``). A carrier is a must-consume value the same way a
bare linear value is: packing a linear handle into a struct field and
then dropping the struct leaks the handle.

Both the analyzer (``capa/analyzer/_linear.py``, which ENFORCES the
obligation) and the manifest builder (``capa/manifest/_funrec.py``,
which REPORTS it as ``is_linear`` / ``consumes`` / ``produces_linear``)
import and call these helpers. Keeping the classification in one place is
the point: the two used to compute it independently and drifted (the
manifest's local set excluded typestates and carriers), so a function
could enforce an obligation the SBOM never reported. There is exactly one
predicate here; a second copy anywhere is a bug.

The predicate is parameterized so each caller supplies its own view of
the program:

- ``linear_names``: the set of linear/typestate type names (built once
  via :func:`linear_type_names`, shared by both callers).
- ``field_roots``: a callable ``name -> Optional[iterable[str]]`` giving
  the ROOT type names of a struct/typestate's declared fields (``None``
  for a name that is not a struct/typestate). The analyzer feeds a
  Symbol-based lookup, the manifest an AST-based one; the fail-closed
  guard in the analyzer asserts the two agree.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from . import capa_ast as A


# A linear/typestate value cannot contain itself by value, so a carrier
# chain is naturally bounded; this defensive depth cap keeps the walk
# finite on any pathological (cyclic) type. Mirrors the analyzer's
# ``_LinearMixin._LINEAR_PATH_MAX_DEPTH``.
_MAX_DEPTH = 8


def carries_linear(
    root: Optional[str],
    linear_names: set[str],
    field_roots: Callable[[str], Optional[Iterable[str]]],
    _depth: int = 0,
) -> bool:
    """True iff the struct/typestate named ``root`` transitively reaches a
    linear/typestate type through its declared (non-container) struct
    fields. ``root`` itself is NOT tested for linear-ness here (that is
    :func:`owned_obligation`'s job); this walks only the fields."""
    if root is None or _depth >= _MAX_DEPTH:
        return False
    fields = field_roots(root)
    if not fields:
        return False
    for froot in fields:
        if froot in linear_names:
            return True
        if carries_linear(froot, linear_names, field_roots, _depth + 1):
            return True
    return False


def owned_obligation(
    root: Optional[str],
    linear_names: set[str],
    field_roots: Callable[[str], Optional[Iterable[str]]],
) -> bool:
    """True iff a value whose ROOT type name is ``root`` carries a
    must-consume obligation: it is itself a linear/typestate type, OR a
    carrier struct that transitively owns a linear/typestate field."""
    if root is not None and root in linear_names:
        return True
    return carries_linear(root, linear_names, field_roots)


def linear_type_names(module: A.Module) -> set[str]:
    """The set of linear/typestate type NAMES declared in ``module``: every
    ``linear type`` struct plus every typestate (a typestate value is
    linear too -- it must be consumed / transitioned before it leaves
    scope). The single source both the analyzer and the manifest use, so
    the two can never disagree on which bare names are linear."""
    names: set[str] = set()
    for item in module.items:
        if isinstance(item, A.TypeStruct) and getattr(item, "is_linear", False):
            names.add(item.name)
        elif isinstance(item, A.TypestateDecl):
            names.add(item.name)
    return names


def field_roots_from_module(module: A.Module) -> dict[str, list[str]]:
    """Map each struct / typestate name declared in ``module`` to the ROOT
    type names of its declared fields (a ``TypeName`` head, dropping
    generic args / containers / tuples). The AST-based ``field_roots``
    lookup the manifest feeds :func:`owned_obligation`, and the reference
    the analyzer's fail-closed guard checks its Symbol-based lookup
    against."""
    out: dict[str, list[str]] = {}
    for item in module.items:
        if isinstance(item, (A.TypeStruct, A.TypestateDecl)):
            out[item.name] = [
                f.type_expr.name
                for f in item.fields
                if isinstance(f.type_expr, A.TypeName)
            ]
    return out

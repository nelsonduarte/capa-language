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

TWO consumers walk the ONE field-root seam, and they are deliberately
NOT the same generator because each needs a different complexity-safe
shape (folding them into one memo would be unsound for the enumerator):

- the PREDICATE (:func:`carries_linear`) answers a path-INDEPENDENT
  yes/no -- "does struct S reach any linear/typestate leaf" -- so it
  walks with a GLOBAL ``seen`` set, giving the identical verdict in
  O(V+E). A path-scoped predicate is exponential on a diamond DAG (a
  non-carrier ``P { a: S, b: S }`` chain blows up), which this avoids.
- the ENUMERATOR (:func:`linear_leaf_paths`) lists every distinct
  ``place.f...`` sub-path whose leaf is linear/typestate, so it MUST be
  PATH-SCOPED -- a diamond ``P { a: S, b: S }`` owns BOTH ``a``'s and
  ``b``'s leaf, and a global memo would drop the second. It is therefore
  inherently exponential in the path-distinct leaf count, so it carries a
  fail-CLOSED total-work BUDGET: on exhaustion (reachable only by a
  crafted exponential-diamond type, never real code) it collapses the
  carrier to a single whole-value obligation rather than silently
  dropping a leaf.

Neither walk is depth-capped: a by-value struct cycle
(``type Node { next: Node }``) is not rejected elsewhere, so the walks
themselves are cycle-safe (the predicate's global ``seen``, the
enumerator's path-scoped ``visited``) rather than fail-open past a
fixed depth.

The predicate is parameterized so each caller supplies its own view of
the program:

- ``linear_names``: the set of linear/typestate type names (built once
  via :func:`linear_type_names`, shared by both callers).
- ``field_roots``: a callable ``name -> Optional[iterable[(field_name,
  field_root_name)]]`` giving the declared (non-container) struct fields
  of a struct/typestate as ``(field name, ROOT type name)`` pairs
  (``None`` for a name that is not a struct/typestate). The predicate
  ignores ``field_name``; the enumerator uses it to build the dotted
  place. The analyzer feeds a Symbol-based lookup, the manifest an
  AST-based one; the fail-closed guard in the analyzer asserts the two
  agree.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional, Tuple

from . import capa_ast as A

FieldRoots = Callable[[str], Optional[Iterable[Tuple[str, str]]]]

# Fail-CLOSED total-work budget for the path-scoped leaf enumerator. A
# real carrier enumerates a handful of linear leaves; only a crafted
# exponential-diamond type (``P { a: S, b: S }`` chained k deep, 2**k
# path-distinct leaves) approaches this, and on exhaustion the enumerator
# collapses to a single whole-value obligation, never a silent accept.
# Generous by orders of magnitude over any real type; the direction (fail
# closed) is the invariant, not the exact number.
_LINEAR_LEAF_BUDGET = 10_000


class _BudgetExhausted(Exception):
    """Internal signal: the leaf enumerator hit its total-work budget."""


def carries_linear(
    root: Optional[str],
    linear_names: set[str],
    field_roots: FieldRoots,
) -> bool:
    """True iff the struct/typestate named ``root`` transitively reaches a
    linear/typestate type through its declared (non-container) struct
    fields. ``root`` itself is NOT tested for linear-ness here (that is
    :func:`owned_obligation`'s job); this walks only the fields.

    A plain graph reachability with a GLOBAL ``seen`` set: whether a
    struct reaches a linear leaf is path-INDEPENDENT, so revisiting a
    node is pure waste and skipping it (which also breaks any cycle)
    gives the identical verdict in O(V+E). This is the cycle-safe
    replacement for the old fail-open depth cap: a by-value struct cycle
    terminates on the ``seen`` set instead of being judged a non-carrier
    past a fixed depth."""
    if root is None:
        return False
    seen: set[str] = set()
    stack: list[str] = [root]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        fields = field_roots(name)
        if not fields:
            continue
        for _fname, froot in fields:
            if froot in linear_names:
                return True
            if froot not in seen:
                stack.append(froot)
    return False


def owned_obligation(
    root: Optional[str],
    linear_names: set[str],
    field_roots: FieldRoots,
) -> bool:
    """True iff a value whose ROOT type name is ``root`` carries a
    must-consume obligation: it is itself a linear/typestate type, OR a
    carrier struct that transitively owns a linear/typestate field."""
    if root is not None and root in linear_names:
        return True
    return carries_linear(root, linear_names, field_roots)


def linear_leaf_paths(
    place: str,
    root: Optional[str],
    linear_names: set[str],
    field_roots: FieldRoots,
    *,
    budget: int = _LINEAR_LEAF_BUDGET,
) -> list[str]:
    """The finite set of ``place.f...`` sub-paths whose LEAF type is
    linear/typestate, enumerated from the struct named ``root``'s declared
    fields. A linear field is a leaf (consuming it whole satisfies it, so
    we do not descend into it); a non-linear struct field is descended to
    find any deeper linear leaf. Walks struct fields only -- a container
    element or a ``Fun`` signature has no ``(field_name, field_root)``
    entry, so authority reached only through a container / closure is not
    enumerated here (it is barred from containers separately).

    PATH-SCOPED cycle detection (a per-path ``visited`` set of struct
    names): a diamond ``P { a: S, b: S }`` yields BOTH ``place.a...`` and
    ``place.b...`` leaves -- a global memo would drop the second and
    silently under-report a real leak. Because that makes the walk
    inherently exponential in the path-distinct leaf count, it is
    bounded by a fail-CLOSED total-work ``budget``: on exhaustion it
    abandons the partial enumeration and returns the single whole-value
    place ``[place]``, collapsing the carrier to a whole-value
    must-consume so a crafted exponential-diamond type can never silently
    drop a leaf (never a silent accept)."""
    if root is None:
        return []
    out: list[str] = []
    work = [0]

    def walk(pl: str, name: str, visited: frozenset[str]) -> None:
        fields = field_roots(name)
        if not fields:
            return
        for fname, froot in fields:
            work[0] += 1
            if work[0] > budget:
                raise _BudgetExhausted
            sub = f"{pl}.{fname}"
            if froot in linear_names:
                out.append(sub)
            elif froot not in visited:
                walk(sub, froot, visited | {froot})

    try:
        walk(place, root, frozenset({root}))
    except _BudgetExhausted:
        return [place]
    return out


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


def field_roots_from_module(module: A.Module) -> dict[str, list[Tuple[str, str]]]:
    """Map each struct / typestate name declared in ``module`` to the
    ``(field name, ROOT type name)`` pairs of its declared fields (a
    ``TypeName`` head, dropping generic args / containers / tuples). The
    AST-based ``field_roots`` lookup the manifest feeds
    :func:`owned_obligation`, and the reference the analyzer's fail-closed
    guard checks its Symbol-based lookup against. The field name is carried
    (unused by the predicate) so the ONE seam also drives the analyzer's
    leaf enumerator, which builds dotted places from it."""
    out: dict[str, list[Tuple[str, str]]] = {}
    for item in module.items:
        if isinstance(item, (A.TypeStruct, A.TypestateDecl)):
            out[item.name] = [
                (f.name, f.type_expr.name)
                for f in item.fields
                if isinstance(f.type_expr, A.TypeName)
            ]
    return out

"""Crossing-type layout schema for typed foreign components (feature #4,
F2c-1).

F2a/F2b crossed scalars (Int / Bool / Float) and String. F2c-1 crosses
FLAT, one-level, scalar-leaf AGGREGATES: a struct of scalars, a
``List<scalar>``, a tuple of scalars, ``Option<scalar>`` and
``Result<scalar, scalar>``. This module classifies a crossing type and,
for a marshallable aggregate, serialises a LAYOUT SCHEMA the Wasm host
consumes to read the value out of / write it back into the parent's
linear memory.

The byte-offset authority stays in ``capa.ir._emit_wasm._layout``: the
struct field offsets come straight from ``compute_struct_layout`` (with
the same ``reserve_header`` decision the core emitter makes for a
multi-impl-trait struct), and the List element stride comes from
``_size_of``. The host reproduces exactly what those functions compute
rather than re-deriving offsets independently, so the reader and writer
cannot disagree with the emitter.

A NESTED aggregate (``List<struct>``, a struct with a List / nested
aggregate field, a multi-payload sum, Map) is NOT F2c-1: the classifier
returns ``None`` for it so the CLI guard rejects the call with the clean
"aggregate nesting not yet supported at runtime (feature #4 F2c-2)"
error.
"""

from __future__ import annotations

from typing import Optional

from . import capa_ast as A
from .typesys import CAPABILITY_NAMES
from .manifest._strings import _ty_text, _root_type_name


# The scalar LEAF types F2c-1 marshals inside an aggregate. Every leaf of
# a flat aggregate must be one of these; anything else (a nested
# aggregate, a Fun, a capability) makes the whole crossing type F2c-2 /
# unmarshallable.
SCALAR_LEAVES = frozenset({"Int", "Bool", "Float", "String"})

# The scalar crossing types that lower to a single core value (Int / Bool
# / Float). String is handled separately (it crosses as a ptr/len pair).
_SCALARS = frozenset({"Int", "Bool", "Float"})


def _leaf_name(type_expr: Optional[A.TypeExpr]) -> Optional[str]:
    """Return the scalar-leaf name of ``type_expr`` (``Int`` / ``Bool`` /
    ``Float`` / ``String``), or ``None`` when it is not a scalar leaf (a
    nested aggregate, tuple, Fun, capability, ...)."""
    root = _root_type_name(type_expr)
    if root in SCALAR_LEAVES:
        return root
    return None


def crossing_kind(type_expr: Optional[A.TypeExpr]) -> str:
    """Classify a foreign-method crossing parameter / return type into a
    coarse kind WITHOUT resolving struct bodies: ``"cap"``, ``"scalar"``
    (Int / Bool / Float / String), or ``"aggregate"`` (a struct name,
    List, tuple, Option, Result, or anything else that is not a bare
    scalar). The deep "is this a FLAT scalar-leaf aggregate F2c-1 can
    marshal" question is answered by :func:`build_aggregate_schema`."""
    root = _root_type_name(type_expr)
    if root in CAPABILITY_NAMES:
        return "cap"
    if root in SCALAR_LEAVES:
        return "scalar"
    return "aggregate"


def header_struct_types(module: A.Module) -> set[str]:
    """The set of struct type names that reserve an 8-byte trait-dispatch
    header (they implement at least one multi-impl trait), plus the
    per-type type-id assigned to each. Reproduces the core emitter's
    decision in ``_emit_wasm._traits._setup_trait_dispatch`` so a struct
    crossing the boundary lays its fields out at the SAME offsets the
    emitter uses (the header shifts every field by 8 bytes).

    Returns ``(header_names, type_ids)``. ``type_ids`` maps a
    participating type name to the integer written at offset 4; the host
    writes it back when returning such a struct so downstream multi-impl
    dispatch on the value stays correct."""
    by_trait: dict[str, list[A.ImplBlock]] = {}
    for it in module.items:
        if isinstance(it, A.ImplBlock) and it.trait_name:
            by_trait.setdefault(it.trait_name, []).append(it)
    sum_names = {
        it.name for it in module.items if isinstance(it, A.TypeSum)
    }
    headers: set[str] = set()
    type_ids: dict[str, int] = {}
    next_id = 1
    for _trait, impls in by_trait.items():
        if len(impls) <= 1:
            continue
        for impl in impls:
            head = impl.type_name.split("<", 1)[0].split("[", 1)[0]
            if impl.type_name not in type_ids:
                type_ids[impl.type_name] = next_id
                next_id += 1
            if head not in sum_names:
                headers.add(impl.type_name)
    return headers, type_ids


def _struct_decl(module: A.Module, name: str) -> Optional[A.TypeStruct]:
    for it in module.items:
        if isinstance(it, A.TypeStruct) and it.name == name:
            return it
    return None


class _ShimField:
    """Minimal field view for ``compute_struct_layout`` (needs ``.name``
    and ``.ty``)."""

    def __init__(self, name: str, ty: str) -> None:
        self.name = name
        self.ty = ty


class _ShimStruct:
    def __init__(self, fields: list[_ShimField]) -> None:
        self.fields = fields


def build_aggregate_schema(
    type_expr: Optional[A.TypeExpr], module: A.Module,
) -> Optional[dict]:
    """Serialise a FLAT one-level scalar-leaf aggregate crossing type into
    a layout schema the host reader/writer consumes, or return ``None``
    when the type is not an F2c-1 aggregate (a nested aggregate, a
    multi-payload sum, Map, an unresolved struct, ...).

    Schema shapes (all leaves are ``Int`` / ``Bool`` / ``Float`` /
    ``String``):

    - struct:  ``{"kind": "struct", "wit": <record-name>, "size": N,
                  "has_header": bool, "type_id": int,
                  "fields": [{"capa","wit","offset","size","leaf"}, ...]}``
    - list:    ``{"kind": "list", "elem": <leaf>, "stride": N}``
    - tuple:   ``{"kind": "tuple", "elems": [<leaf>, ...]}``
    - option:  ``{"kind": "option", "payload": <leaf>}``
    - result:  ``{"kind": "result", "ok": <leaf>, "err": <leaf>}``
    """
    from .ir._emit_wasm._layout import compute_struct_layout, _size_of

    # Tuple of scalars: uniform 8-byte slot per element.
    if isinstance(type_expr, A.TupleType):
        elems: list[str] = []
        for e in type_expr.elements:
            leaf = _leaf_name(e)
            if leaf is None:
                return None
            elems.append(leaf)
        if not elems:
            return None
        return {"kind": "tuple", "elems": elems}

    root = _root_type_name(type_expr)
    if root is None:
        return None

    if root == "List":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 1:
            return None
        leaf = _leaf_name(args[0])
        if leaf is None:
            return None
        return {
            "kind": "list",
            "elem": leaf,
            "stride": _size_of(leaf, {}, {}),
        }

    if root == "Option":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 1:
            return None
        leaf = _leaf_name(args[0])
        if leaf is None:
            return None
        return {"kind": "option", "payload": leaf}

    if root == "Result":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 2:
            return None
        ok = _leaf_name(args[0])
        err = _leaf_name(args[1])
        if ok is None or err is None:
            return None
        return {"kind": "result", "ok": ok, "err": err}

    # A user struct of scalars. Resolve the declaration; every field must
    # be a scalar leaf (a nested aggregate field is F2c-2).
    decl = _struct_decl(module, root)
    if decl is None:
        return None
    shim_fields: list[_ShimField] = []
    leaves: list[str] = []
    for f in decl.fields:
        leaf = _leaf_name(f.type_expr)
        if leaf is None:
            return None
        leaves.append(leaf)
        shim_fields.append(_ShimField(f.name, leaf))
    if not shim_fields:
        return None
    headers, type_ids = header_struct_types(module)
    reserve = root in headers
    layout = compute_struct_layout(
        _ShimStruct(shim_fields), {}, {}, reserve_header=reserve,
    )
    fields_meta = []
    for f in decl.fields:
        offset, size, _ty = layout["fields"][f.name]
        fields_meta.append({
            "capa": f.name,
            "wit": f.name.replace("_", "-"),
            "offset": offset,
            "size": size,
            "leaf": _leaf_name(f.type_expr),
        })
    return {
        "kind": "struct",
        "wit": root.replace("_", "-"),
        "size": layout["size"],
        "has_header": layout.get("has_header", False),
        "type_id": type_ids.get(root, 0),
        "fields": fields_meta,
    }


def is_flat_aggregate_marshallable(
    type_expr: Optional[A.TypeExpr], module: A.Module,
) -> bool:
    """True when ``type_expr`` is a FLAT one-level scalar-leaf aggregate
    F2c-1 can marshal at runtime."""
    return build_aggregate_schema(type_expr, module) is not None


def capa_type_to_wit(type_expr: Optional[A.TypeExpr], module: A.Module) -> str:
    """Map a crossing Capa type to its WIT type text so the parent import
    and the external child export agree on the canonical ABI
    (record / list / option / result / tuple). Only the F2c-1 shapes are
    covered; an unsupported type raises ``ValueError``.

    The core ``--wasm`` foreign path does not itself consume this (the
    parent import is a raw host closure whose signature the host and the
    guest agree on directly); it documents the canonical-ABI contract the
    child fixture's WIT must match and is the seam a future ``--component``
    foreign path would generate from."""
    root = _root_type_name(type_expr)
    if root == "Int":
        return "s64"
    if root == "Bool":
        return "bool"
    if root == "Float":
        return "f64"
    if root == "String":
        return "string"
    if isinstance(type_expr, A.TupleType):
        inner = ", ".join(
            capa_type_to_wit(e, module) for e in type_expr.elements
        )
        return f"tuple<{inner}>"
    if root == "List":
        args = getattr(type_expr, "args", []) or []
        return f"list<{capa_type_to_wit(args[0], module)}>"
    if root == "Option":
        args = getattr(type_expr, "args", []) or []
        return f"option<{capa_type_to_wit(args[0], module)}>"
    if root == "Result":
        args = getattr(type_expr, "args", []) or []
        return (
            f"result<{capa_type_to_wit(args[0], module)}, "
            f"{capa_type_to_wit(args[1], module)}>"
        )
    if root is not None and _struct_decl(module, root) is not None:
        return root.replace("_", "-")
    raise ValueError(f"no WIT mapping for crossing type {_ty_text(type_expr)!r}")

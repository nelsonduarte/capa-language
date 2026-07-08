"""Crossing-type layout schema for typed foreign components (feature #4,
F2c).

F2a/F2b crossed scalars (Int / Bool / Float) and String. F2c-1 crossed
FLAT, one-level, scalar-leaf AGGREGATES: a struct of scalars, a
``List<scalar>``, a tuple of scalars, ``Option<scalar>`` and
``Result<scalar, scalar>``. F2c-2 (this module) generalises to NESTED,
non-self-referential aggregates of ANY finite depth: a nested struct
field / List element / variant payload carries its OWN sub-schema, so
``List<Point>``, ``struct { items: List<Int>, name: String }``,
``List<(Int, String)>``, ``Option<struct>``, ``Result<struct, String>``,
``List<List<Int>>`` and a multi-payload user sum all cross. The recursion
is the same code at every level.

The byte-offset authority stays in ``capa.ir._emit_wasm._layout``: struct
field offsets come from ``compute_struct_layout`` (with the same
``reserve_header`` decision the core emitter makes for a multi-impl-trait
struct), user-sum payload offsets from ``compute_sum_layout``, and the
List element stride from ``_size_of``. The host reproduces exactly what
those functions compute rather than re-deriving offsets, so the reader and
writer cannot disagree with the emitter.

Two shapes are deliberately NOT supported and reject cleanly (STOP-report
boundaries):

- ``Map<K, V>`` has a different (String-keyed) structure that the
  aggregate marshaller does not cross; raises :class:`MapCrossingUnsupported`.
- a SELF-REFERENTIAL / recursive TYPE (``type Tree { kids: List<Tree> }``)
  would make the compile-time schema build and the WIT emitter loop
  forever; the build detects a type cycle and raises
  :class:`RecursiveCrossingUnsupported`. (Values are finite but the TYPE
  recursion needs named-recursive-WIT machinery that is out of scope.)

IMPORTANT ORDER INVARIANT. :func:`header_struct_types` iterates the AST
``module.items`` to decide which structs / sums reserve a trait-dispatch
header and to assign each participant a type-id, while the core Wasm
emitter iterates the IR (``_emit_wasm._traits._setup_trait_dispatch`` over
``module.impls``). Both walk impl blocks in source order, so the type-ids
line up. A divergence would mis-assign a trait-dispatch type-id and write
the wrong header word into a crossing struct, silently corrupting dynamic
dispatch on the value. To make that robustness explicit rather than
iteration-order-fragile, the schema keys a participant's type-id on the
STABLE type NAME (``type_ids[name]``), not on iteration position: the host
writes ``type_ids[struct_name]`` regardless of which order the structs
were visited in.
"""

from __future__ import annotations

from typing import Optional

from . import capa_ast as A
from .typesys import CAPABILITY_NAMES
from .manifest._strings import _ty_text, _root_type_name


# The scalar LEAF types F2c marshals at the bottom of an aggregate. Every
# leaf of a marshallable aggregate must be one of these; anything else (a
# Fun, a capability, a Set / Char / Map) makes the crossing type
# unmarshallable.
SCALAR_LEAVES = frozenset({"Int", "Bool", "Float", "String"})

# The scalar crossing types that lower to a single core value (Int / Bool
# / Float). String is handled separately (it crosses as a ptr/len pair).
_SCALARS = frozenset({"Int", "Bool", "Float"})


class ForeignCrossingUnsupported(Exception):
    """Base for the two STOP-report boundaries F2c-2 rejects cleanly: a
    ``Map`` crossing type and a self-referential (recursive) crossing
    type. Distinguished from a plain "not a marshallable aggregate"
    (which returns ``None``) so the CLI can print a specific,
    actionable message instead of the generic nesting error."""


class MapCrossingUnsupported(ForeignCrossingUnsupported):
    """A ``Map<K, V>`` appears in a crossing type. Map has a different
    (String-keyed) structure the aggregate marshaller does not cross."""


class RecursiveCrossingUnsupported(ForeignCrossingUnsupported):
    """A self-referential (recursive) named type appears in a crossing
    type (``type Tree { kids: List<Tree> }``). Marshalling the finite
    VALUE is possible but the TYPE recursion needs named-recursive WIT
    machinery out of F2c-2 scope, so it is rejected up front (the schema
    build never loops)."""

    def __init__(self, type_name: str) -> None:
        super().__init__(type_name)
        self.type_name = type_name


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
    (Int / Bool / Float / String), or ``"aggregate"`` (a struct / sum
    name, List, tuple, Option, Result, Map, or anything else that is not a
    bare scalar). The deep "is this a marshallable aggregate" question is
    answered by :func:`build_aggregate_schema`."""
    root = _root_type_name(type_expr)
    if root in CAPABILITY_NAMES:
        return "cap"
    if root in SCALAR_LEAVES:
        return "scalar"
    return "aggregate"


def header_struct_types(module: A.Module) -> tuple[set[str], dict[str, int]]:
    """The set of struct type names that reserve an 8-byte trait-dispatch
    header (they implement at least one multi-impl trait), plus the
    per-type type-id assigned to each. Reproduces the core emitter's
    decision in ``_emit_wasm._traits._setup_trait_dispatch`` so a struct
    crossing the boundary lays its fields out at the SAME offsets the
    emitter uses (the header shifts every field by 8 bytes).

    Returns ``(header_names, type_ids)``. ``type_ids`` maps a
    participating type name to the integer written at offset 4; the host
    writes it back when returning such a struct so downstream multi-impl
    dispatch on the value stays correct. The type-id is keyed on the
    stable type NAME (not iteration order) so it cannot drift from the
    emitter's assignment."""
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


def _sum_decl(module: A.Module, name: str) -> Optional[A.TypeSum]:
    for it in module.items:
        if isinstance(it, A.TypeSum) and it.name == name:
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


class _ShimVariant:
    """Minimal variant view for ``compute_sum_layout`` (needs ``.name``
    and ``.payload_tys``)."""

    def __init__(self, name: str, payload_tys: list[str]) -> None:
        self.name = name
        self.payload_tys = payload_tys


class _ShimSum:
    def __init__(self, variants: list[_ShimVariant]) -> None:
        self.variants = variants


# ---- taggedness (mirror wasmtime.component's VariantLikeType._tagged) --
#
# wasmtime lifts / lowers an option / result / variant as a BARE payload
# (discriminated by Python type) when the cases' Python classes are all
# disjoint ("untagged"), and demands an explicit ``wc.Variant`` when two
# cases share a class ("tagged"). We must agree with that decision to
# build the right Python value for the child (and to interpret its
# return), so we reproduce ``_tagged`` here over stable class SENTINELS.

# Each schema node's Python class, as a stable string matching
# wasmtime.component's ``add_classes``: Int->int, Bool->bool (a DISTINCT
# type object from int, so Result<Int, Bool> is untagged just as wasmtime
# treats it), Float->float, String->str, struct->Record, list->list,
# tuple->tuple. A no-payload variant case contributes ``object``.
_LEAF_CLASS = {
    "Int": "int", "Bool": "bool", "Float": "float", "String": "str",
}


def _node_classes(node: dict) -> frozenset[str]:
    """The set of Python-class sentinels a node's value can take, mirroring
    ``wasmtime.component`` ``add_classes`` so :func:`_variant_tagged`
    matches wasmtime's own taggedness decision at every nesting level."""
    kind = node["kind"]
    if kind == "scalar":
        return frozenset({_LEAF_CLASS[node["leaf"]]})
    if kind == "struct":
        return frozenset({"Record"})
    if kind == "list":
        return frozenset({"list"})
    if kind == "tuple":
        return frozenset({"tuple"})
    if kind == "option":
        return _variant_like_classes([None, node["payload"]])
    if kind == "result":
        return _variant_like_classes([node["ok"], node["err"]])
    if kind == "sum":
        return _variant_like_classes(
            [_sum_case_payload_node(v) for v in node["variants"]]
        )
    return frozenset({"object"})


def _sum_case_payload_node(variant: dict) -> Optional[dict]:
    """The single node a WIT variant case lifts to: ``None`` for a
    no-payload case, the bare node for one payload, a synthetic tuple node
    for a multi-payload case (a WIT case carries at most one payload, so a
    multi-payload Capa variant maps to a ``tuple`` payload)."""
    payloads = variant["payloads"]
    if not payloads:
        return None
    if len(payloads) == 1:
        return payloads[0]["node"]
    return {"kind": "tuple", "elems": [p["node"] for p in payloads]}


def _variant_like_classes(case_nodes: list[Optional[dict]]) -> frozenset[str]:
    if _variant_tagged(case_nodes):
        return frozenset({"Variant"})
    out: set[str] = set()
    for n in case_nodes:
        out |= ({"object"} if n is None else _node_classes(n))
    return frozenset(out)


def _variant_tagged(case_nodes: list[Optional[dict]]) -> bool:
    """True when two cases share a Python class, so wasmtime needs an
    explicit ``wc.Variant`` (exact port of
    ``VariantLikeType._tagged``)."""
    seen: set[str] = set()
    for n in case_nodes:
        case = {"object"} if n is None else set(_node_classes(n))
        if case & seen:
            return True
        seen |= case
    return False


# ---- recursive schema build -------------------------------------------


def _stride_of(node: dict) -> int:
    """Byte stride of a List element / footprint of a scalar leaf: 8 for
    Int / Float / String, 4 for Bool, 4 for any pointer-shape nested
    aggregate (matches ``_size_of``)."""
    from .ir._emit_wasm._layout import _size_of
    if node["kind"] == "scalar":
        return _size_of(node["leaf"], {}, {})
    return 4  # struct / sum / list / tuple / option / result -> i32 pointer


def _build_node(
    type_expr: Optional[A.TypeExpr], module: A.Module, stack: tuple[str, ...],
) -> Optional[dict]:
    """Build the recursive schema node for one crossing type / slot, or
    return ``None`` when it is not marshallable (a Fun, Set, Char, or an
    unresolved / unknown type). Raises :class:`MapCrossingUnsupported` /
    :class:`RecursiveCrossingUnsupported` for the two STOP-report
    boundaries. ``stack`` is the chain of named types currently being
    resolved (ancestors only), used to detect a type cycle."""
    from .ir._emit_wasm._layout import (
        compute_struct_layout, compute_sum_layout,
    )

    # Tuple of nodes: uniform 8-byte slot per element.
    if isinstance(type_expr, A.TupleType):
        elems: list[dict] = []
        for e in type_expr.elements:
            n = _build_node(e, module, stack)
            if n is None:
                return None
            elems.append(n)
        if not elems:
            return None
        return {"kind": "tuple", "elems": elems}

    root = _root_type_name(type_expr)
    if root is None:
        return None

    leaf = _leaf_name(type_expr)
    if leaf is not None:
        return {"kind": "scalar", "leaf": leaf}

    if root == "Map":
        raise MapCrossingUnsupported(_ty_text(type_expr))

    if root == "List":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 1:
            return None
        elem = _build_node(args[0], module, stack)
        if elem is None:
            return None
        return {"kind": "list", "elem": elem, "stride": _stride_of(elem)}

    if root == "Option":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 1:
            return None
        payload = _build_node(args[0], module, stack)
        if payload is None:
            return None
        return {
            "kind": "option", "payload": payload,
            "tagged": _variant_tagged([None, payload]),
        }

    if root == "Result":
        args = getattr(type_expr, "args", []) or []
        if len(args) != 2:
            return None
        ok = _build_node(args[0], module, stack)
        err = _build_node(args[1], module, stack)
        if ok is None or err is None:
            return None
        return {
            "kind": "result", "ok": ok, "err": err,
            "tagged": _variant_tagged([ok, err]),
        }

    # A user struct. Detect a type cycle before descending into fields.
    decl = _struct_decl(module, root)
    if decl is not None:
        if root in stack:
            raise RecursiveCrossingUnsupported(root)
        return _build_struct_node(
            decl, root, module, stack + (root,), compute_struct_layout,
        )

    # A user sum (multi-payload variants supported).
    sdecl = _sum_decl(module, root)
    if sdecl is not None:
        if root in stack:
            raise RecursiveCrossingUnsupported(root)
        return _build_sum_node(
            sdecl, root, module, stack + (root,), compute_sum_layout,
        )

    # Fun / Set / Char / unresolved: not marshallable (generic reject).
    return None


def _build_struct_node(
    decl, root, module, stack, compute_struct_layout,
) -> Optional[dict]:
    shim_fields: list[_ShimField] = []
    field_nodes: list[dict] = []
    for f in decl.fields:
        node = _build_node(f.type_expr, module, stack)
        if node is None:
            return None
        field_nodes.append(node)
        # ``_size_of`` maps a scalar leaf to 8/4 and any nested aggregate
        # (a name / List / tuple / Option / Result / Map) to a 4-byte
        # pointer, exactly as the emitter lays the field out.
        shim_fields.append(_ShimField(f.name, _ty_text(f.type_expr)))
    if not shim_fields:
        return None
    headers, type_ids = header_struct_types(module)
    reserve = root in headers
    layout = compute_struct_layout(
        _ShimStruct(shim_fields), {}, {}, reserve_header=reserve,
    )
    fields_meta = []
    for f, node in zip(decl.fields, field_nodes):
        offset, size, _ty = layout["fields"][f.name]
        fields_meta.append({
            "capa": f.name,
            "wit": f.name.replace("_", "-"),
            "offset": offset,
            "size": size,
            "node": node,
        })
    return {
        "kind": "struct",
        "wit": root.replace("_", "-"),
        "size": layout["size"],
        "has_header": layout.get("has_header", False),
        "type_id": type_ids.get(root, 0),
        "fields": fields_meta,
    }


def _build_sum_node(
    sdecl, root, module, stack, compute_sum_layout,
) -> Optional[dict]:
    shim_variants: list[_ShimVariant] = []
    payload_nodes: list[list[dict]] = []
    for v in sdecl.variants:
        pnodes: list[dict] = []
        ptys: list[str] = []
        for pty in v.payloads:
            node = _build_node(pty, module, stack)
            if node is None:
                return None
            pnodes.append(node)
            ptys.append(_ty_text(pty))
        payload_nodes.append(pnodes)
        shim_variants.append(_ShimVariant(v.name, ptys))
    layout = compute_sum_layout(_ShimSum(shim_variants), {}, {})
    headers, type_ids = header_struct_types(module)
    variants_meta = []
    for v, pnodes in zip(sdecl.variants, payload_nodes):
        tag, payload_layouts = layout["variants"][v.name]
        payloads = [
            {"offset": off, "size": size, "node": node}
            for (off, size, _ty), node in zip(payload_layouts, pnodes)
        ]
        variants_meta.append({
            "name": v.name,
            "wit": v.name.replace("_", "-").lower(),
            "tag": tag,
            "payloads": payloads,
        })
    # A sum keeps its tag at offset 0 and payloads at offset 8, so a
    # multi-impl-trait sum writes its type-id into the free offset-4 word
    # WITHOUT shifting any field (unlike a struct header). ``has_header``
    # for a sum therefore just means "this sum is a dispatch participant"
    # (it has an assigned type-id), matching the emitter's
    # ``_header_sum_types`` write in ``_emit_variant_construction``.
    _sum_type_id = type_ids.get(root, 0)
    node = {
        "kind": "sum",
        "wit": root.replace("_", "-").lower(),
        "size": layout["size"],
        "has_header": _sum_type_id != 0,
        "type_id": _sum_type_id,
        "variants": variants_meta,
    }
    node["tagged"] = _variant_tagged(
        [_sum_case_payload_node(v) for v in variants_meta]
    )
    return node


def build_aggregate_schema(
    type_expr: Optional[A.TypeExpr], module: A.Module,
) -> Optional[dict]:
    """Serialise a NESTED, non-self-referential scalar-leaf aggregate
    crossing type into a recursive layout schema the host reader/writer
    consumes, or return ``None`` when the type is not a marshallable
    aggregate (a bare scalar, a Fun, an unresolved struct, ...). Raises
    :class:`MapCrossingUnsupported` / :class:`RecursiveCrossingUnsupported`
    for the two STOP-report boundaries.

    A slot (struct field / List element / tuple element / variant
    payload) is either an INLINE scalar leaf (``{"kind": "scalar",
    "leaf": ...}``) or a POINTER to a separately-allocated sub-record
    (any other node ``kind``); the host reads / writes the 4-byte pointer
    and recurses. Aggregate node shapes:

    - struct:  ``{"kind":"struct","wit","size","has_header","type_id",
                  "fields":[{"capa","wit","offset","size","node"}]}``
    - list:    ``{"kind":"list","elem":<node>,"stride":N}``
    - tuple:   ``{"kind":"tuple","elems":[<node>,...]}``
    - option:  ``{"kind":"option","payload":<node>,"tagged":bool}``
    - result:  ``{"kind":"result","ok":<node>,"err":<node>,"tagged":bool}``
    - sum:     ``{"kind":"sum","wit","size","has_header","type_id",
                  "tagged":bool,
                  "variants":[{"name","wit","tag",
                               "payloads":[{"offset","size","node"}]}]}``
    """
    node = _build_node(type_expr, module, ())
    if node is None or node["kind"] == "scalar":
        # A bare scalar goes through the scalar / String path, not here.
        return None
    return node


def crossing_type_rejection(
    type_expr: Optional[A.TypeExpr], module: A.Module,
) -> Optional[str]:
    """Return ``None`` when ``type_expr`` is a marshallable crossing type
    (scalar / String / a non-self-referential nested aggregate), else a
    specific, actionable phrase describing WHY it is rejected. Drives the
    CLI's per-call-site diagnostic so a ``Map`` and a self-referential
    type report distinctly from a generic unsupported crossing type."""
    root = _root_type_name(type_expr)
    if root in CAPABILITY_NAMES or root in SCALAR_LEAVES:
        return None
    try:
        schema = build_aggregate_schema(type_expr, module)
    except MapCrossingUnsupported:
        return (
            "uses a Map crossing type, which the foreign-boundary "
            "marshaller does not support (Map's String-keyed structure is "
            "out of scope; feature #4)."
        )
    except RecursiveCrossingUnsupported as e:
        return (
            f"uses the self-referential crossing type {e.type_name!r}, "
            "which the foreign boundary does not support (a recursive type "
            "would need named-recursive WIT machinery; feature #4)."
        )
    if schema is None:
        return (
            "uses a crossing type that cannot be marshalled across the "
            "foreign boundary (only scalars, String, and non-self-"
            "referential nested aggregates of struct / List / tuple / "
            "Option / Result / sum are supported; feature #4)."
        )
    return None


def capa_type_to_wit(type_expr: Optional[A.TypeExpr], module: A.Module) -> str:
    """Map a crossing Capa type to its WIT type text so the parent import
    and the external child export agree on the canonical ABI
    (record / list / option / result / tuple). An unsupported type raises
    ``ValueError``. The core ``--wasm`` foreign path does not itself
    consume this (the parent import is a raw host closure whose signature
    the host and the guest agree on directly); it documents the
    canonical-ABI contract the child fixture's WIT must match and is the
    seam a future ``--component`` foreign path would generate from."""
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
    if root is not None and (
        _struct_decl(module, root) is not None
        or _sum_decl(module, root) is not None
    ):
        return root.replace("_", "-").lower()
    raise ValueError(f"no WIT mapping for crossing type {_ty_text(type_expr)!r}")

"""Memory layout primitives shared by the Wasm emitter.

This module is the foundation of the ``_emit_wasm`` package: it owns
the size/alignment conventions for every Capa value when stored in
linear memory, plus the helpers that turn a Capa type string into a
byte size or a Wasm load/store opcode. It has no dependencies on any
other emitter module so submodules can import it freely.

``WasmEmissionError`` lives here because the load/store helpers raise
it, and every other emitter submodule eventually needs to import the
error class anyway.
"""

from __future__ import annotations

from .._nodes import StructDecl, SumDecl


class WasmEmissionError(Exception):
    """Raised when the Wasm emitter hits an IR construct it does
    not yet support. Phase 6A is intentionally narrow; widening the
    error surface is preferred to silently emitting wrong code."""


from .._capa_types import BUILTIN_CAPS


# Per-type byte size for Capa scalar types. Used by layout
# computation for structs and sum payloads. Strings, Lists, Maps,
# Sets are represented as i32 pointers; their stdlib payloads land
# in 6D and beyond.
_TYPE_SIZE = {
    "Int":    8,  # i64
    "Bool":   4,  # i32
    "Float":  8,  # f64
    # Strings live as (ptr, len) pairs -- two i32s = 8 bytes total.
    # When a struct field has String type, the FieldAccess emitter
    # issues two i32.loads (offset, offset+4) into the bind's
    # ${name}_ptr / ${name}_len locals.
    "String": 8,
}


# Memory layout of a List<T>: 16-byte header (len, cap, data_ptr,
# padding) followed by a separately-allocated element array. The
# header is kept fixed-size so List<T> for any T is a 16-byte
# allocation; the data array's stride depends on T.
_LIST_HEADER_SIZE = 16
_LIST_LEN_OFFSET = 0
_LIST_CAP_OFFSET = 4
_LIST_DATA_OFFSET = 8


# Memory layout of a Map<String, V>: same 16-byte header as List;
# the data array holds (key_ptr, key_len, value) triples each 16
# bytes wide. Phase 6D-3 specialises to String keys and 8-byte
# values (Int / pointer / packed-String-pair). Larger value types
# wait for a later phase that widens the slot.
_MAP_HEADER_SIZE = 16
_MAP_LEN_OFFSET = 0
_MAP_CAP_OFFSET = 4
_MAP_DATA_OFFSET = 8
_MAP_PAIR_SIZE = 16          # key_ptr (4) + key_len (4) + value (8)
_MAP_PAIR_KEY_PTR_OFFSET = 0
_MAP_PAIR_KEY_LEN_OFFSET = 4
_MAP_PAIR_VALUE_OFFSET = 8


# Memory layout of Capa's built-in Option<T>: a sum type with two
# variants (Some with one payload, None with none). Pre-registered
# in the emitter so ``match`` against Option<T> works without the
# user having to declare the type in source.
_OPTION_LAYOUT = {
    "variants": {
        # tag -> 0 for Some, payload at offset 8 (uniform 8-byte slot).
        "Some": (0, [(8, 8, "Any")]),
        # tag -> 1 for None, no payloads.
        "None": (1, []),
    },
    "size": 16,
}


# Memory layout of Capa's built-in Result<T, E>: also pre-registered.
_RESULT_LAYOUT = {
    "variants": {
        "Ok":  (0, [(8, 8, "Any")]),
        "Err": (1, [(8, 8, "Any")]),
    },
    "size": 16,
}


# Memory layout of Capa's built-in JsonValue sum type. Six variants
# in the uniform 16-byte sum layout: tag at offset 0, payload at
# offset 8 in an 8-byte slot (matching the Option/Result shape so
# the existing match-arm payload-extraction logic works unchanged).
#
# - JNull: tag=0, no payload
# - JBool: tag=1, Bool payload (i64-extended)
# - JNum:  tag=2, Float payload (f64 in the slot)
# - JStr:  tag=3, String payload (packed ptr+len as i64)
# - JArr:  tag=4, List<JsonValue> pointer (i64-extended)
# - JObj:  tag=5, Map<String, JsonValue> pointer (i64-extended)
#
# The payload "type" field is set to the Capa type the variant
# carries (or "Any" for the no-payload JNull) so the variant-
# construction emitter picks the correct store opcode.
_JSONVALUE_LAYOUT = {
    "variants": {
        "JNull": (0, []),
        "JBool": (1, [(8, 8, "Bool")]),
        "JNum":  (2, [(8, 8, "Float")]),
        "JStr":  (3, [(8, 8, "String")]),
        "JArr":  (4, [(8, 8, "List<JsonValue>")]),
        "JObj":  (5, [(8, 8, "Map<String, JsonValue>")]),
    },
    "size": 16,
}


# Memory layout of Capa's built-in IoError struct. The Capa runtime
# defines this in capa.runtime._capabilities; pre-registering the
# Wasm layout here means Capa code that pattern-matches on
# ``Err(io_error)`` and then reads ``io_error.message`` works
# through the existing struct field-access machinery without the
# user declaring the type in source.
_IOERROR_LAYOUT = {
    "fields": {
        # Each String field is 8 bytes (ptr@offset + len@offset+4).
        # The FieldAccess emitter handles the two-load expansion
        # when the field's recorded type is "String".
        "message": (0, 8, "String"),
        "cause":   (8, 8, "String"),
    },
    "size": 16,
}


def _map_value_type(map_ty: str) -> str:
    """Extract V from ``Map<K, V>``. Phase 6D-3 only supports K =
    String, so we ignore K; returning V drives method dispatch.
    Defaults to ``Int`` if the type string lacks args (consistent
    with the List analogue)."""
    if map_ty.startswith("Map<") and map_ty.endswith(">"):
        inner = map_ty[4:-1].strip()
        _k, _, v = inner.partition(",")
        v = v.strip()
        if v.startswith("?") or not v:
            return "Int"
        return v
    return "Int"


def _element_type_of_list(list_ty: str) -> str:
    """Extract T from ``List<T>``. Defaults to ``Int`` if the
    string lacks a type argument (the lowerer occasionally leaves
    bare ``List`` when the analyzer has no precise inference),
    or if the inner type is an unresolved type variable like
    ``?lst_0`` (the analyzer's type-var notation; happens for
    empty literals where inference happens elsewhere). Phase 6D-2
    defaults the unresolved case to Int because that is by far
    the most common element type in practice. A subsequent
    analyzer fix that propagates annotations into IR type strings
    will obsolete this fallback."""
    if list_ty.startswith("List<") and list_ty.endswith(">"):
        inner = list_ty[5:-1].strip()
        if inner.startswith("?"):
            return "Int"
        return inner
    return "Int"


def _size_of(capa_ty: str, sum_layouts: dict, struct_layouts: dict) -> int:
    """Byte size of a Capa type when stored in linear memory.
    Sum types and structs are stored by pointer (4 bytes); their
    actual content lives at the pointed-to address."""
    head = capa_ty.split("<", 1)[0]
    if head in _TYPE_SIZE:
        return _TYPE_SIZE[head]
    if head in sum_layouts or head in struct_layouts:
        return 4  # i32 pointer
    # Closure values are packed i64 (fn_idx << 32) | env_ptr.
    if capa_ty.startswith("Fun"):
        return 8
    # Conservatively pessimistic: treat unknowns as pointer-sized.
    # Real source-level types should resolve via the analyzer; this
    # fallback only matters during incremental development.
    return 4


def _store_op_for_size(size: int) -> str:
    """Wasm store opcode for a value of given size. The IR only
    produces values of size 4 (i32 / pointer) or 8 (i64); other
    sizes raise."""
    if size == 4:
        return "i32.store"
    if size == 8:
        return "i64.store"
    raise WasmEmissionError(
        f"no store opcode for {size}-byte value"
    )


def _load_op_for_size(size: int) -> str:
    if size == 4:
        return "i32.load"
    if size == 8:
        return "i64.load"
    raise WasmEmissionError(
        f"no load opcode for {size}-byte value"
    )


def _align_up(offset: int, alignment: int) -> int:
    """Round ``offset`` up to a multiple of ``alignment``."""
    return (offset + alignment - 1) & ~(alignment - 1)


def compute_struct_layout(
    decl: StructDecl,
    sum_layouts: dict,
    struct_layouts: dict,
) -> dict:
    """Compute per-field offsets and total size for a struct,
    laying fields out in declaration order with natural alignment.
    Returns a dict with ``fields`` (name -> (offset, size, capa_ty))
    and ``size`` (total bytes, rounded up to 8 for downstream
    alignment)."""
    fields: dict[str, tuple[int, int, str]] = {}
    offset = 0
    for f in decl.fields:
        size = _size_of(f.ty, sum_layouts, struct_layouts)
        offset = _align_up(offset, size)
        fields[f.name] = (offset, size, f.ty)
        offset += size
    return {"fields": fields, "size": _align_up(offset, 8)}


def compute_sum_layout(
    decl: SumDecl,
    sum_layouts: dict,
    struct_layouts: dict,
) -> dict:
    """Compute layout for a sum type:
    - tag (i32) at offset 0
    - per-variant payloads starting at offset 8 (aligned for i64)
    - total size = max over variants of payload end-offset

    Returns a dict with ``variants`` (name -> (tag_value, payloads
    list of (offset, size, capa_ty))) and ``size`` (total bytes,
    fits the largest variant + tag)."""
    variants: dict[str, tuple[int, list[tuple[int, int, str]]]] = {}
    max_size = 8  # tag + padding minimum
    for idx, v in enumerate(decl.variants):
        # Each variant's payloads start at offset 8 (after the tag
        # and padding for 8-byte alignment of the first payload).
        offset = 8
        payloads: list[tuple[int, int, str]] = []
        for ty in v.payload_tys:
            size = _size_of(ty, sum_layouts, struct_layouts)
            offset = _align_up(offset, size)
            payloads.append((offset, size, ty))
            offset += size
        variants[v.name] = (idx, payloads)
        max_size = max(max_size, _align_up(offset, 8))
    return {"variants": variants, "size": max_size}

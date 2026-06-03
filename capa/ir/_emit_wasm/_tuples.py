"""Tuple emission mixin.

Owns the Wasm lowering for tuple values: ``MakeTuple`` (a
``(v1, v2)`` literal) and ``Index`` over a tuple receiver.

Tuples in Capa are positional records with statically-known
element types (``(String, Int)`` is the only shape that matters
for the demos). At the Wasm level each tuple is a 16-byte heap
record allocated via ``$alloc``, with one uniform 8-byte slot
per element:

- Element 0 at offset 0
- Element 1 at offset 8

Each slot's encoding follows the same conventions as Option /
Result / variant payloads:

- ``Int`` -> i64 stored directly
- ``Float`` -> f64 in the slot
- ``Bool`` -> i32 extended to i64
- ``String`` -> packed (ptr | (len << 32)) as i64
- pointer-shaped (struct / sum / List / Map) -> i32 extended to i64

Arity: any positive integer. The 8-byte uniform slot stride
covers any element shape, so a tuple of arity N is just an
``N * 8``-byte heap record. ``_emit_make_tuple`` allocates that
many bytes; ``_emit_tuple_index`` reads slot ``i * 8``.
"""

from __future__ import annotations

from .._nodes import Index, MakeTuple, Value
from ._layout import WasmEmissionError


def _tuple_arity(tuple_ty: str) -> int:
    """Count elements in a tuple type string. ``(A, B)`` -> 2.
    Returns 0 when the string isn't tuple-shaped."""
    if not tuple_ty.startswith("(") or not tuple_ty.endswith(")"):
        return 0
    inner = tuple_ty[1:-1].strip()
    if not inner:
        return 0
    depth = 0
    n = 1
    for ch in inner:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        elif ch == "," and depth == 0:
            n += 1
    return n


def _tuple_elem_types(tuple_ty: str) -> list[str]:
    """``(String, Int)`` -> ``['String', 'Int']``. Mirrors
    capa.ir._lower._split_tuple_elem_types so the emitter can
    parse the same shape the lowerer produced."""
    if not tuple_ty.startswith("(") or not tuple_ty.endswith(")"):
        return []
    inner = tuple_ty[1:-1].strip()
    if not inner:
        return []
    out: list[str] = []
    buf = ""
    depth = 0
    for ch in inner:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(buf.strip())
            buf = ""
            continue
        buf += ch
    if buf.strip():
        out.append(buf.strip())
    return out


class _TupleEmissionMixin:
    def _is_tuple_ty(self, ty: str) -> bool:
        return ty.startswith("(") and ty.endswith(")") and ty != "()"

    def _emit_make_tuple(self, instr: MakeTuple) -> None:
        """Allocate a tuple record and write each element at its
        uniform 8-byte slot. The dst's Capa type tells us the
        element types; element shape selects the store opcode."""
        if instr.dst is None:
            raise WasmEmissionError("MakeTuple needs a dst")
        dst_ty = self._dst_capa_ty(instr.dst)
        elem_types = _tuple_elem_types(dst_ty)
        # When the lowerer didn't carry precise element types,
        # fall back to each element Value's ty.
        if len(elem_types) != len(instr.elements):
            elem_types = [e.ty or "Unknown" for e in instr.elements]
        arity = len(instr.elements)
        if arity < 1:
            raise WasmEmissionError(
                "MakeTuple requires at least one element"
            )
        total_size = arity * 8
        self._write(f"i32.const {total_size}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        for idx, (elem, ty) in enumerate(zip(instr.elements, elem_types)):
            self._write(f"local.get ${instr.dst}")
            offset = idx * 8
            self._store_tuple_slot(elem, ty, offset)

    def _store_tuple_slot(self, v: Value, ty: str, offset: int) -> None:
        """Store ``v`` at ``offset`` of the tuple addr on the
        operand stack. The addr was pushed by the caller; this
        helper pushes the value with the right encoding and emits
        the store. Mirrors the variant-payload encoding so down-
        stream consumers (Index reads) can decode uniformly."""
        if ty == "String":
            self._emit_pack_string_value_to_i64(v)
            self._write(f"i64.store offset={offset}")
            return
        if ty == "Float":
            self._push_value(v)
            self._write(f"f64.store offset={offset}")
            return
        if ty == "Bool":
            self._push_value(v)
            self._write("i64.extend_i32_u")
            self._write(f"i64.store offset={offset}")
            return
        if self._is_pointer_shape_ty(ty) or ty in self._variant_to_sum:
            # Pointer-shaped value: extend i32 to i64.
            self._push_value(v)
            self._write("i64.extend_i32_u")
            self._write(f"i64.store offset={offset}")
            return
        # Int / Unknown -> i64 store.
        self._push_value(v)
        self._write(f"i64.store offset={offset}")

    def _emit_tuple_index(self, instr: Index) -> None:
        """Lower ``pair[idx]`` for a tuple receiver. The index is
        a literal int in source (TuplePat destructuring lowers to
        ``Index(receiver=pair, index=lit_int(idx))``); the
        emitter loads the slot at ``idx * 8`` and decodes with
        the dst's recorded type.

        Called from the dispatch path in ``_emit_index`` when the
        receiver's type is a tuple."""
        if instr.dst is None:
            return
        if instr.index.kind != "lit_int":
            raise WasmEmissionError(
                f"tuple index must be a literal integer (got "
                f"kind={instr.index.kind!r}); dynamic indexing "
                f"into tuples isn't a Capa surface construct"
            )
        idx = int(instr.index.literal)
        offset = idx * 8
        dst_ty = self._dst_capa_ty(instr.dst) or ""
        # Push receiver pointer.
        self._push_value(instr.receiver)
        if dst_ty == "String":
            # Unpack packed i64 into dst's (ptr, len) locals.
            self._write(f"i64.load offset={offset}")
            self._write("local.set $_alloc_tmp_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_ptr")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_len")
            return
        if dst_ty == "Float":
            self._write(f"f64.load offset={offset}")
            self._write(f"local.set ${instr.dst}")
            return
        if dst_ty == "Bool":
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}")
            return
        head = dst_ty.split("<", 1)[0]
        if (head in self._struct_layouts
                or head in self._sum_layouts
                or dst_ty.startswith(("List", "Map", "Set"))
                or self._is_tuple_ty(dst_ty)):
            # A nested tuple element is an i32 pointer in the slot, just
            # like a struct / list element, so decode it the same way.
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}")
            return
        # Int / Unknown -> direct i64.load.
        self._write(f"i64.load offset={offset}")
        self._write(f"local.set ${instr.dst}")

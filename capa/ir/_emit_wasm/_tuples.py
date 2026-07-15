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
from .._lower_helpers import _split_tuple_elem_types
from ._layout import WasmEmissionError


def _is_unknown_slot_ty(ty: str) -> bool:
    """True iff ``ty`` is an unresolved placeholder (empty, ``Unknown``,
    ``Any``, or an analyzer tyvar ``?...``). Such a type carries no
    shape information, so the emitter cannot pick the correct slot
    encoding from it alone."""
    return ty in ("", "Unknown", "Any") or ty.startswith("?")


def _tuple_arity(tuple_ty: str) -> int:
    """Count elements in a tuple type string. ``(A, B)`` -> 2.
    Returns 0 when the string isn't tuple-shaped."""
    return len(_split_tuple_elem_types(tuple_ty))


def _tuple_elem_types(tuple_ty: str) -> list[str]:
    """``(String, Int)`` -> ``['String', 'Int']``. Delegates to the
    lowerer's arrow-aware ``_split_tuple_elem_types`` so the emitter
    parses the same shape the lowerer produced -- including a tuple
    whose elements are ``Fun(...) -> R`` values, whose ``->`` arrows
    must not be mistaken for bracket closes."""
    return _split_tuple_elem_types(tuple_ty)


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
        # Int -> i64 store. Fail-loud guard (defense in depth): a
        # pointer-shaped VALUE reaching an unresolved slot type is a
        # compiler type-propagation gap. The value is an i32 heap
        # pointer, so sizing the slot as a bare i64 would ship invalid
        # Wasm (an operand-stack type mismatch at the validator). The
        # guard only fires when the value itself is pointer-shaped, so
        # a legitimately i64-typed Int element never trips it.
        if _is_unknown_slot_ty(ty) and (
            self._is_pointer_shape_ty(v.ty or "")
            or (v.ty or "") in self._variant_to_sum
        ):
            raise WasmEmissionError(
                f"tuple element at offset {offset} has an unresolved "
                f"slot type {ty!r} but its value is pointer-shaped "
                f"(value type {v.ty!r}); the slot would be mis-sized "
                f"as i64. This is a compiler type-propagation gap, "
                f"not a source error."
            )
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
        if self._is_pointer_shape_ty(dst_ty):
            # A nested tuple / struct / sum / collection / trait-value
            # element is an i32 pointer in the slot, so decode it the
            # same way (i64.extend on store, i32.wrap on read).
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}")
            return
        # Int -> direct i64.load. Fail-loud guard (defense in depth):
        # when the dst binder type is unresolved we recover the slot's
        # real type from the receiver tuple's element list. If that
        # element is pointer-shaped the binder would be read as a bare
        # i64 and stored into an i32 local, shipping invalid Wasm.
        # Fail loud on that type-propagation gap; a genuine Int element
        # (non-pointer) still falls through to the i64.load below.
        if _is_unknown_slot_ty(dst_ty):
            recv_elems = _tuple_elem_types(instr.receiver.ty or "")
            slot_ty = recv_elems[idx] if idx < len(recv_elems) else ""
            if self._is_pointer_shape_ty(slot_ty) \
                    or slot_ty in self._variant_to_sum:
                raise WasmEmissionError(
                    f"tuple index {idx} binds an unresolved dst type "
                    f"{dst_ty!r} but the element is pointer-shaped "
                    f"(slot type {slot_ty!r}); reading it as an i64 "
                    f"would ship invalid Wasm. This is a compiler "
                    f"type-propagation gap, not a source error."
                )
        self._write(f"i64.load offset={offset}")
        self._write(f"local.set ${instr.dst}")

"""Struct + variant construction emission.

Three closely-related Wasm emitters were pulled out of the main
WasmEmitter class:

- ``_emit_variant_construction`` -- ``Ok(value)`` / ``Err(e)`` /
  user variant constructors that allocate the variant's heap
  record and lay out the tag + payload.
- ``_emit_make_struct`` -- ``Point { x: 1, y: 2 }`` literals.
- ``_emit_field_access`` -- ``p.x`` reads against either a
  built-in or user-defined struct layout.

All three share the same backing layout tables
(``self._struct_layouts``, ``self._sum_layouts``,
``self._variant_to_sum``) and the encoding helpers
(``_emit_pack_string_value_to_i64``, ``_emit_unpack_i64_to_string``,
``_is_pointer_shape_ty``) from the encoding mixin.

Audit P1 split: kept together because they share the same
layout-table accesses; splitting them further would force
duplicate inline checks at every call site.
"""

from __future__ import annotations

from .._nodes import (
    Call, FieldAccess, MakeStruct, Value,
)
from .._capa_types import BUILTIN_CAPS
from ._layout import (
    WasmEmissionError, _store_op_for_size, _load_op_for_size,
)


class _StructEmissionMixin:
    def _emit_variant_construction(self, instr: Call) -> None:
        """Emit code that allocates a sum-type instance, writes the
        variant tag at offset 0, and stores each payload at its
        layout-determined offset. Leaves the i32 pointer in
        ``instr.dst``."""
        sum_name = self._variant_to_sum[instr.callee_name]
        sum_layout = self._sum_layouts[sum_name]
        tag, payload_layouts = sum_layout["variants"][instr.callee_name]
        total_size = sum_layout["size"]
        if len(payload_layouts) != len(instr.args):
            raise WasmEmissionError(
                f"variant {instr.callee_name}: expected "
                f"{len(payload_layouts)} payloads, got {len(instr.args)}"
            )
        # Allocate. Leave pointer in dst local.
        if instr.dst is None:
            raise WasmEmissionError(
                "variant construction must bind a dst (its pointer)"
            )
        self._write(f"i32.const {total_size}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        # Store the discriminant tag at offset 0.
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {tag}")
        self._write("i32.store")
        # Store each payload at its offset. Phase 7B+ uses uniform
        # 8-byte payload slots for Option / Result. The arg's type
        # determines whether we store directly (Int -> i64) or
        # pack/extend:
        # - String: pack (ptr, len) into i64 = ptr | (len << 32)
        # - Pointer-shaped (struct, sum, list, map): extend i32
        #   to i64 to fit the uniform slot
        # - Bool: extend i32 to i64
        # - Int / Float: store as-is at the i64 slot
        for arg, (offset, size, _ty) in zip(instr.args, payload_layouts):
            self._write(f"local.get ${instr.dst}")
            if size == 8 and arg.ty == "String":
                self._emit_pack_string_value_to_i64(arg)
                self._write(f"i64.store offset={offset}")
                continue
            if size == 8 and arg.ty == "Bool":
                self._push_value(arg)
                self._write("i64.extend_i32_u")
                self._write(f"i64.store offset={offset}")
                continue
            is_pointer_shape = (
                self._is_pointer_shape_ty(arg.ty)
                # Variant constructors produce a sum-record pointer
                # (i32); the Value's ty carries the variant name
                # (e.g. "HelpRequested") rather than the sum name
                # (e.g. "ArgError"), so resolve via _variant_to_sum.
                or arg.ty in self._variant_to_sum
                or arg.kind == "variant_ctor"
            )
            if size == 8 and is_pointer_shape:
                # Pointer payload: extend i32 to i64.
                self._push_value(arg)
                self._write("i64.extend_i32_u")
                self._write(f"i64.store offset={offset}")
                continue
            if size == 8 and arg.ty == "Float":
                # Float payload stays as f64 in the slot.
                self._push_value(arg)
                self._write(f"f64.store offset={offset}")
                continue
            if arg.ty == "Unit" or arg.kind == "lit_unit":
                # Unit values have no Wasm representation;
                # _push_value is a no-op. Write a placeholder zero
                # into the slot so it stays deterministically
                # initialised. The dst addr was already pushed at
                # the top of this iteration.
                self._write("i64.const 0")
                self._write(f"i64.store offset={offset}")
                continue
            self._push_value(arg)
            self._write(f"{_store_op_for_size(size)} offset={offset}")

    def _emit_make_struct(self, instr: MakeStruct) -> None:
        """Emit alloc + per-field store for a struct literal. The
        pointer to the newly-allocated struct lands in ``instr.dst``.
        Field order follows the declaration; the lowerer guarantees
        ``instr.fields`` matches.

        String fields are stored as two adjacent i32s (ptr@offset,
        len@offset+4) so the FieldAccess emitter can recover the
        pair without unpacking. Other field types use the regular
        size-dispatched store."""
        layout = self._struct_layouts.get(instr.type_name)
        if layout is None:
            raise WasmEmissionError(
                f"struct {instr.type_name!r} has no layout; was the "
                f"type declared in module.types?"
            )
        self._write(f"i32.const {layout['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        for fname, fval in instr.fields:
            f_info = layout["fields"].get(fname)
            if f_info is None:
                raise WasmEmissionError(
                    f"struct {instr.type_name}: field {fname!r} not in layout"
                )
            offset, size, field_ty = f_info
            if field_ty in BUILTIN_CAPS:
                # Capability field: erased at the Wasm level. The
                # slot exists in the struct layout (so subsequent
                # FieldAccess on it returns *something*), but no
                # value is stored; the FieldAccess emitter knows
                # not to read from a capability-typed field. We
                # could omit the slot entirely, but keeping it
                # makes layouts uniform with the analyzer's view.
                #
                # Slices 25.2 - 25.6 (2026-05-30): Fs / Net / Db /
                # Proc / Env / Clock become i32 handles the struct
                # must carry so a restricted cap stashed in a record
                # survives across function boundaries.
                if field_ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    self._write(f"local.get ${instr.dst}")
                    self._push_value(fval)
                    self._write(f"i32.store offset={offset}")
                continue
            if field_ty == "String":
                # Two i32 stores: ptr at offset, len at offset+4.
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_ptr_only(fval)
                self._write(f"i32.store offset={offset}")
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_len_only(fval)
                self._write(f"i32.store offset={offset + 4}")
                continue
            self._write(f"local.get ${instr.dst}")
            self._push_value(fval)
            if field_ty == "Float":
                # f64 field stays as a native f64 slot; using
                # ``i64.store`` here would trip the Wasm validator
                # because ``_push_value`` left an f64 on the stack.
                self._write(f"f64.store offset={offset}")
            else:
                self._write(f"{_store_op_for_size(size)} offset={offset}")

    def _emit_field_access(self, instr: FieldAccess) -> None:
        """Load a struct field by offset. The receiver is an i32
        pointer to the struct in linear memory; we add the field's
        layout offset and emit the appropriate load opcode.

        String fields expand to two i32 loads (offset, offset+4)
        into the destination String's ``${dst}_ptr`` and
        ``${dst}_len`` locals -- mirroring how String params and
        locals carry their (ptr, len) pair through the emitter."""
        # Roadmap S3.4: a typestate receiver carries a state index in
        # its type string (``Socket[Connected]``); the struct layout is
        # keyed by the bare name, so strip the index before lookup.
        recv_ty = instr.receiver.ty.split("[", 1)[0]
        layout = self._struct_layouts.get(recv_ty)
        if layout is None:
            # Analyzer-side type-propagation gap: the FieldAccess's
            # receiver Value sometimes carries ``ty="Unknown"`` even
            # though the receiver itself is a local with a concrete
            # struct type recorded in fn.locals. Fall back to the
            # local's declared type before giving up.
            if (instr.receiver.kind in ("local", "param")
                    and self._current_fn is not None
                    and instr.receiver.name in self._current_fn.locals):
                fallback = self._current_fn.locals[instr.receiver.name].split("[", 1)[0]
                layout = self._struct_layouts.get(fallback)
                if layout is not None:
                    recv_ty = fallback
        if layout is None:
            raise WasmEmissionError(
                f"FieldAccess on receiver of type {recv_ty!r}: no "
                f"struct layout known. The IR's type inference must "
                f"have produced an unexpected receiver type."
            )
        f_info = layout["fields"].get(instr.field)
        if f_info is None:
            raise WasmEmissionError(
                f"struct {recv_ty}: field {instr.field!r} not found"
            )
        offset, size, field_ty = f_info
        if field_ty in BUILTIN_CAPS:
            # Capability field: erased at the Wasm level. The dst
            # local has no Wasm representation either; consumers
            # that need to invoke a method on the capability route
            # to the imported function by name without reading the
            # receiver value.
            #
            # Slices 25.2 - 25.6 (2026-05-30): Fs / Net / Db / Proc
            # / Env / Clock become i32 handles the consumer threads
            # as the receiver of subsequent privileged calls
            # (closing audit slice 25 F1 for cap values stashed in
            # records).
            if field_ty in (
                "Fs", "Net", "Db", "Proc", "Env", "Clock",
            ):
                self._push_value(instr.receiver)
                self._write(f"i32.load offset={offset}")
                self._write(f"local.set ${instr.dst}")
            return
        if field_ty == "String":
            # Two i32 loads: ptr@offset, len@offset+4 -> dst's pair.
            self._push_value(instr.receiver)
            self._write(f"i32.load offset={offset}")
            self._write(f"local.set ${instr.dst}_ptr")
            self._push_value(instr.receiver)
            self._write(f"i32.load offset={offset + 4}")
            self._write(f"local.set ${instr.dst}_len")
            return
        self._push_value(instr.receiver)
        if field_ty == "Float":
            # f64 slot: load the native f64, not an i64 reinterp.
            self._write(f"f64.load offset={offset}")
        else:
            self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${instr.dst}")


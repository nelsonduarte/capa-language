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
    Call, FieldAccess, FieldStore, MakeStruct, Value,
)
from .._capa_types import BUILTIN_CAPS
from ._layout import (
    WasmEmissionError, _store_op_for_size, _load_op_for_size,
    _strip_type_qualifiers, _TYPE_ID_OFFSET,
)


class _StructEmissionMixin:
    def _capture_type_of(self, recv: Value) -> str | None:
        """Return the concrete Capa type of a captured local/param
        receiver while a lifted lambda body is being emitted, or
        ``None`` when the receiver is not a capture.

        A lambda nested inside an impl method captures ``self`` (and
        possibly other struct locals); the lowerer leaves the
        FieldAccess receiver Value typed ``Unknown`` and the
        synthesised lifted function's ``locals`` omits the name
        because it is a capture, not a body-local. The lift's env
        layout (``self._current_captures``) did resolve the concrete
        type, so it is the authoritative source here -- the same map
        ``_push_value`` already uses to load the captured pointer."""
        if recv.kind not in ("local", "param"):
            return None
        entry = self._current_captures.get(recv.name)
        if entry is None:
            return None
        _, capa_ty = entry
        return _strip_type_qualifiers(capa_ty)

    def _resolve_receiver_layout(self, recv: Value):
        """Resolve ``(layout, recv_ty)`` for a struct-field receiver, or
        ``(None, recv_ty)`` when no layout is known. Shared by
        ``_emit_field_access`` and ``_emit_field_store`` so the READ and
        the WRITE never resolve the receiver differently.

        Three sources are tried in order:

        1. The receiver Value's own type (the common case).
        2. The current function's declared ``locals`` -- covers an
           analyzer type-propagation gap where the receiver Value
           carries ``ty="Unknown"`` while ``fn.locals`` names the
           concrete struct.
        3. The lift's env layout (``_capture_type_of``) -- covers a
           lambda nested inside an impl method that captures ``self``
           (or any struct local): its concrete type is threaded neither
           onto the receiver Value (stays ``Unknown``) nor into the
           synthesised lifted function's ``locals`` (it is a capture,
           not a body-local)."""
        recv_ty = _strip_type_qualifiers(recv.ty)
        layout = self._struct_layouts.get(recv_ty)
        if layout is None and (
            recv.kind in ("local", "param")
            and self._current_fn is not None
            and recv.name in self._current_fn.locals
        ):
            fallback = _strip_type_qualifiers(
                self._current_fn.locals[recv.name]
            )
            local_layout = self._struct_layouts.get(fallback)
            if local_layout is not None:
                layout, recv_ty = local_layout, fallback
        if layout is None:
            cap = self._capture_type_of(recv)
            if cap is not None:
                cap_layout = self._struct_layouts.get(cap)
                if cap_layout is not None:
                    layout, recv_ty = cap_layout, cap
        return layout, recv_ty

    def _resolve_construction_sum(self, instr: Call) -> str:
        """Resolve the sum type a variant constructor builds.

        The ``_variant_to_sum`` table is keyed by the bare variant
        name, which collides once a generic sum is monomorphised into
        several concrete clones that share a variant name (e.g.
        ``Opt<T>`` -> ``Opt__Char`` and ``Opt__Point`` both declare a
        ``Just`` variant). The table then maps ``Just`` to whichever
        clone was declared last, so a ``Just('z')`` whose dst is typed
        ``Opt__Char`` would be laid out with ``Opt__Point``'s payload
        sizes -- a silent miscompile.

        The monomorphiser pins the constructor call's dst local to the
        concrete sum type, so prefer that: if the dst's declared type
        names a sum layout that actually declares this variant, use it.
        Fall back to the bare-name table for the non-generic case (and
        for built-in Option / Result, whose dst type is the bare sum
        name already)."""
        if instr.dst is not None and self._current_fn is not None:
            dst_ty = self._current_fn.locals.get(instr.dst, "")
            head = _strip_type_qualifiers(dst_ty)
            layout = self._sum_layouts.get(head)
            if layout is not None and instr.callee_name in layout["variants"]:
                return head
        return self._variant_to_sum[instr.callee_name]

    def _emit_variant_construction(self, instr: Call) -> None:
        """Emit code that allocates a sum-type instance, writes the
        variant tag at offset 0, and stores each payload at its
        layout-determined offset. Leaves the i32 pointer in
        ``instr.dst``."""
        sum_name = self._resolve_construction_sum(instr)
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
        # Multi-impl-trait dispatch header for a SUM participant: write
        # this concrete sum's type-id at the uniform offset 4 (free
        # padding between the offset-0 tag and the offset-8 payloads).
        # match / equality / TryUnwrap read only offset 0 and offset 8+,
        # so this write is invisible to every other sum operation. Only
        # sums that implement a multi-impl trait carry a type-id.
        if sum_name in getattr(self, "_header_sum_types", ()):
            type_id = self._type_ids.get(sum_name)
            if type_id is None:
                raise WasmEmissionError(
                    f"sum {sum_name!r} participates in multi-impl "
                    f"dispatch but has no assigned type-id; the trait "
                    f"dispatch setup is inconsistent."
                )
            self._write(f"local.get ${instr.dst}")
            self._write(f"i32.const {type_id}")
            self._write(f"i32.store offset={_TYPE_ID_OFFSET}")
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

    def _emit_ioerror_construction(self, instr: Call) -> None:
        """Construct a built-in ``IoError`` record from a positional
        ``IoError(message)`` / ``IoError(message, cause)`` call.

        IoError is the one built-in value type Capa builds with call
        syntax rather than a struct literal; the Python runtime backs it
        with a ``@dataclass(message, cause="")``. No ``$IoError`` function
        is emitted, so lower the construction inline exactly the way
        ``_emit_make_struct`` lowers a struct literal: allocate the record
        and store each String field as a (ptr, len) pair at its layout
        offset (see ``_IOERROR_LAYOUT``). A one-arg call leaves ``cause``
        as the empty string (ptr=0, len=0), matching the dataclass default.
        Both forms now render identically to the Python backend's
        ``__str__``: the FormatStr emitter's IoError branch (in
        ``_strings.py``) branches on ``cause_len`` at runtime and
        renders ``message`` when the cause is empty, ``message: cause``
        otherwise -- so the constructed error's observable behaviour
        (formatted / matched) matches Python for the one-arg and
        two-arg forms alike."""
        if instr.dst is None:
            raise WasmEmissionError(
                "IoError construction must bind a dst (its pointer)"
            )
        layout = self._struct_layouts["IoError"]
        fields = list(layout["fields"].items())
        if not 1 <= len(instr.args) <= len(fields):
            raise WasmEmissionError(
                f"IoError takes 1 or {len(fields)} arguments, got "
                f"{len(instr.args)}"
            )
        self._write(f"i32.const {layout['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        for i, (fname, (offset, _size, _field_ty)) in enumerate(fields):
            if i < len(instr.args):
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_ptr_only(instr.args[i])
                self._write(f"i32.store offset={offset}")
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_len_only(instr.args[i])
                self._write(f"i32.store offset={offset + 4}")
                continue
            # Absent trailing field (the one-arg ``cause`` default):
            # the empty string is (ptr=0, len=0).
            self._write(f"local.get ${instr.dst}")
            self._write("i32.const 0")
            self._write(f"i32.store offset={offset}")
            self._write(f"local.get ${instr.dst}")
            self._write("i32.const 0")
            self._write(f"i32.store offset={offset + 4}")

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
        # Multi-impl-trait dispatch header: write this concrete type's
        # type-id into the offset-4 word (the uniform dispatch offset)
        # so a later method call through a trait-typed receiver can load
        # the tag and dispatch to the right impl. The header is invisible
        # to field iteration (it is not in layout["fields"]); only
        # construction writes it. Offset 4 (not 0) so a sum participant
        # can carry its variant tag at offset 0 and the dispatcher reads
        # the type-id from the same offset for both.
        if layout.get("has_header"):
            type_id = self._type_ids.get(instr.type_name)
            if type_id is None:
                raise WasmEmissionError(
                    f"struct {instr.type_name!r} reserves a dispatch "
                    f"header but has no assigned type-id; the trait "
                    f"dispatch setup is inconsistent."
                )
            self._write(f"local.get ${instr.dst}")
            self._write(f"i32.const {type_id}")
            self._write(f"i32.store offset={_TYPE_ID_OFFSET}")
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
        # keyed by the bare name, so strip qualifiers before lookup.
        layout, recv_ty = self._resolve_receiver_layout(instr.receiver)
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

    def _emit_field_store(self, instr: FieldStore) -> None:
        """Write a value into a struct field slot in place. The
        receiver is an i32 pointer to the heap record; we resolve the
        field's layout offset and emit the store opcode that mirrors
        the per-field-type encoding ``_emit_make_struct`` and
        ``_emit_field_access`` use. This is the symmetric WRITE to a
        field READ; reusing the same layout machinery guarantees the
        read-back recovers exactly what was stored.

        Wasm store ordering: push the field address (receiver pointer),
        then the value, then the store opcode (the offset rides on the
        opcode)."""
        layout, recv_ty = self._resolve_receiver_layout(instr.receiver)
        if layout is None:
            raise WasmEmissionError(
                f"FieldStore on receiver of type {recv_ty!r}: no "
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
            # Capability field. Fs / Net / Db / Proc / Env / Clock
            # carry i32 handles (slices 25.2 - 25.6); store the
            # handle. Every other cap is erased and has no Wasm value,
            # so the store is a no-op (matching _emit_make_struct).
            if field_ty in ("Fs", "Net", "Db", "Proc", "Env", "Clock"):
                self._push_value(instr.receiver)
                self._push_value(instr.src)
                self._write(f"i32.store offset={offset}")
            return
        if field_ty == "String":
            # Two i32 stores: ptr@offset, len@offset+4.
            self._push_value(instr.receiver)
            self._push_string_field_ptr_only(instr.src)
            self._write(f"i32.store offset={offset}")
            self._push_value(instr.receiver)
            self._push_string_field_len_only(instr.src)
            self._write(f"i32.store offset={offset + 4}")
            return
        self._push_value(instr.receiver)
        self._push_value(instr.src)
        if field_ty == "Float":
            # f64 slot stays native f64; matches _emit_make_struct.
            self._write(f"f64.store offset={offset}")
        else:
            self._write(f"{_store_op_for_size(size)} offset={offset}")


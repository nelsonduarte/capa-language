"""List<T> emission mixin.

Owns the Wasm lowering for ``List<T>``: allocation of the 16-byte
header + element data array, method dispatch (length / is_empty /
push / contains -- HOF dispatch is delegated to the closures mixin),
``xs[i]`` indexing, and ``for x in xs`` iteration.

Each list value is an i32 pointer to a 16-byte header (len, cap,
data_ptr, padding). The data array is a separate allocation sized
``cap * elem_size``; ``push`` grows it via ``memory.copy`` when at
capacity. ``String`` elements live as packed i64 (ptr in low 32,
len in high 32) so they fit the uniform 8-byte slot.

Depends on the layout primitives in ``_layout`` (header offsets,
element-size dispatch) and the closures mixin (``_emit_list_hof``
is invoked from ``_emit_list_method_call`` when the method is
``map`` / ``filter`` / ``fold``).
"""

from __future__ import annotations

from .._nodes import For, Index, MakeList, MakeRange, MethodCall, Value
from ._layout import (
    WasmEmissionError,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _OPTION_LAYOUT,
    _element_type_of_list,
    _load_op_for_size, _store_op_for_size,
)


class _ListEmissionMixin:
    def _emit_list_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a List receiver. Methods that read
        the header (length, is_empty) emit a single i32.load + a
        compare/store. ``push`` does grow-if-needed + store + len
        increment. ``contains`` walks the array linearly. HOFs
        (``map`` / ``filter`` / ``fold``) route through the closures
        mixin, which lifts each lambda to a top-level Wasm function
        and dispatches the body via ``call_indirect``."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        elem_ty = _element_type_of_list(recv_ty)
        elem_size = self._size_of(elem_ty)

        if method in ("map", "filter", "fold", "flat_map"):
            self._emit_list_hof(instr, elem_ty)
            return
        if method == "reverse":
            self._emit_list_reverse(instr, elem_size, elem_ty)
            return
        if method == "enumerate":
            self._emit_list_enumerate(instr, elem_size, elem_ty)
            return
        if method == "zip":
            self._emit_list_zip(instr, elem_size, elem_ty)
            return
        if method == "length":
            # Result is Int (i64). Capa.List.length returns the
            # number of elements; the header stores it as i32, so
            # extend to i64 before binding the dst.
            self._push_value(recv)
            self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
            self._write("i64.extend_i32_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            self._push_value(recv)
            self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
            self._write("i32.eqz")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "push":
            self._emit_list_push(recv, instr.args[0], elem_size, elem_ty)
            return
        if method == "get":
            self._emit_list_get(recv, instr.args[0], elem_size, elem_ty,
                                instr.dst)
            return
        if method in ("first", "last"):
            self._emit_list_first_last(
                recv, method, elem_size, elem_ty, instr.dst,
            )
            return
        if method in ("find", "find_index"):
            self._emit_list_find(
                instr, method, elem_size, elem_ty,
            )
            return
        if method == "sorted_by":
            self._emit_list_sorted_by(instr, elem_size, elem_ty)
            return
        if method == "contains":
            # Pointer-shape elements (struct / sum / tuple / nested
            # List) compare structurally via the element's generated
            # ``$eq_*`` helper (collected by ``_collect_eq_types``
            # when it sees a pointer-shape ``List.contains``), matching
            # the Python backend's by-value semantics. Scalars and
            # String keep their existing identity / byte-compare paths.
            if self._is_pointer_shape_ty(elem_ty):
                self._emit_list_pointer_contains(
                    recv, instr.args[0], elem_size, elem_ty,
                )
            else:
                self._emit_list_contains(
                    recv, instr.args[0], elem_size, elem_ty,
                )
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"List method {method!r} is not implemented on the Wasm backend"
        )

    def _emit_list_push(
        self, recv: Value, elem: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Emit ``recv.push(elem)``. Grows the data array if the
        list is at capacity (doubling strategy); stores the element
        at ``data_ptr + len * elem_size``; increments len.

        Uses ``$_m_scrut`` / ``$_m_tag`` / ``$_alloc_tmp`` as scratch
        for the list pointer, current length, and new data pointer
        respectively; these are guaranteed declared by
        ``_collect_locals``."""
        list_local = "_m_scrut"
        len_local = "_m_tag"
        # Stash the list pointer so we can re-read header fields
        # without re-evaluating the receiver.
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        # Branch: if len >= cap, grow. Otherwise reuse data array.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"local.tee ${len_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # Grow: new_cap = max(cap * 2, 8). Allocate fresh data, copy
        # old contents, install in header. ``memory.copy`` (bulk
        # memory ops) is supported by wasmtime; we use it for the
        # element copy because the loop alternative would be tedious
        # to emit by hand.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.const 2")
        self._write("i32.mul")
        # If cap was 0, new_cap is 0; bump to 8 in that case.
        self._write("local.tee $_alloc_tmp")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_alloc_tmp")
        self._indent -= 1
        self._write("end")
        # Allocate new data array: $_alloc_tmp * elem_size bytes.
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("call $alloc")
        # Stack: new_data_ptr. Save it.
        self._write("local.tee $_m_tag")  # reuse len_local as new_data
        # Now memory.copy: dst=new_data, src=old_data, n=len*elem_size
        # Sequence: dst, src, size.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header: data_ptr = new_data, cap = new_cap.
        self._write(f"local.get ${list_local}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Refresh the cached len_local; it lost its value when we
        # reused $_m_tag.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"local.set ${len_local}")
        self._indent -= 1
        self._write("end")
        # Store the new element at data[len]. Address = data_ptr +
        # len * elem_size.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${len_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        if elem_ty == "String":
            # Pack (ptr, len) into the 8-byte slot. Mirrors the
            # same packing dance _emit_make_list does for String
            # elements; the consumer (for-iter / Index over
            # List<String>) unpacks the inverse way.
            self._push_string_value_as_ptr_len(elem)
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("drop")
            self._write("i64.extend_i32_u")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.or")
            self._write("i64.store")
        else:
            self._push_value(elem)
            if elem_ty == "Float":
                # f64.store to write the IEEE-754 bit pattern; a
                # plain i64.store would type-mismatch since the
                # operand stack carries f64 after _push_value.
                self._write("f64.store")
            else:
                self._write(_store_op_for_size(elem_size))
        # Increment len.
        self._write(f"local.get ${list_local}")
        self._write(f"local.get ${len_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    def _emit_list_contains(
        self, recv: Value, needle: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Emit a linear-scan ``recv.contains(needle)``. Leaves an
        i32 0/1 on the stack. Scalar elements (Int / Bool / pointer)
        compare via i32.eq / i64.eq; String elements unpack the
        packed-i64 slot to a (ptr, len) pair and route to the
        ``$str_eq`` byte-compare helper."""
        if elem_ty == "String":
            self._emit_list_string_contains(recv, needle)
            return
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Compare op + needle width depend on the element type.
        # Float must use a dedicated f64 scratch + ``f64.eq`` + an
        # f64 element load: a Float needle pushes f64 onto the stack,
        # so stashing it into the i64 scratch (``local.set
        # $_alloc_tmp_i64``) type-mismatches the wasm verifier, and
        # an ``i64.eq`` bit-compare would give wrong NaN semantics
        # (Python: ``float('nan') != float('nan')``; bit-eq says
        # equal). This mirrors the Set<Float> membership fix in
        # ``_sets.py`` (``$_alloc_tmp_f64`` + ``f64.eq``).
        if elem_ty == "Float":
            eq_op = "f64.eq"
            load_op = "f64.load"
            self._push_value(needle)
            self._write("local.set $_alloc_tmp_f64")
            needle_local = "_alloc_tmp_f64"
        elif elem_size == 8:
            # Int (or other 8-byte scalar): i64 scratch + i64.eq.
            eq_op = "i64.eq"
            load_op = _load_op_for_size(elem_size)
            self._push_value(needle)
            self._write(f"local.set $_alloc_tmp_i64")
            needle_local = "_alloc_tmp_i64"
        else:
            # Bool / Char: 4-byte i32 scratch + i32.eq.
            eq_op = "i32.eq"
            load_op = _load_op_for_size(elem_size)
            self._push_value(needle)
            self._write(f"local.set $_alloc_tmp")
            needle_local = "_alloc_tmp"
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        # Loop: while idx < len, compare element with needle; break
        # with 1 on match; fall through to 0 if none matched.
        self._block_counter += 1
        loop_label = f"$C{self._block_counter}_loop"
        exit_label = f"$C{self._block_counter}_exit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> push 0 and exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Compare element with needle.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        self._write(f"local.get ${needle_local}")
        self._write(eq_op)
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Advance index and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        # Loop never falls through; the outer block expects an
        # i32 result, so an unreachable terminator satisfies the
        # type-checker without producing a spurious value.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_list_string_contains(
        self, recv: Value, needle: Value,
    ) -> None:
        """Emit ``recv.contains(needle)`` for ``List<String>``. Each
        element is stored as a packed i64 in the data array (low 32
        bits = ptr, high 32 bits = len); the needle's (ptr, len)
        pair is byte-compared against each element via the shared
        ``$str_eq`` helper. Leaves an i32 0/1 on the stack.

        Uses the same ``_str_a_*`` / ``_str_b_*`` scratch the String
        method emitters use, plus ``$_m_scrut`` (list pointer) and
        ``$_m_tag`` (index) -- all declared by ``_collect_locals``
        once ``has_string_method`` + ``has_list_method`` fire."""
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Stash the needle's (ptr, len) in $_str_b_ptr / $_str_b_len
        # so the inner loop can call $str_eq without re-evaluating
        # the needle expression each iteration.
        self._push_string_value_as_ptr_len(needle)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # Stash the list pointer and reset idx.
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop_label = f"$C{self._block_counter}_loop"
        exit_label = f"$C{self._block_counter}_exit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> push 0 + exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Load packed i64 at data[idx], unpack into _str_a_ptr/_len.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i32.wrap_i64")
        self._write("local.set $_str_a_ptr")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write("local.set $_str_a_len")
        # Compare element vs needle via $str_eq.
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Advance and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        # Loop body always exits via br; the outer block's i32 result
        # is satisfied by an unreachable terminator the validator
        # treats as polymorphic.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_list_pointer_contains(
        self, recv: Value, needle: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Emit a linear-scan ``recv.contains(needle)`` for a
        pointer-shape element type (struct / sum / tuple / nested
        List). Each element is a 4-byte i32 heap pointer; the compare
        is the element type's generated ``$eq_<key>`` helper (deep,
        by-value), so two distinct records with the same contents
        match - mirroring the Python backend's structural ``in``.
        Leaves an i32 0/1 on the stack.

        Uses ``$_m_scrut`` (list pointer), ``$_m_tag`` (index), and
        ``$_alloc_tmp`` (the needle pointer), all declared by
        ``_collect_locals``."""
        from ._equality import _eq_key
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Stash the needle pointer once so the inner loop does not
        # re-evaluate the needle expression each iteration.
        self._push_value(needle)
        self._write("local.set $_alloc_tmp")
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop_label = f"$C{self._block_counter}_loop"
        exit_label = f"$C{self._block_counter}_exit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> push 0 and exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Compare element pointer vs needle pointer via the element's
        # structural eq helper. Element address = data_ptr + idx *
        # elem_size; load the 4-byte i32 pointer there.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i32.load")
        self._write("local.get $_alloc_tmp")
        self._write(f"call $eq_{_eq_key(elem_ty)}")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Advance index and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        # Loop never falls through; satisfy the block's i32 result
        # with an unreachable terminator.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_list_get(
        self, recv: Value, idx: Value, elem_size: int, elem_ty: str, dst,
    ) -> None:
        """``xs.get(i) -> Option<T>``: bounds-check the index and
        return Some(xs[i]) when valid, None otherwise. Allocates a
        fresh 16-byte Option record each call.

        Payload encoding into the Option's 8-byte slot mirrors how
        the data array stores each element:

        - Int: 8-byte i64 slot, direct i64 copy
        - Float: 8-byte f64 slot, f64 copy
        - Bool: 4-byte i32 slot, extend i32 -> i64 to fit uniform
          Option payload slot
        - String: 8-byte packed-i64 slot, direct i64 copy
        - pointer-shaped (struct/sum/list/map): 4-byte i32 slot,
          extend i32 -> i64
        """
        if dst is None:
            return
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        result_local = "_alloc_tmp_result"
        # Stash list pointer + the i64 index (we check bounds at
        # i64 width before wrapping; see the same audit-hardening
        # in _emit_index for the trap-style xs[i] path). Wrapping
        # a negative i64 like ``-2**32 = 0xFFFFFFFF_00000000`` to
        # i32 gives 0, which would pass an i32-width bounds check
        # and silently return Some(xs[0]) -- Python's
        # List.get returns None on i < 0. The i64-width check
        # makes both backends agree.
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._push_value(idx)
        self._write("local.set $_bounds_idx_i64")
        # Alloc Option<T> result up front; tag filled by branch.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        # Bounds check at i64 width: idx < 0 OR idx >= len -> None.
        self._write("local.get $_bounds_idx_i64")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("local.get $_bounds_idx_i64")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i64.extend_i32_u")
        self._write("i64.ge_s")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        # Out of bounds: None (tag = 1).
        self._write(f"local.get ${result_local}")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # In bounds: Some(xs[i]). Tag = 0. Wrap the i64 idx once
        # into ``${idx_local}`` for the address compute below; we
        # know it's in [0, len) so the wrap is lossless.
        self._write("local.get $_bounds_idx_i64")
        self._write("i32.wrap_i64")
        self._write(f"local.set ${idx_local}")
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")
        self._write("i32.store")
        # Stack: []. Push result_ptr (target of the payload store),
        # then push the element address, then load and store
        # through type-appropriate ops.
        self._write(f"local.get ${result_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        # Stack: [result_ptr, elem_addr]; load + store into the
        # Option's 8-byte Some slot per the element shape.
        self._emit_load_elem_store_option_payload(elem_ty)
        self._indent -= 1
        self._write("end")
        # Bind result Option pointer to dst.
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

    def _emit_load_elem_store_option_payload(self, elem_ty: str) -> None:
        """Operand stack on entry: ``[result_ptr, elem_addr]``. Load the
        list element at ``elem_addr`` and store it into the Some payload
        slot (offset 8) of the Option record at ``result_ptr``,
        choosing the load / store widths from the element shape. Shared
        by ``get`` / ``first`` / ``last`` / ``find`` so the payload
        encoding never drifts between them."""
        if elem_ty == "Float":
            self._write("f64.load")
            self._write("f64.store offset=8")
        elif elem_ty == "Bool":
            self._write("i32.load")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
        elif elem_ty == "String":
            self._write("i64.load")
            self._write("i64.store offset=8")
        elif self._is_pointer_shape_ty(elem_ty):
            # Pointer-shape element (struct / sum / collection / tuple /
            # trait value): the list slot holds a 4-byte i32 pointer;
            # i64-extend it into the Option's uniform 8-byte Some slot.
            self._write("i32.load")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
        else:
            # Int (or unknown defaulting to i64). Direct i64 copy.
            self._write("i64.load")
            self._write("i64.store offset=8")

    def _emit_list_first_last(
        self, recv: Value, method: str, elem_size: int, elem_ty: str, dst,
    ) -> None:
        """``xs.first()`` / ``xs.last() -> Option<T>``. Returns
        ``Some(xs[0])`` / ``Some(xs[len-1])`` on a non-empty list and
        ``None`` on an empty one (matching the Python ``CapaList.first``
        / ``last``: ``Some(self[0])``/``Some(self[-1])`` if ``len > 0``
        else ``None``). Allocates a fresh 16-byte Option record."""
        if dst is None:
            return
        list_local = "_m_scrut"
        result_local = "_alloc_tmp_result"
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        # Alloc the Option record up front; tag filled by the branch.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        # len == 0 -> None.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"local.get ${result_local}")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Some(elem). tag = 0.
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")
        self._write("i32.store")
        # Element address. first -> idx 0; last -> idx len-1.
        self._write(f"local.get ${result_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        if method == "last":
            self._write(f"local.get ${list_local}")
            self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
            self._write("i32.const 1")
            self._write("i32.sub")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
        # first: address is just data_ptr (idx 0).
        self._emit_load_elem_store_option_payload(elem_ty)
        self._indent -= 1
        self._write("end")
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

    def _emit_list_find(
        self, instr: MethodCall, method: str, elem_size: int, elem_ty: str,
    ) -> None:
        """``xs.find(pred) -> Option<T>`` / ``xs.find_index(pred) ->
        Option<Int>``. Linear scan invoking the predicate closure on
        each element via the shared closure-call ABI; returns the first
        match (the element for ``find``, its index for ``find_index``)
        wrapped in ``Some``, or ``None`` when nothing matches. Matches
        the Python ``CapaList.find`` / ``find_index`` first-match-wins
        order, including a match at index 0 and at the last index."""
        recv = instr.receiver
        pred = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        sig_key = self._closure_sig_key_for([elem_ty], "Bool")
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.{method}: no closure registered with sig "
                f"{sig_key!r} (elem={elem_ty!r})"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        result_local = "_alloc_tmp_result"
        # Stash the list pointer + the closure value.
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._push_value(pred)
        self._write("local.set $_lam_fn_tmp")
        # Alloc the Option record up front; default to None (tag = 1).
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        self._write(f"local.get ${result_local}")
        self._write("i32.const 1")
        self._write("i32.store")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop_label = f"$Lfind{self._block_counter}_loop"
        exit_label = f"$Lfind{self._block_counter}_exit"
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> exit (result stays None).
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # Call pred(xs[idx]): push env_ptr, the decoded element,
        # then fn_idx + call_indirect.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # Element address -> decode into closure-arg shape.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_load_elem_for_call(elem_ty)
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")
        # If the predicate returned true, build Some and exit.
        self._write("if")
        self._indent += 1
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")
        self._write("i32.store")
        if method == "find_index":
            # Payload is the index as i64.
            self._write(f"local.get ${result_local}")
            self._write(f"local.get ${idx_local}")
            self._write("i64.extend_i32_s")
            self._write("i64.store offset=8")
        else:
            # Payload is the element xs[idx].
            self._write(f"local.get ${result_local}")
            self._write(f"local.get ${list_local}")
            self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
            self._emit_load_elem_store_option_payload(elem_ty)
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Advance index and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

    def _emit_list_sorted_by(
        self, instr: MethodCall, elem_size: int, elem_ty: str,
    ) -> None:
        """``xs.sorted_by(cmp) -> List<T>``: a NEW list sorted by the
        user comparator (``cmp(a, b)`` returns Int < 0 / 0 / > 0). The
        receiver is not mutated.

        Stability: Python's ``sorted`` (Timsort) is stable, so equal-
        comparing elements keep their input order. We reproduce that
        with an iterative bottom-up MERGE sort whose merge takes the
        left element when ``cmp(left, right) <= 0`` (left-biased on
        ties), which is the textbook stable merge. The classic
        in-place quicksort / heapsort are NOT stable and would diverge
        from Python on ties, so merge sort is the only correct choice
        here.

        Layout: copy the receiver's data array into a fresh buffer
        ``A`` (the result list's storage), allocate a scratch buffer
        ``B`` of the same size, then merge runs of width ``w = 1, 2,
        4, ...`` from ``A`` into ``B`` and swap the roles each pass.
        After the final pass the sorted data lives in whichever buffer
        the loop left it in; we point the result header at that one.
        Every element slot is ``elem_size`` bytes (8 for Int / Float /
        String / pointer-packed, 4 for Bool / pointer-shape), copied
        verbatim with ``memory.copy`` so the encoding is shape-
        agnostic; only the comparator call decodes the element."""
        recv = instr.receiver
        cmp = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        sig_key = self._closure_sig_key_for([elem_ty, elem_ty], "Int")
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.sorted_by: no closure registered with sig "
                f"{sig_key!r} (elem={elem_ty!r})"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        es = elem_size
        # Locals (all already declared by the sorted_by gate in
        # _collect_locals):
        #   $_srt_n     length (element count)
        #   $_srt_a     buffer A base pointer (source this pass)
        #   $_srt_b     buffer B base pointer (dest this pass)
        #   $_srt_w     current run width
        #   $_srt_i     left-run start index
        #   $_srt_lo / $_srt_mid / $_srt_hi   run boundaries
        #   $_srt_li / $_srt_ri / $_srt_k     left / right / dest cursors
        #   $_srt_tmp   swap scratch
        # Result header.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(cmp)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_srt_n")
        # Allocate the result list header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_srt_n")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_srt_n")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Buffer A = fresh copy of the receiver's data (n slots, but at
        # least 1 slot so $alloc(0) on an empty list still yields a
        # valid pointer). Buffer B = scratch of the same size.
        self._write("local.get $_srt_n")
        self._write("i32.const 1")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_srt_n")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("local.set $_srt_tmp")  # byte size of a buffer
        self._write("local.get $_srt_tmp")
        self._write("call $alloc")
        self._write("local.set $_srt_a")
        self._write("local.get $_srt_tmp")
        self._write("call $alloc")
        self._write("local.set $_srt_b")
        # Copy receiver data -> A: dst=A, src=recv.data, n=n*es bytes.
        self._write("local.get $_srt_a")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_srt_n")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Bottom-up merge: for (w = 1; w < n; w *= 2) merge A -> B,
        # then swap A and B.
        self._write("i32.const 1")
        self._write("local.set $_srt_w")
        self._block_counter += 1
        wloop = f"$Lsrt{self._block_counter}_wloop"
        wexit = f"$Lsrt{self._block_counter}_wexit"
        iloop = f"$Lsrt{self._block_counter}_iloop"
        iexit = f"$Lsrt{self._block_counter}_iexit"
        mloop = f"$Lsrt{self._block_counter}_mloop"
        mexit = f"$Lsrt{self._block_counter}_mexit"
        self._write(f"block {wexit}")
        self._indent += 1
        self._write(f"loop {wloop}")
        self._indent += 1
        # while w < n.
        self._write("local.get $_srt_w")
        self._write("local.get $_srt_n")
        self._write("i32.ge_s")
        self._write(f"br_if {wexit}")
        # for (i = 0; i < n; i += 2*w): merge [i, i+w) and [i+w, i+2w)
        # from A into B[i..].
        self._write("i32.const 0")
        self._write("local.set $_srt_i")
        self._write(f"block {iexit}")
        self._indent += 1
        self._write(f"loop {iloop}")
        self._indent += 1
        self._write("local.get $_srt_i")
        self._write("local.get $_srt_n")
        self._write("i32.ge_s")
        self._write(f"br_if {iexit}")
        # lo = i; mid = min(i+w, n); hi = min(i+2w, n).
        self._write("local.get $_srt_i")
        self._write("local.set $_srt_lo")
        self._emit_srt_min("_srt_mid", "_srt_i", "_srt_w")
        # hi = min(i + 2w, n): reuse mid path with 2w. Compute i+2w.
        self._write("local.get $_srt_i")
        self._write("local.get $_srt_w")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $_srt_n")
        self._emit_srt_min_pair("_srt_hi")
        # Merge runs [lo, mid) and [mid, hi) into B[lo..].
        self._write("local.get $_srt_lo")
        self._write("local.set $_srt_li")  # left cursor
        self._write("local.get $_srt_mid")
        self._write("local.set $_srt_ri")  # right cursor
        self._write("local.get $_srt_lo")
        self._write("local.set $_srt_k")   # dest cursor
        self._write(f"block {mexit}")
        self._indent += 1
        self._write(f"loop {mloop}")
        self._indent += 1
        # Stop when k >= hi (all merged).
        self._write("local.get $_srt_k")
        self._write("local.get $_srt_hi")
        self._write("i32.ge_s")
        self._write(f"br_if {mexit}")
        # Decide which side supplies B[k]:
        #   take left  iff  li < mid AND (ri >= hi OR cmp(A[li], A[ri]) <= 0)
        #   else take right.
        # Compute the "take left" predicate into $_srt_tmp.
        self._write("local.get $_srt_li")
        self._write("local.get $_srt_mid")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        # left has remaining; check right exhausted OR cmp<=0.
        self._write("local.get $_srt_ri")
        self._write("local.get $_srt_hi")
        self._write("i32.ge_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # cmp(A[li], A[ri]) <= 0 ?  (left-biased -> stable)
        self._emit_srt_cmp_call(sig_idx, elem_ty, es, "_srt_li", "_srt_ri")
        self._write("i64.const 0")
        self._write("i64.le_s")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # left exhausted -> take right.
        self._write("i32.const 0")
        self._indent -= 1
        self._write("end")
        # Branch on the predicate: copy one element A[src] -> B[k].
        self._write("if")
        self._indent += 1
        # take left: B[k] = A[li]; li++.
        self._emit_srt_copy_slot("_srt_b", "_srt_k", "_srt_a", "_srt_li", es)
        self._write("local.get $_srt_li")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_srt_li")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # take right: B[k] = A[ri]; ri++.
        self._emit_srt_copy_slot("_srt_b", "_srt_k", "_srt_a", "_srt_ri", es)
        self._write("local.get $_srt_ri")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_srt_ri")
        self._indent -= 1
        self._write("end")
        # k++.
        self._write("local.get $_srt_k")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_srt_k")
        self._write(f"br {mloop}")
        self._indent -= 1
        self._write("end")  # loop mloop
        self._indent -= 1
        self._write("end")  # block mexit
        # i += 2*w.
        self._write("local.get $_srt_i")
        self._write("local.get $_srt_w")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_srt_i")
        self._write(f"br {iloop}")
        self._indent -= 1
        self._write("end")  # loop iloop
        self._indent -= 1
        self._write("end")  # block iexit
        # Swap A and B (the merged data is now in B; it becomes the
        # source for the next, wider pass).
        self._write("local.get $_srt_a")
        self._write("local.set $_srt_tmp")
        self._write("local.get $_srt_b")
        self._write("local.set $_srt_a")
        self._write("local.get $_srt_tmp")
        self._write("local.set $_srt_b")
        # w *= 2.
        self._write("local.get $_srt_w")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.set $_srt_w")
        self._write(f"br {wloop}")
        self._indent -= 1
        self._write("end")  # loop wloop
        self._indent -= 1
        self._write("end")  # block wexit
        # The sorted data lives in $_srt_a (after the final swap).
        self._write(f"local.get ${dst}")
        self._write("local.get $_srt_a")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")

    def _emit_srt_min(self, out_local: str, base_local: str, add_local: str) -> None:
        """``$out = min($base + $add, $_srt_n)``. Leaves nothing on the
        stack; used to compute the mid boundary of a merge run."""
        self._write(f"local.get ${base_local}")
        self._write(f"local.get ${add_local}")
        self._write("i32.add")
        self._write("local.get $_srt_n")
        self._emit_srt_min_pair(out_local)

    def _emit_srt_min_pair(self, out_local: str) -> None:
        """Operand stack on entry: ``[x, y]``. Stores ``min(x, y)`` into
        ``$out_local``."""
        # Stack: [x, y]. select x if x < y else y.
        self._write("local.set $_srt_tmp")  # y
        self._write("local.set $_srt_k")    # x (k is free here)
        self._write("local.get $_srt_k")
        self._write("local.get $_srt_tmp")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $_srt_k")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_srt_tmp")
        self._indent -= 1
        self._write("end")
        self._write(f"local.set ${out_local}")

    def _emit_srt_copy_slot(
        self, dst_base: str, dst_idx: str, src_base: str, src_idx: str,
        es: int,
    ) -> None:
        """Copy one ``es``-byte element from ``$src_base[$src_idx]`` to
        ``$dst_base[$dst_idx]`` via ``memory.copy``. Shape-agnostic: the
        raw slot bytes carry whatever encoding the element type uses."""
        # dst address.
        self._write(f"local.get ${dst_base}")
        self._write(f"local.get ${dst_idx}")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        # src address.
        self._write(f"local.get ${src_base}")
        self._write(f"local.get ${src_idx}")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        # n bytes.
        self._write(f"i32.const {es}")
        self._write("memory.copy")

    def _emit_srt_cmp_call(
        self, sig_idx: int, elem_ty: str, es: int,
        li_local: str, ri_local: str,
    ) -> None:
        """Emit ``cmp(A[$li], A[$ri])`` via the closure-call ABI and
        leave the i64 result on the operand stack. ``$_srt_a`` is the
        source buffer base for this pass."""
        # env_ptr.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # arg 0 = A[li].
        self._write("local.get $_srt_a")
        self._write(f"local.get ${li_local}")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_load_elem_for_call(elem_ty)
        self._srt_stash_elem(elem_ty)
        # arg 1 = A[ri].
        self._write("local.get $_srt_a")
        self._write(f"local.get ${ri_local}")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_load_elem_for_call(elem_ty)
        # Now the stack has: [env, <arg0 wire>, <arg1 wire>] only if
        # arg0 survived; but loading arg1 happened AFTER stashing arg0,
        # so re-push arg0 between env and arg1. Rebuild the frame.
        self._srt_rebuild_cmp_frame(elem_ty)
        # fn_idx + call_indirect.
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")

    def _srt_stash_elem(self, elem_ty: str) -> None:
        """Pop arg0's decoded value(s) into dedicated comparator-arg
        scratch so arg1 can be loaded without disturbing the frame."""
        if elem_ty == "String":
            # _emit_load_elem_for_call left ptr/len in $_str_a_*, and
            # duplicates on the stack; drop the duplicates and move
            # arg0 into $_str_b_* so the second element load (which
            # overwrites $_str_a_*) does not clobber it.
            self._write("drop")
            self._write("drop")
            self._write("local.get $_str_a_ptr")
            self._write("local.set $_str_b_ptr")
            self._write("local.get $_str_a_len")
            self._write("local.set $_str_b_len")
            return
        if elem_ty == "Float":
            self._write("local.set $_srt_arg0_f64")
            return
        if elem_ty == "Int":
            self._write("local.set $_srt_arg0_i64")
            return
        # Bool / pointer-shape: i32.
        self._write("local.set $_srt_arg0_i32")

    def _srt_rebuild_cmp_frame(self, elem_ty: str) -> None:
        """Stack on entry: ``[env, <arg1 wire tys>]`` (arg0 was stashed
        by ``_srt_stash_elem``). The call needs ``[env, <arg0>,
        <arg1>]``, so splice arg0 back in between. Stash arg1, push
        arg0, then push arg1 again."""
        if elem_ty == "String":
            # arg1's ptr/len are in $_str_a_* plus duplicated on stack;
            # drop the stack duplicates, then push arg0 (from $_str_b_*)
            # and arg1 (from $_str_a_*).
            self._write("drop")
            self._write("drop")
            # arg0 was left in $_str_a_* by the FIRST load, but the
            # SECOND load overwrote $_str_a_*. To avoid that we stash
            # arg0 into $_str_b_* in _srt_stash_elem instead. Handled
            # there; here just push both pairs.
            self._write("local.get $_str_b_ptr")
            self._write("local.get $_str_b_len")
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            return
        if elem_ty == "Float":
            self._write("local.set $_srt_arg1_f64")
            self._write("local.get $_srt_arg0_f64")
            self._write("local.get $_srt_arg1_f64")
            return
        if elem_ty == "Int":
            self._write("local.set $_srt_arg1_i64")
            self._write("local.get $_srt_arg0_i64")
            self._write("local.get $_srt_arg1_i64")
            return
        # Bool / pointer-shape.
        self._write("local.set $_srt_arg1_i32")
        self._write("local.get $_srt_arg0_i32")
        self._write("local.get $_srt_arg1_i32")

    def _emit_list_reverse(
        self, instr: MethodCall, elem_size: int, elem_ty: str,
    ) -> None:
        """``xs.reverse() -> List<T>``: a NEW list with the elements in
        reverse order. The receiver is not mutated. Each element slot
        is copied verbatim with ``memory.copy`` (shape-agnostic: the
        raw ``elem_size`` bytes carry whatever encoding the element
        type uses), so the result is byte-identical to the Python
        ``CapaList(reversed(self))``.

        Layout: allocate a result header (len = cap = n) + a fresh
        data array of ``n * elem_size`` bytes, then copy source slot
        ``n - 1 - i`` into destination slot ``i`` for ``i`` in
        ``[0, n)``. Reuses ``$_m_scrut`` (receiver pointer) and the
        ``$_lz_*`` cursor / pointer scratch."""
        recv = instr.receiver
        dst = instr.dst
        if dst is None:
            return
        es = elem_size
        # Stash receiver + its length.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_lz_n")
        # Allocate result header; len = cap = n.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Data array = max(n, 1) slots so $alloc(0) on an empty list
        # still yields a valid pointer.
        self._emit_lz_alloc_data(es, "_lz_dst")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_dst")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Source data pointer.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.set $_lz_src")
        # for (i = 0; i < n; i++): dst[i] = src[n - 1 - i].
        self._write("i32.const 0")
        self._write("local.set $_lz_i")
        self._block_counter += 1
        loop = f"$Lrev{self._block_counter}_loop"
        exit_ = f"$Lrev{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lz_i")
        self._write("local.get $_lz_n")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # dst address = dst_data + i * es.
        self._write("local.get $_lz_dst")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        # src address = src_data + (n - 1 - i) * es.
        self._write("local.get $_lz_src")
        self._write("local.get $_lz_n")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.get $_lz_i")
        self._write("i32.sub")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        # n bytes = es.
        self._write(f"i32.const {es}")
        self._write("memory.copy")
        # i++.
        self._write("local.get $_lz_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lz_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_list_enumerate(
        self, instr: MethodCall, elem_size: int, elem_ty: str,
    ) -> None:
        """``xs.enumerate() -> List<(Int, T)>``: a NEW list pairing
        each element with its 0-based index, in the original order.
        Each result element is a 16-byte tuple record (slot 0 = index
        as i64, slot 8 = the element re-encoded into the uniform
        8-byte tuple slot). The result list's element stride is 4 (a
        pointer-shape tuple). Matches the Python ``CapaList((i, x) for
        i, x in enumerate(self))``."""
        recv = instr.receiver
        dst = instr.dst
        if dst is None:
            return
        es = elem_size
        out_stride = 4  # tuple records are pointer-shape
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_lz_n")
        # Result header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._emit_lz_alloc_data(out_stride, "_lz_dst")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_dst")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Source data pointer.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.set $_lz_src")
        # for (i = 0; i < n; i++): build tuple (i, src[i]).
        self._write("i32.const 0")
        self._write("local.set $_lz_i")
        self._block_counter += 1
        loop = f"$Lenum{self._block_counter}_loop"
        exit_ = f"$Lenum{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lz_i")
        self._write("local.get $_lz_n")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Allocate the 16-byte tuple record.
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $_lz_tup")
        # Slot 0 = index as i64.
        self._write("local.get $_lz_tup")
        self._write("local.get $_lz_i")
        self._write("i64.extend_i32_s")
        self._write("i64.store offset=0")
        # Slot 8 = src[i] re-encoded into the tuple slot.
        self._write("local.get $_lz_tup")
        self._write("local.get $_lz_src")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_copy_list_slot_to_tuple_slot(elem_ty, 8)
        # Store the tuple pointer into dst[i].
        self._write("local.get $_lz_dst")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {out_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $_lz_tup")
        self._write("i32.store")
        # i++.
        self._write("local.get $_lz_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lz_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_list_zip(
        self, instr: MethodCall, elem_size: int, elem_ty: str,
    ) -> None:
        """``xs.zip(other) -> List<(T, U)>``: a NEW list pairing
        ``xs[i]`` with ``other[i]`` up to the shorter of the two
        lengths. Each result element is a 16-byte tuple record (slot 0
        = xs[i] re-encoded, slot 8 = other[i] re-encoded). Matches the
        Python ``CapaList(zip(self, other))`` truncation semantics."""
        recv = instr.receiver
        other = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        es = elem_size
        other_ty = other.ty or "List<Int>"
        other_elem_ty = _element_type_of_list(other_ty)
        es2 = self._size_of(other_elem_ty)
        out_stride = 4
        # Stash xs (in $_m_scrut) and other (in $_m_tag holds nothing;
        # use $_lz_src2 base directly). Compute n = min(len(xs),
        # len(other)).
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(other)
        self._write("local.set $_lz_tup")  # temporarily holds other ptr
        # n = min(len(xs), len(other)).
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.get $_lz_tup")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        # min(a, b): a if a < b else b.
        self._write("local.set $_lz_i")    # b = len(other)
        self._write("local.set $_lz_n")    # a = len(xs)
        self._write("local.get $_lz_n")
        self._write("local.get $_lz_i")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $_lz_n")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_lz_i")
        self._indent -= 1
        self._write("end")
        self._write("local.set $_lz_n")
        # Source data pointers.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.set $_lz_src")
        self._write("local.get $_lz_tup")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.set $_lz_src2")
        # Result header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_n")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._emit_lz_alloc_data(out_stride, "_lz_dst")
        self._write(f"local.get ${dst}")
        self._write("local.get $_lz_dst")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # for (i = 0; i < n; i++): build tuple (xs[i], other[i]).
        self._write("i32.const 0")
        self._write("local.set $_lz_i")
        self._block_counter += 1
        loop = f"$Lzip{self._block_counter}_loop"
        exit_ = f"$Lzip{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lz_i")
        self._write("local.get $_lz_n")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Allocate the 16-byte tuple record.
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $_lz_tup")
        # Slot 0 = xs[i].
        self._write("local.get $_lz_tup")
        self._write("local.get $_lz_src")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {es}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_copy_list_slot_to_tuple_slot(elem_ty, 0)
        # Slot 8 = other[i].
        self._write("local.get $_lz_tup")
        self._write("local.get $_lz_src2")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {es2}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_copy_list_slot_to_tuple_slot(other_elem_ty, 8)
        # Store the tuple pointer into dst[i].
        self._write("local.get $_lz_dst")
        self._write("local.get $_lz_i")
        self._write(f"i32.const {out_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $_lz_tup")
        self._write("i32.store")
        # i++.
        self._write("local.get $_lz_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lz_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_lz_alloc_data(self, stride: int, out_local: str) -> None:
        """Allocate ``max($_lz_n, 1) * stride`` bytes for a result
        list's data array and bind the pointer to ``$<out_local>``.
        The ``max(.., 1)`` keeps ``$alloc(0)`` on an empty source from
        handing back a degenerate pointer (mirrors the sorted_by
        buffer allocation)."""
        self._write("local.get $_lz_n")
        self._write("i32.const 1")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_lz_n")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {stride}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write(f"local.set ${out_local}")

    def _emit_copy_list_slot_to_tuple_slot(
        self, elem_ty: str, tuple_offset: int,
    ) -> None:
        """Operand stack on entry: ``[tuple_ptr, slot_addr]``. Load the
        list element at ``slot_addr`` and store it into the tuple
        record's slot at ``tuple_offset``, re-encoding so the tuple
        slot matches what ``_store_tuple_slot`` / ``_emit_tuple_index``
        expect (the uniform 8-byte tuple-slot convention):

        - Int / Float / String already occupy an 8-byte list slot with
          the identical encoding (i64 / f64-bits / packed ptr+len), so
          a direct ``i64.load`` + ``i64.store`` copies the bytes.
        - Bool occupies a 4-byte list slot (i32); load it and
          ``i64.extend_i32_u`` into the tuple's 8-byte slot.
        - pointer-shape (struct / sum / tuple / nested collection)
          occupies a 4-byte list slot (i32 pointer); load and
          ``i64.extend_i32_u`` likewise.
        """
        if elem_ty == "Bool" or self._is_pointer_shape_ty(elem_ty):
            # 4-byte list slot -> i64-extended 8-byte tuple slot.
            self._write("i32.load")
            self._write("i64.extend_i32_u")
            self._write(f"i64.store offset={tuple_offset}")
            return
        # Int / Float / String: 8-byte list slot, direct i64 copy.
        # (Float bits and the packed String (ptr,len) round-trip
        # losslessly through an integer load/store.)
        self._write("i64.load")
        self._write(f"i64.store offset={tuple_offset}")

    def _emit_make_list(self, instr: MakeList) -> None:
        """Allocate a List<T> header (16 bytes) + an element data
        array sized for the literal's elements. Store len = cap =
        n, then write each element at its index. The list pointer
        lands in ``instr.dst``."""
        list_ty = self._dst_capa_ty(instr.dst) or "List<Int>"
        elem_ty = _element_type_of_list(list_ty)
        elem_size = self._size_of(elem_ty)
        n = len(instr.elements)
        # Allocate the header. Empty literals get cap=8 so a
        # subsequent ``push`` lands without immediate realloc.
        cap = max(n, 8)
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        # Store len and cap. Header layout: len@0, cap@4, data_ptr@8.
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {n}")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {cap}")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Allocate the data array (cap * elem_size); record the
        # base pointer in the header's data slot. Even for empty
        # literals we allocate an array of cap slots so push has
        # somewhere to write without an immediate grow.
        # Push order is addr-then-value for i32.store; ``local.set``
        # the freshly allocated pointer first so we can re-push it
        # both as the store's value and as the base address for
        # the element writes below without leaving a stale copy
        # on the operand stack.
        data_bytes = cap * elem_size
        self._write(f"i32.const {data_bytes}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${instr.dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Write each literal element. The base pointer of the data
        # array is re-read from the list header (``instr.dst``'s
        # data_ptr slot) for EACH element store rather than cached in
        # ``$_alloc_tmp``: a payloadless sum element (e.g. ``Nil`` /
        # ``Off``) pushes via the ``variant_ctor`` path in
        # ``_push_value``, which does ``call $alloc`` + ``local.tee
        # $_alloc_tmp`` and so overwrites that scratch with the fresh
        # variant pointer. With a cached base, every element after the
        # first payloadless variant would compute its store address
        # from that variant pointer instead of the data array and the
        # value would land in the wrong heap region (read back as 0).
        # Re-reading data_ptr from the header each iteration mirrors
        # how ``_emit_list_push`` addresses the slot and is immune to
        # any element push that clobbers a scratch local.
        store_op = _store_op_for_size(elem_size)
        for i, elem in enumerate(instr.elements):
            if elem_ty == "String":
                # Pack (ptr, len) -> i64. Mirrors the variant-ctor
                # String payload path. Stack progression:
                #   [base]
                #   [base, ptr, len]
                #   [base, ptr, len_i64]
                #   [base, ptr, (len_i64<<32)]   (also stashed)
                #   [base, ptr]
                #   [base, ptr_i64]
                #   [base, ptr_i64, (len_i64<<32)]
                #   [base, packed_i64]
                self._write(f"local.get ${instr.dst}")
                self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
                self._push_string_value_as_ptr_len(elem)
                self._write("i64.extend_i32_u")
                self._write("i64.const 32")
                self._write("i64.shl")
                self._write("local.tee $_alloc_tmp_i64")
                self._write("drop")
                self._write("i64.extend_i32_u")
                self._write("local.get $_alloc_tmp_i64")
                self._write("i64.or")
                self._write(f"i64.store offset={i * elem_size}")
                continue
            self._write(f"local.get ${instr.dst}")
            self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
            self._push_value(elem)
            if elem_ty == "Float":
                self._write(f"f64.store offset={i * elem_size}")
            else:
                self._write(f"{store_op} offset={i * elem_size}")

    def _emit_index(self, instr: Index) -> None:
        """Lower ``xs[i]`` for a List receiver. Bounds-check ``i``
        against the list header's len, then load
        ``data_ptr + i * elem_size`` from memory.

        Bounds check (audit fix C1): the wrapped-i32 index is
        stashed in ``$_bounds_idx`` via ``local.tee`` so the check
        (``idx i32.ge_u len`` -> trap on out-of-range) and the
        subsequent address compute can both read it without re-
        evaluating the IR Value. The unsigned compare also catches
        negative IR-level indices: ``i32.wrap_i64`` of a negative
        i64 is a huge u32, which exceeds any list's length and so
        traps via the same path. Capa is non-negative-index-only
        on both backends; the Python helper ``_capa_list_get`` in
        ``capa.runtime._safety`` raises ``IndexError`` on the same
        inputs.

        String elements are stored as packed i64 (ptr in low 32,
        len in high 32). After the i64.load we unpack into the
        dst's ``_ptr`` / ``_len`` pair so downstream String ops
        work transparently, mirroring the for-iter String path."""
        recv_ty = instr.receiver.ty
        if not recv_ty.startswith("List"):
            raise WasmEmissionError(
                f"Index on receiver of type {recv_ty!r}: only List "
                f"indexing is supported in Phase 6D-2"
            )
        elem_ty = _element_type_of_list(recv_ty)
        elem_size = self._size_of(elem_ty)
        # Float elements use ``f64.load`` so the resulting stack
        # type matches the dst's declared f64 local; the size-
        # dispatched i64.load would push i64 and mismatch.
        if elem_ty == "Float":
            load_op = "f64.load"
        else:
            load_op = _load_op_for_size(elem_size)
        # Bounds check (audit fix C1, hardened 2026-05-29
        # post-slice-15): trap if idx < 0 or idx >= len. The
        # original "unsigned compare on the wrapped i32 also
        # catches negative" reasoning had a hole: an i64 like
        # ``-2**32 = 0xFFFFFFFF_00000000`` wraps to i32 0, which
        # passes ``0 < len`` and silently returns ``xs[0]`` --
        # Python raises IndexError on the same input. Check the
        # original i64 against ``0 <= i < len`` BEFORE wrapping
        # so no negative index can slip through.
        self._push_value(instr.index)
        self._write("local.tee $_bounds_idx_i64")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_bounds_idx_i64")
        self._push_value(instr.receiver)
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i64.extend_i32_u")
        self._write("i64.ge_s")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        # Now the i64 idx is known in [0, len), so wrapping to i32
        # is lossless. Stash so the address compute below can reuse.
        self._write("local.get $_bounds_idx_i64")
        self._write("i32.wrap_i64")
        self._write("local.set $_bounds_idx")
        # Compute address: data_ptr + index * elem_size.
        self._push_value(instr.receiver)
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_bounds_idx")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        if elem_ty == "String":
            # Unpack packed i64 into (ptr, len) locals.
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
        self._write(f"local.set ${instr.dst}")

    def _emit_for(self, instr: For) -> None:
        """Lower ``for x in xs`` for a List / Set / Range iterator.
        Emits a counted loop:
        ``i = 0; while i < len(xs) { x = xs[i]; ...body...; i += 1 }``
        Uses the function's match-helper locals (``$_m_scrut`` and
        ``$_m_tag``) as scratch space for the iterator pointer and
        index, plus the bind name's own local for the element."""
        iter_ty = self._effective_value_ty(instr.iter)
        # Sets share the List in-memory layout (len@0, cap@4,
        # data_ptr@8) and store each element identically, so the
        # same counted-loop body iterates a Set's element array in
        # insertion order. The only difference is how the element
        # type is parsed out of the receiver type string.
        if iter_ty.startswith("List"):
            elem_ty = _element_type_of_list(iter_ty)
        elif iter_ty.startswith("Set"):
            from ._layout import _element_type_of_set
            elem_ty = _element_type_of_set(iter_ty)
        elif iter_ty.startswith("Range"):
            # ``for i in a..b`` / ``for i in a..=b``: the Range
            # record stores (start_i64@0, end_i64@8, inclusive_i32@16).
            # Counted loop reads them directly, bumps i by 1 per
            # iteration, exits on inclusive ? i > end : i >= end.
            # No data array, no materialised List<Int>.
            self._emit_for_range(instr)
            return
        elif iter_ty == "String":
            # ``for c in s``: iterate each Unicode code point of the
            # UTF-8 byte slice, binding ``c`` as a one-codepoint
            # String (ptr into the original buffer, len = the code
            # point's byte length). Matches the Python backend, which
            # yields one-character strings.
            self._emit_for_string(instr)
            return
        else:
            raise WasmEmissionError(
                f"For-iter over type {iter_ty!r}: only List, Set, and "
                f"Range iteration are supported"
            )
        elem_size = self._size_of(elem_ty)
        # Float elements need ``f64.load`` (the bind local is f64);
        # other types take the size-dispatched i32/i64 load.
        if elem_ty == "Float":
            load_op = "f64.load"
        else:
            load_op = _load_op_for_size(elem_size)
        # For-loop needs its own list-pointer and index scratch
        # locals distinct from the match-helper locals: a match
        # inside the for-body would otherwise clobber the
        # iteration state mid-loop (the match's tag/scrutinee
        # writes overwrite the loop's idx/list pointer, so the
        # loop's increment + guard read garbage and exit
        # prematurely). Nested for-loops also need *each* loop's
        # locals to be unique -- using a single pair across nested
        # loops would let the inner loop overwrite the outer's
        # iteration state and silently truncate the outer
        # iteration (a classic bug in audit-trail-reporter's
        # ``for c in classified; for f in c.findings`` shape). The
        # depth index is the live ``_for_depth`` (incremented
        # below before the body emits and decremented after); the
        # function-prelude declared one pair per max depth seen by
        # ``_collect_locals``.
        list_local = f"_f_list_{self._for_depth}"
        idx_local = f"_f_idx_{self._for_depth}"
        # Capture the list pointer in $list_local.
        self._push_value(instr.iter)
        self._write(f"local.set ${list_local}")
        self._write(f"i32.const 0")
        self._write(f"local.set ${idx_local}")
        # block/loop encoding. A ``while`` loop's ``continue`` jumps
        # back to the loop top and re-evaluates the condition, but a
        # ``for`` loop's body has its own index increment that must
        # still run on continue -- otherwise an empty-line skip with
        # ``if line.is_empty(): continue`` reuses the same index
        # forever and the program spins. Wrap the body in an inner
        # ``block`` so the ``continue`` label is the *end* of that
        # block; control falls through to the increment + back-branch
        # naturally after the body or after a ``br`` to the body
        # block's exit.
        self._block_counter += 1
        loop_label = f"$F{self._block_counter}_loop"
        exit_label = f"$F{self._block_counter}_exit"
        cont_label = f"$F{self._block_counter}_cont"
        self._loop_labels.append((cont_label, exit_label))
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Loop guard: if idx >= len(list), exit. Audit C1: this is
        # the only path into the data array for ``for x in xs``, so
        # the index is structurally bounded by the loop's own
        # ``idx < len`` invariant. No extra runtime bounds check is
        # needed beyond this guard.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # Bind the iteration variable: list.data[idx].
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        if elem_ty == "String":
            # String element stored as packed i64 (ptr low, len
            # high). Stash the packed value, unpack into the bind's
            # (ptr, len) locals so downstream String operations
            # work transparently.
            self._write(f"local.set $_alloc_tmp_i64")
            self._write(f"local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.name}_ptr")
            self._write(f"local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.name}_len")
        else:
            self._write(f"local.set ${instr.name}")
        # Body wrapped in an inner block whose end is the ``continue``
        # target. Falling off the body or branching to ``cont_label``
        # both arrive at the increment site below. Bump ``_for_depth``
        # so any nested for-loop inside the body uses fresh
        # ``$_f_list_N+1`` / ``$_f_idx_N+1`` scratch locals.
        self._write(f"block {cont_label}")
        self._indent += 1
        self._for_depth += 1
        for sub in instr.body:
            self._emit_instr(sub)
        self._for_depth -= 1
        self._indent -= 1
        self._write("end")
        # Increment idx and back-branch.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._loop_labels.pop()

    def _emit_range_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a ``Range`` receiver used as a value.
        The Range record is ``{start_i64@0, end_i64@8, inclusive_i32@16}``.
        The Python ``CapaRange`` wraps ``range(start, stop)`` where
        ``stop = end + 1`` for an inclusive (``a..=b``) range and
        ``stop = end`` for an exclusive (``a..b``) one, so every method
        is defined against the half-open ``[start, stop)`` interval with
        step 1.

        - ``length() -> Int``: ``max(0, stop - start)``.
        - ``contains(n) -> Bool``: ``start <= n < stop``.
        - ``is_empty() -> Bool``: ``stop - start <= 0``.
        - ``to_list() -> List<Int>``: materialise ``[start, ..., stop-1]``.
        """
        method = instr.method
        recv = instr.receiver
        if method == "length":
            self._emit_range_length(recv)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            # is_empty == (length <= 0). length is always >= 0, so
            # compare the raw (stop - start) against 0 directly.
            self._emit_range_count(recv)
            self._write("i64.const 0")
            self._write("i64.le_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "contains":
            self._emit_range_contains(recv, instr.args[0])
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "to_list":
            self._emit_range_to_list(recv, instr.dst)
            return
        raise WasmEmissionError(
            f"Range method {method!r} is not implemented on the Wasm backend"
        )

    def _emit_range_stop(self, recv: Value) -> None:
        """Push the half-open ``stop`` bound (i64) of the Range: ``end +
        1`` when inclusive, ``end`` otherwise. Consumes nothing else off
        the stack. Uses ``$_alloc_tmp`` to stash the record pointer."""
        self._push_value(recv)
        self._write("local.set $_alloc_tmp")
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=8")  # end
        self._write("local.get $_alloc_tmp")
        self._write("i32.load offset=16")  # inclusive (i32 0/1)
        self._write("i64.extend_i32_u")
        self._write("i64.add")  # end + inclusive

    def _emit_range_count(self, recv: Value) -> None:
        """Push ``stop - start`` (i64) on the stack -- the signed
        element count BEFORE clamping at 0. ``length`` clamps; the
        ``is_empty`` ``<= 0`` test does not need to."""
        self._push_value(recv)
        self._write("local.set $_alloc_tmp")
        # stop = end + inclusive.
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=8")
        self._write("local.get $_alloc_tmp")
        self._write("i32.load offset=16")
        self._write("i64.extend_i32_u")
        self._write("i64.add")
        # - start.
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=0")
        self._write("i64.sub")

    def _emit_range_length(self, recv: Value) -> None:
        """Push ``max(0, stop - start)`` (i64). Matches Python's
        ``len(range(start, stop))`` which never goes negative."""
        self._emit_range_count(recv)
        self._write("local.set $_alloc_tmp_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if (result i64)")
        self._indent += 1
        self._write("i64.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_alloc_tmp_i64")
        self._indent -= 1
        self._write("end")

    def _emit_range_contains(self, recv: Value, n: Value) -> None:
        """Push an i32 0/1: ``start <= n AND n < stop``. Mirrors
        Python's ``n in range(start, stop)`` for the step-1 case."""
        self._push_value(n)
        self._write("local.set $_alloc_tmp_i64")  # n
        self._push_value(recv)
        self._write("local.set $_alloc_tmp")
        # start <= n.
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=0")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.le_s")
        # n < stop  (stop = end + inclusive).
        self._write("local.get $_alloc_tmp_i64")
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=8")
        self._write("local.get $_alloc_tmp")
        self._write("i32.load offset=16")
        self._write("i64.extend_i32_u")
        self._write("i64.add")
        self._write("i64.lt_s")
        # AND.
        self._write("i32.and")

    def _emit_range_to_list(self, recv: Value, dst) -> None:
        """``r.to_list() -> List<Int>``: materialise ``[start, start+1,
        ..., stop-1]``. Allocates a List<Int> header + data array sized
        ``max(0, stop - start)`` (cap clamped to >= 1 so $alloc returns
        a usable pointer), then fills it with a counted loop."""
        if dst is None:
            return
        from ._layout import _LIST_HEADER_SIZE
        # Stash start / stop in i64 scratch, n in i32.
        self._push_value(recv)
        self._write("local.set $_alloc_tmp")
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=0")
        self._write("local.set $_srt_start_i64")  # start
        # stop = end + inclusive.
        self._write("local.get $_alloc_tmp")
        self._write("i64.load offset=8")
        self._write("local.get $_alloc_tmp")
        self._write("i32.load offset=16")
        self._write("i64.extend_i32_u")
        self._write("i64.add")
        self._write("local.set $_srt_stop_i64")  # stop
        # n = max(0, stop - start) as i32.
        self._write("local.get $_srt_stop_i64")
        self._write("local.get $_srt_start_i64")
        self._write("i64.sub")
        self._write("local.set $_alloc_tmp_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if (result i64)")
        self._indent += 1
        self._write("i64.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_alloc_tmp_i64")
        self._indent -= 1
        self._write("end")
        self._write("i32.wrap_i64")
        self._write("local.set $_m_tag")  # n (count)
        # Allocate header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Data array: max(n, 1) * 8 bytes (Int stride is 8).
        self._write("local.get $_m_tag")
        self._write("i32.const 1")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_m_tag")
        self._indent -= 1
        self._write("end")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Fill: i = 0; while i < n: data[i] = start + i; i++.
        self._write("i32.const 0")
        self._write("local.set $_m_scrut")  # i (index)
        self._block_counter += 1
        loop_label = f"$Rtl{self._block_counter}_loop"
        exit_label = f"$Rtl{self._block_counter}_exit"
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        self._write("local.get $_m_scrut")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # data[i] = start + i.
        self._write("local.get $_alloc_tmp")
        self._write("local.get $_m_scrut")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $_srt_start_i64")
        self._write("local.get $_m_scrut")
        self._write("i64.extend_i32_s")
        self._write("i64.add")
        self._write("i64.store")
        # i++.
        self._write("local.get $_m_scrut")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_m_scrut")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_make_range(self, instr: MakeRange) -> None:
        """Allocate a Range record: 24 bytes laid out as
        ``{ start_i64 @0, end_i64 @8, inclusive_i32 @16 }``.
        The For-iter fast-path reads all three fields directly
        without ever materialising the integer sequence."""
        self._write("i32.const 24")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        # start @0
        self._write(f"local.get ${instr.dst}")
        self._push_value(instr.start)
        self._write("i64.store offset=0")
        # end @8
        self._write(f"local.get ${instr.dst}")
        self._push_value(instr.end)
        self._write("i64.store offset=8")
        # inclusive @16
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {1 if instr.inclusive else 0}")
        self._write("i32.store offset=16")

    def _emit_for_range(self, instr: For) -> None:
        """``for i in Range`` fast-path. Reads start / end / inclusive
        out of the Range record once into depth-indexed scratch
        locals, then runs ``i = start; while inclusive ? i <= end :
        i < end: body; i += 1``.

        The induction variable ``i`` lives in the bind name's own
        i64 local (Int convention). End and inclusive scratch are
        keyed by ``_for_depth`` so nested ``for o in 1..=3: for p
        in 0..o`` doesn't have the inner loop's end-compare clobber
        the outer's (manifested before the fix as the outer loop
        running only one iteration's worth of inner work, e.g. 1
        pair total instead of 6)."""
        depth = self._for_depth
        list_local = f"_f_list_{depth}"
        end_local = f"_range_end_i64_{depth}"
        incl_local = f"_range_incl_i32_{depth}"
        # Stash the range pointer.
        self._push_value(instr.iter)
        self._write(f"local.set ${list_local}")
        # Read end (i64 @8) into the depth-indexed i64 scratch.
        self._write(f"local.get ${list_local}")
        self._write("i64.load offset=8")
        self._write(f"local.set ${end_local}")
        # Read inclusive (i32 @16) into the depth-indexed i32 scratch.
        self._write(f"local.get ${list_local}")
        self._write("i32.load offset=16")
        self._write(f"local.set ${incl_local}")
        # Initialise i = start (i64 @0) into the bind's own local.
        self._write(f"local.get ${list_local}")
        self._write("i64.load offset=0")
        self._write(f"local.set ${instr.name}")
        self._block_counter += 1
        loop_label = f"$FR{self._block_counter}_loop"
        exit_label = f"$FR{self._block_counter}_exit"
        cont_label = f"$FR{self._block_counter}_cont"
        self._loop_labels.append((cont_label, exit_label))
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Loop guard: inclusive ? i > end : i >= end -> exit.
        # Branch on inclusive: if-then-else picks the right compare.
        self._write(f"local.get ${incl_local}")
        self._write("if")
        self._indent += 1
        self._write(f"local.get ${instr.name}")
        self._write(f"local.get ${end_local}")
        self._write("i64.gt_s")
        self._write(f"br_if {exit_label}")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"local.get ${instr.name}")
        self._write(f"local.get ${end_local}")
        self._write("i64.ge_s")
        self._write(f"br_if {exit_label}")
        self._indent -= 1
        self._write("end")
        # Body in an inner block so ``continue`` falls through to
        # the increment site. ``_for_depth`` bumped per loop, same
        # convention as the List path.
        self._write(f"block {cont_label}")
        self._indent += 1
        self._for_depth += 1
        for sub in instr.body:
            self._emit_instr(sub)
        self._for_depth -= 1
        self._indent -= 1
        self._write("end")
        # i += 1
        self._write(f"local.get ${instr.name}")
        self._write("i64.const 1")
        self._write("i64.add")
        self._write(f"local.set ${instr.name}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._loop_labels.pop()

    def _emit_for_string(self, instr: For) -> None:
        """``for c in s`` over a String. Walks the receiver's UTF-8
        byte slice one code point at a time, binding ``c`` as a
        one-codepoint String per iteration: ``c_ptr`` points into
        the original buffer at the code point's first byte and
        ``c_len`` is the code point's byte length (1/2/3/4). Each
        iteration advances the byte cursor by that byte length, so
        the loop runs exactly once per code point and zero times for
        an empty string -- parity with the Python backend, which
        yields one-character strings.

        Reuses the same UTF-8 leading-byte classification as
        ``_emit_string_char_at`` / ``$str_cp_to_byte_offset``:
        ``0xxxxxxx`` -> 1, ``110xxxxx`` -> 2, ``1110xxxx`` -> 3,
        ``11110xxx`` -> 4. No allocation: the element is a (ptr, len)
        view into the immutable receiver buffer, like ``trim`` /
        ``substring`` views.

        Scratch is depth-indexed (``_f_list_N`` / ``_f_idx_N`` /
        ``_f_strlen_N`` / ``_f_byte_N`` / ``_f_cplen_N``) so a String
        iteration nested inside (or containing) another for-loop
        keeps its own cursor state; a match in the body can't clobber
        it either (the match helper locals are distinct)."""
        depth = self._for_depth
        ptr_local = f"_f_list_{depth}"
        idx_local = f"_f_idx_{depth}"
        len_local = f"_f_strlen_{depth}"
        byte_local = f"_f_byte_{depth}"
        cplen_local = f"_f_cplen_{depth}"
        # Stash receiver (ptr, len) into the depth-indexed scratch and
        # start the byte cursor at 0.
        self._push_string_value_as_ptr_len(instr.iter)
        self._write(f"local.set ${len_local}")
        self._write(f"local.set ${ptr_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop_label = f"$FS{self._block_counter}_loop"
        exit_label = f"$FS{self._block_counter}_exit"
        cont_label = f"$FS{self._block_counter}_cont"
        self._loop_labels.append((cont_label, exit_label))
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Loop guard: byte cursor >= receiver byte length -> exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${len_local}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # Classify the leading byte at ptr+idx into a code-point byte
        # length (1/2/3/4); stash in $cplen_local.
        self._write(f"local.get ${ptr_local}")
        self._write(f"local.get ${idx_local}")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write(f"local.tee ${byte_local}")
        self._write("i32.const 0x80")
        self._write("i32.and")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"local.get ${byte_local}")
        self._write("i32.const 0xe0")
        self._write("i32.and")
        self._write("i32.const 0xc0")
        self._write("i32.eq")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 2")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"local.get ${byte_local}")
        self._write("i32.const 0xf0")
        self._write("i32.and")
        self._write("i32.const 0xe0")
        self._write("i32.eq")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 3")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("i32.const 4")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write(f"local.set ${cplen_local}")
        # Bind the element as a one-codepoint String view:
        #   c_ptr = receiver.ptr + idx ; c_len = cp_len.
        self._write(f"local.get ${ptr_local}")
        self._write(f"local.get ${idx_local}")
        self._write("i32.add")
        self._write(f"local.set ${instr.name}_ptr")
        self._write(f"local.get ${cplen_local}")
        self._write(f"local.set ${instr.name}_len")
        # Body wrapped in an inner block whose end is the ``continue``
        # target, so a ``continue`` still runs the byte-cursor bump.
        self._write(f"block {cont_label}")
        self._indent += 1
        self._for_depth += 1
        for sub in instr.body:
            self._emit_instr(sub)
        self._for_depth -= 1
        self._indent -= 1
        self._write("end")
        # Advance the byte cursor by the code point's byte length.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${cplen_local}")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._loop_labels.pop()

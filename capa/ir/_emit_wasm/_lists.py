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

from .._nodes import For, Index, MakeList, MethodCall, Value
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
        increment. ``contains`` walks the array linearly. Methods
        that need closures (map / filter / fold / find) raise; they
        land in Phase 6E."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        elem_ty = _element_type_of_list(recv_ty)
        elem_size = self._size_of(elem_ty)

        if method in ("map", "filter", "fold"):
            self._emit_list_hof(instr, elem_ty)
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
            f"Phase 6D-2: List method {method!r} not supported "
            f"(map / filter / fold need closures, see 6E)"
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
        # Compare op depends on element width.
        eq_op = "i64.eq" if elem_size == 8 else "i32.eq"
        load_op = _load_op_for_size(elem_size)
        # Push needle once into a fresh local; reusing $_alloc_tmp.
        # Needle is a scalar (Int or Bool) so it fits in i64 / i32.
        if elem_size == 8:
            self._push_value(needle)
            self._write(f"local.set $_alloc_tmp_i64")
            needle_local = "_alloc_tmp_i64"
        else:
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
        # Stash list pointer and index (the IR's i64 index narrowed
        # to i32 for address arithmetic).
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._push_value(idx)
        self._write("i32.wrap_i64")
        self._write(f"local.set ${idx_local}")
        # Alloc Option<T> result up front; tag filled by branch.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        # Bounds check: idx < 0 OR idx >= len -> None.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 0")
        self._write("i32.lt_s")
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
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
        # In bounds: Some(xs[i]). Tag = 0.
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
        # Stack: [result_ptr, elem_addr]
        head = elem_ty.split("<", 1)[0]
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
        elif (head in self._struct_layouts
                or head in self._sum_layouts
                or elem_ty.startswith(("List", "Map", "Set"))):
            self._write("i32.load")
            self._write("i64.extend_i32_u")
            self._write("i64.store offset=8")
        else:
            # Int (or unknown defaulting to i64). Direct i64 copy.
            self._write("i64.load")
            self._write("i64.store offset=8")
        self._indent -= 1
        self._write("end")
        # Bind result Option pointer to dst.
        self._write(f"local.get ${result_local}")
        self._write(f"local.set ${dst}")

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
        # Write each literal element. ``_alloc_tmp`` holds the base
        # pointer of the data array. String elements pack (ptr, len)
        # into the 8-byte slot as ``ptr | (len << 32)``; Float
        # elements use ``f64.store`` so the slot bytes are the
        # IEEE-754 bit pattern (a subsequent ``f64.load`` reads them
        # back as an f64; an ``i64.load`` reads the same bits as i64
        # for HOF emission's uniform i64 slot path). Other types use
        # the size-dispatched store directly.
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
                self._write("local.get $_alloc_tmp")
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
            self._write("local.get $_alloc_tmp")
            self._push_value(elem)
            if elem_ty == "Float":
                self._write(f"f64.store offset={i * elem_size}")
            else:
                self._write(f"{store_op} offset={i * elem_size}")
        # Drop the leftover from local.tee (it lives in $_alloc_tmp
        # but the stack value persisted). i32.store consumed the tag
        # offset's stack value already in the data_ptr store above,
        # so the stack is balanced at this point.

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
        # Bounds check (audit fix C1): trap if idx >= len (unsigned
        # compare also catches negative IR indices). Stash the
        # wrapped idx so the address compute below can reuse it.
        self._push_value(instr.index)
        self._write("i32.wrap_i64")
        self._write("local.tee $_bounds_idx")
        self._push_value(instr.receiver)
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_u")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
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
        """Lower ``for x in xs`` for a List iterator. Emits a
        counted loop:
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
        else:
            raise WasmEmissionError(
                f"For-iter over type {iter_ty!r}: only List and Set "
                f"iteration are supported (range iteration lands in a "
                f"later phase)"
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

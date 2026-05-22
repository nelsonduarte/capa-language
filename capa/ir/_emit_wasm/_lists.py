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
            # List<T>.get returns Option<T>. Building Option here
            # requires the Option sum-type layout, which lives in
            # the module's user-defined types. Defer this until the
            # standard library wraps Option centrally in 6D-3.
            raise WasmEmissionError(
                "Phase 6D-2: List.get returning Option<T> not yet "
                "supported; use direct indexing xs[i]"
            )
        if method == "contains":
            self._emit_list_contains(recv, instr.args[0], elem_size, elem_ty)
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
        self._push_value(elem)
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
        i32 0/1 on the stack. String element type would need a
        per-byte comparator and is deferred until 6D-4."""
        if elem_ty == "String":
            raise WasmEmissionError(
                "Phase 6D-2: List<String>.contains not yet supported"
            )
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
        # into the 8-byte slot as ``ptr | (len << 32)``; other types
        # use the size-dispatched store directly.
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
            self._write(f"{store_op} offset={i * elem_size}")
        # Drop the leftover from local.tee (it lives in $_alloc_tmp
        # but the stack value persisted). i32.store consumed the tag
        # offset's stack value already in the data_ptr store above,
        # so the stack is balanced at this point.

    def _emit_index(self, instr: Index) -> None:
        """Lower ``xs[i]`` for a List receiver. Loads
        ``data_ptr + i * elem_size`` from memory. The bounds
        check is the analyzer's job (or the IR's; the Wasm path
        trusts that the index is valid).

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
        load_op = _load_op_for_size(elem_size)
        # Compute address: data_ptr + index * elem_size.
        self._push_value(instr.receiver)
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        # Index needs to be an i32 offset; the IR's Value for the
        # index is typically lit_int (i64) or local Int (i64).
        # Cast i64 -> i32 with ``i32.wrap_i64``.
        self._push_value(instr.index)
        self._write("i32.wrap_i64")
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
        iter_ty = instr.iter.ty
        if not iter_ty.startswith("List"):
            raise WasmEmissionError(
                f"For-iter over type {iter_ty!r}: only List iteration "
                f"is supported in Phase 6D-2 (range iteration lands "
                f"in a later phase)"
            )
        elem_ty = _element_type_of_list(iter_ty)
        elem_size = self._size_of(elem_ty)
        load_op = _load_op_for_size(elem_size)
        # We need a list-pointer scratch and an index scratch. Reuse
        # the match helpers; their live range does not overlap the
        # for loop's body (no match runs concurrently). The IR
        # walker has ensured these locals exist when needed (see
        # ``_collect_locals``).
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Capture the list pointer in $list_local.
        self._push_value(instr.iter)
        self._write(f"local.set ${list_local}")
        self._write(f"i32.const 0")
        self._write(f"local.set ${idx_local}")
        # block/loop encoding (same shape as while):
        self._block_counter += 1
        loop_label = f"$F{self._block_counter}_loop"
        exit_label = f"$F{self._block_counter}_exit"
        self._loop_labels.append((loop_label, exit_label))
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Loop guard: if idx >= len(list), exit.
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
        # Body.
        for sub in instr.body:
            self._emit_instr(sub)
        # Increment idx and continue.
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

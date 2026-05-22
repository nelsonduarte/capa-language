"""Map<String, V> emission mixin.

Owns the Wasm lowering for the ``Map<String, V>`` stdlib type:
allocation of the 16-byte header + initial 128-byte pair data
array, method dispatch (length / is_empty / set / contains_key /
get), the doubling-grow path, and the (key_ptr, key_len, value)
pair packing.

Phase 6D-3 specialises to String keys and a uniform 8-byte value
slot; widening the value slot for ``Map<String, String>`` lands
later. Map.get returns an ``Option<V>`` allocated inline via the
pre-registered Option layout.

Depends on the layout primitives in ``_layout`` and the String
push helpers in ``_strings`` (for ``_push_string_value_as_ptr_len``).
"""

from __future__ import annotations

from .._nodes import MakeMap, MethodCall, Value
from ._layout import (
    WasmEmissionError,
    _MAP_HEADER_SIZE, _MAP_LEN_OFFSET, _MAP_CAP_OFFSET, _MAP_DATA_OFFSET,
    _MAP_PAIR_SIZE, _MAP_PAIR_KEY_PTR_OFFSET, _MAP_PAIR_KEY_LEN_OFFSET,
    _MAP_PAIR_VALUE_OFFSET,
    _OPTION_LAYOUT,
    _map_value_type,
)


class _MapEmissionMixin:
    def _emit_make_map(self, instr: MakeMap) -> None:
        """Allocate a Map<String, V> header (16 bytes) + an initial
        data array of 8 pair slots (8 * 16 = 128 bytes). Layout
        matches Phase 6D-2 List for the header; the data slots are
        (key_ptr, key_len, value) triples each 16 bytes wide."""
        initial_cap = 8
        self._write(f"i32.const {_MAP_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        self._write(f"local.get ${instr.dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_MAP_LEN_OFFSET}")
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {initial_cap}")
        self._write(f"i32.store offset={_MAP_CAP_OFFSET}")
        # Data array allocation. Save the freshly-allocated pointer
        # to ``$_alloc_tmp`` so we can both write it into the header
        # and reuse it for any later per-pair element initialisation
        # (currently none for an empty map). The store consumes
        # (addr=header_ptr, value=data_ptr): wasm pops value first,
        # then addr, so the push order must be addr-then-value.
        self._write(f"i32.const {initial_cap * _MAP_PAIR_SIZE}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${instr.dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_MAP_DATA_OFFSET}")

    def _emit_map_method_call(self, instr: MethodCall) -> None:
        """Dispatch Map<String, V> methods. Phase 6D-3 supports:
        - length / is_empty: read header
        - set(k, v): linear scan, overwrite-or-append
        - contains_key(k): linear scan -> Bool
        - get(k): linear scan -> Option<V>

        Other methods (keys, values, pairs, ...) wait until List<T>
        can hold structured element types (tuples, strings) in 6D-4."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        value_ty = _map_value_type(recv_ty)

        if method == "length":
            self._push_value(recv)
            self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
            self._write("i64.extend_i32_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            self._push_value(recv)
            self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
            self._write("i32.eqz")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "set":
            self._emit_map_set(recv, instr.args[0], instr.args[1], value_ty)
            return
        if method == "contains_key":
            self._emit_map_contains_key(recv, instr.args[0])
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "get":
            self._emit_map_get(recv, instr.args[0], value_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "pairs":
            self._emit_map_pairs(recv, value_ty, instr.dst)
            return
        raise WasmEmissionError(
            f"Phase 6D-3: Map method {method!r} not yet supported "
            f"(keys / values need List of K / V, 6D-4+)"
        )

    def _emit_map_pairs(self, recv: Value, value_ty: str, dst) -> None:
        """``m.pairs() -> List<(K, V)>``. Iterate the map's data
        array, allocate a fresh ``(K, V)`` tuple per pair, push
        each tuple's pointer into a new List<Tuple>. K is fixed
        to String today (Phase 6D-3 map specialisation); the
        tuple's slot 0 stores the packed-i64 String, slot 1
        stores V via the same shape-aware encoding the rest of
        the emitter uses.

        Reuses ``$_m_scrut`` (map ptr) and ``$_m_tag`` (iteration
        index) as scratch; the for-loop's own scratch is separate
        (\$_f_list / \$_f_idx) so a ``for pair in m.pairs(): ...``
        doesn't clobber the iteration state."""
        if dst is None:
            return
        # _LIST_*_OFFSET constants come from the layout module; we
        # import locally so the _maps mixin stays close to the
        # data structures it works with.
        from ._layout import (
            _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET,
            _LIST_DATA_OFFSET,
        )
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        # Stash map pointer.
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        # Allocate list header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        # Copy len + cap from map into the new list header; the
        # data array is sized to the map's cap (max likely needed)
        # so subsequent ``.push`` operations on the returned list
        # don't immediately realloc.
        self._write(f"local.get ${dst}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Allocate the data array: cap * 4 (tuple pointers).
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write("i32.const 4")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Iterate i = 0 .. len.
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop = f"$Mpairs{self._block_counter}_loop"
        exit_ = f"$Mpairs{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if idx >= len: break
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # pair_addr = map.data_ptr + idx * 16
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_alloc_tmp_pair")
        # Allocate the tuple record (16 bytes: K + V).
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write(f"local.set $_alloc_tmp_result")
        # tuple[0] = packed-i64(key_ptr, key_len). The map's pair
        # already stores key_ptr at offset 0 and key_len at offset
        # 4; pack them into a single i64.
        self._write(f"local.get $_alloc_tmp_result")
        self._write("local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write("i64.extend_i32_u")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("local.tee $_alloc_tmp_i64")
        self._write("drop")
        self._write("local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write("i64.extend_i32_u")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.or")
        self._write("i64.store offset=0")
        # tuple[1] = pair.value (already encoded as i64 in the
        # map's pair record; direct copy).
        self._write(f"local.get $_alloc_tmp_result")
        self._write("local.get $_alloc_tmp_pair")
        self._write(f"i64.load offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write("i64.store offset=8")
        # data[idx] = tuple_ptr (i32, list's slots are 4 bytes).
        self._write("local.get $_alloc_tmp")
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 4")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.get $_alloc_tmp_result")
        self._write("i32.store")
        # idx++
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _push_map_value_as_i64(self, v: Value, value_ty: str) -> None:
        """Push a Map value onto the stack as a 64-bit packed slot.
        Int values use i64 directly; Bool / pointers are extended
        to i64 from their i32 wire form. String values pack
        ``ptr | (len << 32)`` into the 8-byte slot, identical to
        how List<String> stores its elements; downstream Map.get
        returns an Option<String> whose payload is the same packed
        i64, transparently consumed by the match-arm String unpack
        and Option.unwrap_or paths."""
        if value_ty == "Int":
            self._push_value(v)
            return
        if value_ty == "Bool":
            self._push_value(v)
            self._write("i64.extend_i32_s")
            return
        if value_ty == "Float":
            # Bitcast f64 -> i64 to fit the uniform 8-byte value
            # slot. The Map.get path's Option<Float> reads the
            # slot as f64.load directly (the i64 bytes are the
            # IEEE-754 f64 bit pattern); a future ``as_float``
            # accessor on the Option would just be an alias for
            # the existing JsonValue.as_num path.
            self._push_value(v)
            self._write("i64.reinterpret_f64")
            return
        if value_ty == "String":
            # Pack (ptr, len) into i64. Same dance as variant-ctor
            # String payload + MakeList<String>.
            self._push_string_value_as_ptr_len(v)
            self._write("i64.extend_i32_u")  # len -> i64
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("drop")
            self._write("i64.extend_i32_u")  # ptr -> i64
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.or")
            return
        # Pointer-shaped types (struct, sum, list, map). Extend i32
        # to i64 to fit the uniform value slot.
        if value_ty.split("<", 1)[0] in self._struct_layouts \
                or value_ty.split("<", 1)[0] in self._sum_layouts \
                or value_ty.startswith(("List", "Map", "Set")):
            self._push_value(v)
            self._write("i64.extend_i32_u")
            return
        raise WasmEmissionError(
            f"Phase 6D-3: Map value type {value_ty!r} not supported"
        )

    def _emit_map_set(
        self, recv: Value, k: Value, v: Value, value_ty: str,
    ) -> None:
        """Linear-scan ``m.set(k, v)``: replace value at existing
        key or append a new pair, growing the data array if at
        cap. Uses ``$_m_scrut`` for the map pointer, ``$_m_tag``
        for the iteration index, and ``$_alloc_tmp`` / ``$_alloc_tmp_i64``
        for the new value buffer."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        value_local = "_alloc_tmp_i64"

        # Stash receiver and key into scratch locals.
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        # Stash the value (packed to i64).
        self._push_map_value_as_i64(v, value_ty)
        self._write(f"local.set ${value_local}")
        # Two-level block: $set_done wraps the whole operation;
        # $scan_exit lets the inner scan terminate when the key is
        # not found. The overwrite branch ``br $set_done`` skips
        # the append fallback; the scan-not-found path falls
        # through to the append code below.
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        set_done = f"$Mset{self._block_counter}_done"
        scan_loop = f"$Mset{self._block_counter}_loop"
        scan_exit = f"$Mset{self._block_counter}_exit"
        self._write(f"block {set_done}")
        self._indent += 1
        self._write(f"block {scan_exit}")
        self._indent += 1
        self._write(f"loop {scan_loop}")
        self._indent += 1
        # Guard: idx >= len -> exit scan, fall through to append.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {scan_exit}")
        # pair_base = data_ptr + idx * 16
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        # Compare keys: $str_eq(pair.key_ptr, pair.key_len, key_ptr, key_len)
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Match: overwrite value and exit (skip append).
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${value_local}")
        self._write(f"i64.store offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write(f"br {set_done}")
        self._indent -= 1
        self._write("end")
        # idx++ and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {scan_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

        # Append branch: idx == len (reached via $scan_exit).
        # Check capacity; grow if needed.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._emit_map_grow(map_local)
        self._indent -= 1
        self._write("end")
        # pair_base = data_ptr + len * 16
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        # Store key_ptr, key_len, value.
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"i32.store offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${key_len_local}")
        self._write(f"i32.store offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${value_local}")
        self._write(f"i64.store offset={_MAP_PAIR_VALUE_OFFSET}")
        # Increment len.
        self._write(f"local.get ${map_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_MAP_LEN_OFFSET}")
        # Close the outer $set_done block.
        self._indent -= 1
        self._write("end")

    def _emit_map_grow(self, map_local: str) -> None:
        """Grow the map's data array by doubling capacity. Uses
        ``memory.copy`` to move existing pairs into the fresh
        allocation. The new cap is written to the header along
        with the new data_ptr.

        Uses ``$_alloc_tmp_new_data`` for the freshly-allocated
        data array so the caller's other ``$_alloc_tmp_*`` slots
        (e.g. the key_ptr being inserted) are not clobbered."""
        # new_cap = cap * 2 (min 8 if cap was 0).
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.tee $_alloc_tmp_newcap")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_alloc_tmp_newcap")
        self._indent -= 1
        self._write("end")
        # Allocate new data area.
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.tee $_alloc_tmp_new_data")
        # memory.copy(dst=new_data, src=old_data, n=len*pair_size).
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header.
        self._write(f"local.get ${map_local}")
        self._write("local.get $_alloc_tmp_new_data")
        self._write(f"i32.store offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.store offset={_MAP_CAP_OFFSET}")

    def _emit_map_contains_key(self, recv: Value, k: Value) -> None:
        """Linear-scan ``m.contains_key(k)``. Leaves an i32 (0/1)
        on the stack."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop = f"$Mck{self._block_counter}_loop"
        exit_ = f"$Mck{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # Compare key.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # idx++, loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        # Verifier-satisfying terminator: the loop never falls
        # through (it either br's to $exit_ with a value or br's
        # back to itself), but Wasm's static checker cannot prove
        # that, so we mark fall-through as unreachable.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_map_get(self, recv: Value, k: Value, value_ty: str) -> None:
        """Linear-scan ``m.get(k)`` returning an Option<V> pointer.
        Allocates a fresh 16-byte Option<V> with tag=Some + value
        on hit, or tag=None on miss."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        result_local = "_alloc_tmp_result"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        # Alloc the Option result up front; we will fill the tag
        # (and maybe value) below depending on hit/miss.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop = f"$Mget{self._block_counter}_loop"
        exit_ = f"$Mget{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: idx >= len -> miss path.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # Miss: store tag=None.
        self._write(f"local.get ${result_local}")
        self._write(f"i32.const 1")  # None tag
        self._write("i32.store")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # Compare key.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Hit: store tag=Some + value from pair.
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")  # Some tag
        self._write("i32.store")
        self._write(f"local.get ${result_local}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i64.load offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write(f"i64.store offset={_OPTION_LAYOUT['variants']['Some'][1][0][0]}")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # idx++, loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Leave result pointer on the stack.
        self._write(f"local.get ${result_local}")

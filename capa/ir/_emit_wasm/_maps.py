"""Map<K, V> emission mixin.

Owns the Wasm lowering for the ``Map<K, V>`` stdlib type:
allocation of the 16-byte header + initial 128-byte pair data
array, method dispatch (length / is_empty / set / contains_key /
get / pairs), the doubling-grow path, and the per-key-type pair
shape.

Pair layout (uniform 16 bytes per slot, indexed by key type so
the allocator, grow loop, and pair iterator stay generic):

- String: ``key_ptr i32 @0, key_len i32 @4, value i64 @8``
- Int:    ``key i64 @0, value i64 @8``
- Bool:   ``key i32 @0, pad i32 @4, value i64 @8``

Per-key dispatch is funneled through two helpers:

- ``_emit_push_map_key_canonical(key_value, key_ty)``: pushes the
  lookup key onto the operand stack in its canonical form (Int
  pushes i64, Bool pushes i32, String pushes a ptr/len pair into
  the scratch locals the existing code already used).
- ``_emit_compare_pair_key_to(key_ty, pair_addr_local)``: emits a
  zero/one i32 comparison of the pair's key at ``pair_addr_local``
  against the canonical key pushed/stashed by the helper above.

Value encoding (``_push_map_value_as_i64``) is unchanged: every
value type packs into the 8-byte slot at offset 8 the same way it
did before the key generalisation. Map.get keeps returning an
``Option<V>`` allocated inline via the pre-registered Option layout.

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
    _map_value_type, _map_key_type,
)


class _MapEmissionMixin:
    def _emit_make_map(self, instr: MakeMap) -> None:
        """Allocate a Map<K, V> header (16 bytes) + an initial data
        array of 8 pair slots (8 * 16 = 128 bytes). The header
        matches Phase 6D-2 List; the per-pair shape is uniform 16
        bytes so the allocator and grow loop are independent of K."""
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
        """Dispatch Map<K, V> methods. Supports:
        - length / is_empty: read header
        - set(k, v): linear scan, overwrite-or-append
        - contains_key(k): linear scan -> Bool
        - get(k): linear scan -> Option<V>
        - pairs(): allocate List<(K, V)> in insertion order

        Other methods (keys, values) wait until List<T> can hold
        structured element types for non-String K (the existing
        path packs key+value into a 16-byte tuple)."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        key_ty = _map_key_type(recv_ty)
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
            self._emit_map_set(recv, instr.args[0], instr.args[1], key_ty, value_ty)
            return
        if method == "contains_key":
            self._emit_map_contains_key(recv, instr.args[0], key_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "get":
            self._emit_map_get(recv, instr.args[0], key_ty, value_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "pairs":
            self._emit_map_pairs(recv, key_ty, value_ty, instr.dst)
            return
        raise WasmEmissionError(
            f"Map method {method!r} not yet supported on the Wasm backend "
            f"(keys / values need List of K / V tuples)"
        )

    # ----- per-key canonical push + compare helpers -----------

    def _emit_push_map_key_canonical(self, key_value: Value, key_ty: str) -> None:
        """Stash the lookup key in canonical form in the scratch
        locals the rest of the emitter consults during the linear
        scan. Per-type:

        - String: push ptr/len via the existing string helper, stash
          into ``$_alloc_tmp`` (ptr) and ``$_alloc_tmp_key_len`` (len).
        - Int: push i64, stash into ``$_alloc_tmp_key_i64``.
        - Bool: push i32, stash into ``$_alloc_tmp`` (i32 slot).
        - Pointer-shape (struct / sum / tuple): push i32 pointer,
          stash into ``$_alloc_tmp_key_ptr`` so the linear scan can
          pass it as the second operand of ``call $eq_<TypeName>``
          without re-evaluating the key Value.

        The compare helper reads the same scratch locals back, so
        the pair (canonical-push, pair-key-compare) is the only
        pair of calls a Map-method emitter needs to make."""
        if key_ty == "String":
            self._push_string_value_as_ptr_len(key_value)
            self._write("local.set $_alloc_tmp_key_len")
            self._write("local.set $_alloc_tmp")
            return
        if key_ty == "Int":
            # Dedicated key local: $_alloc_tmp_i64 is also used by
            # the String-value packing dance and by Map.set's value
            # encoder, so storing the Int key there would be
            # overwritten before the linear-scan compare.
            self._push_value(key_value)
            self._write("local.set $_alloc_tmp_key_i64")
            return
        if key_ty == "Bool":
            self._push_value(key_value)
            self._write("local.set $_alloc_tmp")
            return
        if self._is_pointer_shape_ty(key_ty):
            self._push_value(key_value)
            self._write("local.set $_alloc_tmp_key_ptr")
            return
        raise WasmEmissionError(
            f"Map key type {key_ty!r} not supported on the Wasm backend "
            f"(supported: String / Int / Bool / struct / sum / tuple)"
        )

    def _emit_compare_pair_key_to(self, key_ty: str, pair_addr_local: str) -> None:
        """Push an i32 0/1 onto the stack that compares the map
        pair at ``pair_addr_local`` against the canonical key
        previously stashed by ``_emit_push_map_key_canonical``.

        Per-type:

        - String: ``$str_eq(pair.key_ptr, pair.key_len, canon_ptr, canon_len)``
        - Int: ``pair.key_i64 == canonical_i64``
        - Bool: ``pair.key_i32 == canonical_i32``
        - Pointer-shape: ``$eq_<TypeName>(pair.key_ptr, canonical_ptr)``
          (the slice-3 structural-equality helper compares the two
          heap records by value).
        """
        if key_ty == "String":
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
            self._write("local.get $_alloc_tmp")
            self._write("local.get $_alloc_tmp_key_len")
            self._write("call $str_eq")
            return
        if key_ty == "Int":
            self._write(f"local.get ${pair_addr_local}")
            self._write("i64.load offset=0")
            self._write("local.get $_alloc_tmp_key_i64")
            self._write("i64.eq")
            return
        if key_ty == "Bool":
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("local.get $_alloc_tmp")
            self._write("i32.eq")
            return
        if self._is_pointer_shape_ty(key_ty):
            from ._equality import _eq_key
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("local.get $_alloc_tmp_key_ptr")
            self._write(f"call $eq_{_eq_key(key_ty)}")
            return
        raise WasmEmissionError(
            f"Map key type {key_ty!r} not supported on the Wasm backend "
            f"(supported: String / Int / Bool / struct / sum / tuple)"
        )

    def _emit_store_pair_key(self, key_ty: str, pair_addr_local: str) -> None:
        """Write the canonical key into the pair at ``pair_addr_local``.
        Mirrors ``_emit_compare_pair_key_to`` for the append branch
        of ``_emit_map_set``: the canonical key is in the same
        scratch locals; the per-type layout determines the store.

        - String: ``pair.key_ptr = canon_ptr; pair.key_len = canon_len``
        - Int: ``pair[0..8] = canonical_i64``
        - Bool: ``pair[0..4] = canonical_i32`` (4-byte pad at offset 4
          left untouched, matches the uniform 16-byte stride)
        - Pointer-shape: ``pair[0..4] = canonical_i32`` (the key
          slot holds the heap pointer; same 4-byte pad as Bool).
        """
        if key_ty == "String":
            self._write(f"local.get ${pair_addr_local}")
            self._write("local.get $_alloc_tmp")
            self._write(f"i32.store offset={_MAP_PAIR_KEY_PTR_OFFSET}")
            self._write(f"local.get ${pair_addr_local}")
            self._write("local.get $_alloc_tmp_key_len")
            self._write(f"i32.store offset={_MAP_PAIR_KEY_LEN_OFFSET}")
            return
        if key_ty == "Int":
            self._write(f"local.get ${pair_addr_local}")
            self._write("local.get $_alloc_tmp_key_i64")
            self._write("i64.store offset=0")
            return
        if key_ty == "Bool":
            self._write(f"local.get ${pair_addr_local}")
            self._write("local.get $_alloc_tmp")
            self._write("i32.store offset=0")
            return
        if self._is_pointer_shape_ty(key_ty):
            self._write(f"local.get ${pair_addr_local}")
            self._write("local.get $_alloc_tmp_key_ptr")
            self._write("i32.store offset=0")
            return
        raise WasmEmissionError(
            f"Map key type {key_ty!r} not supported on the Wasm backend "
            f"(supported: String / Int / Bool / struct / sum / tuple)"
        )

    def _emit_load_pair_key_for_tuple(
        self, key_ty: str, pair_addr_local: str, tuple_addr_local: str,
    ) -> None:
        """Materialise the pair's key into slot 0 of a fresh
        ``(K, V)`` tuple at ``tuple_addr_local``. Per-type:

        - String: pack (ptr, len) into a single packed i64 and store
          to ``tuple[0]`` (matches the existing tuple-of-String shape
          the rest of the emitter uses, e.g. List<(String, V)>).
        - Int: store the i64 key directly at ``tuple[0]``.
        - Bool: store the i32 key at ``tuple[0]`` (the tuple slot is
          4-byte wide for a Bool element; this matches the layout
          the for-loop's tuple-destructure code expects).
        - Pointer-shape (struct / sum / tuple): copy the i32 heap
          pointer at ``pair[0]`` into ``tuple[0]``. Per slice 1,
          pointer-shape tuple elements occupy 4 bytes at offset 0.
        """
        if key_ty == "String":
            self._write(f"local.get ${tuple_addr_local}")
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("drop")
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
            self._write("i64.extend_i32_u")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.or")
            self._write("i64.store offset=0")
            return
        if key_ty == "Int":
            self._write(f"local.get ${tuple_addr_local}")
            self._write(f"local.get ${pair_addr_local}")
            self._write("i64.load offset=0")
            self._write("i64.store offset=0")
            return
        if key_ty == "Bool":
            self._write(f"local.get ${tuple_addr_local}")
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("i32.store offset=0")
            return
        if self._is_pointer_shape_ty(key_ty):
            self._write(f"local.get ${tuple_addr_local}")
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("i32.store offset=0")
            return
        raise WasmEmissionError(
            f"Map key type {key_ty!r} not supported on the Wasm backend "
            f"(supported: String / Int / Bool / struct / sum / tuple)"
        )

    def _emit_map_pairs(
        self, recv: Value, key_ty: str, value_ty: str, dst,
    ) -> None:
        """``m.pairs() -> List<(K, V)>``. Iterate the map's data
        array, allocate a fresh ``(K, V)`` tuple per pair, push
        each tuple's pointer into a new List<Tuple>. Key encoding
        in tuple slot 0 is per-type (see
        ``_emit_load_pair_key_for_tuple``); value in slot 1 is the
        same 8-byte slot the map stores it in.

        Reuses ``$_m_scrut`` (map ptr) and ``$_m_tag`` (iteration
        index) as scratch; the for-loop's own scratch is separate
        ($_f_list / $_f_idx) so a ``for pair in m.pairs(): ...``
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
        self._write("local.set $_alloc_tmp_result")
        # tuple[0] = pair.key (encoding depends on K).
        self._emit_load_pair_key_for_tuple(
            key_ty, "_alloc_tmp_pair", "_alloc_tmp_result",
        )
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
            f"Map value type {value_ty!r} not supported on the Wasm backend"
        )

    def _emit_map_set(
        self, recv: Value, k: Value, v: Value, key_ty: str, value_ty: str,
    ) -> None:
        """Linear-scan ``m.set(k, v)``: replace value at existing
        key or append a new pair, growing the data array if at
        cap. Uses ``$_m_scrut`` for the map pointer, ``$_m_tag``
        for the iteration index, the per-type key scratch locals
        (``$_alloc_tmp`` / ``$_alloc_tmp_key_len`` / ``$_alloc_tmp_i64``,
        see ``_emit_push_map_key_canonical``), and
        ``$_alloc_tmp_set_value`` for the value buffer (separate so
        Int-key emission doesn't clobber its key i64 stash with the
        value i64)."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        value_local = "_alloc_tmp_set_value"

        # Stash receiver and key into scratch locals.
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._emit_push_map_key_canonical(k, key_ty)
        # Stash the value (packed to i64). For Int keys this MUST
        # land in a different local than the key (which already
        # occupies $_alloc_tmp_i64); $_alloc_tmp_set_value is
        # dedicated so the key and value coexist.
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
        self._write(f"local.set $_alloc_tmp_pair")
        # Compare keys via the per-type helper.
        self._emit_compare_pair_key_to(key_ty, "_alloc_tmp_pair")
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
        self._write(f"local.set $_alloc_tmp_pair")
        # Store key (per type) + value.
        self._emit_store_pair_key(key_ty, "_alloc_tmp_pair")
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

    def _emit_map_contains_key(
        self, recv: Value, k: Value, key_ty: str,
    ) -> None:
        """Linear-scan ``m.contains_key(k)``. Leaves an i32 (0/1)
        on the stack."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._emit_push_map_key_canonical(k, key_ty)
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
        # Compute pair address.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.set $_alloc_tmp_pair")
        # Compare key (per type).
        self._emit_compare_pair_key_to(key_ty, "_alloc_tmp_pair")
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

    def _emit_map_get(
        self, recv: Value, k: Value, key_ty: str, value_ty: str,
    ) -> None:
        """Linear-scan ``m.get(k)`` returning an Option<V> pointer.
        Allocates a fresh 16-byte Option<V> with tag=Some + value
        on hit, or tag=None on miss."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        result_local = "_alloc_tmp_result"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._emit_push_map_key_canonical(k, key_ty)
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
        # Compute pair address.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.set $_alloc_tmp_pair")
        # Compare key (per type).
        self._emit_compare_pair_key_to(key_ty, "_alloc_tmp_pair")
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

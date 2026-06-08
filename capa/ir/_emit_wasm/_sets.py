"""Set<T> emission mixin.

Owns the Wasm lowering for the ``Set<T>`` stdlib type. A Set is
represented exactly like a List<T> (a 16-byte header of len, cap,
data_ptr, padding, plus a separately-allocated element array) with
two behavioural differences:

- ``add`` dedups: it scans the existing elements and only appends
  when no structurally-equal element is already present, so the
  element array never holds duplicates.
- the array is treated as *insertion-ordered*: ``remove`` shifts the
  tail down by one slot (rather than swap-removing the last element
  into the gap) so the surviving elements keep their first-insertion
  order. ``for x in set``, ``to_list()``, and iteration all observe
  that order, matching the dict-backed Python ``CapaSet`` oracle.

Element load / store / compare are per-type, identical to List:
Int is an 8-byte i64, Bool a 4-byte i32, Float an 8-byte f64,
String a packed i64 (ptr in low 32, len in high 32), and any
pointer-shape (struct / sum / tuple / nested collection) a 4-byte
i32 heap pointer. Structural compare for the dedup / membership scan
reuses ``_emit_leaf_compare`` from ``_equality`` so two separately
built but equal records dedup correctly (via the element's
``$eq_<key>`` helper) and Strings compare by bytes (via ``$str_eq``).

Depends on the layout primitives in ``_layout`` and the String push
helper in ``_strings`` (``_push_string_value_as_ptr_len``).
"""

from __future__ import annotations

from .._nodes import MethodCall, Value
from ._layout import (
    WasmEmissionError,
    _SET_HEADER_SIZE, _SET_LEN_OFFSET, _SET_CAP_OFFSET, _SET_DATA_OFFSET,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _element_type_of_set,
    _load_op_for_size, _store_op_for_size,
)


class _SetEmissionMixin:
    def _emit_make_set(self, instr) -> None:
        """Allocate a Set<T> header (16 bytes) + an initial element
        data array of cap 8, with len 0. ``new_set()`` is always
        empty (the analyzer requires a type annotation but no
        elements), so this mirrors the empty-List allocation path:
        len = 0, cap = 8, a fresh ``cap * elem_size`` data array
        installed in the header's data slot. The set pointer lands
        in ``instr.dst``."""
        set_ty = self._dst_capa_ty(instr.dst) or "Set<Int>"
        elem_ty = _element_type_of_set(set_ty)
        elem_size = self._size_of(elem_ty)
        cap = 8
        self._write(f"i32.const {_SET_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        self._write(f"local.get ${instr.dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_SET_LEN_OFFSET}")
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {cap}")
        self._write(f"i32.store offset={_SET_CAP_OFFSET}")
        # Data array: cap * elem_size bytes. Save the pointer so we
        # can both write it into the header and (if this were a
        # literal) initialise slots; for an empty set the store is
        # the only use. Push order is addr-then-value for i32.store.
        self._write(f"i32.const {cap * elem_size}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${instr.dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_SET_DATA_OFFSET}")

    def _emit_set_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a Set receiver:
        - length / is_empty: read the header
        - add(x): dedup-scan, grow-if-needed, append at len
        - remove(x): scan, shift tail down, decrement len
        - contains(x): linear scan -> i32 0/1
        - to_list(): copy the element array into a fresh List<T>"""
        recv = instr.receiver
        method = instr.method
        recv_ty = self._effective_value_ty(recv)
        elem_ty = _element_type_of_set(recv_ty)
        elem_size = self._size_of(elem_ty)

        if method == "length":
            # Result is Int (i64); the header stores len as i32.
            self._push_value(recv)
            self._write(f"i32.load offset={_SET_LEN_OFFSET}")
            self._write("i64.extend_i32_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            self._push_value(recv)
            self._write(f"i32.load offset={_SET_LEN_OFFSET}")
            self._write("i32.eqz")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "contains":
            self._emit_set_contains(recv, instr.args[0], elem_size, elem_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "add":
            self._emit_set_add(recv, instr.args[0], elem_size, elem_ty)
            return
        if method == "remove":
            self._emit_set_remove(recv, instr.args[0], elem_size, elem_ty)
            return
        if method == "to_list":
            self._emit_set_to_list(recv, elem_size, instr.dst)
            return
        raise WasmEmissionError(
            f"Set method {method!r} is not supported by the Wasm backend"
        )

    # ----- the shared dedup / membership compare ---------------------

    def _emit_set_compare_at(
        self, set_local: str, idx_local: str, elem_size: int, elem_ty: str,
        needle_scalar_local: str | None,
    ) -> None:
        """Push an i32 0/1 indicating whether the element at
        ``$idx_local`` of ``$set_local`` equals the needle. The
        needle must already be stashed:
        - scalar (Int / Bool): in ``needle_scalar_local`` (i64 for
          8-byte Int, i32 for 4-byte Bool / pointer fallback)
        - String: in ``$_str_b_ptr`` / ``$_str_b_len``
        - pointer-shape: in ``$_alloc_tmp`` (the needle pointer)
        Element address is ``data_ptr + idx * elem_size``."""
        from ._equality import _eq_key
        # Compute the element address.
        if elem_ty == "String":
            # Load packed i64, unpack into $_str_a_ptr / $_str_a_len,
            # compare via $str_eq against the stashed needle pair.
            self._write(f"local.get ${set_local}")
            self._write(f"i32.load offset={_SET_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
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
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            self._write("local.get $_str_b_ptr")
            self._write("local.get $_str_b_len")
            self._write("call $str_eq")
            return
        if elem_ty.split("<", 1)[0] in getattr(
            self, "_trait_value_types", ()
        ):
            # A trait element needs structural equality on its concrete
            # dynamic type, which has no compile-time ``$eq_<Trait>``
            # helper (a trait is not a structural-equality type), so the
            # ``call $eq_<elem>`` below would link to a missing function.
            # On the Python backend a sum-typed dynamic value is
            # additionally unhashable (a struct-typed one is hashable),
            # so a sum-typed trait Set element fails there too. Raise a
            # precise loud error; this slice covers trait values /
            # payloads, not trait Set elements.
            raise WasmEmissionError(
                f"Set element type {elem_ty!r} (a trait) is not supported "
                f"on the Wasm backend: a Set element needs structural "
                f"equality on the concrete value, which a trait-typed "
                f"element cannot resolve at compile time (and a sum-typed "
                f"dynamic value is unhashable on the Python backend too). "
                f"Use a concrete element type."
            )
        if self._is_pointer_shape_ty(elem_ty):
            # Load the element's i32 pointer, compare structurally
            # against the stashed needle pointer.
            self._write(f"local.get ${set_local}")
            self._write(f"i32.load offset={_SET_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
            self._write("i32.load")
            self._write("local.get $_alloc_tmp")
            self._write(f"call $eq_{_eq_key(elem_ty)}")
            return
        # Scalar element (Int 8-byte i64, Bool 4-byte i32, Float
        # 8-byte f64). Load with the size-dispatched op and compare
        # against the stashed needle with the matching width's eq.
        # Audit 2026-05-29 (post-slice-15): Float was being loaded
        # as i64 and compared via i64.eq on the bit pattern, which
        # both (a) crashed the wasm verifier on the stash side
        # (``local.set $_alloc_tmp_i64`` of an f64 push) and (b)
        # gave wrong NaN semantics (Python: ``float('nan') !=
        # float('nan')``; bit-eq would have said equal). The
        # dedicated Float branch loads f64 + compares with
        # ``f64.eq`` so both backends agree on the NaN case too.
        if elem_ty == "Float":
            self._write(f"local.get ${set_local}")
            self._write(f"i32.load offset={_SET_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
            self._write("f64.load")
            self._write("local.get $_alloc_tmp_f64")
            self._write("f64.eq")
            return
        eq_op = "i64.eq" if elem_size == 8 else "i32.eq"
        load_op = _load_op_for_size(elem_size)
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        self._write(f"local.get ${needle_scalar_local}")
        self._write(eq_op)

    def _emit_set_stash_needle(
        self, needle: Value, elem_size: int, elem_ty: str,
    ) -> str | None:
        """Stash the needle into the right scratch local(s) for its
        kind and return the scalar needle local name (for scalar
        kinds) or None (String / pointer-shape, which use the
        dedicated $_str_b_* / $_alloc_tmp slots)."""
        if elem_ty == "String":
            self._push_string_value_as_ptr_len(needle)
            self._write("local.set $_str_b_len")
            self._write("local.set $_str_b_ptr")
            return None
        if self._is_pointer_shape_ty(elem_ty):
            self._push_value(needle)
            self._write("local.set $_alloc_tmp")
            return None
        # Float gets its own f64 scratch (``$_alloc_tmp_f64``,
        # declared on demand). ``_emit_set_compare_at``'s Float
        # branch reads from there with ``f64.eq``.
        if elem_ty == "Float":
            self._push_value(needle)
            self._write("local.set $_alloc_tmp_f64")
            return "_alloc_tmp_f64"
        # Scalar: 8-byte Int -> i64 scratch, 4-byte Bool -> i32.
        if elem_size == 8:
            self._push_value(needle)
            self._write("local.set $_alloc_tmp_i64")
            return "_alloc_tmp_i64"
        self._push_value(needle)
        self._write("local.set $_alloc_tmp")
        return "_alloc_tmp"

    # ----- contains --------------------------------------------------

    def _emit_set_contains(
        self, recv: Value, needle: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Linear-scan ``s.contains(needle)``. Leaves an i32 0/1 on
        the stack. Uses ``$_m_scrut`` (set pointer) and ``$_m_tag``
        (index) as scratch, plus the per-kind needle scratch."""
        set_local = "_m_scrut"
        idx_local = "_m_tag"
        needle_scalar = self._emit_set_stash_needle(needle, elem_size, elem_ty)
        self._push_value(recv)
        self._write(f"local.set ${set_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop_label = f"$S{self._block_counter}_loop"
        exit_label = f"$S{self._block_counter}_exit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> push 0 and exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Compare element vs needle; on match push 1 and exit.
        self._emit_set_compare_at(
            set_local, idx_local, elem_size, elem_ty, needle_scalar,
        )
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
        # The loop body always exits via br; satisfy the block's i32
        # result with an unreachable terminator the validator treats
        # as polymorphic.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    # ----- add -------------------------------------------------------

    def _emit_set_add(
        self, recv: Value, elem: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """``s.add(elem)``: dedup-scan; if a structurally-equal
        element already exists, no-op; otherwise grow the data array
        if at capacity (doubling) and append at index len, then bump
        len. Insertion order is preserved because new elements always
        land at the tail.

        Uses ``$_m_scrut`` (set pointer), ``$_m_tag`` (scan index),
        and ``$_alloc_tmp`` (grow scratch / new data pointer) plus
        the per-kind needle scratch. The element value is re-pushed
        from ``elem`` at the store site (the scan stashes the same
        value into the compare scratch, so the original Value is
        still safe to evaluate twice -- it is a local / literal,
        not an effectful expression)."""
        set_local = "_m_scrut"
        idx_local = "_m_tag"
        needle_scalar = self._emit_set_stash_needle(elem, elem_size, elem_ty)
        self._push_value(recv)
        self._write(f"local.set ${set_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        # Two-level block: $add_done wraps the whole op; $scan_exit
        # ends the dedup scan when the element is not yet present.
        # A scan match ``br $add_done`` skips the append; the
        # not-found path falls through $scan_exit to the append code.
        self._block_counter += 1
        add_done = f"$Sadd{self._block_counter}_done"
        scan_loop = f"$Sadd{self._block_counter}_loop"
        scan_exit = f"$Sadd{self._block_counter}_exit"
        self._write(f"block {add_done}")
        self._indent += 1
        self._write(f"block {scan_exit}")
        self._indent += 1
        self._write(f"loop {scan_loop}")
        self._indent += 1
        # Guard: idx >= len -> exit scan (element not found).
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {scan_exit}")
        # Compare element at idx vs needle; on match, no-op + done.
        self._emit_set_compare_at(
            set_local, idx_local, elem_size, elem_ty, needle_scalar,
        )
        self._write("if")
        self._indent += 1
        self._write(f"br {add_done}")
        self._indent -= 1
        self._write("end")
        # idx++ and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {scan_loop}")
        self._indent -= 1
        self._write("end")  # loop
        self._indent -= 1
        self._write("end")  # scan_exit block

        # Append branch: element not present. Grow if at capacity.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._emit_set_grow(set_local, elem_size)
        self._indent -= 1
        self._write("end")
        # Store the element at data[len]. Address = data_ptr + len *
        # elem_size; re-read len from the header (grow does not touch
        # it). Mirrors the List push store path per element kind.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        if elem_ty == "String":
            # Pack (ptr, len) into the 8-byte slot, same dance as
            # List<String> push.
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
                self._write("f64.store")
            else:
                self._write(_store_op_for_size(elem_size))
        # Increment len.
        self._write(f"local.get ${set_local}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_SET_LEN_OFFSET}")
        # Close the outer $add_done block.
        self._indent -= 1
        self._write("end")

    def _emit_set_grow(self, set_local: str, elem_size: int) -> None:
        """Grow the set's element data array by doubling capacity
        (min 8 if cap was 0), copying existing elements via
        ``memory.copy``, and updating the header's data_ptr + cap.
        Mirrors the List / Map grow. Uses ``$_alloc_tmp`` for the new
        data pointer and ``$_alloc_tmp_newcap`` for the new capacity."""
        # new_cap = cap * 2 (bump to 8 if cap was 0).
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_CAP_OFFSET}")
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
        # Allocate new data array: new_cap * elem_size bytes.
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.tee $_alloc_tmp")
        # memory.copy(dst=new_data, src=old_data, n=len*elem_size).
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header: data_ptr = new_data, cap = new_cap.
        self._write(f"local.get ${set_local}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${set_local}")
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.store offset={_SET_CAP_OFFSET}")

    # ----- remove ----------------------------------------------------

    def _emit_set_remove(
        self, recv: Value, elem: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """``s.remove(elem)``: scan for a structurally-equal element;
        if found at index ``i``, shift every later element down by one
        slot (``memory.copy`` the tail back one stride) so insertion
        order of the survivors is preserved, then decrement len. If
        not found, no-op (discard-safe, matching the Python
        ``CapaSet.remove``).

        A swap-remove (moving the last element into the gap) would be
        cheaper but would REORDER the survivors, diverging from the
        dict-backed Python oracle's stable iteration. The shift keeps
        parity.

        Uses ``$_m_scrut`` (set pointer), ``$_m_tag`` (scan index)
        plus the per-kind needle scratch, and ``$_alloc_tmp`` /
        ``$_alloc_tmp_newcap`` for the shift address math."""
        set_local = "_m_scrut"
        idx_local = "_m_tag"
        needle_scalar = self._emit_set_stash_needle(elem, elem_size, elem_ty)
        self._push_value(recv)
        self._write(f"local.set ${set_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        rm_done = f"$Srm{self._block_counter}_done"
        scan_loop = f"$Srm{self._block_counter}_loop"
        self._write(f"block {rm_done}")
        self._indent += 1
        self._write(f"loop {scan_loop}")
        self._indent += 1
        # Guard: idx >= len -> not found, done (no-op).
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {rm_done}")
        # Compare element at idx vs needle; on match, shift + done.
        self._emit_set_compare_at(
            set_local, idx_local, elem_size, elem_ty, needle_scalar,
        )
        self._write("if")
        self._indent += 1
        # Shift the tail [idx+1, len) down by one slot:
        #   dst = data_ptr + idx * elem_size
        #   src = data_ptr + (idx + 1) * elem_size
        #   n   = (len - idx - 1) * elem_size
        # memory.copy handles overlapping forward-moving regions
        # correctly (it is specified to behave as if via a temporary).
        # dst address.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        # src address.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        # n = (len - idx - 1) * elem_size.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write("i32.sub")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("memory.copy")
        # len -= 1.
        self._write(f"local.get ${set_local}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write(f"i32.store offset={_SET_LEN_OFFSET}")
        self._write(f"br {rm_done}")
        self._indent -= 1
        self._write("end")
        # idx++ and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {scan_loop}")
        self._indent -= 1
        self._write("end")  # loop
        self._indent -= 1
        self._write("end")  # rm_done block

    # ----- to_list ---------------------------------------------------

    def _emit_set_to_list(self, recv: Value, elem_size: int, dst) -> None:
        """``s.to_list() -> List<T>``: allocate a fresh List header
        with the same len / cap and ``memory.copy`` the element array
        (same stride). The element encoding is identical between Set
        and List (both store T the same way), so a raw byte copy
        yields a valid List<T>. Insertion order is preserved because
        the copy is order-preserving. The List pointer lands in
        ``dst``."""
        if dst is None:
            return
        set_local = "_m_scrut"
        self._push_value(recv)
        self._write(f"local.set ${set_local}")
        # Allocate the List header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        # Copy len + cap from the set into the new list header.
        self._write(f"local.get ${dst}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_CAP_OFFSET}")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Allocate the list's data array (cap * elem_size) and copy.
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_CAP_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # memory.copy(dst=new_data, src=set_data, n=len*elem_size).
        self._write("local.get $_alloc_tmp")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${set_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("memory.copy")

"""Set<T> algebra emission: union / intersection / difference /
is_subset.

Each operation is lowered to a generated module-level helper
``$set_<op>_<key>(a i32, b i32) -> i32`` (mirroring the ``$eq_<key>``
helpers in ``_equality``). A helper owns its own locals, so the nested
"walk one set, test membership in another, append into a third" logic
never has to share the function-body scratch registers
(``$_m_scrut`` / ``$_m_tag`` / ``$_alloc_tmp``) that an inline lowering
would collide on. The method call site just pushes ``a`` and ``b`` and
``call``s the helper; the returned i32 set / bool pointer lands in the
instruction's ``dst``.

Result and ORDER are byte-identical with the Python ``CapaSet`` oracle
(``capa/runtime/_set.py``):

- ``union(a, b)``: copy ``a`` verbatim (it is already dedup'd and
  ordered), then for each element of ``b`` in ``b``'s order append it
  only if the result does not already hold it. So the result is
  ``a``'s elements in ``a``'s order, then ``b``'s new elements in
  ``b``'s order.
- ``intersection(a, b)``: walk ``a`` in ``a``'s order, append each
  element that ``b`` contains.
- ``difference(a, b)``: walk ``a`` in ``a``'s order, append each
  element that ``b`` does NOT contain.
- ``is_subset(a, b) -> i32``: walk ``a``; return 0 at the first
  element ``b`` lacks, else 1. The empty set returns 1 (vacuously).

Membership tests reuse ``_emit_set_stash_element_at`` +
``_emit_set_compare_at`` (from ``_equality`` / ``_sets``) so the per-
element-kind unpack / compare logic stays in one place and uses the
exact same notion of element equality as ``add`` / ``contains``. The
append path reuses ``_emit_set_copy_element_at`` (defined here), a
runtime-index analogue of ``_emit_set_add``'s store sequence.
"""

from __future__ import annotations

from .._nodes import MethodCall, Value
from .._walk import walk_module
from ._layout import (
    WasmEmissionError,
    _SET_HEADER_SIZE, _SET_LEN_OFFSET, _SET_CAP_OFFSET, _SET_DATA_OFFSET,
    _element_type_of_set,
    _load_op_for_size, _store_op_for_size,
)
from ._equality import _eq_key


_SET_ALGEBRA_METHODS = ("union", "intersection", "difference", "is_subset")


class _SetAlgebraMixin:
    # ----- call-site dispatch ----------------------------------------

    def _emit_set_algebra_call(self, instr: MethodCall) -> None:
        """``a.union(b)`` / ``.intersection(b)`` / ``.difference(b)`` ->
        a fresh Set<T> pointer; ``a.is_subset(b)`` -> an i32 0/1. Push
        ``a`` then ``b`` and call the generated helper; stash the result
        in ``dst``."""
        recv_ty = self._effective_value_ty(instr.receiver)
        elem_ty = _element_type_of_set(recv_ty)
        self._reject_unsupported_set_elem(elem_ty)
        key = _eq_key(f"Set<{elem_ty}>")
        self._push_value(instr.receiver)
        self._push_value(instr.args[0])
        self._write(f"call $set_{instr.method}_{key}")
        # union / intersection / difference yield a fresh Set<T> pointer;
        # is_subset yields an i32 Bool. Both are a single slot, dropped
        # when the call's value is discarded.
        ret_ty = "Bool" if instr.method == "is_subset" else f"Set<{elem_ty}>"
        self._store_or_drop_result(instr.dst, ret_ty)

    def _reject_unsupported_set_elem(self, elem_ty: str) -> None:
        """Trait-typed Set elements are rejected for the same Python-
        parity reason ``_emit_set_compare_at`` rejects them: a sum
        dynamic type is unhashable as a Python Set element, so the two
        backends cannot agree. Raise the same precise error here so the
        algebra surface fails loudly rather than emitting a broken
        helper."""
        if elem_ty.split("<", 1)[0] in getattr(self, "_trait_value_types", ()):
            raise WasmEmissionError(
                f"Set element type {elem_ty!r} (a trait) is not supported "
                f"on the Wasm backend: set algebra needs structural "
                f"equality on the concrete element, which a trait-typed "
                f"element cannot resolve at compile time. Use a concrete "
                f"element type."
            )

    # ----- discovery -------------------------------------------------

    def _collect_set_algebra_types(self, module) -> list[str]:
        """Concrete ``Set<T>`` types that need an algebra helper family,
        in first-seen order. A pointer-shape element additionally needs
        its ``$eq_<elem>`` helper, but the algebra never has to request it
        on its own: a non-empty ``Set<Struct>`` is always populated through
        ``add()``, which the equality discovery covers and which already
        pulls in ``$eq_<elem>``, and ``new_set()`` is the only Set
        constructor, so the helper is guaranteed to be present whenever the
        algebra needs it."""
        seen: set[str] = set()
        order: list[str] = []
        for _fn, instr in walk_module(module):
            if (isinstance(instr, MethodCall)
                    and instr.method in _SET_ALGEBRA_METHODS):
                recv_ty = instr.receiver.ty or ""
                if not recv_ty.startswith("Set"):
                    continue
                elem_ty = _element_type_of_set(recv_ty)
                norm = f"Set<{elem_ty}>"
                if norm not in seen:
                    seen.add(norm)
                    order.append(norm)
        return order

    def _set_algebra_needs_str_eq(self, module) -> bool:
        """Whether any algebra helper compares a ``Set<String>``
        element, so the module knows to emit ``$str_eq`` even if nothing
        else needs it."""
        for ty in self._collect_set_algebra_types(module):
            if _element_type_of_set(ty) == "String":
                return True
        return False

    # ----- helper emission -------------------------------------------

    def _emit_set_algebra_helpers(self, module) -> None:
        """Emit the four ``$set_<op>_<key>`` helpers for every Set type
        that uses any of them. All four are emitted per type (cheap, and
        keeps the discovery / emission symmetric); WAT resolves calls by
        name regardless of which subset a given program actually uses,
        and the wasm validator does not complain about unreferenced but
        well-formed functions."""
        for ty in self._collect_set_algebra_types(module):
            self._reject_unsupported_set_elem(_element_type_of_set(ty))
            self._emit_set_union_helper(ty)
            self._emit_set_intersection_helper(ty)
            self._emit_set_difference_helper(ty)
            self._emit_set_is_subset_helper(ty)

    def _set_helper_locals(self, elem_ty: str) -> None:
        """Declare the locals shared by every algebra helper: the result
        set pointer, two scan indices, the per-kind needle scratch slots
        that ``_emit_set_stash_element_at`` / ``_emit_set_compare_at``
        consult, plus the grow / address scratch the append path uses.
        Declared unconditionally (a few unused locals cost nothing and
        keep the four emitters uniform)."""
        self._write("(local $_res i32)")
        self._write("(local $_i i32)")
        self._write("(local $_j i32)")
        self._write("(local $_found i32)")
        # Append + grow scratch (mirrors $_alloc_tmp / $_alloc_tmp_newcap
        # in _emit_set_add / _emit_set_grow).
        self._write("(local $_alloc_tmp i32)")
        self._write("(local $_alloc_tmp_newcap i32)")
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("(local $_alloc_tmp_f64 f64)")
        # String compares unpack into the shared $_str_a_* / $_str_b_*
        # pairs the $str_eq call site reads.
        self._write("(local $_str_a_ptr i32)")
        self._write("(local $_str_a_len i32)")
        self._write("(local $_str_b_ptr i32)")
        self._write("(local $_str_b_len i32)")

    def _emit_alloc_empty_set(self, dst_local: str, elem_size: int) -> None:
        """Allocate a fresh empty Set<T> (16-byte header, len 0, cap 8,
        a cap*elem_size data array) into ``$dst_local``. Mirrors
        ``_emit_make_set`` but writes to a caller-chosen local instead of
        an instruction's dst, and uses ``$_alloc_tmp`` (declared by
        ``_set_helper_locals``) for the data pointer."""
        cap = 8
        self._write(f"i32.const {_SET_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst_local}")
        self._write(f"local.get ${dst_local}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_SET_LEN_OFFSET}")
        self._write(f"local.get ${dst_local}")
        self._write(f"i32.const {cap}")
        self._write(f"i32.store offset={_SET_CAP_OFFSET}")
        self._write(f"i32.const {cap * elem_size}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst_local}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_SET_DATA_OFFSET}")

    # ----- the runtime-index membership + append primitives ----------

    def _emit_set_contains_at(
        self, container_local: str, src_local: str, idx_local: str,
        elem_size: int, elem_ty: str,
    ) -> None:
        """Push i32 0/1: does ``$container_local`` hold the element at
        ``$src_local[$idx_local]``? Stashes that element as the needle
        (via ``_emit_set_stash_element_at``) and linear-scans the
        container with ``_emit_set_compare_at``. Uses ``$_j`` as the
        container scan index (the caller owns ``$idx_local`` / ``$_i``)."""
        needle_scalar = self._emit_set_stash_element_at(
            f"${src_local}", idx_local, elem_size, elem_ty,
        )
        self._write("i32.const 0")
        self._write("local.set $_j")
        self._block_counter += 1
        loop_label = f"$SA{self._block_counter}_cloop"
        exit_label = f"$SA{self._block_counter}_cexit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # $_j >= container.len -> not found, push 0.
        self._write("local.get $_j")
        self._write(f"local.get ${container_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # compare container[$_j] vs needle.
        self._emit_set_compare_at(
            container_local, "_j", elem_size, elem_ty, needle_scalar,
        )
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_j")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_j")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_set_append_at(
        self, res_local: str, src_local: str, idx_local: str,
        elem_size: int, elem_ty: str,
    ) -> None:
        """Append ``$src_local[$idx_local]`` to the end of ``$res_local``
        (no dedup; callers append only known-new elements). Grows the
        result's data array if at capacity, raw-copies the element slot
        (byte-identical Set/List element encoding), then bumps len.
        Mirrors ``_emit_set_add``'s append branch but the source is a
        runtime (set, index) pair rather than a Capa Value."""
        # Grow if res.len >= res.cap.
        self._write(f"local.get ${res_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"local.get ${res_local}")
        self._write(f"i32.load offset={_SET_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._emit_set_grow(res_local, elem_size)
        self._indent -= 1
        self._write("end")
        # dst address = res.data + res.len * elem_size.
        self._write(f"local.get ${res_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${res_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        # value = src[idx] loaded with the kind's op; raw byte copy keeps
        # packed-i64 String slots and i32 pointer slots valid as-is.
        self._write(f"local.get ${src_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        if elem_ty == "String":
            self._write("i64.load")
            self._write("i64.store")
        elif elem_ty == "Float":
            self._write("f64.load")
            self._write("f64.store")
        else:
            self._write(_load_op_for_size(elem_size))
            self._write(_store_op_for_size(elem_size))
        # res.len += 1.
        self._write(f"local.get ${res_local}")
        self._write(f"local.get ${res_local}")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_SET_LEN_OFFSET}")

    # ----- a shared walk-and-conditionally-append scaffold -----------

    def _emit_walk_a_append(
        self, ty: str, keep_when_b_contains: bool,
    ) -> None:
        """Body shared by intersection (keep when b contains) and
        difference (keep when b does not). Allocates an empty result,
        walks ``a`` in order, tests b-membership of each a-element, and
        appends the kept ones. Leaves the result pointer on the stack."""
        elem_ty = _element_type_of_set(ty)
        elem_size = self._size_of(elem_ty)
        self._emit_alloc_empty_set("_res", elem_size)
        self._write("i32.const 0")
        self._write("local.set $_i")
        self._block_counter += 1
        loop_label = f"$SA{self._block_counter}_aloop"
        exit_label = f"$SA{self._block_counter}_aexit"
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # $_i >= a.len -> done.
        self._write("local.get $_i")
        self._write("local.get $a")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # b contains a[$_i] ?
        self._emit_set_contains_at("b", "a", "_i", elem_size, elem_ty)
        if not keep_when_b_contains:
            self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_set_append_at("_res", "a", "_i", elem_size, elem_ty)
        self._indent -= 1
        self._write("end")
        # $_i++.
        self._write("local.get $_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_i")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_res")

    def _emit_set_intersection_helper(self, ty: str) -> None:
        key = _eq_key(ty)
        self._write(
            f"(func $set_intersection_{key} "
            f"(param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        self._set_helper_locals(_element_type_of_set(ty))
        self._emit_walk_a_append(ty, keep_when_b_contains=True)
        self._indent -= 1
        self._write(")")

    def _emit_set_difference_helper(self, ty: str) -> None:
        key = _eq_key(ty)
        self._write(
            f"(func $set_difference_{key} "
            f"(param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        self._set_helper_locals(_element_type_of_set(ty))
        self._emit_walk_a_append(ty, keep_when_b_contains=False)
        self._indent -= 1
        self._write(")")

    def _emit_set_union_helper(self, ty: str) -> None:
        """``$set_union_<key>(a, b)``: start from a copy of ``a`` (all
        of a's elements appended in a's order; a has no dups so no scan
        needed), then walk ``b`` and append each element the result does
        not already hold."""
        elem_ty = _element_type_of_set(ty)
        elem_size = self._size_of(elem_ty)
        key = _eq_key(ty)
        self._write(
            f"(func $set_union_{key} "
            f"(param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        self._set_helper_locals(elem_ty)
        self._emit_alloc_empty_set("_res", elem_size)
        # Phase 1: append every element of a (in a's order).
        self._write("i32.const 0")
        self._write("local.set $_i")
        self._block_counter += 1
        a_loop = f"$SA{self._block_counter}_uloopA"
        a_exit = f"$SA{self._block_counter}_uexitA"
        self._write(f"block {a_exit}")
        self._indent += 1
        self._write(f"loop {a_loop}")
        self._indent += 1
        self._write("local.get $_i")
        self._write("local.get $a")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {a_exit}")
        self._emit_set_append_at("_res", "a", "_i", elem_size, elem_ty)
        self._write("local.get $_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_i")
        self._write(f"br {a_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Phase 2: walk b; append each element not already in the result.
        self._write("i32.const 0")
        self._write("local.set $_i")
        self._block_counter += 1
        b_loop = f"$SA{self._block_counter}_uloopB"
        b_exit = f"$SA{self._block_counter}_uexitB"
        self._write(f"block {b_exit}")
        self._indent += 1
        self._write(f"loop {b_loop}")
        self._indent += 1
        self._write("local.get $_i")
        self._write("local.get $b")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {b_exit}")
        # result contains b[$_i] ?  (skip append when it does)
        self._emit_set_contains_at("_res", "b", "_i", elem_size, elem_ty)
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_set_append_at("_res", "b", "_i", elem_size, elem_ty)
        self._indent -= 1
        self._write("end")
        self._write("local.get $_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_i")
        self._write(f"br {b_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_res")
        self._indent -= 1
        self._write(")")

    def _emit_set_is_subset_helper(self, ty: str) -> None:
        """``$set_is_subset_<key>(a, b) -> i32``: walk ``a``; return 0 at
        the first a-element ``b`` does not contain, else 1. Empty ``a``
        falls straight through to 1 (vacuously a subset)."""
        elem_ty = _element_type_of_set(ty)
        elem_size = self._size_of(elem_ty)
        key = _eq_key(ty)
        self._write(
            f"(func $set_is_subset_{key} "
            f"(param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        self._set_helper_locals(elem_ty)
        self._write("i32.const 0")
        self._write("local.set $_i")
        self._block_counter += 1
        done = f"$SA{self._block_counter}_subdone"
        loop_label = f"$SA{self._block_counter}_subloop"
        a_exit = f"$SA{self._block_counter}_subexit"
        self._write(f"block {done} (result i32)")
        self._indent += 1
        self._write(f"block {a_exit}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        self._write("local.get $_i")
        self._write("local.get $a")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {a_exit}")
        # if b does NOT contain a[$_i] -> not a subset, return 0.
        self._emit_set_contains_at("b", "a", "_i", elem_size, elem_ty)
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {done}")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_i")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")  # loop
        self._indent -= 1
        self._write("end")  # a_exit block
        # Survived the walk -> subset.
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")  # done block
        self._indent -= 1
        self._write(")")

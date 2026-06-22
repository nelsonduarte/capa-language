"""String-emission mixin.

Owns every String-related emission path that does not also belong
to a different family of types:

- Concatenation (``a + b`` for String operands)
- Method dispatch (``length``, ``is_empty``, ``contains``,
  ``starts_with``, ``ends_with``, ``substring``, ``to_upper``,
  ``to_lower``, ``trim``, ``trim_start``, ``trim_end``)
- Helpers that flatten a String Value to operand-stack form:
  ``_push_string_value_as_ptr_len``, ``_push_string_len_only``,
  ``_push_string_field_ptr_only`` / ``_field_len_only``
- ``_set_string_dst`` -- bind (ptr, len) on the stack into a String
  local
- ``_emit_string_assign`` -- local-to-local String binding
- FormatStr lowering (``_emit_format_str``, ``_emit_format_part_stash``)
- ``_emit_byte_is_whitespace`` -- inline whitespace predicate used
  by trim

Capture-aware throughout: when called inside a lifted lambda body,
String pushes load from the env record at the capture's offset
instead of the missing ``${name}_ptr`` / ``${name}_len`` locals.
"""

from __future__ import annotations

from typing import Optional

from .._nodes import BinOp, FormatStr, MethodCall, Value
from ._layout import (
    WasmEmissionError,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _OPTION_LAYOUT,
)


class _StringEmissionMixin:
    def _emit_string_concat(self, instr: BinOp) -> None:
        """Emit a String + String concatenation by delegating to the
        ``$str_concat`` runtime helper, which returns the result's
        (ptr, len) on the operand stack.

        Used by source-level ``a + b`` where both operands have type
        String. ``$str_concat`` grows the left operand's buffer in
        place when it is the last bump allocation (so ``out = out +
        chunk`` in a loop is O(n) amortised instead of O(n^2)) and
        otherwise allocates a fresh buffer and copies both operands;
        either way the result is a new (ptr, len) pair that leaves
        the existing bytes of both operands untouched, so every live
        view of ``a`` or ``b`` stays valid. See
        ``_RuntimeHelpersMixin._emit_str_concat_function`` for the
        grow-only safety argument."""
        self._push_string_value_as_ptr_len(instr.left)
        self._push_string_value_as_ptr_len(instr.right)
        self._write("call $str_concat")
        self._set_string_dst(instr.dst)

    def _push_string_field_ptr_only(self, v: Value) -> None:
        """Push the ptr half of a String Value as i32 (for struct
        field stores). Wraps the existing ``_push_string_value_as_ptr_len``
        but only keeps the ptr; the caller handles the len via
        ``_push_string_field_len_only``."""
        if v.kind == "lit_str":
            offset, _length = self._intern_string(v.literal)
            self._write(f"i32.const {offset}")
            return
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}_ptr")
            return
        if v.kind == "global" and v.name in self._const_values:
            # Top-level String ``const`` used as a struct-field
            # initializer. Re-dispatch on the underlying lit_str
            # literal, mirroring the const branch in
            # ``_push_string_value_as_ptr_len``.
            self._push_string_field_ptr_only(self._const_values[v.name])
            return
        raise WasmEmissionError(
            f"cannot push string ptr of Value kind {v.kind!r}"
        )

    def _push_string_field_len_only(self, v: Value) -> None:
        if v.kind == "lit_str":
            _offset, length = self._intern_string(v.literal)
            self._write(f"i32.const {length}")
            return
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}_len")
            return
        if v.kind == "global" and v.name in self._const_values:
            # Top-level String ``const`` used as a struct-field
            # initializer. Re-dispatch on the underlying lit_str
            # literal, mirroring the const branch in
            # ``_push_string_value_as_ptr_len``.
            self._push_string_field_len_only(self._const_values[v.name])
            return
        raise WasmEmissionError(
            f"cannot push string len of Value kind {v.kind!r}"
        )

    def _emit_string_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a String receiver. Strings are
        (ptr, len) pairs throughout; this method's job is to read
        from the receiver, optionally allocate a fresh buffer, and
        bind the result to ``instr.dst``.

        Methods supported: length, is_empty, contains, starts_with,
        ends_with, substring, to_upper, to_lower, trim, trim_start,
        trim_end, split, replace, char_at, index_of. The last three
        landed in slice 4 (2026-05); replace allocates a fresh buffer
        sized by an upfront occurrence count, char_at walks UTF-8
        codepoints to assemble an ``Option<String>``, and index_of
        returns an ``Option<Int>`` byte offset (no ``-1`` sentinel)."""
        method = instr.method
        recv = instr.receiver
        dst = instr.dst

        # Push (recv_ptr, recv_len) onto the operand stack twice
        # for any method that compares against a needle; the two
        # copies live in scratch locals so we can read multiple
        # times without re-evaluating the receiver.
        if method == "length":
            # Slice 17 (2026-05-29): code-point count, not byte
            # count. Matches Python ``len(s)``. Pre-fix Wasm
            # returned the byte length which diverged silently on
            # any non-ASCII string (no parity test exercised
            # multi-byte strings).
            self._push_string_value_as_ptr_len(recv)
            self._write("call $str_codepoint_count")
            self._write("i64.extend_i32_s")
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "is_empty":
            self._push_string_len_only(recv)
            self._write("i32.eqz")
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "contains":
            self._emit_string_contains(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "starts_with":
            self._emit_string_starts_with(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "ends_with":
            self._emit_string_ends_with(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "substring":
            self._emit_string_substring(recv, instr.args[0], instr.args[1], dst)
            return
        if method == "to_upper":
            self._emit_string_case_transform(recv, dst, upper=True)
            return
        if method == "to_lower":
            self._emit_string_case_transform(recv, dst, upper=False)
            return
        if method == "trim":
            self._emit_string_trim(recv, dst, left=True, right=True)
            return
        if method == "trim_start":
            self._emit_string_trim(recv, dst, left=True, right=False)
            return
        if method == "trim_end":
            self._emit_string_trim(recv, dst, left=False, right=True)
            return
        if method == "split":
            self._emit_string_split(recv, instr.args[0], dst)
            return
        if method == "replace":
            self._emit_string_replace(recv, instr.args[0], instr.args[1], dst)
            return
        if method == "char_at":
            self._emit_string_char_at(recv, instr.args[0], dst)
            return
        if method == "index_of":
            self._emit_string_index_of(recv, instr.args[0], dst)
            return
        if method == "bytes":
            self._emit_string_bytes(recv, dst)
            return
        raise WasmEmissionError(
            f"String method {method!r} is not implemented on the Wasm "
            f"backend"
        )

    def _push_string_len_only(self, v: Value) -> None:
        """Push just the length component (i32) of a String value
        onto the operand stack. Used by length / is_empty handlers
        that do not need the pointer."""
        if v.kind == "lit_str":
            _offset, length = self._intern_string(v.literal)
            self._write(f"i32.const {length}")
            return
        if v.kind in ("local", "param") and v.name in self._current_captures:
            offset, capa_ty = self._current_captures[v.name]
            if capa_ty == "String":
                self._write("local.get $env")
                self._write(f"i32.load offset={offset + 4}")
                return
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}_len")
            return
        raise WasmEmissionError(
            f"cannot push string length of Value kind {v.kind!r}"
        )

    def _set_string_dst(self, dst: str) -> None:
        """Pop (ptr, len) from the operand stack into the dst
        String's two locals. Used by every method that returns a
        String. The push order is (ptr, len) so the consumer sets
        len first (top of stack), then ptr."""
        self._write(f"local.set ${dst}_len")
        self._write(f"local.set ${dst}_ptr")

    def _emit_string_contains(self, recv: Value, needle: Value) -> None:
        """Linear scan: ``recv.contains(needle)``. For each position
        i in [0, recv.len - needle.len], check if needle equals
        recv[i:i+needle.len]; return 1 on first match, 0 if
        exhausted. Empty needle is treated as always-found."""
        # Save (ptr, len) for both receiver and needle.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_string_value_as_ptr_len(needle)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # i = 0; while i + needle.len <= recv.len, str_eq the slice.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        loop = f"$Sc{self._block_counter}_loop"
        exit_ = f"$Sc{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: i + needle.len > recv.len -> done with 0.
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # str_eq(recv.ptr + i, needle.len, needle.ptr, needle.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # i++; continue.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_string_starts_with(self, recv: Value, prefix: Value) -> None:
        """``recv.starts_with(prefix)``: false if prefix.len >
        recv.len, else compare the first prefix.len bytes."""
        self._push_string_value_as_ptr_len(prefix)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # if prefix.len > recv.len: 0
        self._block_counter += 1
        exit_ = f"$Ss{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # str_eq(recv.ptr, prefix.len, prefix.ptr, prefix.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._indent -= 1
        self._write("end")

    def _emit_string_ends_with(self, recv: Value, suffix: Value) -> None:
        """``recv.ends_with(suffix)``: false if suffix.len >
        recv.len, else compare the last suffix.len bytes."""
        self._push_string_value_as_ptr_len(suffix)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._block_counter += 1
        exit_ = f"$Se{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        # if suffix.len > recv.len: 0
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # offset = recv.len - suffix.len
        # str_eq(recv.ptr + offset, suffix.len, suffix.ptr, suffix.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_b_len")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._indent -= 1
        self._write("end")

    def _emit_string_substring(
        self, recv: Value, start: Value, end: Value, dst: Optional[str],
    ) -> None:
        """``recv.substring(start, end)``: ``start`` and ``end`` are
        CODE-POINT indices (slice 17, 2026-05-29). Translate each
        to a byte offset via ``$str_cp_to_byte_offset``, bounds-
        check, allocate the resulting byte range, memory.copy from
        ``recv.ptr + byte_start``, leave the result in dst's
        (ptr, len) locals.

        Pre-slice-17 the indices were byte offsets, which diverged
        silently from Python's ``_capa_substring`` (Python indexes
        by code points). A program calling ``"abcé".substring(0,
        4)`` would return the full ``"abcé"`` on Python and the
        broken UTF-8 ``"abc\\xC3"`` on Wasm. Now both backends
        return ``"abcé"``.

        Bounds check (audit fix C1, retained): trap if
        ``start > end`` or ``end > recv.codepoint_count``. The
        helper clamps cp_idx >= count to byte len, but ``end >
        count`` would silently truncate; we keep the explicit
        trap so a parser downstream can't be fed a quietly-
        shortened token. Negative indices wrap to a huge u32 and
        also trip the guard via the unsigned compare. The
        Python helper ``_capa_substring`` in
        ``capa.runtime._safety`` raises ``ValueError`` on the
        same inputs."""
        if dst is None:
            return
        # Save receiver ptr + len.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Save start and end as i32 code-point indices.
        self._push_value(start)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_start")
        self._push_value(end)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_end")
        # Bounds check on code-point indices: trap on start > end
        # OR end > codepoint_count. Compute the count once and
        # stash; the helper is also called for each cp -> byte
        # translation below, but we read the count to validate the
        # range first. (Two extra walks; cheaper than re-walking
        # in a non-validated translation.)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("call $str_codepoint_count")
        self._write("local.set $_str_cp_count")
        self._write("local.get $_str_start")
        self._write("local.get $_str_end")
        self._write("i32.gt_u")
        self._write("local.get $_str_end")
        self._write("local.get $_str_cp_count")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        # Translate start / end from cp indices to byte offsets.
        # ``$str_cp_to_byte_offset(p, l, cp_idx)`` returns the byte
        # offset of the cp_idx-th code-point boundary (or ``l`` if
        # cp_idx is at the end). Stash in $_str_b_ptr / $_str_b_len
        # (re-use of the second-needle scratch as transient).
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_start")
        self._write("call $str_cp_to_byte_offset")
        self._write("local.set $_str_b_ptr")
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_end")
        self._write("call $str_cp_to_byte_offset")
        self._write("local.set $_str_b_len")
        # new_len = byte_end - byte_start
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("i32.sub")
        self._write("local.tee $_str_new_len")
        # alloc(new_len)
        self._write("call $alloc")
        self._write("local.tee $_str_new_ptr")
        # memory.copy(dst=new_ptr, src=recv.ptr + byte_start, n=new_len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_b_ptr")
        self._write("i32.add")
        self._write("local.get $_str_new_len")
        self._write("memory.copy")
        # Bind dst.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_new_len")
        self._set_string_dst(dst)

    def _emit_string_case_transform(
        self, recv: Value, dst: Optional[str], upper: bool,
    ) -> None:
        """``recv.to_upper()`` / ``recv.to_lower()`` allocate a
        fresh ``recv.len`` buffer and copy each byte with ASCII
        case folding. Non-ASCII bytes pass through unchanged --
        Phase 6D-4's "ASCII-only" caveat that the legacy Python
        runtime does not have (it uses Python's full Unicode
        ``.upper()``); a UTF-8-aware version arrives when the
        stdlib grows a real character iterator."""
        if dst is None:
            return
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Allocate new buffer of the same length.
        self._write("local.get $_str_a_len")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        # i = 0; while i < len, transform byte.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        loop = f"$Sx{self._block_counter}_loop"
        exit_ = f"$Sx{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: i >= len -> done.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load byte.
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        # Case transform.
        if upper:
            # if b >= 'a' (0x61) && b <= 'z' (0x7a), subtract 32.
            self._write("local.tee $_str_byte")
            self._write("i32.const 97")
            self._write("i32.ge_u")
            self._write("local.get $_str_byte")
            self._write("i32.const 122")
            self._write("i32.le_u")
            self._write("i32.and")
            self._write("if")
            self._indent += 1
            self._write("local.get $_str_byte")
            self._write("i32.const 32")
            self._write("i32.sub")
            self._write("local.set $_str_byte")
            self._indent -= 1
            self._write("end")
        else:
            # if b >= 'A' (0x41) && b <= 'Z' (0x5a), add 32.
            self._write("local.tee $_str_byte")
            self._write("i32.const 65")
            self._write("i32.ge_u")
            self._write("local.get $_str_byte")
            self._write("i32.const 90")
            self._write("i32.le_u")
            self._write("i32.and")
            self._write("if")
            self._indent += 1
            self._write("local.get $_str_byte")
            self._write("i32.const 32")
            self._write("i32.add")
            self._write("local.set $_str_byte")
            self._indent -= 1
            self._write("end")
        # Store the (possibly transformed) byte to new_ptr + i.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_byte")
        self._write("i32.store8")
        # i++.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Bind dst.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_a_len")
        self._set_string_dst(dst)

    def _emit_string_trim(
        self, recv: Value, dst: Optional[str], left: bool, right: bool,
    ) -> None:
        """``recv.trim()`` returns a (ptr, len) view into the
        original buffer with leading/trailing ASCII whitespace
        skipped. No allocation; trim is purely a bounds adjustment.
        Whitespace: space, tab, newline, carriage return."""
        if dst is None:
            return
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # start = 0; end = recv.len.
        self._write("i32.const 0")
        self._write("local.set $_str_start")
        self._write("local.get $_str_a_len")
        self._write("local.set $_str_end")
        if left:
            self._block_counter += 1
            lloop = f"$St{self._block_counter}_lloop"
            lexit = f"$St{self._block_counter}_lexit"
            self._write(f"block {lexit}")
            self._indent += 1
            self._write(f"loop {lloop}")
            self._indent += 1
            # if start >= end: stop trimming.
            self._write("local.get $_str_start")
            self._write("local.get $_str_end")
            self._write("i32.ge_s")
            self._write(f"br_if {lexit}")
            # if byte at start is whitespace, advance.
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_start")
            self._write("i32.add")
            self._write("i32.load8_u")
            self._emit_byte_is_whitespace()
            self._write("i32.eqz")
            self._write(f"br_if {lexit}")
            self._write("local.get $_str_start")
            self._write("i32.const 1")
            self._write("i32.add")
            self._write("local.set $_str_start")
            self._write(f"br {lloop}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
        if right:
            self._block_counter += 1
            rloop = f"$St{self._block_counter}_rloop"
            rexit = f"$St{self._block_counter}_rexit"
            self._write(f"block {rexit}")
            self._indent += 1
            self._write(f"loop {rloop}")
            self._indent += 1
            self._write("local.get $_str_end")
            self._write("local.get $_str_start")
            self._write("i32.le_s")
            self._write(f"br_if {rexit}")
            # Look at byte at end-1.
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_end")
            self._write("i32.const 1")
            self._write("i32.sub")
            self._write("i32.add")
            self._write("i32.load8_u")
            self._emit_byte_is_whitespace()
            self._write("i32.eqz")
            self._write(f"br_if {rexit}")
            self._write("local.get $_str_end")
            self._write("i32.const 1")
            self._write("i32.sub")
            self._write("local.set $_str_end")
            self._write(f"br {rloop}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
        # Result: (recv.ptr + start, end - start)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_start")
        self._write("i32.add")
        self._write("local.get $_str_end")
        self._write("local.get $_str_start")
        self._write("i32.sub")
        self._set_string_dst(dst)

    def _emit_string_split(
        self, recv: Value, sep: Value, dst: Optional[str],
    ) -> None:
        """``recv.split(sep) -> List<String>``. Phase 6H supports
        single-byte separators only (the only shape policy-eval and
        the gallery demos use). The result is a ``List<String>``
        where each element occupies an 8-byte slot packed as
        ``ptr | (len << 32)``.

        Algorithm: linear scan over the receiver. At each position
        where ``recv[i] == sep_byte``, emit chunk ``[start, i)``
        into the result list; advance start to ``i + 1``. After the
        loop, emit the trailing chunk ``[start, recv.len)`` (which
        is empty when the receiver ends with the separator). Grow
        the data array inline if the chunk count exceeds the
        initial capacity.

        For an empty receiver, the result is a single empty-string
        element -- mirrors Python's ``"".split(",") == [""]``."""
        if dst is None:
            return

        # Save receiver (ptr, len).
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Load the separator (ptr, len).
        self._push_string_value_as_ptr_len(sep)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # Bug #4: an empty separator is a usage error. Python's
        # ``str.split("")`` raises ``ValueError: empty separator``;
        # the Wasm backend used to silently return the whole receiver
        # as a single chunk. Trap (``unreachable``) on ``sep.len == 0``
        # so both backends fail loud on the same invalid input, in line
        # with Capa's secure-by-default stance.
        self._write("local.get $_str_b_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        # sep_byte = i32.load8_u(sep.ptr)
        self._write("local.get $_str_b_ptr")
        self._write("i32.load8_u")
        self._write("local.set $_str_byte")

        # Allocate list header + initial 16-slot data array
        # (128 bytes). The grow path doubles cap when full.
        initial_cap = 16
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"i32.const {initial_cap * 8}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write(f"i32.const {initial_cap}")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")

        # State locals:
        #   $_str_i       = scan index
        #   $_str_start   = current chunk start
        #   $_m_tag       = chunk count (output index)
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._write("i32.const 0")
        self._write("local.set $_str_start")
        self._write("i32.const 0")
        self._write("local.set $_m_tag")

        # Outer block: scan loop. Each iteration tests the byte at
        # recv[i]; on match, pushes chunk [start, i) and advances
        # start. On loop exit (i == recv.len), pushes the trailing
        # chunk [start, recv.len).
        self._block_counter += 1
        loop = f"$Ssplit{self._block_counter}_loop"
        exit_ = f"$Ssplit{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i >= len: exit.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # byte = recv[i]
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $_str_byte")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Match: push chunk [start, i). chunk_ptr = recv_ptr+start;
        # chunk_len = i - start.
        self._emit_split_push_chunk(dst, start_local="_str_start",
                                    end_local="_str_i")
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_start")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

        # Trailing chunk [start, recv.len).
        self._emit_split_push_chunk(dst, start_local="_str_start",
                                    end_local="_str_a_len")

        # Write final len into header.
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    def _emit_split_push_chunk(
        self, dst: str, start_local: str, end_local: str,
    ) -> None:
        """Push one chunk ``[start, end)`` of ``$_str_a_ptr`` onto
        the result list whose header pointer is in ``$<dst>`` and
        whose current element count is in ``$_m_tag``. Grows the
        data array via memory.copy if the count has reached cap.

        Used by ``_emit_string_split`` for each separator match and
        for the trailing chunk after the scan."""
        # Capacity check: if count >= cap, grow.
        self._write("local.get $_m_tag")
        self._write(f"local.get ${dst}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # new_cap = cap * 2. Save in $_alloc_tmp_newcap is wishful;
        # split-specific scratch reuses $_str_new_len which has
        # no live conflict in this path.
        self._write(f"local.get ${dst}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.set $_str_new_len")
        # new_data = alloc(new_cap * 8)
        self._write("local.get $_str_new_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        # memory.copy(new_data, old_data, count * 8)
        self._write("local.get $_str_new_ptr")
        self._write(f"local.get ${dst}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_m_tag")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header.
        self._write(f"local.get ${dst}")
        self._write("local.get $_str_new_ptr")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_str_new_len")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._indent -= 1
        self._write("end")

        # Compute chunk_ptr = recv_ptr + start, chunk_len = end - start.
        # Stash chunk_len in $_str_i temporarily? No -- $_str_i is
        # the scan index (live across calls). Use $_str_new_len for
        # chunk_len since the grow path is done with it.
        self._write(f"local.get ${end_local}")
        self._write(f"local.get ${start_local}")
        self._write("i32.sub")
        self._write("local.set $_str_new_len")
        # slot_addr = data_ptr + count * 8
        self._write(f"local.get ${dst}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_m_tag")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        # packed = chunk_ptr | (chunk_len << 32)
        # chunk_ptr = recv_ptr + start
        self._write("local.get $_str_a_ptr")
        self._write(f"local.get ${start_local}")
        self._write("i32.add")
        self._write("i64.extend_i32_u")
        # chunk_len as i64 shifted
        self._write("local.get $_str_new_len")
        self._write("i64.extend_i32_u")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("i64.or")
        self._write("i64.store")
        # count++
        self._write("local.get $_m_tag")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_m_tag")

    def _emit_string_replace(
        self, recv: Value, old: Value, new: Value, dst,
    ) -> None:
        """``recv.replace(old, new) -> String``. Two-pass: scan the
        receiver counting occurrences of ``old`` to size the result
        buffer (``recv.len + count * (new.len - old.len)``), then
        scan again, copying ``new`` at every match position and
        passing the in-between bytes through unchanged.

        Empty ``old`` (D3 slice 4, 2026-05): returns the receiver
        unchanged. Python's ``"abc".replace("", "X")`` produces
        ``"XaXbXcX"``; we deliberately differ on both backends to
        avoid the empty-needle inf-loop trap, and the Python
        emitter's lowering applies the same guard so parity holds.
        """
        if dst is None:
            return
        # Stash receiver, old needle, and new replacement pairs.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_string_value_as_ptr_len(old)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        self._push_string_value_as_ptr_len(new)
        self._write("local.set $_str_c_len")
        self._write("local.set $_str_c_ptr")
        # Empty-needle fast path: bind dst to (recv.ptr, recv.len)
        # and skip every scan / alloc. Mirrors the Python lambda
        # guard in capa/ir/_emit_python.py::_string_method.
        self._block_counter += 1
        empty_exit = f"$Sr{self._block_counter}_empty_exit"
        self._write(f"block {empty_exit}")
        self._indent += 1
        self._write("local.get $_str_b_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $_str_a_ptr")
        self._write(f"local.set ${dst}_ptr")
        self._write("local.get $_str_a_len")
        self._write(f"local.set ${dst}_len")
        self._write(f"br {empty_exit}")
        self._indent -= 1
        self._write("end")
        # Pass 1: count occurrences of ``old`` in receiver. Linear
        # scan; on match advance ``i`` by old.len to skip the matched
        # region (so overlapping matches don't double-count, matching
        # Python's ``str.replace`` semantics).
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._write("i32.const 0")
        self._write("local.set $_str_count")
        self._block_counter += 1
        c_loop = f"$Sr{self._block_counter}_cloop"
        c_exit = f"$Sr{self._block_counter}_cexit"
        self._write(f"block {c_exit}")
        self._indent += 1
        self._write(f"loop {c_loop}")
        self._indent += 1
        # if i + old.len > recv.len: done counting.
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write(f"br_if {c_exit}")
        # str_eq(recv.ptr + i, old.len, old.ptr, old.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Match: count++, i += old.len.
        self._write("local.get $_str_count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_count")
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # No match: i++.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._indent -= 1
        self._write("end")
        self._write(f"br {c_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # result_len = recv.len + count * (new.len - old.len).
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_count")
        self._write("local.get $_str_c_len")
        self._write("local.get $_str_b_len")
        self._write("i32.sub")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_str_new_len")
        # Allocate result buffer.
        self._write("local.get $_str_new_len")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        # Pass 2: copy recv to result, substituting ``new`` at each
        # match. ``i`` walks the receiver; ``end`` doubles as the
        # write offset into the result buffer.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._write("i32.const 0")
        self._write("local.set $_str_end")
        self._block_counter += 1
        w_loop = f"$Sr{self._block_counter}_wloop"
        w_exit = f"$Sr{self._block_counter}_wexit"
        self._write(f"block {w_exit}")
        self._indent += 1
        self._write(f"loop {w_loop}")
        self._indent += 1
        # if i >= recv.len: done writing.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {w_exit}")
        # Match check: i + old.len <= recv.len AND
        # str_eq(recv.ptr+i, old.len, old.ptr, old.len).
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.get $_str_a_len")
        self._write("i32.le_s")
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # Match: memory.copy(new_ptr+end, new_str.ptr, new_str.len).
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_end")
        self._write("i32.add")
        self._write("local.get $_str_c_ptr")
        self._write("local.get $_str_c_len")
        self._write("memory.copy")
        # end += new.len, i += old.len.
        self._write("local.get $_str_end")
        self._write("local.get $_str_c_len")
        self._write("i32.add")
        self._write("local.set $_str_end")
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # No match: copy one byte from recv[i] to result[end].
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_end")
        self._write("i32.add")
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._write("local.get $_str_end")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_end")
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._indent -= 1
        self._write("end")
        self._write(f"br {w_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Bind dst (ptr, len) for the non-empty-needle path.
        self._write("local.get $_str_new_ptr")
        self._write(f"local.set ${dst}_ptr")
        self._write("local.get $_str_new_len")
        self._write(f"local.set ${dst}_len")
        # Close the empty-needle short-circuit block.
        self._indent -= 1
        self._write("end")

    def _emit_string_char_at(
        self, recv: Value, idx: Value, dst,
    ) -> None:
        """``recv.char_at(idx) -> Option<String>``. Walks the
        receiver byte-by-byte, decoding the UTF-8 leading byte at
        each step (``0xxxxxxx`` = 1 byte, ``110xxxxx`` = 2 bytes,
        ``1110xxxx`` = 3 bytes, ``11110xxx`` = 4 bytes). Counts
        codepoints; on the ``idx``-th codepoint, copies the
        codepoint's bytes into a fresh String and wraps it in
        ``Some``. Returns ``None`` when ``idx`` is out of range
        (codepoint count), matching the Python emitter's
        ``Some(s[idx]) if 0 <= idx < len(s) else None_`` semantics
        (Python ``str`` indexes per-codepoint, not per-byte)."""
        if dst is None:
            return
        # Stash receiver and target codepoint index.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_value(idx)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_start")
        # Allocate the Option<String> record up front; tag/payload
        # are filled in by the branches below.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp_result")
        # Out-of-bounds short-circuit on negative ``idx``: Python's
        # ``0 <= idx`` would return None_ for a negative index, so
        # mirror that without scanning the receiver.
        self._block_counter += 1
        done = f"$Sca{self._block_counter}_done"
        self._write(f"block {done}")
        self._indent += 1
        self._write("local.get $_str_start")
        self._write("i32.const 0")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $_alloc_tmp_result")
        self._write("i32.const 1")
        self._write("i32.store")
        self._write(f"br {done}")
        self._indent -= 1
        self._write("end")
        # Walk the receiver, counting codepoints. _str_i = byte cursor,
        # _str_end = codepoint cursor, _str_byte = current leading byte,
        # _str_new_len = codepoint byte length (1/2/3/4).
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._write("i32.const 0")
        self._write("local.set $_str_end")
        self._block_counter += 1
        loop = f"$Sca{self._block_counter}_loop"
        exit_ = f"$Sca{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i >= recv.len: exhausted, return None.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # leading = recv.ptr[i]. UTF-8 byte-length classification:
        # 0xxxxxxx -> 1, 110xxxxx -> 2, 1110xxxx -> 3, 11110xxx -> 4.
        # Use successive ``and`` masks so the cheapest case (ASCII)
        # exits first; the order keeps the inner loop tight for
        # typical mostly-ASCII strings.
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.tee $_str_byte")
        self._write("i32.const 0x80")
        self._write("i32.and")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $_str_byte")
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
        self._write("local.get $_str_byte")
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
        self._write("local.set $_str_new_len")
        # If this is the target codepoint, capture + emit Some.
        self._write("local.get $_str_end")
        self._write("local.get $_str_start")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # Allocate a fresh String of cp_len bytes; memory.copy from
        # recv.ptr+i.
        self._write("local.get $_str_new_len")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_new_len")
        self._write("memory.copy")
        # Build Some(cp_string) in the Option record.
        self._write("local.get $_alloc_tmp_result")
        self._write("i32.const 0")
        self._write("i32.store")
        # Pack (new_ptr, new_len) into the payload i64 slot
        # (low 32 bits = ptr, high 32 bits = len).
        self._write("local.get $_alloc_tmp_result")
        self._write("local.get $_str_new_ptr")
        self._write("i64.extend_i32_u")
        self._write("local.get $_str_new_len")
        self._write("i64.extend_i32_u")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("i64.or")
        self._write("i64.store offset=8")
        self._write(f"br {done}")
        self._indent -= 1
        self._write("end")
        # Advance: i += cp_len, codepoint_idx++.
        self._write("local.get $_str_i")
        self._write("local.get $_str_new_len")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write("local.get $_str_end")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_end")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Loop fell through without hitting the target: idx >=
        # codepoint count. Emit None.
        self._write("local.get $_alloc_tmp_result")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("end")
        # Bind dst.
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")

    def _emit_string_index_of(
        self, recv: Value, needle: Value, dst,
    ) -> None:
        """``recv.index_of(needle) -> Option<Int>``. Naive
        substring scan; on first match writes ``Some(cp_offset)``
        and exits, otherwise the loop exhausts to the fall-through
        and writes ``None``. D3 slice 4 (2026-05) changed the
        contract from the legacy ``-1`` sentinel to ``Option<Int>``;
        the Python emitter in ``capa/ir/_emit_python.py`` and the
        legacy transpiler both produce the same shape so the
        backends stay in lockstep.

        The returned index is a CODE-POINT offset, not a byte
        offset (slice 17, 2026-05-29). The scan still works
        bytewise, but on a match the matched byte offset is
        translated to a code-point offset by counting the UTF-8
        code points (bytes whose top two bits are not ``10``)
        strictly before the match. This mirrors the inline UTF-8
        walk in ``_emit_string_char_at``; it is inlined rather than
        calling ``$str_codepoint_count`` because the runtime helper
        is only emitted when discovery sees ``length`` / ``substring``
        in the module, which would not fire for an index_of-only
        program. Pre-fix the Wasm backend returned the raw byte
        offset, diverging from Python's ``str.find`` (which is
        code-point indexed) on any non-ASCII prefix:
        ``"a\\u{1F600}b".index_of("b")`` gave 5 on Wasm but 2 on
        Python. Now both return 2.

        Empty-needle behaviour matches Python's ``str.find("")``:
        the empty needle is found at offset 0 for any receiver
        (including the empty receiver), so the scan's first
        iteration always emits ``Some(0)``."""
        if dst is None:
            return
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_string_value_as_ptr_len(needle)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # Allocate Option<Int> record up front.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp_result")
        # Scan: i in [0, recv.len - needle.len]. On match write
        # Some(cp_offset) into the Option record and ``br`` past the
        # None-write tail, where cp_offset is the code-point count of
        # the receiver bytes strictly before the matched byte offset.
        # On loop exhaustion fall through to the tail which writes None.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        outer = f"$Sio{self._block_counter}_outer"
        loop = f"$Sio{self._block_counter}_loop"
        self._write(f"block {outer}")
        self._indent += 1
        # Inner block + loop for the scan.
        self._block_counter += 1
        scan_exit = f"$Sio{self._block_counter}_scan_exit"
        self._write(f"block {scan_exit}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i + needle.len > recv.len: not found, exit scan.
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write(f"br_if {scan_exit}")
        # str_eq(recv.ptr + i, needle.len, needle.ptr, needle.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Match: write Some(cp_offset) and bail past the None-write
        # tail. The scan index $_str_i is a byte offset; translate it
        # to a code-point offset by counting the receiver bytes in
        # [0, i) that are NOT UTF-8 continuation bytes (i.e. whose
        # top two bits are not ``10``). $_str_count = running cp
        # count, $_str_end = byte cursor, $_str_byte = current byte.
        # None case is unaffected.
        self._write("local.get $_alloc_tmp_result")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write("i32.const 0")
        self._write("local.set $_str_count")
        self._write("i32.const 0")
        self._write("local.set $_str_end")
        self._block_counter += 1
        cp_loop = f"$Sio{self._block_counter}_cploop"
        cp_exit = f"$Sio{self._block_counter}_cpexit"
        self._write(f"block {cp_exit}")
        self._indent += 1
        self._write(f"loop {cp_loop}")
        self._indent += 1
        # if cursor >= match byte offset: done counting.
        self._write("local.get $_str_end")
        self._write("local.get $_str_i")
        self._write("i32.ge_s")
        self._write(f"br_if {cp_exit}")
        # if (byte & 0xC0) != 0x80: count++ (non-continuation byte).
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_end")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("local.get $_str_count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_count")
        self._indent -= 1
        self._write("end")
        # cursor++
        self._write("local.get $_str_end")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_end")
        self._write(f"br {cp_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Store Some(cp_count).
        self._write("local.get $_alloc_tmp_result")
        self._write("local.get $_str_count")
        self._write("i64.extend_i32_s")
        self._write("i64.store offset=8")
        self._write(f"br {outer}")
        self._indent -= 1
        self._write("end")
        # i++; continue.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Not found: write None (tag = 1).
        self._write("local.get $_alloc_tmp_result")
        self._write("i32.const 1")
        self._write("i32.store")
        self._indent -= 1
        self._write("end")
        # Bind dst.
        self._write("local.get $_alloc_tmp_result")
        self._write(f"local.set ${dst}")

    def _emit_string_bytes(self, recv: Value, dst) -> None:
        """``recv.bytes() -> List<Int>``. Strings are stored as their
        raw UTF-8 byte slice throughout the Wasm backend, so this is a
        direct copy: allocate a ``List<Int>`` of ``recv.len`` elements
        and zero-extend each receiver byte into its 8-byte i64 slot
        (every value lands in 0..255).

        No UTF-8 decode happens -- the bytes ARE the result. A lone
        surrogate already lives as its 3-byte WTF-8 form in the
        buffer (the ``$chr`` runtime stores it that way), so its
        bytes come straight through, matching the Python backend's
        ``encode('utf-8', 'surrogatepass')``. For well-formed text
        the bytes equal a strict ``str.encode('utf-8')``.

        Reuses the String-method scratch locals: ``$_str_a_ptr`` /
        ``$_str_a_len`` hold the receiver, ``$_str_new_ptr`` the
        data-array base, ``$_str_i`` the byte cursor."""
        if dst is None:
            return
        # Receiver (ptr, len). len doubles as the element count.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Allocate the list header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        # Allocate the data array: len slots * 8 bytes each. ``alloc``
        # accepts 0 (empty string -> empty list), returning a valid
        # base we simply never write through.
        self._write("local.get $_str_a_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        # Header: len = cap = recv.len; data = the fresh array.
        self._write(f"local.get ${dst}")
        self._write("local.get $_str_a_len")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_str_a_len")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_str_new_ptr")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Copy loop: for i in [0, recv.len): slot[i] = (i64) recv[i].
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        loop = f"$Sby{self._block_counter}_loop"
        exit_ = f"$Sby{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i >= len: done.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # slot_addr = data + i * 8.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        # byte = recv.ptr[i], zero-extended to i64 (0..255).
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i64.extend_i32_u")
        self._write("i64.store")
        # i++.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_byte_is_whitespace(self) -> None:
        """Consume an i32 byte on the stack; push i32 1 if it is
        ASCII whitespace (space, tab, LF, CR), else 0. Used by
        trim methods."""
        # Save the byte into $_str_byte so we can compare against
        # each whitespace character without re-reading from memory.
        self._write("local.set $_str_byte")
        self._write("local.get $_str_byte")
        self._write("i32.const 32")        # space
        self._write("i32.eq")
        self._write("local.get $_str_byte")
        self._write("i32.const 9")         # tab
        self._write("i32.eq")
        self._write("i32.or")
        self._write("local.get $_str_byte")
        self._write("i32.const 10")        # LF
        self._write("i32.eq")
        self._write("i32.or")
        self._write("local.get $_str_byte")
        self._write("i32.const 13")        # CR
        self._write("i32.eq")
        self._write("i32.or")

    def _push_string_value_as_ptr_len(self, v: Value) -> None:
        """Push a String value as two consecutive i32s (ptr, len).
        Used for map keys and any other site that needs to flatten
        a String onto the operand stack.

        Capture-aware: when called inside a lifted lambda body and
        ``v.name`` is a String-typed capture, loads the ptr and
        len out of the env record at the capture's offset rather
        than from per-name (``$name_ptr`` / ``$name_len``) locals
        that don't exist in the lifted function."""
        if v.kind == "lit_str":
            offset, length = self._intern_string(v.literal)
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            return
        if v.kind in ("local", "param") and v.name in self._current_captures:
            offset, capa_ty = self._current_captures[v.name]
            if capa_ty == "String":
                self._write("local.get $env")
                self._write(f"i32.load offset={offset}")
                self._write("local.get $env")
                self._write(f"i32.load offset={offset + 4}")
                return
        if v.kind == "local":
            self._write(f"local.get ${v.name}_ptr")
            self._write(f"local.get ${v.name}_len")
            return
        if v.kind == "param":
            self._write(f"local.get ${v.name}_ptr")
            self._write(f"local.get ${v.name}_len")
            return
        if v.kind == "global" and v.name in self._const_values:
            # Top-level ``pub const NAME: String = "..."``. The
            # module-init pass populated ``_const_values`` with
            # the RHS literal Value; recurse to land in the
            # ``lit_str`` branch above, which interns the bytes
            # and pushes (ptr, len). Mirrors how the packed-i64
            # ``_push_value`` path handles the same kind via
            # the same dict.
            self._push_string_value_as_ptr_len(self._const_values[v.name])
            return
        raise WasmEmissionError(
            f"cannot push string Value of kind {v.kind!r} as (ptr, len)"
        )

    def _emit_format_str(self, instr: FormatStr) -> None:
        """Lower a ``FormatStr`` to the equivalent inline string
        building: stash each Value part's (ptr, len), sum total
        length, allocate, memory.copy each piece in order, bind dst.

        Phase 6F supports Int / Bool / String value parts. Int uses
        the ``$itoa`` helper for decimal conversion; Bool indexes
        pre-interned ``"true"`` / ``"false"`` literals; String
        copies its existing (ptr, len). Up to 8 value parts per
        format string -- a generous ceiling that covers all of the
        gallery / demo programs without runtime cost."""
        if instr.dst is None:
            return
        value_parts = [p for p in instr.parts if isinstance(p, Value)]
        if len(value_parts) > 8:
            raise WasmEmissionError(
                f"FormatStr with {len(value_parts)} value parts "
                f"exceeds the Phase 6F max of 8"
            )
        # Stash each Value part's (ptr, len) into scratch locals.
        # Index into the parts-of-Value subset, not the full parts.
        value_idx = 0
        for part in instr.parts:
            if isinstance(part, Value):
                self._emit_format_part_stash(part, value_idx)
                value_idx += 1
        # Compute total length.
        literal_len = sum(
            len(p.encode("utf-8")) for p in instr.parts if isinstance(p, str)
        )
        self._write(f"i32.const {literal_len}")
        for i in range(len(value_parts)):
            self._write(f"local.get $_fs_l{i}")
            self._write("i32.add")
        self._write("local.set $_fs_total_len")
        # Allocate result buffer.
        self._write("local.get $_fs_total_len")
        self._write("call $alloc")
        self._write("local.set $_fs_buf")
        # Write pieces in order. Track write position in $_fs_pos.
        self._write("i32.const 0")
        self._write("local.set $_fs_pos")
        value_idx = 0
        for part in instr.parts:
            if isinstance(part, str):
                if not part:
                    continue
                offset, length = self._intern_string(part)
                # memory.copy(dst=buf+pos, src=lit_ptr, n=lit_len)
                self._write("local.get $_fs_buf")
                self._write("local.get $_fs_pos")
                self._write("i32.add")
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
                self._write("memory.copy")
                self._write("local.get $_fs_pos")
                self._write(f"i32.const {length}")
                self._write("i32.add")
                self._write("local.set $_fs_pos")
            else:
                # Value: memory.copy from stashed ptr.
                self._write("local.get $_fs_buf")
                self._write("local.get $_fs_pos")
                self._write("i32.add")
                self._write(f"local.get $_fs_p{value_idx}")
                self._write(f"local.get $_fs_l{value_idx}")
                self._write("memory.copy")
                self._write("local.get $_fs_pos")
                self._write(f"local.get $_fs_l{value_idx}")
                self._write("i32.add")
                self._write("local.set $_fs_pos")
                value_idx += 1
        # Bind dst.
        self._write("local.get $_fs_buf")
        self._write("local.get $_fs_total_len")
        self._set_string_dst(instr.dst)

    def _emit_format_part_stash(self, v: Value, idx: int) -> None:
        """Compute the (ptr, len) representation of ``v`` for inline
        string building and stash into ``$_fs_p{idx}`` /
        ``$_fs_l{idx}``."""
        ty = v.ty
        # Unresolved tyvars (``?``) default to Int -- the most
        # common case for analyzer-side type inference that bails
        # out (e.g. inside a Fun-typed param call chain). Before
        # falling back to Int, consult the function's locals dict:
        # pattern-bound names refined by the match emitter live
        # there with their actual type (Float, Bool, ...) even
        # when the analyzer left ``v.ty`` as Unknown.
        if ty in ("?", "Unknown", ""):
            if (v.kind in ("local", "param")
                    and self._current_fn is not None
                    and v.name in self._current_fn.locals):
                refined = self._current_fn.locals[v.name]
                if refined and refined not in ("?", "Unknown", "Any"):
                    ty = refined
        if ty in ("?", "Unknown", ""):
            ty = "Int"
        if ty == "String":
            self._push_string_value_as_ptr_len(v)
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Int":
            self._push_value(v)
            self._write("call $itoa")
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Float":
            self._push_value(v)
            self._write("call $ftoa")
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Bool":
            # Use pre-interned "true" / "false". Branch on the value
            # at runtime and stash the right (ptr, len) pair.
            true_off, true_len = self._intern_string("true")
            false_off, false_len = self._intern_string("false")
            self._push_value(v)
            self._write("if")
            self._indent += 1
            self._write(f"i32.const {true_off}")
            self._write(f"local.set $_fs_p{idx}")
            self._write(f"i32.const {true_len}")
            self._write(f"local.set $_fs_l{idx}")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            self._write(f"i32.const {false_off}")
            self._write(f"local.set $_fs_p{idx}")
            self._write(f"i32.const {false_len}")
            self._write(f"local.set $_fs_l{idx}")
            self._indent -= 1
            self._write("end")
            return
        if ty == "IoError":
            # ``${io}`` where ``io: IoError`` mirrors the Python
            # runtime's ``__str__``: render the ``message`` field
            # (a String at offset 0 of the IoError record, see
            # ``_IOERROR_LAYOUT``). The ``cause`` field is
            # intentionally skipped here -- Python's ``__str__``
            # also drops it when empty, and the common formatter
            # usage is just ``${io}`` for a one-line diagnostic.
            # IoError keeps the field-access fast path; user-
            # defined structs route through the Display protocol
            # below.
            # Push the receiver twice rather than stash through a
            # scratch local; avoids needing _collect_locals to
            # declare a new helper local just for this branch.
            self._push_value(v)              # i32 ptr -> IoError record
            self._write("i32.load offset=0")  # message_ptr
            self._write(f"local.set $_fs_p{idx}")
            self._push_value(v)              # again
            self._write("i32.load offset=4")  # message_len
            self._write(f"local.set $_fs_l{idx}")
            return
        # Display protocol: if the value's type declares a
        # ``fun to_string(self) -> String`` in an impl block, call
        # it and use the returned String's (ptr, len) pair. The
        # method appears in ``_method_table`` under the concrete
        # type name (or its head when generic), populated by
        # ``_build_method_table`` from every impl block. Mirrors
        # the Python emitter's ``${v}`` -> ``{v.to_string()}``
        # rewrite, so both backends agree on the formatting of
        # any struct that opts in.
        head = ty.split("<", 1)[0]
        target = self._method_table.get((head, "to_string"))
        if target is not None:
            self._push_value(v)
            self._write(f"call ${target}")
            # call returns (i32 i32) = (ptr, len) multi-value; len
            # is on top of stack, ptr below. Stash in the same
            # order as the Int / Float / Bool branches above.
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        raise WasmEmissionError(
            f"FormatStr value of type {ty!r} not supported: built-in "
            f"types (Int / Bool / Float / String / IoError) and any "
            f"user type that declares a `fun to_string(self) -> "
            f"String` method are rendered automatically; other "
            f"structs are not. Either declare "
            f"`fun to_string(self) -> String` in an impl block for "
            f"{ty!r}, or interpolate a specific field "
            f"(e.g. ${{value.name}} instead of ${{value}})."
        )

    def _emit_string_assign(self, dst: str, src: Value) -> None:
        """Bind a String value to the (ptr, len) pair representing
        ``dst``. ``src`` may be a literal (from the pool) or another
        String local."""
        if src.kind == "lit_str":
            offset, length = self._intern_string(src.literal)
            self._write(f"i32.const {offset}")
            self._write(f"local.set ${dst}_ptr")
            self._write(f"i32.const {length}")
            self._write(f"local.set ${dst}_len")
            return
        if src.kind == "local" and self._is_string_local(src.name):
            self._write(f"local.get ${src.name}_ptr")
            self._write(f"local.set ${dst}_ptr")
            self._write(f"local.get ${src.name}_len")
            self._write(f"local.set ${dst}_len")
            return
        if src.kind == "param" and self._param_is_string(src.name):
            # String params arrive as the same (ptr, len) pair shape
            # as String locals; only the local name differs. Surfaces
            # when a let-binding aliases a String param directly,
            # e.g. ``let m = fallback`` where ``fallback: String`` is
            # a function parameter (capa_governance_pack/render.capa
            # hit this in the prefer-wasm path).
            self._write(f"local.get ${src.name}_ptr")
            self._write(f"local.set ${dst}_ptr")
            self._write(f"local.get ${src.name}_len")
            self._write(f"local.set ${dst}_len")
            return
        if src.kind == "lit_unit":
            # The IR lowerer emits a Unit placeholder when a Match
            # expression assigning to a String dst has an arm whose
            # body doesn't produce a value (early return, etc.).
            # Treat as empty string so the (ptr, len) locals get
            # initialised to (0, 0) -- harmless because the path that
            # reaches this assign always either branches away or the
            # caller's logic guards on an outer Result/Option.
            self._write("i32.const 0")
            self._write(f"local.set ${dst}_ptr")
            self._write("i32.const 0")
            self._write(f"local.set ${dst}_len")
            return
        if src.kind == "global" and src.name in self._const_values:
            # Top-level ``pub const NAME: String = "..."``. The
            # module-init pre-interned the RHS literal; recurse
            # via the lit_str branch above to lift the
            # (offset, length) into the dst's ${name}_ptr /
            # ${name}_len locals.
            self._emit_string_assign(dst, self._const_values[src.name])
            return
        raise WasmEmissionError(
            f"cannot bind String dst {dst!r} from value {src!r}"
        )

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
)


class _StringEmissionMixin:
    def _emit_string_concat(self, instr: BinOp) -> None:
        """Emit a String + String concatenation: allocate a new
        buffer of combined length, memory.copy each operand, bind
        the resulting (ptr, len) to the dst String locals.

        Used by source-level ``a + b`` where both operands have
        type String. Allocates one fresh buffer per concat.
        """
        self._push_string_value_as_ptr_len(instr.left)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_string_value_as_ptr_len(instr.right)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # total = a_len + b_len
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.tee $_str_new_len")
        # alloc total
        self._write("call $alloc")
        self._write("local.tee $_str_new_ptr")
        # memory.copy(new_ptr, a_ptr, a_len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("memory.copy")
        # memory.copy(new_ptr + a_len, b_ptr, b_len)
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_a_len")
        self._write("i32.add")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("memory.copy")
        # bind dst
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_new_len")
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
        raise WasmEmissionError(
            f"cannot push string len of Value kind {v.kind!r}"
        )

    def _emit_string_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a String receiver. Strings are
        (ptr, len) pairs throughout; this method's job is to read
        from the receiver, optionally allocate a fresh buffer, and
        bind the result to ``instr.dst``.

        Methods supported in Phase 6D-4: length, is_empty,
        contains, starts_with, ends_with, substring, to_upper,
        to_lower, trim, trim_start, trim_end, char_at, index_of.
        ``split`` and ``replace`` are deferred until List<String>
        support arrives in a later sub-phase."""
        method = instr.method
        recv = instr.receiver
        dst = instr.dst

        # Push (recv_ptr, recv_len) onto the operand stack twice
        # for any method that compares against a needle; the two
        # copies live in scratch locals so we can read multiple
        # times without re-evaluating the receiver.
        if method == "length":
            self._push_string_len_only(recv)
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
        raise WasmEmissionError(
            f"Phase 6D-4: String method {method!r} not supported "
            f"(replace / char_at / index_of land later)"
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
        """``recv.substring(start, end)``: allocate ``end-start``
        bytes, memory.copy from ``recv.ptr + start``, leave the
        result in dst's (ptr, len) locals."""
        if dst is None:
            return
        # Save receiver ptr + len.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Save start and end as i32 (the IR pushes Int as i64;
        # narrow with i32.wrap_i64).
        self._push_value(start)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_start")
        self._push_value(end)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_end")
        # new_len = end - start
        self._write("local.get $_str_end")
        self._write("local.get $_str_start")
        self._write("i32.sub")
        self._write("local.tee $_str_new_len")
        # alloc(new_len)
        self._write("call $alloc")
        self._write("local.tee $_str_new_ptr")
        # memory.copy(dst=new_ptr, src=recv.ptr + start, n=new_len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_start")
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
        # Load the separator byte (first byte of sep). Assumes
        # sep.len >= 1; an empty sep would degenerate to a per-
        # character split which is not yet supported. We do not
        # error here; the result is just the unchanged receiver in
        # one chunk.
        self._push_string_value_as_ptr_len(sep)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
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
        raise WasmEmissionError(
            f"Phase 6F: FormatStr value of type {ty!r} not supported "
            f"(Int / Bool / String only)"
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

"""Runtime-helper emission mixin.

Owns the small self-contained Wasm helper functions every emitted
module ships with:

- ``$alloc(size: i32) -> i32`` -- 8-byte-aligned bump allocator,
  exported so host bridges can construct Option/Result wrappers.
- ``$str_eq(p1, l1, p2, l2) -> i32`` -- byte-by-byte string
  equality, used by Map's String-keyed linear scan.
- ``$itoa(n: i64) -> (i32 ptr, i32 len)`` -- decimal integer
  formatting for ``${int}`` interpolation.
- ``$parse_int``, ``$parse_float`` -- inverse of the toa helpers
  for the Capa-side ``parse_int(s)`` / ``parse_float(s)`` builtins.
- ``$cabi_realloc`` -- the Component Model canonical-ABI realloc
  the host expects from any component import.

``$ftoa`` plus its Grisu2 machinery live in ``_grisu.py`` since
the algorithm alone is ~1100 LOC. The two files share no state
beyond ``self._cached_powers_offset`` and the standard emitter
state set up by ``WasmEmitter.__init__``.
"""

from __future__ import annotations


class _RuntimeHelpersMixin:
    def _emit_str_eq_function(self) -> None:
        """Helper: ``$str_eq(p1: i32, l1: i32, p2: i32, l2: i32) -> i32``
        returns 1 if the two byte slices are equal, 0 otherwise.
        Length mismatch is the fast-path no-match; the byte-by-byte
        compare loops only when lengths match.

        Used by Map.set / Map.get / Map.contains_key to identify
        the matching slot in the linear-scan key array."""
        self._write(
            "(func $str_eq (param $p1 i32) (param $l1 i32) "
            "(param $p2 i32) (param $l2 i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        # Length mismatch: return 0.
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Byte-by-byte loop.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("block $eq_exit (result i32)")
        self._indent += 1
        self._write("loop $eq_loop")
        self._indent += 1
        # if i >= l1: exit with 1.
        self._write("local.get $i")
        self._write("local.get $l1")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # Load byte from p1+i and p2+i, compare.
        self._write("local.get $p1")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $p2")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $eq_loop")
        self._indent -= 1
        self._write("end")
        # Wasm's stack type checker wants a value at every path's
        # exit; the loop never falls through (every iteration ends
        # with either ``br $eq_exit`` or ``br $eq_loop``) but the
        # verifier cannot prove that. Mark the fall-through as
        # unreachable so the block's i32 result type is satisfied.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_str_concat_function(self) -> None:
        """Helper: ``$str_concat(a_ptr, a_len, b_ptr, b_len) ->
        (i32 ptr, i32 len)`` returns the (ptr, len) of ``a ++ b``.

        Two paths:

        - GROW-IN-PLACE: when ``a``'s buffer is the last allocation in
          the bump heap (``a_ptr + align8(a_len) == heap_top``) and
          ``b`` is disjoint from the bytes we are about to write
          (``b_ptr + b_len <= a_ptr + a_len``), append ``b`` directly
          after ``a`` in the free space, bump ``heap_top`` by whatever
          the extension needs, and return ``(a_ptr, a_len + b_len)``.
          This is what turns ``out = out + chunk`` in a loop from
          O(n^2) total bytes copied into O(n) amortised: the growing
          accumulator is the last allocation each iteration, so each
          concat copies only the freshly-appended ``b``, never the
          already-accumulated prefix.

        - FALLBACK (a is a data-segment literal, or some other
          allocation has happened after a, or b overlaps the write
          region): allocate a fresh ``a_len + b_len`` buffer and
          ``memory.copy`` both operands. Identical to the pre-
          optimisation inline emit.

        Grow-only safety: the in-place path writes ONLY into the free
        space at/after ``a_ptr + a_len`` (the align-8 padding of a's
        own allocation plus newly-bumped, previously-unallocated
        bytes). It never moves, frees, or mutates the existing bytes
        ``[a_ptr, a_ptr + a_len)``. Capa strings are immutable
        (ptr, len) views and every live view of a's buffer has
        ``len <= a_len``, so no existing view can observe the appended
        bytes: a snapshot ``let s = a`` taken before the concat still
        reads ``(a_ptr, old a_len)``. The result is a brand-new
        (ptr, len) pair; the old ``a`` value, if still live, keeps its
        own length. The disjointness guard ``b_ptr + b_len <= a_ptr +
        a_len`` makes the append a non-overlapping copy (source ends
        at or before the write cursor) even when ``b`` aliases ``a``
        (the ``out = out + out`` case: b is [a_ptr, a_ptr+a_len), the
        write target is [a_ptr+a_len, ...), the two are disjoint, so
        the result is a correct ``out ++ out``)."""
        self._write(
            "(func $str_concat (param $a_ptr i32) (param $a_len i32) "
            "(param $b_ptr i32) (param $b_len i32) (result i32 i32)"
        )
        self._indent += 1
        self._write("(local $new_len i32)")
        self._write("(local $a_end i32)")
        self._write("(local $a_cap_end i32)")
        self._write("(local $new_ptr i32)")
        self._write("(local $new_top i32)")
        self._write("(local $needed_pages i32)")
        self._write("(local $cur_pages i32)")
        # new_len = a_len + b_len
        self._write("local.get $a_len")
        self._write("local.get $b_len")
        self._write("i32.add")
        self._write("local.set $new_len")
        # a_end = a_ptr + a_len (the byte just past a's content)
        self._write("local.get $a_ptr")
        self._write("local.get $a_len")
        self._write("i32.add")
        self._write("local.set $a_end")
        # a_cap_end = a_ptr + align8(a_len) = a_ptr + ((a_len + 7) & -8)
        self._write("local.get $a_ptr")
        self._write("local.get $a_len")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("i32.add")
        self._write("local.set $a_cap_end")
        # In-place grow guard:
        #   a is the last allocation:  a_cap_end == heap_top
        #   AND b is disjoint from the write region:
        #       b_ptr + b_len <= a_end
        # Both must hold (i32.and); when either fails we fall through
        # to the alloc + copy path below.
        self._write("local.get $a_cap_end")
        self._write("global.get $heap_top")
        self._write("i32.eq")
        self._write("local.get $b_ptr")
        self._write("local.get $b_len")
        self._write("i32.add")
        self._write("local.get $a_end")
        self._write("i32.le_u")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # --- grow in place ---
        # new_top = align8(a_len + b_len) past a_ptr. The grown
        # buffer's own capacity end becomes the heap top so the next
        # allocation starts cleanly and this buffer can grow again
        # next iteration.
        self._write("local.get $a_ptr")
        self._write("local.get $new_len")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("i32.add")
        self._write("local.set $new_top")
        # Page-grow exactly like $alloc: the append may write past the
        # current memory.size boundary, so grow linear memory first
        # (and trap on host refusal at the source-declared ceiling)
        # before any store. Omitting this was an out-of-bounds write
        # the moment the accumulator crossed a 64 KiB page.
        # needed_pages = (new_top + 65535) >> 16
        self._write("local.get $new_top")
        self._write("i32.const 65535")
        self._write("i32.add")
        self._write("i32.const 16")
        self._write("i32.shr_u")
        self._write("local.set $needed_pages")
        # cur_pages = memory.size
        self._write("memory.size")
        self._write("local.set $cur_pages")
        # if needed_pages > cur_pages: grow(needed_pages - cur_pages)
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.sub")
        self._write("memory.grow")
        self._write("i32.const -1")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Commit the bump and append b into the freed space.
        self._write("local.get $new_top")
        self._write("global.set $heap_top")
        # memory.copy(dst = a_end, src = b_ptr, n = b_len)
        self._write("local.get $a_end")
        self._write("local.get $b_ptr")
        self._write("local.get $b_len")
        self._write("memory.copy")
        # Result: (a_ptr, new_len)
        self._write("local.get $a_ptr")
        self._write("local.get $new_len")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # --- fallback: alloc fresh + copy both operands ---
        self._write("local.get $new_len")
        self._write("call $alloc")
        self._write("local.set $new_ptr")
        # memory.copy(dst = new_ptr, src = a_ptr, n = a_len)
        self._write("local.get $new_ptr")
        self._write("local.get $a_ptr")
        self._write("local.get $a_len")
        self._write("memory.copy")
        # memory.copy(dst = new_ptr + a_len, src = b_ptr, n = b_len)
        self._write("local.get $new_ptr")
        self._write("local.get $a_len")
        self._write("i32.add")
        self._write("local.get $b_ptr")
        self._write("local.get $b_len")
        self._write("memory.copy")
        # Result: (new_ptr, new_len)
        self._write("local.get $new_ptr")
        self._write("local.get $new_len")
        self._indent -= 1
        self._write(")")

    def _emit_str_cmp_function(self) -> None:
        """Helper: ``$str_cmp(p1, l1, p2, l2) -> i32`` returns -1, 0
        or 1 for the lexicographic ordering of the two byte slices
        (``s1 < s2`` -> -1, equal -> 0, ``s1 > s2`` -> 1).

        Bytes are compared UNSIGNED (``i32.load8_u``); for well-formed
        UTF-8 a byte-by-byte unsigned comparison yields the same order
        as comparing Unicode code points, which is exactly Python's
        ``str`` ordering (verified by oracle over ASCII, accents and
        astral-plane code points). At the first differing byte the
        slice with the smaller byte is smaller. If one slice is a
        prefix of the other, the shorter slice is smaller. Backs the
        Wasm lowering of the String ``<`` / ``>`` / ``<=`` / ``>=``
        operators so they match the Python backend byte-for-byte."""
        self._write(
            "(func $str_cmp (param $p1 i32) (param $l1 i32) "
            "(param $p2 i32) (param $l2 i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $n i32)")
        self._write("(local $b1 i32)")
        self._write("(local $b2 i32)")
        # n = min(l1, l2): the common prefix length to scan.
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.lt_s")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $l1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $l2")
        self._indent -= 1
        self._write("end")
        self._write("local.set $n")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("block $cmp_exit (result i32)")
        self._indent += 1
        self._write("loop $cmp_loop")
        self._indent += 1
        # if i >= n: prefix matched; order by length.
        self._write("local.get $i")
        self._write("local.get $n")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # l1 < l2 -> -1; l1 > l2 -> 1; equal -> 0.
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const -1")
        self._write("br $cmp_exit")
        self._indent -= 1
        self._write("end")
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $cmp_exit")
        self._indent -= 1
        self._write("end")
        self._write("i32.const 0")
        self._write("br $cmp_exit")
        self._indent -= 1
        self._write("end")
        # b1 = p1[i], b2 = p2[i] (unsigned).
        self._write("local.get $p1")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b1")
        self._write("local.get $p2")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b2")
        # if b1 < b2 -> -1; if b1 > b2 -> 1; else continue.
        self._write("local.get $b1")
        self._write("local.get $b2")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const -1")
        self._write("br $cmp_exit")
        self._indent -= 1
        self._write("end")
        self._write("local.get $b1")
        self._write("local.get $b2")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $cmp_exit")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $cmp_loop")
        self._indent -= 1
        self._write("end")
        # The loop never falls through; satisfy the block's result type.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_itoa_function(self) -> None:
        """Helper: ``$itoa(n: i64) -> (i32 ptr, i32 len)`` writes
        the decimal representation of ``n`` into freshly-allocated
        heap memory and returns its (ptr, len). Handles negative
        numbers with a leading ``-``; max output is 21 bytes
        (``-9223372036854775808`` is 20 chars + sign), so we always
        reserve 32 to leave room for a future hex prefix.

        Algorithm: write digits backwards into a scratch buffer at
        the top of the alloc, then memory.copy them forward into a
        tight result buffer. The two-step approach keeps the loop
        trivial; the cost is one extra alloc + copy per int."""
        self._write("(func $itoa (param $n i64) (result i32 i32)")
        self._indent += 1
        self._write("(local $abs i64)")
        self._write("(local $neg i32)")
        self._write("(local $buf i32)")
        self._write("(local $i i32)")
        self._write("(local $digit i32)")
        self._write("(local $ret_ptr i32)")
        self._write("(local $ret_len i32)")
        # Allocate 32-byte scratch buffer.
        self._write("i32.const 32")
        self._write("call $alloc")
        self._write("local.set $buf")
        # Handle sign.
        self._write("local.get $n")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i64.const 0")
        self._write("local.get $n")
        self._write("i64.sub")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $n")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("end")
        # Write digits backwards into buf+31, buf+30, ... at index $i.
        # $i tracks how many digits we wrote.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        loop = f"$itoa{self._block_counter}_loop"
        exit_ = f"$itoa{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # digit = abs % 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.rem_u")
        self._write("i32.wrap_i64")
        self._write("local.set $digit")
        # buf[31 - i] = '0' + digit
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $digit")
        self._write("i32.const 48")    # '0'
        self._write("i32.add")
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        # abs /= 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.div_u")
        self._write("local.tee $abs")
        # if abs == 0: exit.
        self._write("i64.eqz")
        self._write(f"br_if {exit_}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Optionally prepend '-'.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        # Write '-' at buf[31 - i] -- the slot just before the
        # lowest-order digit written at buf[32 - i]. The returned
        # slice is buf[32 - (i+1)..32] = buf[31 - i..32], so this
        # position lies inside the result. Without the correction
        # the '-' lands at buf[30 - i], outside the slice.
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.const 45")    # '-'
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        # ret_ptr = buf + 32 - i; ret_len = i. Return (ret_ptr, ret_len).
        self._write("local.get $buf")
        self._write("i32.const 32")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $i")
        self._indent -= 1
        self._write(")")

    def _emit_parse_int_ws_predicate(self) -> None:
        """Leave 1 on the stack iff ``$byte`` is one of the six ASCII
        whitespace bytes trimmed by ``parse_int`` (space 0x20, tab
        0x09, LF 0x0A, VT 0x0B, FF 0x0C, CR 0x0D). The caller has
        already loaded the byte into ``$byte``."""
        # (byte == 0x20) | (byte >= 0x09 & byte <= 0x0D)
        self._write("local.get $byte")
        self._write("i32.const 32")
        self._write("i32.eq")
        self._write("local.get $byte")
        self._write("i32.const 9")
        self._write("i32.ge_u")
        self._write("local.get $byte")
        self._write("i32.const 13")
        self._write("i32.le_u")
        self._write("i32.and")
        self._write("i32.or")

    def _emit_parse_int_trim_leading_ws(self) -> None:
        """Advance ``$ptr`` and shrink ``$len`` past leading ASCII
        whitespace bytes."""
        self._block_counter += 1
        loop = f"$pitl{self._block_counter}_loop"
        exit_ = f"$pitl{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if len == 0: break
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write(f"br_if {exit_}")
        # byte = ptr[0]; if not whitespace: break
        self._write("local.get $ptr")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._emit_parse_int_ws_predicate()
        self._write("i32.eqz")
        self._write(f"br_if {exit_}")
        # ptr += 1; len -= 1
        self._write("local.get $ptr")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $ptr")
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $len")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_parse_int_trim_trailing_ws(self) -> None:
        """Shrink ``$len`` past trailing ASCII whitespace bytes."""
        self._block_counter += 1
        loop = f"$pitt{self._block_counter}_loop"
        exit_ = f"$pitt{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if len == 0: break
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write(f"br_if {exit_}")
        # byte = ptr[len - 1]; if not whitespace: break
        self._write("local.get $ptr")
        self._write("local.get $len")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._emit_parse_int_ws_predicate()
        self._write("i32.eqz")
        self._write(f"br_if {exit_}")
        # len -= 1
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $len")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_parse_int_function(self) -> None:
        """Emit ``$parse_int(ptr: i32, len: i32) -> i32`` returning
        a freshly-allocated ``Option<Int>`` pointer.

        Algorithm: linear scan, optional leading '-' or '+',
        accumulate digits in i64. On any non-digit (or empty
        input), return None. Otherwise return Some(value).

        Builtin name in source is ``parse_int(s: String) ->
        Option<Int>``; the user-call interceptor routes the bare
        ``parse_int`` to a ``call $parse_int`` against this
        function."""
        self._write(
            "(func $parse_int (param $ptr i32) (param $len i32) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $byte i32)")
        self._write("(local $acc i64)")
        self._write("(local $neg i32)")
        self._write("(local $any i32)")
        self._write("(local $result i32)")
        # alloc Option<Int> result up front (16 bytes).
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $result")
        # Default to None (tag = 1). Filled in below on success.
        self._write("local.get $result")
        self._write("i32.const 1")
        self._write("i32.store")
        # Empty string -> None (already default).
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Trim surrounding ASCII whitespace (space / tab / LF / VT /
        # FF / CR -- bytes 0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D), the
        # same six bytes the Python helper trims via ``str.strip``
        # over an explicit set. After trimming, $ptr points at the
        # first non-whitespace byte and $len is the trimmed length;
        # the sign check and digit loop below run on that window.
        self._emit_parse_int_trim_leading_ws()
        self._emit_parse_int_trim_trailing_ws()
        # An all-whitespace input trims to empty -> None.
        self._write("local.get $len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Check sign byte.
        self._write("local.get $ptr")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        self._write("local.get $byte")
        self._write("i32.const 45")  # '-'
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $byte")
        self._write("i32.const 43")  # '+'
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Loop: i in [i, len). Reject non-digit; accumulate.
        self._block_counter += 1
        loop = f"$pi{self._block_counter}_loop"
        exit_ = f"$pi{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # if i >= len: break
        self._write("local.get $i")
        self._write("local.get $len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # byte = ptr[i]
        self._write("local.get $ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        # if byte < '0' or byte > '9': return None.
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.lt_u")
        self._write("local.get $byte")
        self._write("i32.const 57")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Overflow check: before ``acc = acc * 10 + digit``, reject
        # inputs that would push the magnitude past the allowed
        # bound. Threshold is ``i64::MAX / 10 == 922337203685477580``;
        # if ``acc`` already exceeds it, the multiply overflows.
        #
        # At the boundary (``acc == threshold``) the last admissible
        # digit depends on the sign: the positive bound is
        # ``i64::MAX == ...807`` (last digit 7) and the negative bound
        # is the magnitude ``2**63 == ...808`` (last digit 8, which
        # is ``i64::MIN``). So the boundary rejects ``digit > 7`` for
        # a positive value and ``digit > 8`` for a negative one; the
        # rejecting byte is ``'7' + neg`` (55 or 56). Magnitude 2**63
        # is accumulated as the bit pattern 0x8000000000000000 and the
        # later ``0 - acc`` step wraps it back to ``i64::MIN``
        # exactly. This mirrors the Python helper's
        # ``-(2**63) <= n < 2**63`` window, including ``i64::MIN``.
        self._write("local.get $acc")
        self._write("i64.const 922337203685477580")
        self._write("i64.gt_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $acc")
        self._write("i64.const 922337203685477580")
        self._write("i64.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $byte")
        self._write("i32.const 55")  # '7'
        self._write("local.get $neg")
        self._write("i32.add")       # '7' + neg -> '7' (pos) / '8' (neg)
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # acc = acc * 10 + (byte - '0')
        self._write("local.get $acc")
        self._write("i64.const 10")
        self._write("i64.mul")
        self._write("local.get $byte")
        self._write("i32.const 48")
        self._write("i32.sub")
        self._write("i64.extend_i32_u")
        self._write("i64.add")
        self._write("local.set $acc")
        # any = 1; i++
        self._write("i32.const 1")
        self._write("local.set $any")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # If no digits seen at all -> None (sign-only input).
        self._write("local.get $any")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $result")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Apply sign.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("i64.const 0")
        self._write("local.get $acc")
        self._write("i64.sub")
        self._write("local.set $acc")
        self._indent -= 1
        self._write("end")
        # Some(acc): tag=0, payload i64 at offset 8.
        self._write("local.get $result")
        self._write("i32.const 0")
        self._write("i32.store")
        self._write("local.get $result")
        self._write("local.get $acc")
        self._write("i64.store offset=8")
        self._write("local.get $result")
        self._indent -= 1
        self._write(")")

    def _parse_float_trim_leading(self) -> str:
        """WAT fragment: advance ``$ptr`` / shrink ``$len`` past leading
        ASCII whitespace (the same six bytes ``$parse_int`` trims)."""
        return r"""
            block $pf_tl_exit
              loop $pf_tl_loop
                local.get $len
                i32.eqz
                br_if $pf_tl_exit
                local.get $ptr
                i32.load8_u
                local.set $byte
                %WS%
                i32.eqz
                br_if $pf_tl_exit
                local.get $ptr
                i32.const 1
                i32.add
                local.set $ptr
                local.get $len
                i32.const 1
                i32.sub
                local.set $len
                br $pf_tl_loop
              end
            end
        """.replace("%WS%", self._parse_float_ws_predicate())

    def _parse_float_trim_trailing(self) -> str:
        """WAT fragment: shrink ``$len`` past trailing ASCII whitespace."""
        return r"""
            block $pf_tt_exit
              loop $pf_tt_loop
                local.get $len
                i32.eqz
                br_if $pf_tt_exit
                local.get $ptr
                local.get $len
                i32.add
                i32.const 1
                i32.sub
                i32.load8_u
                local.set $byte
                %WS%
                i32.eqz
                br_if $pf_tt_exit
                local.get $len
                i32.const 1
                i32.sub
                local.set $len
                br $pf_tt_loop
              end
            end
        """.replace("%WS%", self._parse_float_ws_predicate())

    def _parse_float_ws_predicate(self) -> str:
        """Leave 1 iff ``$byte`` is one of the six ASCII whitespace
        bytes (space, tab, LF, VT, FF, CR)."""
        return r"""
            local.get $byte
            i32.const 32
            i32.eq
            local.get $byte
            i32.const 9
            i32.ge_u
            local.get $byte
            i32.const 13
            i32.le_u
            i32.and
            i32.or
        """

    def _parse_float_accum_digit(self) -> str:
        """WAT fragment: fold the ASCII digit in ``$byte`` into the
        running significand. Leading zeros (before the first non-zero
        significant digit) are skipped from the significand span (they
        do not change the value); fractional leading zeros still lower
        ``$e10`` via the caller's per-fraction-digit decrement.

        Once a non-zero digit is seen, ``$started`` is set, the digit
        span ``[$dstart, $dend)`` is extended (the bignum slow path
        reads the full significand from it), and ``$sig_digits`` counts
        the significant digits. The i64 ``$mant`` accumulates the first
        15 significant digits for the Clinger fast path; once
        ``$sig_digits`` exceeds 15 the fast path is disabled
        (``$overflow64``) and only the span keeps growing for the slow
        path. ``$e10`` is NOT touched here: the slow path multiplies the
        FULL significand (every span digit) by ``10^$e10`` directly,
        exactly as ``tools/float_ref.py::strtod`` does."""
        return r"""
            block $pf_ad_done
              # Skip leading zeros (not yet started, digit == 0).
              local.get $started
              i32.eqz
              local.get $byte
              i32.const 48
              i32.eq
              i32.and
              br_if $pf_ad_done
              # First significant digit: open the span, mark started.
              local.get $started
              i32.eqz
              if
                i32.const 1
                local.set $started
                local.get $ptr
                local.get $i
                i32.add
                local.set $dstart
              end
              # dend = one past this digit.
              local.get $ptr
              local.get $i
              i32.add
              i32.const 1
              i32.add
              local.set $dend
              local.get $sig_digits
              i32.const 1
              i32.add
              local.set $sig_digits
              # Accumulate into $mant while <= 15 significant digits;
              # beyond that, disable the fast path (the slow path reads
              # the span instead).
              local.get $sig_digits
              i32.const 15
              i32.le_s
              if
                local.get $mant
                i64.const 10
                i64.mul
                local.get $byte
                i32.const 48
                i32.sub
                i64.extend_i32_u
                i64.add
                local.set $mant
              else
                i32.const 1
                local.set $overflow64
              end
            end
        """

    def _emit_parse_float_function(self) -> None:
        """Emit ``$parse_float(ptr: i32, len: i32) -> i32`` returning a
        freshly-allocated ``Option<Float>`` (tag at offset 0: 1 == None,
        0 == Some; f64 value at offset 8).

        Correctly-rounded decimal-string -> f64, bit-identical to
        CPython's ``float()`` on every grammar-valid, non-overflowing
        input. Faithful transliteration of ``tools/float_ref.py::strtod``
        (validated against ``float()`` on millions of cases):

        - Grammar: surrounding ASCII whitespace (the six bytes
          ``$parse_int`` trims), optional sign, a digit mantissa with an
          optional ``.``, an optional ``[eE][+-]?digits`` exponent, and
          nothing else. No inf / nan / underscores / hex -> None.
        - Clinger fast path: when the significand fits exactly in f64
          (<= 15 digits, < 2^53) and ``10^|e10|`` is exact (|e10| <= 22),
          a single f64 multiply or divide is correctly rounded.
        - Bignum slow path: otherwise round the exact rational
          ``mantissa * 10^e10`` to nearest-even f64 using the shared
          limb-bignum helpers ($bn_*). Overflow past DBL_MAX -> None;
          underflow -> signed zero."""
        self._emit_wat_block(
            r"""
            (func $parse_float (param $ptr i32) (param $len i32) (result i32)
              (local $i i32)
              (local $byte i32)
              (local $neg i32)
              (local $result i32)
              (local $mant i64)
              (local $sig_digits i32)   # count of significant (post leading-zero) digits
              (local $e10 i32)          # decimal exponent of the significand
              (local $any i32)          # saw at least one mantissa digit
              (local $started i32)      # started accumulating non-zero significant digits
              (local $exp_sign i32)
              (local $exp_val i32)
              (local $exp_any i32)
              (local $overflow64 i32)   # mantissa exceeded 19 reliable digits -> need bignum from string
              (local $dstart i32)       # byte offset of first accumulated significant digit
              (local $dend i32)         # byte offset one past last significant digit
              (local $f f64)
              (local $p10 f64)
              (local $k i32)
              # bignum slow-path locals
              (local $m i32)
              (local $num i32)
              (local $den i32)
              (local $approx i32)
              # Option<Float> result buffer; default tag = None (1).
              i32.const 16
              call $alloc
              local.set $result
              local.get $result
              i32.const 1
              i32.store
              # Trim leading / trailing ASCII whitespace (mutates $ptr / $len).
              %TRIM_LEADING%
              %TRIM_TRAILING%
              # Empty after trim -> None.
              local.get $len
              i32.eqz
              if
                local.get $result
                return
              end
              # Optional sign.
              i32.const 0
              local.set $i
              local.get $ptr
              i32.load8_u
              local.set $byte
              local.get $byte
              i32.const 45            # '-'
              i32.eq
              if
                i32.const 1
                local.set $neg
                i32.const 1
                local.set $i
              else
                local.get $byte
                i32.const 43          # '+'
                i32.eq
                if
                  i32.const 1
                  local.set $i
                end
              end
              # ---- Integer-part digits. ----
              i32.const -1
              local.set $dstart
              block $pf_int_exit
                loop $pf_int_loop
                  local.get $i
                  local.get $len
                  i32.ge_s
                  br_if $pf_int_exit
                  local.get $ptr
                  local.get $i
                  i32.add
                  i32.load8_u
                  local.set $byte
                  # stop at '.' or 'e'/'E'
                  local.get $byte
                  i32.const 46
                  i32.eq
                  br_if $pf_int_exit
                  local.get $byte
                  i32.const 101       # 'e'
                  i32.eq
                  local.get $byte
                  i32.const 69        # 'E'
                  i32.eq
                  i32.or
                  br_if $pf_int_exit
                  # non-digit -> reject (None).
                  local.get $byte
                  i32.const 48
                  i32.lt_u
                  local.get $byte
                  i32.const 57
                  i32.gt_u
                  i32.or
                  if
                    local.get $result
                    return
                  end
                  i32.const 1
                  local.set $any
                  %ACCUM_DIGIT%
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  br $pf_int_loop
                end
              end
              # ---- Optional fraction. ----
              local.get $i
              local.get $len
              i32.lt_s
              if
                local.get $ptr
                local.get $i
                i32.add
                i32.load8_u
                i32.const 46          # '.'
                i32.eq
                if
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  block $pf_frac_exit
                    loop $pf_frac_loop
                      local.get $i
                      local.get $len
                      i32.ge_s
                      br_if $pf_frac_exit
                      local.get $ptr
                      local.get $i
                      i32.add
                      i32.load8_u
                      local.set $byte
                      local.get $byte
                      i32.const 101    # 'e'
                      i32.eq
                      local.get $byte
                      i32.const 69     # 'E'
                      i32.eq
                      i32.or
                      br_if $pf_frac_exit
                      local.get $byte
                      i32.const 48
                      i32.lt_u
                      local.get $byte
                      i32.const 57
                      i32.gt_u
                      i32.or
                      if
                        local.get $result
                        return
                      end
                      i32.const 1
                      local.set $any
                      # each fractional digit lowers e10 by 1.
                      local.get $e10
                      i32.const 1
                      i32.sub
                      local.set $e10
                      %ACCUM_DIGIT%
                      local.get $i
                      i32.const 1
                      i32.add
                      local.set $i
                      br $pf_frac_loop
                    end
                  end
                end
              end
              # No mantissa digit at all -> None.
              local.get $any
              i32.eqz
              if
                local.get $result
                return
              end
              # ---- Optional exponent. ----
              local.get $i
              local.get $len
              i32.lt_s
              if
                local.get $ptr
                local.get $i
                i32.add
                i32.load8_u
                local.set $byte
                local.get $byte
                i32.const 101
                i32.eq
                local.get $byte
                i32.const 69
                i32.eq
                i32.or
                if
                  local.get $i
                  i32.const 1
                  i32.add
                  local.set $i
                  i32.const 1
                  local.set $exp_sign
                  local.get $i
                  local.get $len
                  i32.lt_s
                  if
                    local.get $ptr
                    local.get $i
                    i32.add
                    i32.load8_u
                    local.set $byte
                    local.get $byte
                    i32.const 43
                    i32.eq
                    if
                      local.get $i
                      i32.const 1
                      i32.add
                      local.set $i
                    else
                      local.get $byte
                      i32.const 45
                      i32.eq
                      if
                        i32.const -1
                        local.set $exp_sign
                        local.get $i
                        i32.const 1
                        i32.add
                        local.set $i
                      end
                    end
                  end
                  block $pf_exp_exit
                    loop $pf_exp_loop
                      local.get $i
                      local.get $len
                      i32.ge_s
                      br_if $pf_exp_exit
                      local.get $ptr
                      local.get $i
                      i32.add
                      i32.load8_u
                      local.set $byte
                      local.get $byte
                      i32.const 48
                      i32.lt_u
                      local.get $byte
                      i32.const 57
                      i32.gt_u
                      i32.or
                      if
                        local.get $result
                        return
                      end
                      i32.const 1
                      local.set $exp_any
                      # clamp exp_val to avoid i32 overflow; 100000 is far
                      # past any representable magnitude and keeps the
                      # overflow / underflow screens correct.
                      local.get $exp_val
                      i32.const 100000
                      i32.lt_s
                      if
                        local.get $exp_val
                        i32.const 10
                        i32.mul
                        local.get $byte
                        i32.const 48
                        i32.sub
                        i32.add
                        local.set $exp_val
                      end
                      local.get $i
                      i32.const 1
                      i32.add
                      local.set $i
                      br $pf_exp_loop
                    end
                  end
                  # 'e' with no exponent digit -> None.
                  local.get $exp_any
                  i32.eqz
                  if
                    local.get $result
                    return
                  end
                  # e10 += exp_sign * exp_val
                  local.get $e10
                  local.get $exp_sign
                  local.get $exp_val
                  i32.mul
                  i32.add
                  local.set $e10
                end
              end
              # Trailing garbage -> None.
              local.get $i
              local.get $len
              i32.lt_s
              if
                local.get $result
                return
              end
              # ---- All-zero significand -> signed zero. ----
              local.get $started
              i32.eqz
              if
                f64.const 0
                local.set $f
                local.get $neg
                if
                  local.get $f
                  f64.neg
                  local.set $f
                end
                local.get $result
                i32.const 0
                i32.store
                local.get $result
                local.get $f
                f64.store offset=8
                local.get $result
                return
              end
              # ---- Clinger fast path. ----
              # sig_digits <= 15 (mantissa < 10^15 < 2^53) and not
              # overflow64, and |e10| <= 22 (10^|e10| exact in f64).
              local.get $overflow64
              i32.eqz
              local.get $sig_digits
              i32.const 15
              i32.le_s
              i32.and
              local.get $e10
              i32.const 22
              i32.le_s
              i32.and
              local.get $e10
              i32.const -22
              i32.ge_s
              i32.and
              if
                local.get $mant
                f64.convert_i64_u
                local.set $f
                # p10 = 10^|e10| built by exact repeated *10.
                f64.const 1
                local.set $p10
                local.get $e10
                i32.const 0
                i32.ge_s
                if (result i32)
                  local.get $e10
                else
                  i32.const 0
                  local.get $e10
                  i32.sub
                end
                local.set $k
                block $pf_p10_exit
                  loop $pf_p10_loop
                    local.get $k
                    i32.eqz
                    br_if $pf_p10_exit
                    local.get $p10
                    f64.const 10
                    f64.mul
                    local.set $p10
                    local.get $k
                    i32.const 1
                    i32.sub
                    local.set $k
                    br $pf_p10_loop
                  end
                end
                local.get $e10
                i32.const 0
                i32.ge_s
                if
                  local.get $f
                  local.get $p10
                  f64.mul
                  local.set $f
                else
                  local.get $f
                  local.get $p10
                  f64.div
                  local.set $f
                end
                local.get $neg
                if
                  local.get $f
                  f64.neg
                  local.set $f
                end
                local.get $result
                i32.const 0
                i32.store
                local.get $result
                local.get $f
                f64.store offset=8
                local.get $result
                return
              end
              # ---- Overflow / underflow screens (bound bignum work). ----
              # approx = sig_digits + e10  (~ log10 of |value|).
              local.get $sig_digits
              local.get $e10
              i32.add
              local.set $approx
              local.get $approx
              i32.const 309
              i32.gt_s
              if
                local.get $result      # overflow -> None
                return
              end
              local.get $approx
              i32.const -324
              i32.lt_s
              if
                f64.const 0            # underflow -> signed zero
                local.set $f
                local.get $neg
                if
                  local.get $f
                  f64.neg
                  local.set $f
                end
                local.get $result
                i32.const 0
                i32.store
                local.get $result
                local.get $f
                f64.store offset=8
                local.get $result
                return
              end
              # ---- Bignum slow path. ----
              # Build the significand bignum from the full digit span
              # [$dstart, $dend); the span holds every significant digit
              # (leading zeros already excluded), so $m * 10^e10 is the
              # exact value, matching tools/float_ref.py::strtod.
              local.get $dstart
              local.get $dend
              call $bn_from_digits
              local.set $m
              # num / den = m * 10^e10.
              local.get $e10
              i32.const 0
              i32.ge_s
              if
                local.get $m
                local.get $e10
                call $bn_mul_pow10
                local.set $num
                i64.const 1
                call $bn_from_u64
                local.set $den
              else
                local.get $m
                local.set $num
                i64.const 1
                call $bn_from_u64
                i32.const 0
                local.get $e10
                i32.sub
                call $bn_mul_pow10
                local.set $den
              end
              # Round num/den to nearest-even f64; returns (f64 value,
              # i32 overflow_flag). overflow -> None.
              local.get $num
              local.get $den
              local.get $neg
              call $bn_ratio_to_f64
              local.set $overflow64    # reuse: 1 == overflow
              local.set $f
              local.get $overflow64
              if
                local.get $result
                return
              end
              local.get $result
              i32.const 0
              i32.store
              local.get $result
              local.get $f
              f64.store offset=8
              local.get $result
            )
            """
            .replace("%TRIM_LEADING%", self._parse_float_trim_leading())
            .replace("%TRIM_TRAILING%", self._parse_float_trim_trailing())
            .replace("%ACCUM_DIGIT%", self._parse_float_accum_digit())
        )

    def _emit_chr_function(self) -> None:
        """Emit ``$chr(cp: i64) -> (i32 ptr, i32 len)``: a
        freshly-allocated one-codepoint String holding the UTF-8
        encoding of ``cp``. Backs the internal ``_capa_chr`` builtin
        (Python side: ``chr``), which the bundled JSON parser uses to
        decode ``\\uXXXX`` escapes.

        Surrogate code points (U+D800..U+DFFF) are encoded through
        the ordinary 3-byte branch -- i.e. WTF-8. That is deliberate:
        Python's ``json.loads`` decodes an unpaired ``\\ud800`` to a
        ``str`` holding the lone surrogate (length 1), and the WTF-8
        bytes give the same observable codepoint count on the Wasm
        side. Out-of-range input (< 0 or > 0x10FFFF) traps, mirroring
        the ``ValueError`` from the Python runtime's ``_capa_chr``."""
        self._write("(func $chr (param $cp i64) (result i32 i32)")
        self._indent += 1
        self._write("(local $c i32)")
        self._write("(local $dst i32)")
        # Range check: 0 <= cp <= 0x10FFFF, else trap (loud, like
        # the Python runtime's ValueError).
        self._write("local.get $cp")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("local.get $cp")
        self._write("i64.const 1114111")
        self._write("i64.gt_s")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._write("local.get $cp")
        self._write("i32.wrap_i64")
        self._write("local.set $c")
        # 1 byte: cp < 0x80.
        self._write("local.get $c")
        self._write("i32.const 128")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("call $alloc")
        self._write("local.set $dst")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.store8")
        self._write("local.get $dst")
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # 2 bytes: cp < 0x800. 110xxxxx 10xxxxxx.
        self._write("local.get $c")
        self._write("i32.const 2048")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 2")
        self._write("call $alloc")
        self._write("local.set $dst")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 6")
        self._write("i32.shr_u")
        self._write("i32.const 192")
        self._write("i32.or")
        self._write("i32.store8")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=1")
        self._write("local.get $dst")
        self._write("i32.const 2")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # 3 bytes: cp < 0x10000 (surrogates included: WTF-8).
        # 1110xxxx 10xxxxxx 10xxxxxx.
        self._write("local.get $c")
        self._write("i32.const 65536")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 3")
        self._write("call $alloc")
        self._write("local.set $dst")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 12")
        self._write("i32.shr_u")
        self._write("i32.const 224")
        self._write("i32.or")
        self._write("i32.store8")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 6")
        self._write("i32.shr_u")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=1")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=2")
        self._write("local.get $dst")
        self._write("i32.const 3")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # 4 bytes: cp <= 0x10FFFF. 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx.
        self._write("i32.const 4")
        self._write("call $alloc")
        self._write("local.set $dst")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 18")
        self._write("i32.shr_u")
        self._write("i32.const 240")
        self._write("i32.or")
        self._write("i32.store8")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 12")
        self._write("i32.shr_u")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=1")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 6")
        self._write("i32.shr_u")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=2")
        self._write("local.get $dst")
        self._write("local.get $c")
        self._write("i32.const 63")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.or")
        self._write("i32.store8 offset=3")
        self._write("local.get $dst")
        self._write("i32.const 4")
        self._indent -= 1
        self._write(")")

    def _emit_alloc_function(self) -> None:
        """Emit a bump allocator: ``$alloc(size: i32) -> i32`` that
        returns the current heap_top, aligned to 8, and advances it
        by the requested size. Grows linear memory in 64 KB pages
        when the bump would cross the current ``memory.size``
        boundary; traps via ``unreachable`` if the host refuses to
        grow further. No free, no GC; the simplest allocator that
        survives realistic input sizes.

        Exported so host bridges (capa:host/env etc.) can allocate
        Option / Result wrappers in linear memory before handing
        them back to the wasm code.

        Audit H1 (2026-05): the ``memory.grow`` -> ``i32.const -1``
        check below covers the host-refuses-to-grow path. The host
        refuses when the requested page count exceeds the limits
        clause baked into the module's ``(memory ...)`` declaration.
        ``WasmEmitter.__init__(memory_cap_pages=...)`` sets that
        ceiling (default 256 pages = 16 MiB), exposed via the CLI
        as ``--wasm-memory-cap <pages>``. A runaway allocator thus
        traps at the deterministic, source-declared ceiling instead
        of at some host-dependent OOM point."""
        self._write('(func $alloc (export "alloc") (param $size i32) (result i32)')
        self._indent += 1
        self._write("(local $ret i32)")
        self._write("(local $new_top i32)")
        self._write("(local $needed_pages i32)")
        self._write("(local $cur_pages i32)")
        # ret = align_up(heap_top, 8)
        self._write("global.get $heap_top")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("local.set $ret")
        # new_top = ret + size
        self._write("local.get $ret")
        self._write("local.get $size")
        self._write("i32.add")
        self._write("local.set $new_top")
        # needed_pages = ceil(new_top / 65536) = (new_top + 65535) >> 16
        self._write("local.get $new_top")
        self._write("i32.const 65535")
        self._write("i32.add")
        self._write("i32.const 16")
        self._write("i32.shr_u")
        self._write("local.set $needed_pages")
        # cur_pages = memory.size
        self._write("memory.size")
        self._write("local.set $cur_pages")
        # if needed_pages > cur_pages: memory.grow(needed_pages - cur_pages)
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $needed_pages")
        self._write("local.get $cur_pages")
        self._write("i32.sub")
        self._write("memory.grow")
        self._write("i32.const -1")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # heap_top = new_top; return ret
        self._write("local.get $new_top")
        self._write("global.set $heap_top")
        self._write("local.get $ret")
        self._indent -= 1
        self._write(")")

    def _emit_cabi_realloc_function(self) -> None:
        """Emit the ``cabi_realloc`` export the Component Model
        canonical ABI requires. Signature:

            cabi_realloc(old_ptr: i32, old_size: i32, align: i32,
                         new_size: i32) -> i32

        Semantics:
        - ``new_size == 0`` is a free; the bump allocator has no
          free, so return null.
        - Otherwise allocate ``new_size`` bytes and -- if there
          was prior content -- copy ``min(old_size, new_size)``
          bytes from the old location into the new one. The
          alignment argument is observed by ``$alloc`` (which
          aligns to 8 already).

        Required by ``wasm-tools component new`` whenever a host
        import lowering needs to allocate caller-owned memory
        (e.g. the data buffer for a ``list<string>`` result)."""
        self._write(
            '(func $cabi_realloc (export "cabi_realloc") '
            '(param $old_ptr i32) (param $old_size i32) '
            '(param $align i32) (param $new_size i32) (result i32)'
        )
        self._indent += 1
        self._write("(local $new_ptr i32)")
        self._write("(local $copy_size i32)")
        # new_size == 0 -> free path: return null (no real free
        # because the bump allocator has nothing to release).
        self._write("local.get $new_size")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Fresh allocation.
        self._write("local.get $new_size")
        self._write("call $alloc")
        self._write("local.set $new_ptr")
        # If old_ptr != 0 and old_size != 0, copy min(old, new).
        self._write("local.get $old_ptr")
        self._write("i32.const 0")
        self._write("i32.ne")
        self._write("local.get $old_size")
        self._write("i32.const 0")
        self._write("i32.ne")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # copy_size = min(old_size, new_size). The ``if/else``
        # produces an i32 result on both arms, so the block's
        # result type must be annotated; without ``(result i32)``
        # the validator rejects the value on the arm's stack.
        self._write("local.get $old_size")
        self._write("local.get $new_size")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $old_size")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $new_size")
        self._indent -= 1
        self._write("end")
        self._write("local.set $copy_size")
        # memory.copy(dst=new_ptr, src=old_ptr, n=copy_size)
        self._write("local.get $new_ptr")
        self._write("local.get $old_ptr")
        self._write("local.get $copy_size")
        self._write("memory.copy")
        self._indent -= 1
        self._write("end")
        self._write("local.get $new_ptr")
        self._indent -= 1
        self._write(")")

    def _emit_str_codepoint_count_function(self) -> None:
        """``$str_codepoint_count(p: i32, l: i32) -> i32`` - return
        the number of Unicode code points in the UTF-8 byte slice
        ``[p, p+l)``. Counts bytes whose high bits are NOT
        ``10xxxxxx`` (continuation bytes). Audit fix 2026-05-29
        (post-slice-16): Wasm's ``String.length`` was returning
        the byte count; Python's was returning the code-point
        count. Both backends now agree on code-point semantics."""
        self._write(
            "(func $str_codepoint_count (param $p i32) (param $l i32) "
            "(result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $count i32)")
        self._write("(local $b i32)")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("i32.const 0")
        self._write("local.set $count")
        self._write("block $cp_exit")
        self._indent += 1
        self._write("loop $cp_loop")
        self._indent += 1
        # if i >= l: exit
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $cp_exit")
        # b = byte at p+i
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b")
        # if (b & 0xC0) != 0x80: count++ (i.e. not a continuation
        # byte: ASCII 0xxxxxxx or 11xxxxxx leading bytes both count)
        self._write("local.get $b")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $count")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $cp_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $count")
        self._indent -= 1
        self._write(")")

    def _emit_str_cp_to_byte_offset_function(self) -> None:
        """``$str_cp_to_byte_offset(p: i32, l: i32, cp_idx: i32)
        -> i32`` - return the byte offset of the ``cp_idx``-th
        code-point boundary in the UTF-8 byte slice ``[p, p+l)``.
        Returns ``l`` if ``cp_idx`` is at or past the end (so the
        caller doesn't need a separate length check; clamps to
        the end naturally).

        Walks the bytes counting code-point starts (bytes NOT in
        ``10xxxxxx``); on the ``cp_idx``-th start it returns the
        current byte offset. If ``cp_idx == 0`` returns 0 (the
        start of the slice is always a code-point boundary by
        definition for valid UTF-8). Audit fix 2026-05-29
        (post-slice-16): Wasm's ``String.substring`` was indexing
        bytes; Python's was indexing code points."""
        self._write(
            "(func $str_cp_to_byte_offset (param $p i32) "
            "(param $l i32) (param $cp_idx i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        self._write("(local $count i32)")
        self._write("(local $b i32)")
        # Fast path: cp_idx == 0 returns 0.
        self._write("local.get $cp_idx")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("i32.const 0")
        self._write("local.set $count")
        self._write("block $b2o_exit")
        self._indent += 1
        self._write("loop $b2o_loop")
        self._indent += 1
        # if i >= l: exit (return l as fallback below)
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $b2o_exit")
        # b = byte at p+i
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.set $b")
        # if (b & 0xC0) != 0x80: count++; if count == cp_idx,
        # return i.
        self._write("local.get $b")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.tee $count")
        self._write("local.get $cp_idx")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        # We just stepped onto the cp_idx-th code-point boundary
        # AFTER the byte at position i was its leading byte. The
        # boundary is at i+1's leading byte; walk i forward until
        # we hit either l or the next non-continuation. Easier:
        # return i+1 (since we just passed a leading byte, the
        # next byte is the start of the next code point... unless
        # this codepoint has continuation bytes). Walk past any
        # continuation bytes starting at i+1.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("block $skip_exit")
        self._indent += 1
        self._write("loop $skip_loop")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $l")
        self._write("i32.ge_s")
        self._write(f"br_if $skip_exit")
        self._write("local.get $p")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 192")
        self._write("i32.and")
        self._write("i32.const 128")
        self._write("i32.ne")
        self._write(f"br_if $skip_exit")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $skip_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._write("local.get $i")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br $b2o_loop")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Fell out: cp_idx past the end. Return l.
        self._write("local.get $l")
        self._indent -= 1
        self._write(")")

    def _emit_str_span_function(self) -> None:
        """``$str_span(chars: i32, a: i64, b: i64) -> (i32 ptr, i32 len)``
        - form a String as an O(1) view spanning code points ``[a, b)``
        of ``chars``, a ``List<String>`` whose every element is a
        one-code-point view (the per-character list the bundled JSON
        parser builds once per parse). Backs the internal
        ``_capa_str_span`` builtin.

        Each ``chars[p]`` is stored as a packed i64 (ptr in the low 32
        bits, byte length in the high 32) pointing at the UTF-8 bytes
        of code point ``p`` inside the input buffer. Because ``for c
        in s`` binds these views in input order with no copies, the
        bytes of code points ``a..b`` are exactly the contiguous run
        ``chars[a].ptr .. chars[b-1].ptr + chars[b-1].len``. The span
        is therefore ``(chars[a].ptr, end - chars[a].ptr)`` with NO
        walk from the buffer start and NO copy -- the result aliases
        the input buffer, which is safe in the bump heap (no free,
        strings immutable, and ``parse_json`` never grows the input in
        place; the escape path allocates a separate ``out``).

        Empty-span guard: ``a == b`` returns ``(0, 0)`` WITHOUT reading
        ``chars[b-1]`` (which would underflow at ``a == b == 0``). The
        bundled parser only ever passes ``0 <= a <= b <= length`` and
        the per-character views span the whole input, so the end byte
        never exceeds ``input.ptr + input.len``; this helper trusts the
        caller's range like the other ``__cj_*`` internals and is
        unreachable from user code (analyzer-gated)."""
        self._write(
            "(func $str_span (param $chars i32) (param $a i64) "
            "(param $b i64) (result i32 i32)"
        )
        self._indent += 1
        self._write("(local $ai i32)")
        self._write("(local $bi i32)")
        self._write("(local $data i32)")
        self._write("(local $start_ptr i32)")
        self._write("(local $last i64)")
        self._write("(local $end i32)")
        # ai = wrap(a); bi = wrap(b).
        self._write("local.get $a")
        self._write("i32.wrap_i64")
        self._write("local.set $ai")
        self._write("local.get $b")
        self._write("i32.wrap_i64")
        self._write("local.set $bi")
        # Empty span (a == b): return (0, 0) without touching chars.
        self._write("local.get $ai")
        self._write("local.get $bi")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # data = chars.data_ptr (List header: data_ptr at offset 8).
        self._write("local.get $chars")
        self._write("i32.load offset=8")
        self._write("local.set $data")
        # start_ptr = low32(chars[a]) = i32.load(data + a*8).
        self._write("local.get $data")
        self._write("local.get $ai")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i32.load")
        self._write("local.set $start_ptr")
        # last = chars[b-1] (packed i64 at data + (b-1)*8).
        self._write("local.get $data")
        self._write("local.get $bi")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $last")
        # end = low32(last) + high32(last) = last_ptr + last_len.
        self._write("local.get $last")
        self._write("i32.wrap_i64")
        self._write("local.get $last")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write("i32.add")
        self._write("local.set $end")
        # Result: (start_ptr, end - start_ptr).
        self._write("local.get $start_ptr")
        self._write("local.get $end")
        self._write("local.get $start_ptr")
        self._write("i32.sub")
        self._indent -= 1
        self._write(")")
